/**
 *		Tempesta FW
 *
 * HTTP message manipulation helpers for the protocol processing.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/ctype.h>

#undef DEBUG
#if DBG_HTTP_PARSER > 0
#define DEBUG DBG_HTTP_PARSER
#endif

#include "lib/str.h"
#include "gfsm.h"
#include "http_msg.h"
#include "http_parser.h"
#include "ss_skb.h"
#include "http_limits.h"

/*
 * Used during allocating from TfwPool first fragment for containing headers.
 * If room in TfwPool below than this constant a full page will be allocated.
 * Quite rare case when headers with framing data have a size below 128.
 */
#define MIN_HDR_FRAG_SIZE 128

/**
 * Build TfwStr representing HTTP header.
 * @name	- header name without ':';
 * @value	- header value;
 */
TfwStr *
tfw_http_msg_make_hdr(TfwPool *pool, const char *name, const char *val)
{
	size_t n_len = strlen(name);
	size_t v_len = val ? strlen(val) : 0;
	size_t n;
	TfwStr *hdr, *h_c;
	char *data;

	n = ((val ? 2 : 1) + 1) * sizeof(TfwStr) + n_len + v_len;
	hdr = (TfwStr *)tfw_pool_alloc(pool, n);
	if (!hdr)
		return NULL;
	TFW_STR_INIT(hdr);

	hdr->len = n_len + v_len;
	hdr->eolen = 2;
	hdr->nchunks = (val ? 2 : 1);
	hdr->chunks = hdr + 1;
	data = (char *)(TFW_STR_LAST(hdr) + 1);

	h_c = TFW_STR_CHUNK(hdr, 0);

	TFW_STR_INIT(h_c);
	h_c->data = data;
	h_c->len = n_len;
	tfw_cstrtolower_wo_avx2(data, name, n_len);

	if (val) {
		data += h_c->len;
		++h_c;

		TFW_STR_INIT(h_c);
		h_c->data = data;
		h_c->len = v_len;
		h_c->flags = TFW_STR_HDR_VALUE;
		memcpy(data, val, v_len);
	}

	return hdr;
}

/**
 * Find @hdr in @array. @array must be sorted in alphabetical
 * order. Similar to bsearch().
 */
const void *
__tfw_http_msg_find_hdr(const TfwStr *hdr, const void *array, size_t n,
			size_t member_sz)
{
	size_t start = 0, end = n;
	int result, fc;
	const TfwStr *h;

	if (!TFW_STR_DUP(hdr))
		h = hdr;
	else
		h = hdr->chunks;
	fc = tolower(*(unsigned char *)(TFW_STR_CHUNK(h, 0)->data));

	while (start < end) {
		size_t mid = start + (end - start) / 2;
		const TfwStr *sh = array + mid * member_sz;
		int sc = *(unsigned char *)sh->data;

		result = fc - sc;
		if (!result)
			result = tfw_stricmpspn(h, sh, ':');

		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return sh;
	}

	return NULL;
}

typedef struct {
	TfwStr			hdr;	/* Header name. */
	unsigned int		id;	/* id in TfwHttpHdrTbl */
} TfwHdrDef;
#define TfwStrDefV(v, id)	{{ .data = (v), SLEN(v), NULL, 0 }, (id) }

static inline unsigned int
__tfw_http_msg_spec_hid(const TfwStr *hdr, const TfwHdrDef array[],
			const size_t size)
{
	const TfwHdrDef *def;

	/* TODO: return error if @hdr can't be applied to response or client. */
	def = (TfwHdrDef *)__tfw_http_msg_find_hdr(hdr, array, size,
						   sizeof(TfwHdrDef));

	return def ? def->id : TFW_HTTP_HDR_RAW;
}

/**
 * Get header id in response header table for header @hdr.
 */
unsigned int
tfw_http_msg_resp_spec_hid(const TfwStr *hdr)
{
	static const TfwHdrDef resp_hdrs[] = {
		TfwStrDefV("age:",		TFW_HTTP_HDR_AGE),
		TfwStrDefV("connection:",	TFW_HTTP_HDR_CONNECTION),
		TfwStrDefV("content-encoding:", TFW_HTTP_HDR_CONTENT_ENCODING),
		TfwStrDefV("content-length:",	TFW_HTTP_HDR_CONTENT_LENGTH),
		TfwStrDefV("content-location:", TFW_HTTP_HDR_CONTENT_LOCATION),
		TfwStrDefV("content-type:",	TFW_HTTP_HDR_CONTENT_TYPE),
		TfwStrDefV("etag:",		TFW_HTTP_HDR_ETAG),
		TfwStrDefV("forwarded:",	TFW_HTTP_HDR_FORWARDED),
		TfwStrDefV("host:",		TFW_HTTP_HDR_HOST),
		TfwStrDefV("keep-alive:",	TFW_HTTP_HDR_KEEP_ALIVE),
		TfwStrDefV("referer:",		TFW_HTTP_HDR_REFERER),
		TfwStrDefV("server:",		TFW_HTTP_HDR_SERVER),
		TfwStrDefV("set-cookie:",	TFW_HTTP_HDR_SET_COOKIE),
		TfwStrDefV("transfer-encoding:",TFW_HTTP_HDR_TRANSFER_ENCODING),
		TfwStrDefV("x-forwarded-for:",	TFW_HTTP_HDR_X_FORWARDED_FOR),
		TfwStrDefV("x-tempesta-cache:",	TFW_HTTP_HDR_X_TEMPESTA_CACHE),
		TfwStrDefV("upgrade:",		TFW_HTTP_HDR_UPGRADE),
	};
	const size_t size = tfw_http_resp_header_table_size();

	BUILD_BUG_ON(ARRAY_SIZE(resp_hdrs) != size);

	return __tfw_http_msg_spec_hid(hdr, resp_hdrs, size);
}

/**
 * Get header id in request header table for header @hdr.
 */
unsigned int
tfw_http_msg_req_spec_hid(const TfwStr *hdr)
{
	static const TfwHdrDef req_hdrs[] = {
		TfwStrDefV("connection:",	TFW_HTTP_HDR_CONNECTION),
		TfwStrDefV("content-encoding:", TFW_HTTP_HDR_CONTENT_ENCODING),
		TfwStrDefV("content-length:",	TFW_HTTP_HDR_CONTENT_LENGTH),
		TfwStrDefV("content-type:",	TFW_HTTP_HDR_CONTENT_TYPE),
		TfwStrDefV("cookie:",		TFW_HTTP_HDR_COOKIE),
		TfwStrDefV("expect:",		TFW_HTTP_HDR_EXPECT),
		TfwStrDefV("forwarded:",	TFW_HTTP_HDR_FORWARDED),
		TfwStrDefV("host:",		TFW_HTTP_HDR_HOST),
		TfwStrDefV("if-none-match:",	TFW_HTTP_HDR_IF_NONE_MATCH),
		TfwStrDefV("keep-alive:",	TFW_HTTP_HDR_KEEP_ALIVE),
		TfwStrDefV("referer:",		TFW_HTTP_HDR_REFERER),
		TfwStrDefV("transfer-encoding:",TFW_HTTP_HDR_TRANSFER_ENCODING),
		TfwStrDefV("user-agent:",	TFW_HTTP_HDR_USER_AGENT),
		TfwStrDefV("x-forwarded-for:",	TFW_HTTP_HDR_X_FORWARDED_FOR),
		TfwStrDefV("x-tempesta-cache:",	TFW_HTTP_HDR_X_TEMPESTA_CACHE),
		TfwStrDefV("upgrade:",		TFW_HTTP_HDR_UPGRADE),
	};
	const size_t size = tfw_http_req_header_table_size();

	BUILD_BUG_ON(ARRAY_SIZE(req_hdrs) != size);

	return __tfw_http_msg_spec_hid(hdr, req_hdrs, size);
}

/**
 * Fills @val with second part of special HTTP/1.1 header containing the
 * header value.
 *
 * TODO: with the current HTTP-parser implementation (parsing header name,
 * colon, LWS and value into different chunks) this procedure can be
 * simplified to avoid the usage of predefined header arrays.
 */
void
__http_msg_hdr_val(TfwStr *hdr, unsigned id, TfwStr *val, bool client)
{
	static const unsigned char hdr_lens[2][TFW_HTTP_HDR_RAW] = {
		(unsigned char []) {
			[TFW_HTTP_HDR_HOST]		= SLEN("Host:"),
			[TFW_HTTP_HDR_CONTENT_ENCODING]	= SLEN("Content-Encoding:"),
			[TFW_HTTP_HDR_CONTENT_LENGTH]	= SLEN("Content-Length:"),
			[TFW_HTTP_HDR_CONTENT_LOCATION] = SLEN("Content-Location:"),
			[TFW_HTTP_HDR_CONTENT_TYPE]	= SLEN("Content-Type:"),
			[TFW_HTTP_HDR_AGE]		= SLEN("Age:"),
			[TFW_HTTP_HDR_CONNECTION]	= SLEN("Connection:"),
			[TFW_HTTP_HDR_EXPECT]		= SLEN("Expect:"),
			[TFW_HTTP_HDR_X_FORWARDED_FOR]	= SLEN("X-Forwarded-For:"),
			[TFW_HTTP_HDR_X_TEMPESTA_CACHE]	= SLEN("X-Tempesta-Cache:"),
			[TFW_HTTP_HDR_KEEP_ALIVE]	= SLEN("Keep-Alive:"),
			[TFW_HTTP_HDR_TRANSFER_ENCODING]= SLEN("Transfer-Encoding:"),
			[TFW_HTTP_HDR_SERVER]		= SLEN("Server:"),
			[TFW_HTTP_HDR_SET_COOKIE]	= SLEN("Set-Cookie:"),
			[TFW_HTTP_HDR_ETAG]		= SLEN("ETag:"),
			[TFW_HTTP_HDR_REFERER]		= SLEN("Referer:"),
			[TFW_HTTP_HDR_UPGRADE]		= SLEN("Upgrade:"),
			[TFW_HTTP_HDR_FORWARDED]	= SLEN("Forwarded:"),
		},
		(unsigned char []) {
			[TFW_HTTP_HDR_HOST]		= SLEN("Host:"),
			[TFW_HTTP_HDR_CONTENT_ENCODING]	= SLEN("Content-Encoding:"),
			[TFW_HTTP_HDR_CONTENT_LENGTH]	= SLEN("Content-Length:"),
			[TFW_HTTP_HDR_CONTENT_TYPE]	= SLEN("Content-Type:"),
			[TFW_HTTP_HDR_CONNECTION]	= SLEN("Connection:"),
			[TFW_HTTP_HDR_EXPECT]		= SLEN("Expect:"),
			[TFW_HTTP_HDR_X_FORWARDED_FOR]	= SLEN("X-Forwarded-For:"),
			[TFW_HTTP_HDR_X_TEMPESTA_CACHE]	= SLEN("X-Tempesta-Cache:"),
			[TFW_HTTP_HDR_KEEP_ALIVE]	= SLEN("Keep-Alive:"),
			[TFW_HTTP_HDR_TRANSFER_ENCODING]= SLEN("Transfer-Encoding:"),
			[TFW_HTTP_HDR_USER_AGENT]	= SLEN("User-Agent:"),
			[TFW_HTTP_HDR_COOKIE]		= SLEN("Cookie:"),
			[TFW_HTTP_HDR_IF_NONE_MATCH]	= SLEN("If-None-Match:"),
			[TFW_HTTP_HDR_REFERER]		= SLEN("Referer:"),
			[TFW_HTTP_HDR_UPGRADE]		= SLEN("Upgrade:"),
			[TFW_HTTP_HDR_FORWARDED]	= SLEN("Forwarded:"),
		},
	};
	TfwStr *c, *end;
	int nlen;

	/* Empty and plain strings don't have header value part. */
	if (unlikely(TFW_STR_PLAIN(hdr))) {
		TFW_STR_INIT(val);
		return;
	}
	BUG_ON(TFW_STR_DUP(hdr));
	BUG_ON(id >= TFW_HTTP_HDR_RAW);

	nlen = hdr_lens[client][id];
	/*
	 * Only Host header is allowed to be empty but because
	 * we don't follow RFC and allow Etag header to be not
	 * enclosed in double quotes it also can be empty.
	 * If header string is plain, it is always empty header.
	 * Not empty headers are compound strings.
	 */
	BUG_ON(id == TFW_HTTP_HDR_HOST
	       || id == TFW_HTTP_HDR_ETAG ? nlen > hdr->len : nlen >= hdr->len);

	*val = *hdr;

	/* Field value, if it exist, lies in the separate chunk.
	 * So we skip several first chunks, containing field name,
	 * to get the field value. If we have field with empty value,
	 * we get an empty string with val->len = 0 and val->data from the
	 * last name's chunk, but it is unimportant.
	 */
	for (c = hdr->chunks, end = hdr->chunks + hdr->nchunks;
	     c < end; ++c)
	{
		BUG_ON(!c->len);

		if (nlen > 0) {
			nlen -= c->len;
			val->len -= c->len;
		}
		else if (unlikely((c->data)[0] == ' '
				  || (c->data)[0] == '\t'))
		{
			/*
			 * RFC 7230: skip OWS before header field.
			 * In most cases OWS is on the same chunk with
			 * the header name.
			 * Header field-value always begins at new chunk.
			 */
			val->len -= c->len;
		}
		else {
			val->chunks = c;
			return;
		}
		BUG_ON(val->nchunks < 1);
		val->nchunks--;
	}

	/* Empty header value part. */
	TFW_STR_INIT(val);
}

void
__h2_msg_hdr_val(TfwStr *hdr, TfwStr *out_val)
{
	TfwStr *c, *end;

	if (unlikely(TFW_STR_PLAIN(hdr))) {
		TFW_STR_INIT(out_val);
		return;
	}

	BUG_ON(TFW_STR_DUP(hdr));

	*out_val = *hdr;

	TFW_STR_FOR_EACH_CHUNK(c, hdr, end) {
		if (c->flags & TFW_STR_HDR_VALUE) {
			out_val->chunks = c;
			return;
		}
		out_val->len -= c->len;
		out_val->nchunks--;
	}

	/* Empty header value part. */
	TFW_STR_INIT(out_val);
}

/**
 * Lookup for the header @hdr in already collected headers table @ht,
 * i.e. check whether the header is duplicate.
 * The lookup is performed until ':', so header name only is enough in @hdr.
 * @return the header id.
 */
unsigned int
tfw_http_msg_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	for (id = TFW_HTTP_HDR_RAW; id < ht->off; ++id) {
		TfwStr *h = &ht->tbl[id];
		/* There is no sense to compare against all duplicates. */
		if (h->flags & TFW_STR_DUPLICATE)
			h = TFW_STR_CHUNK(h, 0);
		if (!tfw_stricmpspn(hdr, h, ':'))
			break;
	}

	return id;
}

/**
 * Special procedure comparing the name or HPACK static index of @cmp_hdr (can
 * be in HTTP/2 or HTTP/1.1 format) against the header @hdr which also can be
 * in HTTP/2 or HTTP/1.1 format.
 */
int
__hdr_name_cmp(const TfwStr *hdr, const TfwStr *cmp_hdr)
{
	long n;
	int i1, i2, off1, off2;
	const TfwStr *c1, *c2;

	BUG_ON(hdr->flags & TFW_STR_DUPLICATE);
	BUG_ON(!cmp_hdr->len);

	if (cmp_hdr->hpack_idx && cmp_hdr->hpack_idx == hdr->hpack_idx)
		return 0;

	if (unlikely(!hdr->len))
		return 1;

	i1 = i2 = 0;
	off1 = off2 = 0;
	n = min(hdr->len, cmp_hdr->len);
	c1 = TFW_STR_CHUNK(hdr, 0);
	c2 = TFW_STR_CHUNK(cmp_hdr, 0);
	while (n) {
		int cn = min(c1->len - off1, c2->len - off2);

		if (tfw_cstricmp(c1->data + off1, c2->data + off2, cn))
			return 1;

		n -= cn;
		if (cn == c1->len - off1) {
			off1 = 0;
			++i1;
			c1 = TFW_STR_CHUNK(hdr, i1);
		} else {
			off1 += cn;
		}
		if (cn == c2->len - off2) {
			off2 = 0;
			++i2;
			c2 = TFW_STR_CHUNK(cmp_hdr, i2);
		} else {
			off2 += cn;
		}

		BUG_ON(n && (!c1 || !c2));

		/*
		 * Regardless of the header format (HTTP/2 or HTTP/1.1), the end
		 * of the name must match the end of the chunk, and the following
		 * chunk must contain value with appropriate flag (or it must
		 * contain just a single colon in case of HTTP/1.1-header).
		 */
		if (!off2) {
			const TfwStr *prev_c1;
			/*
			 * If @c2 or @c1 is NULL, then only name is contained in
			 * the @cmp_hdr or @hdr respectively.
			 */
			if (c2
			    && !(c2->flags & TFW_STR_HDR_VALUE)
			    && *c2->data != ':')
				continue;

			prev_c1 = TFW_STR_CHUNK(hdr, i1 - 1);

			if (!off1
			    && !(prev_c1->flags & TFW_STR_HDR_VALUE)
			    && (!c1
				|| c1->flags & TFW_STR_HDR_VALUE
				|| *c1->data == ':'))
				return 0;

			return 1;
		}
	}

	return 1;
}

/**
 * As @__hdr_lookup(), but intended for search during HTTP/1.1=>HTTP/2
 * and HTTP/2=>HTTP/1.1 transformations, comparing the specified name
 * headers in HTTP/2 or HTTP/1.1 format.
 */
int
__http_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	for (id = TFW_HTTP_HDR_RAW; id < ht->off; ++id) {
		TfwStr *h = &ht->tbl[id];
		/*
		 * We are looking only for the header's name matching,
		 * thus, there is no sense to compare against all duplicates.
		 */
		if (h->flags & TFW_STR_DUPLICATE)
			h = TFW_STR_CHUNK(h, 0);
		if (!__hdr_name_cmp(h, hdr))
			break;
	}

	return id;
}

/**
 * Open currently parsed header.
 */
void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start)
{
	TfwStr *hdr = &hm->stream->parser.hdr;

	BUG_ON(!TFW_STR_EMPTY(hdr));

	++hm->h_tbl->cnt;

	hdr->data = hdr_start;
	hdr->skb = ss_skb_peek_tail(&hm->msg.skb_head);

	BUG_ON(!hdr->skb);

	T_DBG3("open header at %p (char=[%c]), skb=%p\n",
	       hdr_start, *hdr_start, hdr->skb);
}

static void
tfw_http_req_calc_tfh_summ_for_raw_hdr(TfwHttpReq *req, TfwStr *hdr)
{
	const TfwStr *dup, *dup_end, *c, *chunk_end;
	size_t len = 0;
	unsigned int summ = 0;

#define TFW_CHAR4_INT(data)	*((u32 *)(data))
#define TFW_CHAR3_INT(data)	((data[2] << 16) | *((u16 *)(data)))
#define TFW_CHAR2_INT(data)	*((u16 *)(data))
#define TFW_CHAR_INT(data)	(data[0])
#define	HDR_LEN_MAX	4

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		TFW_STR_FOR_EACH_CHUNK(c, dup, chunk_end) {
			unsigned int curr_summ = 0;
			unsigned int curr_len = min(c->len, HDR_LEN_MAX - len);

			switch (curr_len) {
			case 4:
				curr_summ = TFW_CHAR4_INT(c->data);
				break;
			case 3:
				curr_summ = TFW_CHAR3_INT(c->data);
				break;
			case 2:
				curr_summ = TFW_CHAR2_INT(c->data);
				break;
			case 1:
				curr_summ = TFW_CHAR_INT(c->data);
				break;
			default:
				WARN_ON(1);
				return;
			}

			curr_summ <<= (len << 3);
			summ += curr_summ;
			len += curr_len;

			if (len == HDR_LEN_MAX)
				goto out;
		}
	}

out:
	COMPUTE_TF_ACCHASH(req->tfh.summ, summ);

#undef HDR_LEN_MAX
#undef TFW_CHAR_INT
#undef TFW_CHAR2_INT
#undef TFW_CHAR3_INT
#undef TFW_CHAR4_INT
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm)
{
	int r;
	TfwStr *hdr, *h;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwHttpParser *parser = &hm->stream->parser;
	unsigned int id = parser->_hdr_tag;
	bool is_srv_conn = TFW_CONN_TYPE(hm->conn) & Conn_Srv;

	BUG_ON(parser->hdr.flags & TFW_STR_DUPLICATE);
	BUG_ON(id > TFW_HTTP_HDR_RAW);

	/* Close just parsed header. */
	parser->hdr.flags |= TFW_STR_COMPLETE;

	/* Cumulate the trailer headers length */
	if (is_srv_conn && parser->hdr.flags & TFW_STR_TRAILER) {
		TfwHttpResp* resp = (TfwHttpResp*) hm;

		resp->trailers_len += parser->hdr.len +
			tfw_str_eolen(&parser->hdr);
	}

	/*
	 * We make this frang check here, because it is the earliest
	 * place where we can determine that new added header is violating
	 * appropriate frang limits. For HTTP2 we check it even earlier when
	 * we decode hpack.
	 */
	if (!is_srv_conn && !TFW_MSG_H2(hm) &&
	    ((r = frang_http_hdr_limit((TfwHttpReq *)hm,
				       parser->hdr.len)) != T_OK))
		return r;

	/* Quick path for special headers. */
	if (likely(id < TFW_HTTP_HDR_RAW)) {
		hdr = h = &ht->tbl[id];
		if (TFW_STR_EMPTY(hdr))
			/* Just store the special header in empty slot. */
			goto done;
		/*
		 * Process duplicate header.
		 *
		 * RFC 7230 3.2.2: all duplicates of special singular
		 * headers must be blocked as early as possible,
		 * just when parser reads them.
		 *
		 * RFC 9113 8.3: Pseudo-header fields MUST not appear
		 * in a trailer section.
		 * For H2 requests which are indexed, @parser->_hdr_tag
		 * would be obtained from the corresponding entry in either
		 * static or dynamic table.
		 * For H2 literal headers, @parser->_hdr_tag would be set
		 * during actual HTTP parsing.
		 */
		if (id < TFW_HTTP_HDR_NONSINGULAR) {
			if (!TFW_MSG_H2(hm) || id != TFW_HTTP_HDR_COOKIE)
				return -EINVAL;
		} else if (id != TFW_HTTP_HDR_X_FORWARDED_FOR &&
			   id != TFW_HTTP_HDR_FORWARDED) {
			/*
			 * RFC 7230 3.2.2: duplicate of non-singular special
			 * header - leave the decision to classification layer.
			 */
			__set_bit(TFW_HTTP_B_FIELD_DUPENTRY, hm->flags);
		}

		goto duplicate;
	}

	/*
	 * A new raw header is to be stored, but it can be a duplicate of some
	 * existing header and we must find appropriate index for it.
	 * Both the headers, the new one and existing one, can already be
	 * compound.
	 */
	id = __http_hdr_lookup(hm, &parser->hdr);

	/* Allocate some more room if not enough to store the header. */
	if (unlikely(id == ht->size)) {
		if ((r = tfw_http_msg_grow_hdr_tbl(hm)))
			return r;

		ht = hm->h_tbl;
	}

	hdr = h = &ht->tbl[id];

	if (TFW_STR_EMPTY(hdr))
		/* Add the new header. */
		goto done;

duplicate:
	if (parser->hdr.flags & TFW_STR_TRAILER)
		hdr->flags |=  TFW_STR_TRAILER_AND_HDR;

	h = tfw_str_add_duplicate(hm->pool, hdr);
	if (unlikely(!h)) {
		T_WARN("Cannot close header %p id=%d\n", &parser->hdr, id);
		return -ENOMEM;
	}

done:
	/*
	 * During response HTTP/1.1=>HTTP/2 transformation we need only regular
	 * headers to be transformed, and status-line must not be present in the
	 * resulting HTTP/2 response at all; thus, we do not need status-line in
	 * the indirection map.
	 */
	if (TFW_RESP_TO_H2(hm)
	    && id > TFW_HTTP_STATUS_LINE
	    && (r = tfw_h2_hdr_map((TfwHttpResp *)hm, hdr, id)))
		return r;

	*h = parser->hdr;

	if (!is_srv_conn) {
		TfwHttpReq *req = (TfwHttpReq *)hm;

		req->header_list_sz += h->len + TFW_HTTP_MSG_HDR_OVERHEAD(hm);
		req->headers_cnt++;
		HTTP_TFH_REQ_CALC_NUM(req, headers, TFW_HTTP_TFH_HEADERS_MAX,
				       1);
		if (likely(id < TFW_HTTP_HDR_RAW))
			COMPUTE_TF_ACCHASH(req->tfh.summ, id);
		else
			tfw_http_req_calc_tfh_summ_for_raw_hdr(req, h);
	}

	TFW_STR_INIT(&parser->hdr);
	T_DBG3("store header w/ ptr=%p len=%lu eolen=%u flags=%x id=%d\n",
	       h->data, h->len, h->eolen, h->flags, id);

	/* Move the offset forward if current header is fully read. */
	if (id == ht->off)
		ht->off++;

	return 0;
}

/**
 * Fixup the new data chunk starting at @data with length @len to @str.
 *
 * If @str is an empty string, then @len may not be zero. Please use
 * other means for making TfwStr{} strings with such special properties.
 *
 * If @str doesn't have the length set yet, then @len is more like
 * an offset from @data which is the current position in the string.
 * The actual length is set relative to the start of @str.
 *
 * @len might be 0 if the field was fully read, but we have realized
 * that just now by facing CRLF at the start of the current data chunk.
 */
int
__tfw_http_msg_add_str_data(TfwHttpMsg *hm, TfwStr *str, void *data, size_t len,
			    struct sk_buff *skb)
{
	if (WARN_ON_ONCE(str->flags & (TFW_STR_DUPLICATE | TFW_STR_COMPLETE)))
		return -EINVAL;

	T_DBG3("store field chunk len=%lu data=%pK(%c) field=<%pK,%#x,%lu,%pK>\n",
	       len, data, isprint(*(char *)data) ? *(char *)data : '.',
	       str, str->flags, str->len, str->data);

	if (TFW_STR_EMPTY(str)) {
		if (!str->data)
			__tfw_str_set_data(str, data, skb);
		str->len = data + len - (void *)str->data;
		BUG_ON(!str->len);
	} else if (likely(len)) {
		TfwStr *sn = tfw_str_add_compound(hm->pool, str);
		if (!sn) {
			T_WARN("Cannot grow HTTP data string\n");
			return -ENOMEM;
		}
		__tfw_str_set_data(sn, data, skb);
		tfw_str_updlen(str, data + len);
	}

	return 0;
}

int
tfw_http_msg_grow_hdr_tbl(TfwHttpMsg *hm)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	size_t order = ht->size / TFW_HTTP_HDR_NUM, new_order = order << 1;

	ht = tfw_pool_realloc(hm->pool, ht, TFW_HHTBL_SZ(order),
			      TFW_HHTBL_SZ(new_order));
	if (!ht)
		return -ENOMEM;
	ht->size = __HHTBL_SZ(new_order);
	ht->off = hm->h_tbl->off;
	bzero_fast(ht->tbl + __HHTBL_SZ(order),
		   __HHTBL_SZ(order) * sizeof(TfwStr));
	hm->h_tbl = ht;

	T_DBG3("grow http headers table to %d items\n", ht->size);

	return 0;
}

/**
 * Delete @str (any parsed part of HTTP message) from skb data and
 * init @str.
 */
int
tfw_http_msg_del_str(TfwHttpMsg *hm, TfwStr *str)
{
	int r;

	BUG_ON(TFW_STR_DUP(str));

	if ((r = ss_skb_cutoff_data(hm->msg.skb_head, str, 0, 0)))
		return r;

	TFW_STR_INIT(str);

	return 0;
}

/**
 * Remove flagged data and EOL from skb of TfwHttpMsg->body.
 *
 * WARNING: After this call TfwHttpMsg->body MUST not be used.
 */
int
tfw_http_msg_cutoff_body_chunks(TfwHttpResp *resp)
{
	int r;

	r = ss_skb_cutoff_data(resp->body.skb, &resp->cut, 0,
			       tfw_str_eolen(&resp->body) +
			       resp->trailers_len);
	if (unlikely(r))
		return r;

	resp->msg.len -= resp->cut.len;
	TFW_STR_INIT(&resp->body);

	return 0;
}

/**
 * Allocate and add a single empty skb (with a place for TCP headers though)
 * to the @hm iterator. The allocated skb has no space for the data, user is
 * expected to add new paged fragments.
 */
int
tfw_http_msg_append_skb(TfwHttpMsg *hm)
{
	TfwMsgIter *it = &hm->iter;
	int r;

	if ((r = ss_skb_alloc_data(&it->skb_head, 0)))
		return r;
	it->skb = ss_skb_peek_tail(&it->skb_head);
	it->frag = -1;

	skb_shinfo(it->skb)->flags = skb_shinfo(it->skb->prev)->flags;

	return 0;
}
EXPORT_SYMBOL(tfw_http_msg_append_skb);

void
tfw_http_msg_pair(TfwHttpResp *resp, TfwHttpReq *req)
{
	if (unlikely(resp->pair || req->pair))
		T_WARN("Response-Request pairing is broken!\n");

	resp->req = req;
	req->resp = resp;
}

void
tfw_http_msg_unpair(TfwHttpMsg *msg)
{
	if (!msg->pair)
		return;

	msg->pair->pair = NULL;
	msg->pair = NULL;
}

void
tfw_http_msg_free(TfwHttpMsg *m)
{
	T_DBG3("Free msg=%p\n", m);
	if (!m)
		return;

	tfw_http_msg_unpair(m);
	ss_skb_queue_purge(&m->msg.skb_head);

	if (m->destructor)
		m->destructor(m);

	if (TFW_MSG_H2(m))
		tfw_pool_destroy(((TfwHttpReq *)m)->pit.pool);

	tfw_pool_destroy(m->pool);
}

/**
 * Allocate a new HTTP message.
 * @full indicates how complex a message object is needed. When @full
 * is true, the message is set up and initialized with full support
 * for parsing and subsequent adjustment.
 */
TfwHttpMsg *
__tfw_http_msg_alloc(int type, bool full)
{
	TfwHttpMsg *hm = (type & Conn_Clnt)
			 ? (TfwHttpMsg *)tfw_pool_new(TfwHttpReq,
						      TFW_POOL_ZERO)
			 : (TfwHttpMsg *)tfw_pool_new(TfwHttpResp,
						      TFW_POOL_ZERO);
	if (!hm) {
		T_WARN("Insufficient memory to create %s message\n",
		       ((type & Conn_Clnt) ? "request" : "response"));
		return NULL;
	}

	if (full) {
		hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool,
							    TFW_HHTBL_SZ(1));
		if (unlikely(!hm->h_tbl)) {
			T_WARN("Insufficient memory to create header table"
			       " for %s\n",
			       ((type & Conn_Clnt) ? "request" : "response"));
			tfw_pool_destroy(hm->pool);
			return NULL;
		}
		hm->h_tbl->size = __HHTBL_SZ(1);
		hm->h_tbl->off = TFW_HTTP_HDR_RAW;
		bzero_fast(hm->h_tbl->tbl, __HHTBL_SZ(1) * sizeof(TfwStr));
	}

	hm->msg.skb_head = NULL;

	if (type & Conn_Clnt) {
		INIT_LIST_HEAD(&hm->msg.seq_list);
		INIT_LIST_HEAD(&((TfwHttpReq *)hm)->fwd_list);
		INIT_LIST_HEAD(&((TfwHttpReq *)hm)->nip_list);
		hm->destructor = tfw_http_req_destruct;
	}

	return hm;
}


/**
 * Expand message by @src placing it to tailroom or to curent fragment.
 * If room in current fragment not enough add new fragment. When number of
 * fragments will be equal to MAX_SKB_FRAGS allocate one more SKB.
 *
 * MUST be used only for messages from cache or messages constructed locally.
 */
int
tfw_http_msg_expand_data(TfwHttpMsg *hm, struct sk_buff **skb_head,
			 const TfwStr *src, unsigned int *start_off)
{
	TfwMsgIter *it = &hm->iter;
	const TfwStr *c, *end;

	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		char *p;
		unsigned long off = 0, cur_len, f_room, min_len;
this_chunk:
		if (!it->skb) {
			if (!(it->skb = ss_skb_alloc(SKB_MAX_HEADER)))
				return -ENOMEM;
			ss_skb_queue_tail(skb_head, it->skb);
			it->frag = -1;
			if (!it->skb_head)
				it->skb_head = *skb_head;

			if (start_off && *start_off) {
				skb_put(it->skb, *start_off);
				*start_off = 0;
			}

			T_DBG3("message expanded by new skb [%p]\n", it->skb);
		}
		else if (start_off && *start_off) {
			skb_frag_t *frag;
			struct page *page;

			if (it->frag + 1 == MAX_SKB_FRAGS) {
				it->skb = NULL;
				goto this_chunk;
			}

			page = alloc_page(GFP_ATOMIC);
			if (!page)
				return -ENOMEM;

			++it->frag;
			frag = &skb_shinfo(it->skb)->frags[it->frag];
			skb_fill_page_desc(it->skb, it->frag, page,
					   0, 0);
			skb_frag_size_add(frag, *start_off);
			ss_skb_adjust_data_len(it->skb, *start_off);
			*start_off = 0;
		}

		cur_len = c->len - off;
		if (it->frag >= 0) {
			unsigned int f_size;
			skb_frag_t *frag;

			frag = &skb_shinfo(it->skb)->frags[it->frag];
			f_size = skb_frag_size(frag);
			f_room = PAGE_SIZE - skb_frag_off(frag) - f_size;
			p = (char *)skb_frag_address(frag) + f_size;
			min_len = min(cur_len, f_room);
			skb_frag_size_add(frag, min_len);
			ss_skb_adjust_data_len(it->skb, min_len);
		} else {
			f_room = skb_tailroom(it->skb);
			min_len = min(cur_len, f_room);
			p = skb_put(it->skb, min_len);
		}

		memcpy_fast(p, c->data + off, min_len);

		if (cur_len >= f_room) {
			/*
			 * If the amount of skb frags is exhausted, allocate new
			 * skb on next iteration (if it will be).
			 */
			if (MAX_SKB_FRAGS <= it->frag + 1) {
				it->skb = NULL;
				it->frag = -1;
			}
			else if (cur_len != f_room || c + 1 < end) {
				struct page *page = alloc_page(GFP_ATOMIC);
				if (!page)
					return -ENOMEM;
				++it->frag;
				skb_fill_page_desc(it->skb, it->frag, page,
						   0, 0);
				T_DBG3("message expanded by new frag %u,"
				       " page=[%p], skb=[%p]\n",
				       skb_shinfo(it->skb)->nr_frags,
				       page_address(page), it->skb);
			}

			if (cur_len != f_room) {
				off += min_len;
				goto this_chunk;
			}
		}
	}

	return 0;
}

static void *
tfw_http_msg_alloc_from_pool(TfwMsgIter *it, TfwPool* pool, size_t size)
{
	int r;
	bool np;
	void *addr;
	struct skb_shared_info *si = skb_shinfo(it->skb);

	addr = tfw_pool_alloc_not_align_np(pool, size, &np);
	if (!addr)
		return ERR_PTR(-ENOMEM);

	if (np || it->frag == -1) {
		it->frag++;
		r = ss_skb_add_frag(it->skb_head, &it->skb, addr,
				    &it->frag, size);
		if (unlikely(r))
			return ERR_PTR(r);
	} else {
		skb_frag_size_add(&si->frags[it->frag], size);
	}

	ss_skb_adjust_data_len(it->skb, size);

	return addr;
}

/**
 * Add first paged fragment using TfwPool and reserve room for frame header.
 *
 * This function must be used as start point of message transformation. After
 * calling this you must use @pool only for allocating paged fragments during
 * message trasformation to prevent splitting continuous memory. If we
 * allocate TfwStr in the middle of encoding process, we got a gap between
 * data, which will split the paged fragment.
 */
int
tfw_http_msg_setup_transform_pool(TfwHttpTransIter *mit, TfwHttpMsg *msg,
				  TfwPool* pool)
{
	TfwMsgIter *it = &msg->iter;
	unsigned int room = TFW_POOL_CHUNK_ROOM(pool);
	char* addr;
	bool np;
	int r;

	BUG_ON(room < 0);

	/* Alloc a full page if room smaller than MIN_FRAG_SIZE. */
	if (room < MIN_HDR_FRAG_SIZE)
		addr = __tfw_pool_alloc_page(pool, FRAME_HEADER_SIZE, false);
	else
		addr = tfw_pool_alloc_not_align_np(pool, FRAME_HEADER_SIZE,
						   &np);

	if (unlikely(!addr))
		return -ENOMEM;

	it->frag++;
	r = ss_skb_add_frag(it->skb_head, &it->skb, addr, &it->frag,
			    FRAME_HEADER_SIZE);
	if (unlikely(r))
		return r;

	ss_skb_adjust_data_len(it->skb, FRAME_HEADER_SIZE);
	mit->frame_head = addr;

	return 0;
}

/*
 * Move body to @nskb if body located in current skb.
 * Return -errno in case of error, 0 if body was not
 * moved and 1 if body was moved.
 */
static inline int
__tfw_http_msg_move_body(TfwHttpMsg *hm, struct sk_buff *nskb, int *frag)
{
	TfwMsgIter *it = &hm->iter;
	struct sk_buff **body;
	TfwStr *c, *end;
	char *p;
	int r;
	const bool is_resp = TFW_CONN_TYPE(hm->conn) & Conn_Srv;

	if (test_bit(TFW_HTTP_B_CHUNKED, hm->flags) && is_resp) {
		TfwHttpResp *resp = (TfwHttpResp *)hm;

		p = resp->body_start_data;
		body = &resp->body_start_skb;
	} else {
		p = TFW_STR_CHUNK(&hm->body, 0)->data;
		body = &hm->body.skb;
	}

	if (*body != it->skb)
		return 0;

	if ((r = ss_skb_find_frag_by_offset(*body, p, frag)))
		return r;

	/* Move body to the next skb. */
	ss_skb_move_frags(it->skb, nskb, *frag,
			  skb_shinfo(it->skb)->nr_frags - *frag);
	/*
	 * After moving body, we should also update `resp->cut`
	 * to correct removing body flag data later.
	 */
	if (test_bit(TFW_HTTP_B_CHUNKED, hm->flags) && is_resp) {
		TfwHttpResp *resp = (TfwHttpResp *)hm;

		TFW_STR_FOR_EACH_CHUNK(c, &resp->cut, end) {
			if (c->skb != *body)
				break;
			c->skb = nskb;
		}
	}
	*body = nskb;

	return 1;
}

/*
 * Expand message by @str increasing size of current paged fragment or add
 * new paged fragment using @pool if room in current pool's chunk is not enough.
 * This function is called only for adding new response headers. If skb lenght
 * limit is reached, this function moves body fragments to the new skb and
 * update pointer to the body skb.
 */
static int
__tfw_http_msg_expand_from_pool(TfwHttpMsg *hm, const TfwStr *str,
				unsigned int *copied,
				void cpy(void *dest, const void *src, size_t n))
{
/**
 * Big number to unlimit skb data length, that enough to process skbs
 * with very large fragments. UINT_MAX / 2 is not something meaningful, it's
 * just a big value that must be enough to process any skb and not overflow
 * skb length in other places, wehre Tempesta modifies skb. e.g during inserting
 * frames or moving fragments from skb to skb. SS_SKB_MAX_DATA_LEN not enough
 * here, some received skbs may have bigger size due to using large fragments.
 * SS_SKB_MAX_DATA_LEN assumes that size of each fragment is limited by
 * PAGE_SIZE.
 */
#define MSG_SKB_MAX_DATA_LEN	(UINT_MAX / 2)

	const TfwStr *c, *end;
	unsigned int room, skb_room, n_copy, rlen, off, acc = 0;
	TfwMsgIter *it = &hm->iter;
	TfwPool* pool = hm->pool;
	void *addr;
	int r;

	if (WARN_ON(it->skb->len > MSG_SKB_MAX_DATA_LEN))
		return -E2BIG;

	TFW_STR_FOR_EACH_CHUNK(c, str, end) {
		rlen = c->len;

		while (rlen) {
			unsigned char nr_frags;

			room = TFW_POOL_CHUNK_ROOM(pool);
			BUG_ON(room < 0);

			/*
			 * Use available room in current pool chunk.
			 * If pool chunk is exhausted new page will be allocated.
			 */
			n_copy = room == 0 ? rlen : min(room, rlen);
			off = c->len - rlen;
			skb_room = MSG_SKB_MAX_DATA_LEN - it->skb->len;
			nr_frags = skb_shinfo(it->skb)->nr_frags;

			if (unlikely(skb_room == 0 || nr_frags == MAX_SKB_FRAGS))
			{
				struct sk_buff *nskb = ss_skb_alloc(0);
				bool body_was_moved = false;
				int frag;

				if (!nskb)
					return -ENOMEM;

				/*
				 * TODO #2136: Remove this flag during reworking
				 * this function. Try to process headers and
				 * trailers without moving body.
				 */
				if (hm->body.len > 0
			            && !test_bit(TFW_HTTP_B_RESP_ENCODE_TRAILERS,
						 hm->flags))
				{
					r = __tfw_http_msg_move_body(hm, nskb,
								     &frag);
					if (unlikely(r < 0)) {
						T_WARN("Error during moving body");
						return r;
					}
					body_was_moved = !!r;
				}

				skb_shinfo(nskb)->flags =
					skb_shinfo(it->skb)->flags;
				ss_skb_insert_after(it->skb, nskb);
				/*
				 * If body was moved to the new allocated skb
				 * we should use current skb.
				 */
				if (likely(!body_was_moved)) {
					it->skb = nskb;
					it->frag = -1;
				} else {
					it->frag = frag - 1;
				}

				skb_room = MSG_SKB_MAX_DATA_LEN - it->skb->len;
			}

			n_copy = min(n_copy, skb_room);

			addr = tfw_http_msg_alloc_from_pool(it, pool, n_copy);
			if (IS_ERR(addr))
				return PTR_ERR(addr);

			cpy(addr, c->data + off, n_copy);
			rlen -= n_copy;
			acc += n_copy;

			T_DBG3("%s: n_copy=%u",  __func__, n_copy);
		}
	}

	*copied = acc;

	return 0;

#undef MSG_SKB_MAX_DATA_LEN
}

int
tfw_http_msg_expand_from_pool(TfwHttpMsg *hm, const TfwStr *str)
{
	unsigned int n = 0;

	return __tfw_http_msg_expand_from_pool(hm, str, &n, memcpy_fast);
}

int
tfw_h2_msg_expand_from_pool(TfwHttpMsg *hm, const TfwStr *str,
			    TfwHttpTransIter *mit)
{
	int r;
	unsigned int n = 0;

	r = __tfw_http_msg_expand_from_pool(hm, str, &n, memcpy_fast);
	mit->acc_len += n;

	return r;
}

int
tfw_h2_msg_expand_from_pool_lc(TfwHttpMsg *hm, const TfwStr *str,
			       TfwHttpTransIter *mit)
{
	int r;
	unsigned int n = 0;

	r = __tfw_http_msg_expand_from_pool(hm, str, &n, tfw_cstrtolower);
	mit->acc_len += n;

	return r;
}

static inline void
__tfw_http_msg_move_frags(struct sk_buff *skb, int frag_idx,
			  TfwHttpMsgCleanup *cleanup)
{
	int i, len;
	struct skb_shared_info *si = skb_shinfo(skb);

	for (i = 0, len = 0; i < frag_idx; i++) {
		cleanup->pages[i] = skb_frag_netmem(&si->frags[i]);
		cleanup->pages_sz++;
		len += skb_frag_size(&si->frags[i]);
	}

	si->nr_frags -= frag_idx;
	ss_skb_adjust_data_len(skb, -len);
	memmove(&si->frags, &si->frags[frag_idx],
		(si->nr_frags) * sizeof(skb_frag_t));
}

static inline void
__tfw_http_msg_rm_all_frags(struct sk_buff *skb, TfwHttpMsgCleanup *cleanup)
{
	int i, len;
	struct skb_shared_info *si = skb_shinfo(skb);

	for (i = 0; i < si->nr_frags; i++)
		cleanup->pages[i] = skb_frag_netmem(&si->frags[i]);

	len = skb->data_len;
	cleanup->pages_sz = si->nr_frags;
	si->nr_frags = 0;
	ss_skb_adjust_data_len(skb, -len);
}

static inline void
__tfw_http_msg_shrink_frag(struct sk_buff *skb, int frag_idx, const char *nbegin)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[frag_idx];
	const int len = nbegin - (char*)skb_frag_address(frag);

	/* Add offset and decrease fragment's size */
	skb_frag_off_add(frag, len);
	skb_frag_size_sub(frag, len);
	ss_skb_adjust_data_len(skb, -len);
}

/*
 * Delete SKBs and paged fragments related to @hm that contains message
 * headers. SKBs and fragments will be "unlinked" and placed to @cleanup.
 * At this point we can't free SKBs, because data that they contain used
 * as source for message trasformation.
 */
int
tfw_http_msg_cutoff_headers(TfwHttpMsg *hm, TfwHttpMsgCleanup* cleanup)
{
	int i, r = 0;
	char *begin, *end;
	TfwMsgIter *it = &hm->iter;
	char* body = TFW_STR_CHUNK(&hm->body, 0)->data;
	TfwStr *crlf = TFW_STR_LAST(&hm->crlf);
	char *off = body ? body : crlf->data + (crlf->len - 1);
	unsigned int mark = hm->msg.skb_head->mark;

	do {
		struct sk_buff *skb;
		struct skb_shared_info *si = skb_shinfo(it->skb);

		if (skb_headlen(it->skb)) {
			begin = it->skb->data;
			end = begin + skb_headlen(it->skb);

			if (ss_skb_is_within_fragment(begin, off, end)) {
				/* We would end up here if the start of the body or
				 * the end of CRLF lies within the linear data area
				 * of the current @it->skb
				 */
				r = ss_skb_linear_transform(it->skb_head,
							    it->skb, body);
				break;
			} else {
				ss_skb_put(it->skb, -skb_headlen(it->skb));
				it->skb->tail_lock = 1;
			}
		}

		for (i = 0; i < si->nr_frags; i++) {
			skb_frag_t *f = &si->frags[i];

			begin = skb_frag_address(f);
			end = begin + skb_frag_size(f);

			if (!ss_skb_is_within_fragment(begin, off, end))
				continue;

			/*
			 * If response doesn't have body simply remove all
			 * fragments from skb where LF is located.
			 */
			if (!body) {
				__tfw_http_msg_rm_all_frags(it->skb, cleanup);
				goto end;
			} else if (off != begin) {
				/*
				 * Fragment contains headers and body.
				 * Set beginning of frag as beginning of body.
				 */
				__tfw_http_msg_shrink_frag(it->skb, i, off);
			}

			/*
			 * If body not in zero fragment save previous
			 * fragments for later cleanup and remove them
			 * from skb.
			 */
			if (i >= 1)
				__tfw_http_msg_move_frags(it->skb, i, cleanup);

			goto end;
		}

		skb = it->skb;
		it->skb = it->skb->next;
		ss_skb_unlink(&it->skb_head, skb);
		ss_skb_queue_tail(&cleanup->skb_head, skb);
	} while (it->skb != NULL);

end:
	/* Pointer to data or CRLF not found in skbs. */
	BUG_ON(!r && (!it->skb_head || !it->skb));

	it->skb_head = it->skb;
	hm->msg.skb_head = it->skb;
	hm->msg.skb_head->mark = mark;

	/* Start from zero fragment */
	it->frag = -1;

	return r;
}
