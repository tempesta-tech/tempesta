/**
 *		Tempesta FW
 *
 * HTTP message manipulation helpers for the protocol processing.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2023 Tempesta Technologies, Inc.
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
			[TFW_HTTP_HDR_CONNECTION]	= SLEN("Connection:"),
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
 * Slow check of generic (raw) header for singularity.
 * Some of the header should be special and moved to tfw_http_hdr_t enum,
 * so linear search is Ok here.
 * @return true for headers which must never have duplicates.
 */
static inline bool
__hdr_is_singular(const TfwStr *hdr)
{
	static const TfwStr hdr_singular[] = {
		TFW_STR_STRING("authorization:"),
		TFW_STR_STRING("from:"),
		TFW_STR_STRING("if-unmodified-since:"),
		TFW_STR_STRING("location:"),
		TFW_STR_STRING("max-forwards:"),
		TFW_STR_STRING("proxy-authorization:"),
		TFW_STR_STRING("referer:"),
	};

	return tfw_http_msg_find_hdr(hdr, hdr_singular);
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
 * Certain header fields are strictly singular and may not be repeated in
 * an HTTP message. Duplicate of a singular header fields is a bug worth
 * blocking the whole HTTP message.
 *
 * TODO: with the current HTTP-parser implementation (parsing header name,
 * colon, LWS and value into different chunks) we can avoid slow string
 * matcher, which is used in @tfw_http_msg_hdr_lookup(), and can compare
 * strings just by chunks (including searching the stop character) for both
 * HTTP/2 and HTTP/1.1 formatted headers (see @__hdr_name_cmp() below).
 * Thus, @__h1_hdr_lookup() and @tfw_http_msg_hdr_lookup() procedures should
 * be unified to @__hdr_name_cmp() and @__http_hdr_lookup() in order to
 * substitute current mess of multiple partially duplicated procedures with
 * one simple interface.
 */
static inline unsigned int
__h1_hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id = tfw_http_msg_hdr_lookup(hm, hdr);

	if ((id < hm->h_tbl->off) && __hdr_is_singular(hdr))
		__set_bit(TFW_HTTP_B_FIELD_DUPENTRY, hm->flags);

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
	if (parser->hdr.flags & TFW_STR_TRAILER) {
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
 * Add new header @hdr to the message @hm just before CRLF.
 */
static int
__hdr_add(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid)
{
	int r;
	TfwStr *dst;
	TfwStr it = {};
	TfwStr *h = TFW_STR_CHUNK(&hm->crlf, 0);

	r = ss_skb_get_room(hm->msg.skb_head, hm->crlf.skb, h->data,
			    tfw_str_total_len(hdr), &it);
	if (r)
		return r;

	tfw_str_fixup_eol(&it, tfw_str_eolen(hdr));
	dst = tfw_strcpy_comp_ext(hm->pool, &it, hdr);
	if (unlikely(!dst))
		return -ENOMEM;

	/*
	 * Initialize the header table item by the iterator chunks.
	 * While the data references in the item are valid, some conventions
	 * (e.g. header name and value are placed in different chunks) aren't
	 * satisfied. So don't consider the header for normal HTTP processing.
	 */
	hm->h_tbl->tbl[hid] = *dst;

	return 0;
}

/**
 * Expand @orig_hdr by appending or replacing with the @hdr.
 * (CRLF is not accounted in TfwStr representation of HTTP headers).
 *
 * Expand the first duplicate header, do not produce more duplicates.
 */
static int
__hdr_expand(TfwHttpMsg *hm, TfwStr *orig_hdr, const TfwStr *hdr, bool append)
{
	int r;
	TfwStr *h, it = {};

	if (TFW_STR_DUP(orig_hdr))
		orig_hdr = __TFW_STR_CH(orig_hdr, 0);
	BUG_ON(!append && (hdr->len < orig_hdr->len));

	h = TFW_STR_LAST(orig_hdr);
	r = ss_skb_get_room(hm->msg.skb_head, h->skb, h->data + h->len,
			    append ? hdr->len : hdr->len - orig_hdr->len, &it);
	if (r)
		return r;

	if ((r = tfw_strcat(hm->pool, orig_hdr, &it))) {
		T_WARN("Cannot concatenate hdr %.*s with %.*s\n",
		       PR_TFW_STR(orig_hdr), PR_TFW_STR(hdr));
		return r;
	}

	return tfw_strcpy(append ? &it : orig_hdr, hdr);
}

/**
 * Delete header with identifier @hid from skb data and header table.
 */
static int
__hdr_del(TfwHttpMsg *hm, unsigned int hid)
{
	int r = 0;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dup, *end, *hdr = &ht->tbl[hid];

	/* Delete the underlying data. */
	TFW_STR_FOR_EACH_DUP(dup, hdr, end) {
		if ((r = ss_skb_cutoff_data(hm->msg.skb_head, dup, 0,
					    tfw_str_eolen(dup))))
			return r;
	};

	/* Delete the header from header table. */
	if (hid < TFW_HTTP_HDR_RAW) {
		TFW_STR_INIT(&ht->tbl[hid]);
	} else {
		if (hid < ht->off - 1)
			memmove(&ht->tbl[hid], &ht->tbl[hid + 1],
				(ht->off - hid - 1) * sizeof(TfwStr));
		--ht->off;
	}

	return 0;
}

/**
 * Substitute header value.
 *
 * The original header may have LF or CRLF as it's EOL and such bytes are
 * not a part of a header field string in Tempesta (at the moment). While
 * substitution, we may want to follow the EOL pattern of the original. So,
 * if the substitute string without the EOL fits into original header, then
 * the fast path can be used. Otherwise, original header is expanded to fit
 * substitute.
 */
static int
__hdr_sub(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid)
{
	int r;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dst, *tmp, *end, *orig_hdr = &ht->tbl[hid];

	TFW_STR_FOR_EACH_DUP(dst, orig_hdr, end) {
		if (dst->len < hdr->len)
			continue;
		/*
		 * Adjust @dst to have no more than @hdr.len bytes and rewrite
		 * the header in-place. Do not call @ss_skb_cutoff_data if no
		 * adjustment is needed.
		 */
		if (dst->len != hdr->len
		    && (r = ss_skb_cutoff_data(hm->msg.skb_head, dst,
					       hdr->len, 0)))
			return r;
		if ((r = tfw_strcpy(dst, hdr)))
			return r;
		goto cleanup;
	}

	if ((r = __hdr_expand(hm, orig_hdr, hdr, false)))
		return r;
	dst = TFW_STR_DUP(orig_hdr) ? __TFW_STR_CH(orig_hdr, 0) : orig_hdr;

cleanup:
	TFW_STR_FOR_EACH_DUP(tmp, orig_hdr, end) {
		if (tmp != dst
		    && (r = ss_skb_cutoff_data(hm->msg.skb_head, tmp, 0,
					       tfw_str_eolen(tmp))))
			return r;
	}

	*orig_hdr = *dst;
	return 0;
}

/**
 * Transform HTTP message @hm header with identifier @hid.
 * @hdr must be compound string and contain two or three parts:
 * header name, colon and header value. If @hdr value is empty,
 * then the header will be deleted from @hm.
 * If @hm already has the header it will be replaced by the new header
 * unless @append.
 * If @append is true, then @val will be concatenated to current
 * header with @hid and @name, otherwise a new header will be created
 * if the message has no the header.
 *
 * Note: The substitute string @hdr should have CRLF as EOL. The original
 * string @orig_hdr may have a single LF as EOL. We may want to follow
 * the EOL pattern of the original. For that, the EOL of @hdr needs
 * to be made the same as in the original header field string.
 *
 * Note: In case of response transformation from HTTP/1.1 to HTTP/2, for
 * optimization purposes, we use special add/replace procedures to adjust
 * headers and create HTTP/2 representation at once; for headers deletion
 * procedure there is no sense to use special HTTP/2 handling (the header
 * must not exist in the resulting response); in case of headers appending
 * we at first create the usual HTTP/1.1 representation of the final header
 * and then transform it into HTTP/2 form at the common stage of response
 * HTTP/2 transformation - we have no other choice, since we need a full
 * header for going through the HTTP/2 transformation (i.e. search in the
 * HPACK encoder dynamic index).
 */
int
tfw_http_msg_hdr_xfrm_str(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid,
			  bool append)
{
	int r;
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *orig_hdr = NULL;
	const TfwStr *s_val = TFW_STR_CHUNK(hdr, 2);

	if (unlikely(!ht)) {
		T_WARN("Try to adjust lightweight response.");
		return -EINVAL;
	}

	/* Firstly, get original message header to transform. */
	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		if (TFW_STR_EMPTY(orig_hdr) && !s_val)
			/* Not found, nothing to delete. */
			return 0;
	} else {
		hid = __h1_hdr_lookup(hm, hdr);
		if (hid == ht->off && !s_val)
			/* Not found, nothing to delete. */
			return 0;
		if (hid == ht->size) {
			if ((r = tfw_http_msg_grow_hdr_tbl(hm)))
				return r;
			ht = hm->h_tbl;
		}
		if (hid == ht->off)
			++ht->off;
		else
			orig_hdr = &ht->tbl[hid];
	}

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		T_WARN("Appending to singular header '%.*s'\n",
		       PR_TFW_STR(TFW_STR_CHUNK(hdr, 0)));
		return 0;
	}

	if (!orig_hdr || TFW_STR_EMPTY(orig_hdr)) {
		if (unlikely(!s_val))
			return 0;
		return __hdr_add(hm, hdr, hid);
	}

	if (!s_val)
		return __hdr_del(hm, hid);

	if (append) {
		TfwStr hdr_app = {
			.chunks = (TfwStr []){
				{ .data = ", ",		.len = 2 },
				{ .data = s_val->data,	.len = s_val->len }
			},
			.len = s_val->len + 2,
			.nchunks = 2
		};
		return __hdr_expand(hm, orig_hdr, &hdr_app, true);
	}

	return __hdr_sub(hm, hdr, hid);
}

/**
 * Same as @tfw_http_msg_hdr_xfrm_str() but use c-strings as argument.
 */
int
tfw_http_msg_hdr_xfrm(TfwHttpMsg *hm, char *name, size_t n_len,
		      char *val, size_t v_len, unsigned int hid, bool append)
{
	TfwStr new_hdr = {
		.chunks = (TfwStr []){
			{ .data = name,		.len = n_len },
			{ .data = S_DLM,	.len = SLEN(S_DLM) },
			{ .data = val,		.len = v_len },
		},
		.len = n_len + SLEN(S_DLM) + v_len,
		.eolen = 2,
		.nchunks = (val ? 3 : 2)
	};

	BUG_ON(!val && v_len);

	return tfw_http_msg_hdr_xfrm_str(hm, &new_hdr, hid, append);
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
 * Remove hop-by-hop headers in the message
 *
 * Connection header should not be removed, tfw_http_set_hdr_connection()
 * optimize removal of the header.
 */
int
tfw_http_msg_del_hbh_hdrs(TfwHttpMsg *hm)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	unsigned int hid = ht->off;
	int r = 0;

	do {
		hid--;
		if (hid == TFW_HTTP_HDR_CONNECTION)
			continue;
		if (ht->tbl[hid].flags & TFW_STR_HBH_HDR)
			if ((r = __hdr_del(hm, hid)))
				return r;
	} while (hid);

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
 * Add a header, probably duplicated, without any checking of current headers.
 * In case of response transformation from HTTP/1.1 to HTTP/2, for optimization
 * purposes, we use special handling for headers adding (see note for
 * @tfw_http_msg_hdr_xfrm_str() for details).
 */
int
tfw_http_msg_hdr_add(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int hid;
	TfwHttpHdrTbl *ht;

	ht = hm->h_tbl;
	hid = ht->off;
	if (hid == ht->size) {
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return -ENOMEM;
		ht = hm->h_tbl;
	}
	++ht->off;

	return __hdr_add(hm, hdr, hid);
}

/**
 * Set up @hm with empty SKB space of size @data_len for data writing.
 * Set up the iterator @it to support consecutive writes.
 *
 * This function is intended to work together with tfw_msg_write()
 * or tfw_http_msg_add_data() which use the @it iterator.
 *
 * @hm must be allocated dynamically (NOT statically) as it may have
 * to sit in a queue long after the caller has finished. It's assumed
 * that @hm is properly initialized.
 *
 * It's essential to understand, that "properly initialized" for @hm
 * may mean different things depending on the intended use. Currently
 * this function is called to send a response from cache, or to send
 * an error response. An error response is not parsed or adjusted, so
 * a shorter/faster version of message allocation and initialization
 * may be used. (See __tfw_http_msg_alloc(full=False)).
 */
int
tfw_http_msg_setup(TfwHttpMsg *hm, TfwMsgIter *it, size_t data_len,
		   unsigned int tx_flags)
{
	int r;

	if ((r = tfw_msg_iter_setup(it, &hm->msg.skb_head, data_len, tx_flags)))
		return r;
	T_DBG2("Set up HTTP message %pK with %lu bytes data\n", hm, data_len);

	return 0;
}
EXPORT_SYMBOL(tfw_http_msg_setup);

/**
 * Fill up an HTTP message by iterator @it with data from string @data.
 * Properly maintain @hm header @field, so that @hm can be used in regular
 * transformations. However, the header name and the value are not split into
 * different chunks, so advanced headers matching is not available for @hm.
 */
int
tfw_http_msg_add_data(TfwMsgIter *it, TfwHttpMsg *hm, TfwStr *field,
		      const TfwStr *data)
{
	const TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(data));
	if (WARN_ON_ONCE(it->frag >= skb_shinfo(it->skb)->nr_frags))
		return -E2BIG;

	TFW_STR_FOR_EACH_CHUNK(c, data, end) {
		char *p;
		unsigned int c_off = 0, c_size, f_room, n_copy;
this_chunk:
		c_size = c->len - c_off;
		if (it->frag >= 0) {
			unsigned int f_size;
			skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];

			f_size = skb_frag_size(frag);
			f_room = PAGE_SIZE - frag->bv_offset - f_size;
			p = (char *)skb_frag_address(frag) + f_size;
			n_copy = min(c_size, f_room);
			skb_frag_size_add(frag, n_copy);
			ss_skb_adjust_data_len(it->skb, n_copy);
		} else {
			f_room = skb_tailroom(it->skb);
			n_copy = min(c_size, f_room);
			p = skb_put(it->skb, n_copy);
		}

		memcpy_fast(p, c->data + c_off, n_copy);
		if (field && n_copy
		    && __tfw_http_msg_add_str_data(hm, field, p, n_copy,
						   it->skb))
		{
			return -ENOMEM;
		}

		/*
		 * The chunk occupied all the spare space in the SKB fragment,
		 * switch to the next fragment.
		 */
		if (c_size >= f_room) {
			if (WARN_ON_ONCE(tfw_msg_iter_next_data_frag(it)
					 && ((c_size != f_room)
					     || (c + 1 < end))))
			{
				return -E2BIG;
			}
			/*
			 * Not all data from the chunk has been copied,
			 * stay in the current chunk and copy the rest to the
			 * next fragment.
			 */
			if (c_size != f_room) {
				c_off += n_copy;
				goto this_chunk;
			}
		}
	}

	return 0;
}

void
tfw_http_msg_pair(TfwHttpResp *resp, TfwHttpReq *req)
{
	if (unlikely(resp->pair || req->pair))
		T_WARN("Response-Request pairing is broken!\n");

	resp->req = req;
	req->resp = resp;
}

static void
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
tfw_http_msg_expand_data(TfwMsgIter *it, struct sk_buff **skb_head,
			 const TfwStr *src, unsigned int *start_off)
{
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
			if (!it->skb_head) {
				it->skb_head = *skb_head;

				if (start_off && *start_off) {
					skb_put(it->skb_head, *start_off);
					*start_off = 0;
				}
			}

			T_DBG3("message expanded by new skb [%p]\n", it->skb);
		}

		cur_len = c->len - off;
		if (it->frag >= 0) {
			unsigned int f_size;
			skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];

			f_size = skb_frag_size(frag);
			f_room = PAGE_SIZE - frag->bv_offset - f_size;
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

static int
tfw_http_msg_alloc_from_pool(TfwHttpTransIter *mit, TfwPool* pool, size_t size)
{
	int r;
	bool np;
	char* addr;
	TfwMsgIter *it = &mit->iter;
	struct sk_buff *skb = it->skb;
	struct skb_shared_info *si = skb_shinfo(skb);

	addr = tfw_pool_alloc_not_align_np(pool, size, &np);
	if (!addr)
		return -ENOMEM;

	if (np || it->frag == -1) {
		r = ss_skb_add_frag(it->skb_head, skb, addr, ++it->frag, size);
		if (unlikely(r))
			return r;
	} else {
		skb_frag_size_add(&si->frags[it->frag], size);
	}

	ss_skb_adjust_data_len(skb, size);
	mit->curr_ptr = addr;

	return 0;
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
tfw_http_msg_setup_transform_pool(TfwHttpTransIter *mit, TfwPool* pool)
{
	int r;
	char* addr;
	bool np;
	TfwMsgIter *it = &mit->iter;
	unsigned int room = TFW_POOL_CHUNK_ROOM(pool);

	BUG_ON(room < 0);
	BUG_ON(mit->iter.frag > 0);

	/* Alloc a full page if room smaller than MIN_FRAG_SIZE. */
	if (room < MIN_HDR_FRAG_SIZE)
		addr = __tfw_pool_alloc_page(pool, FRAME_HEADER_SIZE, false);
	else
		addr = tfw_pool_alloc_not_align_np(pool, FRAME_HEADER_SIZE,
						   &np);

	if (unlikely(!addr))
		return -ENOMEM;

	r = ss_skb_add_frag(it->skb_head, it->skb, addr, ++it->frag,
			    FRAME_HEADER_SIZE);
	if (unlikely(r))
		return r;

	ss_skb_adjust_data_len(mit->iter.skb, FRAME_HEADER_SIZE);
	mit->frame_head = addr;
	mit->curr_ptr = addr + FRAME_HEADER_SIZE;

	return 0;
}

/*
 * Move body to @nskb if body located in current skb.
 */
static inline int
__tfw_http_msg_move_body(TfwHttpResp *resp, struct sk_buff *nskb)
{
	TfwMsgIter *it = &resp->mit.iter;
	struct sk_buff **body;
	int r, frag;
	char *p;

	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags)) {
		p = resp->body_start_data;
		body = &resp->body_start_skb;
	} else {
		p = TFW_STR_CHUNK(&resp->body, 0)->data;
		body = &resp->body.skb;
	}

	if (*body != it->skb)
		return 0;

	if ((r = ss_skb_find_frag_by_offset(*body, p, &frag)))
		return r;

	/* Move body to the next skb. */
	ss_skb_move_frags(it->skb, nskb, frag,
			  skb_shinfo(it->skb)->nr_frags - frag);
	*body = nskb;

	return 0;
}

static inline int
__tfw_http_msg_linear_transform(TfwMsgIter *it)
{
	/*
	 * There is no sense to move linear part if next skb has linear
	 * part as well and current skb has max frags.
	 */
	if (skb_shinfo(it->skb)->nr_frags == MAX_SKB_FRAGS
	    && skb_headlen(it->skb->next))
	{
		struct sk_buff *nskb = ss_skb_alloc(0);

		if (!nskb)
			return -ENOMEM;

		skb_shinfo(nskb)->tx_flags = skb_shinfo(it->skb)->tx_flags;
		ss_skb_insert_before(&it->skb_head, it->skb, nskb);
		it->skb = nskb;
		it->frag = -1;

		return 0;
	} else {
		return ss_skb_linear_transform(it->skb_head, it->skb,
					       it->skb->data);
	}
}

/*
 * Expand message by @str increasing size of current paged fragment or add
 * new paged fragment using @pool if room in current pool's chunk is not enough.
 * This function is called only for adding new response headers. If skb lenght
 * limit is reached, this function moves body fragments to the new skb and
 * update pointer to the body skb.
 */
static int
__tfw_http_msg_expand_from_pool(TfwHttpResp *resp, const TfwStr *str,
				void cpy(void *dest, const void *src, size_t n))
{
	const TfwStr *c, *end;
	unsigned int room, skb_room, n_copy, rlen, off;
	int r;
	TfwHttpTransIter *mit = &resp->mit;
	TfwMsgIter *it = &mit->iter;
	TfwPool* pool = resp->pool;

	BUG_ON(it->skb->len > SS_SKB_MAX_DATA_LEN);

	/*
	 * Move linear data to paged fragment before inserting data into skb.
	 * We must do it, because we want to insert new data "before" linear.
	 * For instance: We want to insert headers. Linear data contains part
	 * of the body, if we insert headers without moving linear part,
	 * headers will be inserted after the body or between the body chunks.
	 */
	if (skb_headlen(it->skb)) {
		if (unlikely((r = __tfw_http_msg_linear_transform(it))))
			return r;
	}

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
			skb_room = SS_SKB_MAX_DATA_LEN - it->skb->len;
			nr_frags = skb_shinfo(it->skb)->nr_frags;

			if (unlikely(skb_room == 0 || nr_frags == MAX_SKB_FRAGS))
			{
				struct sk_buff *nskb = ss_skb_alloc(0);

				if (!nskb)
					return -ENOMEM;

				if (resp->body.len > 0) {
					r = __tfw_http_msg_move_body(resp,
								     nskb);
					if (unlikely(r)) {
						T_WARN("Error during moving body");
						return r;
					}
				}

				skb_shinfo(nskb)->tx_flags =
					skb_shinfo(it->skb)->tx_flags;
				ss_skb_insert_after(it->skb, nskb);
				/*
				 * If body is located in the zero fragment and
				 * takes all SS_SKB_MAX_DATA_LEN bytes, we move
				 * it to the next skb and continue use current
				 * skb.
				 */
				if (likely(nskb->len < SS_SKB_MAX_DATA_LEN))
					it->skb = nskb;

				it->frag = -1;
				skb_room = SS_SKB_MAX_DATA_LEN - it->skb->len;
			}

			n_copy = min(n_copy, skb_room);

			r = tfw_http_msg_alloc_from_pool(mit, pool, n_copy);
			if (unlikely(r))
				return r;

			cpy(mit->curr_ptr, c->data + off, n_copy);
			rlen -= n_copy;
			mit->acc_len += n_copy;

			T_DBG3("%s: acc_len=%lu, n_copy=%u, mit->curr_ptr=%pK",
			       __func__, mit->acc_len,
			       n_copy, mit->curr_ptr);
		}
	}

	return 0;
}

int
tfw_http_msg_expand_from_pool(TfwHttpResp *resp, const TfwStr *str)
{
	return __tfw_http_msg_expand_from_pool(resp, str, memcpy_fast);
}

int
tfw_http_msg_expand_from_pool_lc(TfwHttpResp *resp, const TfwStr *str)
{
	return __tfw_http_msg_expand_from_pool(resp, str, tfw_cstrtolower);
}

static inline void
__tfw_h2_msg_move_frags(struct sk_buff *skb, int frag_idx,
			TfwHttpRespCleanup *cleanup)
{
	int i, len;
	struct page *page;
	struct skb_shared_info *si = skb_shinfo(skb);

	for (i = 0, len = 0; i < frag_idx; i++) {
		page = skb_frag_page(&si->frags[i]);
		cleanup->pages[i] = compound_head(page);
		cleanup->pages_sz++;
		len += skb_frag_size(&si->frags[i]);
	}

	si->nr_frags -= frag_idx;
	ss_skb_adjust_data_len(skb, -len);
	memmove(&si->frags, &si->frags[frag_idx],
		(si->nr_frags) * sizeof(skb_frag_t));
}

static inline void
__tfw_h2_msg_rm_all_frags(struct sk_buff *skb, TfwHttpRespCleanup *cleanup)
{
	int i, len;
	struct page *page;
	struct skb_shared_info *si = skb_shinfo(skb);

	for (i = 0; i < si->nr_frags; i++) {
		page = skb_frag_page(&si->frags[i]);
		cleanup->pages[i] = compound_head(page);
	}

	len = skb->data_len;
	cleanup->pages_sz = si->nr_frags;
	si->nr_frags = 0;
	ss_skb_adjust_data_len(skb, -len);
}

static inline void
__tfw_h2_msg_shrink_frag(struct sk_buff *skb, int frag_idx, const char *nbegin)
{
	skb_frag_t *frag = &skb_shinfo(skb)->frags[frag_idx];
	const int len = nbegin - (char*)skb_frag_address(frag);

	/* Add offset and decrease fragment's size */
	skb_frag_off_add(frag, len);
	skb_frag_size_sub(frag, len);
	ss_skb_adjust_data_len(skb, -len);
}

/*
 * Delete SKBs and paged fragments related to @resp that contains response
 * headers. SKBs and fragments will be "unlinked" and placed to @cleanup.
 * At this point we can't free SKBs, because data that they contain used
 * as source for message trasformation.
 */
int
tfw_h2_msg_cutoff_headers(TfwHttpResp *resp, TfwHttpRespCleanup* cleanup)
{
	int i, ret;
	char *begin, *end;
	TfwMsgIter *it = &resp->mit.iter;
	char* body = TFW_STR_CHUNK(&resp->body, 0)->data;
	TfwStr *crlf = TFW_STR_LAST(&resp->crlf);
	char *off = body ? body : crlf->data + crlf->len;

	do {
		struct sk_buff *skb;
		struct skb_shared_info *si = skb_shinfo(it->skb);

		if (skb_headlen(it->skb)) {
			begin = it->skb->data;
			end = begin + skb_headlen(it->skb);

			if ((begin <= off) && (end >= off)) {
				it->frag = -1;
				/* We would end up here if the start of the body or
				 * the end of CRLF lies within the linear data area
				 * of the current @it->skb
				 */
				ret = ss_skb_linear_transform(it->skb_head,
							      it->skb, body);
				if (unlikely(ret))
					return ret;
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

			if (begin > off || end < off)
				continue;

			/*
			 * If body exists and headers ends in current skb that
			 * has only one fragment and contains only headers
			 * just remove the fragment from skb and continue
			 * to use this skb as head. If response doesn't have
			 * body simply remove all fragments from skb where
			 * LF is located.
			 */
			if (!body || (si->nr_frags == 1 && off == end)) {
				__tfw_h2_msg_rm_all_frags(it->skb, cleanup);
				goto end;
			} else if (off != begin) {
				/*
				 * Fragment contains headers and body.
				 * Set beginning of frag as beginning of body.
				 */
				__tfw_h2_msg_shrink_frag(it->skb, i, off);
			}

			/*
			 * If body not in zero fragment save previous
			 * fragments for later cleanup and remove them
			 * from skb.
			 */
			if (i >= 1)
				__tfw_h2_msg_move_frags(it->skb, i, cleanup);

			goto end;
		}

		skb = it->skb;
		it->skb = it->skb->next;
		ss_skb_unlink(&it->skb_head, skb);
		ss_skb_queue_tail(&cleanup->skb_head, skb);
	} while (it->skb != NULL);

end:
	/* Pointer to data or CRLF not found in skbs. */
	BUG_ON(!it->skb_head || !it->skb);

	it->skb_head = it->skb;
	resp->msg.skb_head = it->skb;

	/* Start from zero fragment */
	it->frag = -1;

	return 0;
}

/**
 * Insert data from string @data to message at offset defined by message
 * iterator @it and @off. This function doesn't maintain message structure.
 * After insertion message iterator and @data will point at the start of
 * inserted data fragment.
 */
int
tfw_http_msg_insert(TfwMsgIter *it, char **off, const TfwStr *data)
{
	int r;
	TfwStr dst = {};

	if ((r = ss_skb_get_room_w_frag(it->skb_head, it->skb, *off, data->len,
					&dst, &it->frag)))
	{
		return r;
	}

	*off = dst.data;
	it->skb = dst.skb;

	return tfw_strcpy(&dst, data);
}
