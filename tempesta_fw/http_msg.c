/**
 *		Tempesta FW
 *
 * HTTP message manipulation helpers for the protocol processing.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include "gfsm.h"
#include "http_msg.h"
#include "ss_skb.h"

/**
 * Fills @val with second part of special HTTP header containing the header
 * value.
 */
void
__http_msg_hdr_val(TfwStr *hdr, unsigned id, TfwStr *val, bool client)
{
	static const size_t hdr_lens[] = {
		[TFW_HTTP_HDR_HOST]	= SLEN("Host:"),
		[TFW_HTTP_HDR_CONTENT_LENGTH] = SLEN("Content-Length:"),
		[TFW_HTTP_HDR_CONTENT_TYPE] = SLEN("Content-Type:"),
		[TFW_HTTP_HDR_CONNECTION] = SLEN("Connection:"),
		[TFW_HTTP_HDR_X_FORWARDED_FOR] = SLEN("X-Forwarded-For:"),
		[TFW_HTTP_HDR_KEEP_ALIVE] = SLEN("Keep-Alive:"),
		[TFW_HTTP_HDR_TRANSFER_ENCODING] = SLEN("Transfer-Encoding:"),
		[TFW_HTTP_HDR_USER_AGENT] = SLEN("User-Agent:"),
		[TFW_HTTP_HDR_SERVER]	= SLEN("Server:"),
		[TFW_HTTP_HDR_COOKIE]	= SLEN("Cookie:"),
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

	if (unlikely(id == TFW_HTTP_HDR_SERVER && client))
		nlen = SLEN("User-Agent:");
	else
		nlen = hdr_lens[id];

	/*
	 * Only Host header is allowed to be empty.
	 * If header string is plain, it is always empty header.
	 * Not empty headers are compound strings.
	 */
	BUG_ON(id == TFW_HTTP_HDR_HOST ? nlen > hdr->len : nlen >= hdr->len);

	*val = *hdr;

	/* Field value, if it exist, lies in the separate chunk.
	 * So we skip several first chunks, containing field name,
	 * to get the field value. If we have field with empty value,
	 * we get an empty string with val->len = 0 and val->ptr from the
	 * last name's chunk, but it is unimportant.
	 */
	for (c = hdr->ptr, end = (TfwStr *)hdr->ptr + TFW_STR_CHUNKN(hdr);
	     c < end; ++c)
	{
		BUG_ON(!c->len);

		if (nlen > 0) {
			nlen -= c->len;
			val->len -= c->len;
		}
		else if (unlikely(((char *)c->ptr)[0] == ' '
				  || ((char *)c->ptr)[0] == '\t'))
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
			val->ptr = c;
			return;
		}
		BUG_ON(TFW_STR_CHUNKN(val) < 1);
		TFW_STR_CHUNKN_SUB(val, 1);
	}

	/* Empty header value part. */
	TFW_STR_INIT(val);
}
EXPORT_SYMBOL(__http_msg_hdr_val);

/**
 * Slow check of generic (raw) header for singularity.
 * Some of the header should be special and moved to tfw_http_hdr_t enum,
 * so linear search is Ok here.
 * @return true for headers which must never have duplicates.
 */
static bool
__hdr_is_singular(const TfwStr *hdr)
{
	int i, fc;
	static const TfwStr hdr_singular[] __read_mostly = {
#define TfwStr_string(v) { (v), NULL, sizeof(v) - 1, 0 }
		TfwStr_string("authorization:"),
		TfwStr_string("from:"),
		TfwStr_string("if-modified-since:"),
		TfwStr_string("if-unmodified-since:"),
		TfwStr_string("location:"),
		TfwStr_string("max-forwards:"),
		TfwStr_string("proxy-authorization:"),
		TfwStr_string("referer:"),
#undef TfwStr_string
	};

	fc = tolower(*(unsigned char *)TFW_STR_CHUNK(hdr, 0));
	for (i = 0; i < ARRAY_SIZE(hdr_singular); i++) {
		const TfwStr *sh = &hdr_singular[i];
		int sc = *(unsigned char *)sh->ptr;
		if (fc > sc)
			continue;
		if (fc < sc)
			break;
		if (!tfw_stricmpspn(hdr, sh, ':'))
			return true;
	}
	return false;
}

/**
 * Lookup for the header @hdr in already collected headers table @ht,
 * i.e. check whether the header is duplicate.
 * The lookup is performed untill ':', so header name only is enough in @hdr.
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
 */
static inline unsigned int
__hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	unsigned int id = tfw_http_msg_hdr_lookup(hm, hdr);

	if ((id <  hm->h_tbl->off) && __hdr_is_singular(hdr))
		hm->flags |= TFW_HTTP_FIELD_DUPENTRY;

	return id;
}

/**
 * Open currently parsed header.
 */
void
tfw_http_msg_hdr_open(TfwHttpMsg *hm, unsigned char *hdr_start)
{
	TfwStr *hdr = &hm->parser.hdr;

	BUG_ON(!TFW_STR_EMPTY(hdr));

	hdr->ptr = hdr_start;
	hdr->skb = ss_skb_peek_tail(&hm->msg.skb_list);

	BUG_ON(!hdr->skb);

	TFW_DBG3("open header at %p (char=[%c]), skb=%p\n",
		 hdr_start, *hdr_start, hdr->skb);
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, unsigned int id)
{
	TfwStr *h;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	BUG_ON(hm->parser.hdr.flags & TFW_STR_DUPLICATE);
	BUG_ON(id > TFW_HTTP_HDR_RAW);

	/* Close just parsed header. */
	hm->parser.hdr.flags |= TFW_STR_COMPLETE;

	/* Quick path for special headers. */
	if (likely(id < TFW_HTTP_HDR_RAW)) {
		h = &ht->tbl[id];
		if (TFW_STR_EMPTY(h))
			/* Just store the special header in empty slot. */
			goto done;

		/*
		 * Process duplicate header.
		 *
		 * RFC 7230 3.2.2: all duplicates of special singular
		 * headers must be blocked as early as possible,
		 * just when parser reads them.
		 */
		BUG_ON(id < TFW_HTTP_HDR_NONSINGULAR);
		/*
		 * RFC 7230 3.2.2: duplicate of non-singular special
		 * header - leave the decision to classification layer.
		 */
		hm->flags |= TFW_HTTP_FIELD_DUPENTRY;
		goto duplicate;
	}

	/*
	 * A new raw header is to be stored, but it can be a duplicate of some
	 * existing header and we must find appropriate index for it.
	 * Both the headers, the new one and existing one, can already be
	 * compound.
	 */
	id = __hdr_lookup(hm, &hm->parser.hdr);

	/* Allocate some more room if not enough to store the header. */
	if (unlikely(id == ht->size)) {
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return TFW_BLOCK;

		ht = hm->h_tbl;
	}

	h = &ht->tbl[id];

	if (TFW_STR_EMPTY(h))
		/* Add the new header. */
		goto done;

duplicate:
	h = tfw_str_add_duplicate(hm->pool, h);
	if (unlikely(!h)) {
		TFW_WARN("Cannot close header %p id=%d\n", &hm->parser.hdr, id);
		return TFW_BLOCK;
	}

done:
	*h = hm->parser.hdr;

	TFW_STR_INIT(&hm->parser.hdr);
	TFW_DBG3("store header w/ ptr=%p len=%lu eolen=%u flags=%x id=%d\n",
		 h->ptr, h->len, h->eolen, h->flags, id);

	/* Move the offset forward if current header is fully read. */
	if (id == ht->off)
		ht->off++;

	return TFW_PASS;
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
__tfw_http_msg_add_str_data(TfwHttpMsg *hm, TfwStr *str, void *data,
			    size_t len, struct sk_buff *skb)
{
	BUG_ON(str->flags & (TFW_STR_DUPLICATE | TFW_STR_COMPLETE));

	TFW_DBG3("store field chunk len=%lu data=%p(%c) field=<%#x,%lu,%p>\n",
		 len, data, isprint(*(char *)data) ? *(char *)data : '.',
		 str->flags, str->len, str->ptr);

	if (TFW_STR_EMPTY(str)) {
		if (!str->ptr)
			__tfw_http_msg_set_str_data(str, data, skb);
		str->len = data + len - str->ptr;
		BUG_ON(!str->len);
	}
	else if (likely(len)) {
		TfwStr *sn = tfw_str_add_compound(hm->pool, str);
		if (!sn) {
			TFW_WARN("Cannot grow HTTP data string\n");
			return -ENOMEM;
		}
		__tfw_http_msg_set_str_data(sn, data, skb);
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
	memset(ht->tbl + __HHTBL_SZ(order), 0,
	       __HHTBL_SZ(order) * sizeof(TfwStr));
	hm->h_tbl = ht;

	TFW_DBG3("grow http headers table to %d items\n", ht->size);

	return 0;
}

/**
 * Add new header @hdr to the message @hm just before CRLF.
 */
static int
__hdr_add(TfwHttpMsg *hm, const TfwStr *hdr, unsigned int hid)
{
	int r;
	TfwStr it = {};
	TfwStr *h = TFW_STR_CHUNK(&hm->crlf, 0);

	r = ss_skb_get_room(&hm->msg.skb_list, hm->crlf.skb,
			    h->ptr, tfw_str_total_len(hdr), &it);
	if (r)
		return r;

	tfw_str_fixup_eol(&it, tfw_str_eolen(hdr));
	if (tfw_strcpy(&it, hdr))
		return TFW_BLOCK;

	/*
	 * Initialize the header table item by the iterator chunks.
	 * While the data references in the item are valid, some convetions
	 * (e.g. header name and value are placed in different chunks) aren't
	 * satisfied. So don't consider the header for normal HTTP processing.
	 */
	hm->h_tbl->tbl[hid] = it;

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
	r = ss_skb_get_room(&hm->msg.skb_list,
			    h->skb, (char *)h->ptr + h->len,
			    append ? hdr->len : hdr->len - orig_hdr->len, &it);
	if (r)
		return r;

	if (tfw_strcat(hm->pool, orig_hdr, &it)) {
		TFW_WARN("Cannot concatenate hdr %.*s with %.*s\n",
			 PR_TFW_STR(orig_hdr), PR_TFW_STR(hdr));
		return TFW_BLOCK;
	}

	return tfw_strcpy(append ? &it : orig_hdr, hdr) ? TFW_BLOCK : 0;
}

/**
 * Delete header with identifier @hid from skb data and header table.
 */
static int
__hdr_del(TfwHttpMsg *hm, unsigned int hid)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dup, *end, *hdr = &ht->tbl[hid];

	/* Delete the underlying data. */
	TFW_STR_FOR_EACH_DUP(dup, hdr, end) {
		if (ss_skb_cutoff_data(&hm->msg.skb_list,
				       dup, 0, tfw_str_eolen(dup)))
			return TFW_BLOCK;
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
__hdr_sub(TfwHttpMsg *hm, char *name, size_t n_len, char *val, size_t v_len,
	  unsigned int hid)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dst, *tmp, *end, *orig_hdr = &ht->tbl[hid];
	TfwStr hdr = {
		.ptr = (TfwStr []){
			{ .ptr = name,	.len = n_len },
			{ .ptr = ": ",	.len = 2 },
			{ .ptr = val,	.len = v_len },
		},
		.len = n_len + 2 + v_len,
		.eolen = 2,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	TFW_STR_FOR_EACH_DUP(dst, orig_hdr, end) {
		if (dst->len < hdr.len)
			continue;
		/*
		 * Adjust @dst to have no more than @hdr.len bytes and rewrite
		 * the header in-place. Do not call @ss_skb_cutoff_data if no
		 * adjustment is needed.
		 */
		if (dst->len != hdr.len
		    && ss_skb_cutoff_data(&hm->msg.skb_list, dst, hdr.len, 0))
			return TFW_BLOCK;
		if (tfw_strcpy(dst, &hdr))
			return TFW_BLOCK;
		goto cleanup;
	}

	if (__hdr_expand(hm, orig_hdr, &hdr, false))
		return TFW_BLOCK;
	dst = TFW_STR_DUP(orig_hdr) ? __TFW_STR_CH(orig_hdr, 0) : orig_hdr;

cleanup:
	TFW_STR_FOR_EACH_DUP(tmp, orig_hdr, end) {
		if (tmp != dst
		    && ss_skb_cutoff_data(&hm->msg.skb_list,
					  tmp, 0, tfw_str_eolen(tmp)))
			return TFW_BLOCK;
	}

	*orig_hdr = *dst;
	return TFW_PASS;
}

/**
 * Transform HTTP message @hm header with identifier @hid.
 * Raw header transforers must provide the header name by @name and @n_len.
 * If @val is NULL, then the header will be deleted from @hm.
 * If @hm already has the header it will be replaced by the new header
 * unless @append.
 * If @append is true, then @val will be concatenated to current
 * header with @hid and @name, otherwise a new header will be created
 * if the message has no the header.
 *
 * Note: The substitute string @new_hdr has CRLF as EOL. The original
 * string @orig_hdr may have a single LF as EOL. We may want to follow
 * the EOL pattern of the original. For that, the EOL of @new_hdr needs
 * to be made the same as in the original header field string.
 *
 * TODO accept TfwStr as header value.
 */
int
tfw_http_msg_hdr_xfrm(TfwHttpMsg *hm, char *name, size_t n_len,
		      char *val, size_t v_len, unsigned int hid, bool append)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *orig_hdr;
	TfwStr new_hdr = {
		.ptr = (TfwStr []){
			{ .ptr = name,	.len = n_len },
			{ .ptr = ": ",	.len = 2 },
			{ .ptr = val,	.len = v_len },
		},
		.len = n_len + 2 + v_len,
		.eolen = 2,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	BUG_ON(!val && v_len);

	/* Firstly, get original message header to transform. */
	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		if (TFW_STR_EMPTY(orig_hdr) && !val)
			/* Not found, nothing to delete. */
			return 0;
	} else {
		hid = __hdr_lookup(hm, &new_hdr);
		if (hid == ht->off && !val)
			/* Not found, nothing to delete. */
			return 0;
		if (hid == ht->size)
			if (tfw_http_msg_grow_hdr_tbl(hm))
				return -ENOMEM;
		orig_hdr = &ht->tbl[hid];
	}

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		TFW_WARN("Appending to nonsingular header %d\n", hid);
		return -ENOENT;
	}

	if (TFW_STR_EMPTY(orig_hdr)) {
		if (unlikely(!val))
			return 0;
		return __hdr_add(hm, &new_hdr, hid);
	}

	if (!val)
		return __hdr_del(hm, hid);

	if (append) {
		TfwStr hdr_app = {
			.ptr = (TfwStr []){
				{ .ptr = ", ",	.len = 2 },
				{ .ptr = val,	.len = v_len }
			},
			.len = v_len + 2,
			.flags = 2 << TFW_STR_CN_SHIFT
		};
		return __hdr_expand(hm, orig_hdr, &hdr_app, true);
	}

	return __hdr_sub(hm, name, n_len, val, v_len, hid);
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
 * Add a header, probably duplicated, without any checking of current headers.
 */
int
tfw_http_msg_hdr_add(TfwHttpMsg *hm, TfwStr *hdr)
{
	unsigned int hid;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	hid = ht->off;
	if (hid == ht->size)
		if (tfw_http_msg_grow_hdr_tbl(hm))
			return -ENOMEM;
	++ht->off;

	return __hdr_add(hm, hdr, hid);
}

/**
 * Allocate skb space for further @hm data writing.
 * Put as much as possible to one skb, TCP GSO will care about segmentation.
 *
 * tfw_http_msg_free() is expected to be called for @hm if the function fails.
 */
static int
__msg_alloc_skb_data(TfwHttpMsg *hm, size_t len)
{
	int i_skb, nr_skbs = DIV_ROUND_UP(len, SS_SKB_MAX_DATA_LEN);
	struct sk_buff *skb;

	for (i_skb = 0; i_skb < nr_skbs; ++i_skb) {
		skb = ss_skb_alloc_pages(min(len, SS_SKB_MAX_DATA_LEN));
		if (!skb)
			return -ENOMEM;
		ss_skb_queue_tail(&hm->msg.skb_list, skb);
	}

	return 0;
}

/**
 * Initialize @hm or allocate an HTTP message if it's NULL.
 * Sets @hm up with empty SKB space of size @data_len for data writing.
 * An iterator @it is set up to support consecutive writes.
 *
 * This function is intended to work together with tfw_http_msg_write()
 * that uses the @it iterator.
 * Use dynamic allocation if you need to do the message transformations
 * (e.g. adjust headers) and avoid it if you just need to send the message.
 */
TfwHttpMsg *
tfw_http_msg_create(TfwHttpMsg *hm, TfwMsgIter *it, int type, size_t data_len)
{
	if (hm) {
		memset(hm, 0, sizeof(*hm));
		ss_skb_queue_head_init(&hm->msg.skb_list);
		INIT_LIST_HEAD(&hm->msg.msg_list);
		if (__msg_alloc_skb_data(hm, data_len))
			return NULL;
	} else {
		if (!(hm = tfw_http_msg_alloc(type)))
			return NULL;
		if (__msg_alloc_skb_data(hm, data_len)) {
			tfw_http_msg_free(hm);
			return NULL;
		}
	}

	it->skb = ss_skb_peek(&hm->msg.skb_list);
	it->frag = 0;

	BUG_ON(!it->skb);
	BUG_ON(!skb_shinfo(it->skb)->nr_frags);

	TFW_DBG2("Created new HTTP message %p: type=%d len=%lu\n",
		 hm, type, data_len);
	return hm;
}
EXPORT_SYMBOL(tfw_http_msg_create);

/*
 * Fill up an HTTP message @hm with data from string @data.
 * This is a quick message creator which doesn't properly initialized
 * the message structure like headers table. So @hm couldn't be used in
 * HTTP message transformations.
 *
 * An iterator @it is used to support multiple calls to this functions after
 * set up. This function can only be called after a call to
 * tfw_http_msg_create(). It works only with empty SKB space prepared by
 * the function.
 */
int
tfw_http_msg_write(TfwMsgIter *it, TfwHttpMsg *hm, const TfwStr *data)
{
	const TfwStr *c, *end;
	skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];
	unsigned int c_off = 0, f_size, c_size, f_room, n_copy;

	BUG_ON(TFW_STR_DUP(data));
	TFW_STR_FOR_EACH_CHUNK(c, data, end) {
this_chunk:
		if (!frag)
			return -E2BIG;

		c_size = c->len - c_off;
		f_size = skb_frag_size(frag);
		f_room = PAGE_SIZE - frag->page_offset - f_size;
		n_copy = min(c_size, f_room);

		memcpy((char *)skb_frag_address(frag) + f_size,
		       (char *)c->ptr + c_off, n_copy);
		skb_frag_size_add(frag, n_copy);
		ss_skb_adjust_data_len(it->skb, n_copy);

		if (c_size < f_room) {
			/*
			 * The chunk has fit in the SKB fragment with room
			 * to spare. Stay in the same SKB fragment, swith
			 * to next chunk of the string.
			 */
			c_off = 0;
		} else {
			frag = ss_skb_frag_next(&it->skb, &it->frag);
			/*
			 * If all data from the chunk has been copied,
			 * then switch to next chunk. Otherwise, stay
			 * in the current chunk.
			 */
			if (c_size == f_room) {
				c_off = 0;
			} else {
				c_off += n_copy;
				goto this_chunk;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(tfw_http_msg_write);

/**
 * Like tfw_http_msg_write(), but properly initialize HTTP message fields,
 * so it can be used in regular transformations.
 * However, the header name and value aren't splitted into different chunks,
 * so advanced headers matching aren't available for @hm.
 */
int
tfw_http_msg_add_data(TfwMsgIter *it, TfwHttpMsg *hm, TfwStr *field,
		      const TfwStr *data)
{
	char *p;
	skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];
	unsigned int d_off = 0, f_size, d_size, f_room, n_copy;

	BUG_ON(TFW_STR_DUP(data));
	BUG_ON(!TFW_STR_PLAIN(data));

next_frag:
	if (!frag)
		return -E2BIG;

	d_size = data->len - d_off;
	f_size = skb_frag_size(frag);
	f_room = PAGE_SIZE - frag->page_offset - f_size;
	n_copy = min(d_size, f_room);
	if (!n_copy)
		return 0;

	p = (char *)skb_frag_address(frag) + f_size;
	memcpy(p, (char *)data->ptr + d_off, n_copy);
	skb_frag_size_add(frag, n_copy);
	ss_skb_adjust_data_len(it->skb, n_copy);

	if (__tfw_http_msg_add_str_data(hm, field, p, n_copy, it->skb))
		return -ENOMEM;

	if (d_size > f_room) {
		frag = ss_skb_frag_next(&it->skb, &it->frag);
		d_off += n_copy;
		goto next_frag;
	}

	return 0;
}

void
tfw_http_msg_free(TfwHttpMsg *m)
{
	TFW_DBG3("Free msg=%p\n", m);
	if (!m)
		return;

	ss_skb_queue_purge(&m->msg.skb_list);

	if (m->destructor)
		m->destructor(m);
	tfw_pool_destroy(m->pool);
}
EXPORT_SYMBOL(tfw_http_msg_free);

/**
 * Add spec header indexes to list of hop-by-hop headers.
 */
static inline void
__hbh_parser_init_req(TfwHttpReq *req)
{
	TfwHttpHbhHdrs *hbh_hdrs = &req->parser.hbh_parser;

	BUG_ON(hbh_hdrs->spec);
	/* Connection is hop-by-hop header by RFC 7230 6.1 */
	hbh_hdrs->spec = 0x1 << TFW_HTTP_HDR_CONNECTION;
}

/**
 * Same as @__hbh_parser_init_req for response.
 */
static inline void
__hbh_parser_init_resp(TfwHttpResp *resp)
{
	TfwHttpHbhHdrs *hbh_hdrs = &resp->parser.hbh_parser;

	BUG_ON(hbh_hdrs->spec);
	/*
	 * Connection is hop-by-hop header by RFC 7230 6.1
	 *
	 * Server header isn't defined as hop-by-hop by the RFC, but we
	 * don't show protected server to world.
	 */
	hbh_hdrs->spec = (0x1 << TFW_HTTP_HDR_CONNECTION) |
			 (0x1 << TFW_HTTP_HDR_SERVER);

}

/**
 * Allocate a new HTTP message.
 * Given the total message length as @data_len, it allocates an appropriate
 * number of SKBs and page fragments to hold the payload, and sets them up
 * in Tempesta message.
 */
TfwHttpMsg *
tfw_http_msg_alloc(int type)
{
	TfwHttpMsg *hm = (type & Conn_Clnt)
			 ? (TfwHttpMsg *)tfw_pool_new(TfwHttpReq,
						      TFW_POOL_ZERO)
			 : (TfwHttpMsg *)tfw_pool_new(TfwHttpResp,
						      TFW_POOL_ZERO);
	if (!hm)
		return NULL;

	hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool, TFW_HHTBL_SZ(1));
	if (unlikely(!hm->h_tbl)) {
		TFW_WARN("Insufficient memory to create message\n");
		tfw_pool_destroy(hm->pool);
		return NULL;
	}

	hm->h_tbl->size = __HHTBL_SZ(1);
	hm->h_tbl->off = TFW_HTTP_HDR_RAW;
	memset(hm->h_tbl->tbl, 0, __HHTBL_SZ(1) * sizeof(TfwStr));

	ss_skb_queue_head_init(&hm->msg.skb_list);
	INIT_LIST_HEAD(&hm->msg.msg_list);

	hm->parser.to_read = -1; /* unknown body size */
	if (type & Conn_Clnt)
		__hbh_parser_init_req((TfwHttpReq *)hm);
	else
		__hbh_parser_init_resp((TfwHttpResp *)hm);

	if (type & Conn_Clnt)
		hm->destructor = tfw_http_req_destruct;

	return hm;
}
