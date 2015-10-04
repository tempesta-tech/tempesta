/**
 *		Tempesta FW
 *
 * HTTP message manipulation helpers for the protocol processing.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/ctype.h>

#include "gfsm.h"
#include "http_msg.h"
#include "lib.h"
#include "ss_skb.h"

/**
 * Fills @val with second part of special HTTP header containing the header
 * value.
 */
void
tfw_http_msg_hdr_val(TfwStr *hdr, int id, TfwStr *val)
{
	static const size_t hdr_lens[] = {
		[TFW_HTTP_HDR_HOST]	= sizeof("Host:") - 1,
		[TFW_HTTP_HDR_CONTENT_LENGTH] = sizeof("Content-Length:") - 1,
		[TFW_HTTP_HDR_CONTENT_TYPE] = sizeof("Content-Type:") - 1,
		[TFW_HTTP_HDR_CONNECTION] = sizeof("Connection:") - 1,
		[TFW_HTTP_HDR_X_FORWARDED_FOR] = sizeof("X-Forwarded-For:") - 1,
	};

	TfwStr *c;
	int nlen = hdr_lens[id];

	BUG_ON(TFW_STR_PLAIN(hdr));
	BUG_ON(TFW_STR_DUP(hdr));
	BUG_ON(nlen >= hdr->len);
	BUG_ON(id >= TFW_HTTP_HDR_RAW);

	*val = *hdr;

	TFW_STR_FOR_EACH_CHUNK(c, hdr, {
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
			break;
		}
		TFW_STR_CHUNKN_SUB(val, 1);
	});

	val->ptr = c;
}
EXPORT_SYMBOL(tfw_http_msg_hdr_val);

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
		TfwStr_string("content-type:"),
		TfwStr_string("from:"),
		TfwStr_string("if-modified-since:"),
		TfwStr_string("if-unmodified-since:"),
		TfwStr_string("location:"),
		TfwStr_string("max-forwards:"),
		TfwStr_string("proxy-authorization:"),
		TfwStr_string("referer:"),
		TfwStr_string("user-agent:"),
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
 *
 * Certain header fields are strictly singular and may not be repeated in
 * an HTTP message. Duplicate of a singular header fields is a bug worth
 * blocking the whole HTTP message.
 */
static int
__hdr_lookup(TfwHttpMsg *hm, const TfwStr *hdr)
{
	int id;
	TfwHttpHdrTbl *ht = hm->h_tbl;

	for (id = TFW_HTTP_HDR_RAW; id < ht->off; ++id) {
		TfwStr *h = &ht->tbl[id];
		/* There is no sense to compare against all duplicates. */
		if (h->flags & TFW_STR_DUPLICATE)
			h = TFW_STR_CHUNK(h, 0);
		if (tfw_stricmpspn(hdr, h, ':'))
			continue;
		if (__hdr_is_singular(hdr))
			hm->flags |= TFW_HTTP_FIELD_DUPENTRY;
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
	TfwStr *hdr = &hm->parser.hdr;

	BUG_ON(!TFW_STR_EMPTY(hdr));

	hdr->ptr = hdr_start;
	hdr->skb = ss_skb_peek_tail(&hm->msg.skb_list);

	BUG_ON(!hdr->skb);

	TFW_DBG3("open header at char [%c], skb=%p\n", *hdr_start, hdr->skb);
}

/**
 * Fixup the new data chunk to currently parsed HTTP field.
 *
 * @len could be 0 if the field was fully read, but we realized this only
 * now by facinng CRLF at begin of current data chunk.
 */
void
tfw_http_msg_field_chunk_fixup(TfwHttpMsg *hm, TfwStr *field,
			       char *data, int len)
{
	BUG_ON(field->flags & TFW_STR_DUPLICATE);

	TFW_DBG3("store field chunk len=%d data=%p field=<%#x,%u,%p>\n",
		 len, data, field->flags, field->len, field->ptr);

	/* The header should be open before. */
	if (unlikely(!field->ptr))
		return;

	if (TFW_STR_EMPTY(field)) {
		/*
		 * The first data chunk case.
		 * The header chunk was explicitly opened at some data
		 * position, so close the chunk by end of @data.
		 */
		BUG_ON(!TFW_STR_PLAIN(field));
		field->len = data + len - (char *)field->ptr;
	}
	else if (len) {
		/*
		 * The data chunk doesn't lay at the header bounds.
		 * There is at least one finished chunk, add a new one.
		 */
		TfwStr *last = tfw_str_add_compound(hm->pool, field);
		if (unlikely(!last)) {
			TFW_WARN("Cannot store chunk [%.*s]\n",
				 min((int)len, 10), data);
			return;
		}
		tfw_http_msg_set_data(hm, last, data);
		tfw_str_updlen(field, data + len);
	}
}

/**
 * Fixup the new data chunk to currently parsed HTTP header.
 *
 * @len could be 0 if the header was fully read, but we realized this only
 * now by facinng CRLF at begin of current data chunk.
 */
void
tfw_http_msg_hdr_chunk_fixup(TfwHttpMsg *hm, char *data, int len)
{
	tfw_http_msg_field_chunk_fixup(hm, &hm->parser.hdr, data, len);
}

/**
 * Store fully parsed, probably compound, header (i.e. close it) to
 * HTTP message headers list.
 */
int
tfw_http_msg_hdr_close(TfwHttpMsg *hm, int id)
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
	TFW_DBG3("store header w/ ptr=%p len=%d flags=%x id=%d\n",
		 h->ptr, h->len, h->flags, id);

	/* Move the offset forward if current header is fully read. */
	if (id == ht->off)
		ht->off++;

	return TFW_PASS;
}

int
tfw_http_msg_add_data_ptr(TfwHttpMsg *hm, TfwStr *str, void *data, size_t len)
{
	if (TFW_STR_EMPTY(str)) {
		tfw_http_msg_set_data(hm, str, data);
		str->len = len;
	} else {
		TfwStr *sn = tfw_str_add_compound(hm->pool, str);
		if (!sn) {
			TFW_WARN("Cannot grow HTTP data string\n");
			return -ENOMEM;
		}
		tfw_http_msg_set_data(hm, sn, data);
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
__hdr_add(TfwHttpMsg *hm, TfwStr *hdr, int hid)
{
	int r;
	TfwStr it = {};
	TfwStr *h = TFW_STR_CHUNK(&hm->crlf, 0);

	r = ss_skb_get_room(hm->crlf.skb, h->ptr, hdr->len, &it);
	if (r)
		return r;

	hm->h_tbl->tbl[hid] = *hdr;
	if (tfw_strcpy(&it, hdr))
		return TFW_BLOCK;

	return 0;
}

/**
 * Insert ', @hdr' at the end of @orig_hdr
 * (CRLF is not accounted in TfwStr representation of HTTP headers).
 *
 * Append to first duplicate header, do not produce more duplicates.
 */
static int
__hdr_append(TfwHttpMsg *hm, TfwStr *orig_hdr, const TfwStr *hdr)
{
	int r;
	TfwStr *h = TFW_STR_LAST(orig_hdr);
	TfwStr it = {};

	if (TFW_STR_DUP(orig_hdr))
		orig_hdr = __TFW_STR_CH(orig_hdr, 0);

	r = ss_skb_get_room(orig_hdr->skb, (char *)h->ptr + h->len,
			    hdr->len, &it);
	if (r)
		return r;

	if (tfw_strcpy(&it, hdr))
		return TFW_BLOCK;
	if (tfw_strcat(hm->pool, orig_hdr, &it))
		TFW_WARN("Cannot concatenate hdr %.*s with %.*s\n",
			 orig_hdr->len, (char *)orig_hdr->ptr,
			 hdr->len, (char *)hdr->ptr);

	return 0;
}

/**
 * Delete header with identifier @hid from skb data and header table.
 */
static int
__hdr_del(TfwHttpMsg *hm, int hid)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *dup, *end, *hdr = &ht->tbl[hid];

	/* Delete the underlying data. */
	TFW_STR_FOR_EACH_DUP(dup, hdr, end) {
		if (ss_skb_cutoff_data(&hm->msg.skb_list, dup, 0, 2))
			return TFW_BLOCK;
	};

	/* Delete the header from header table. */
	if (hid < TFW_HTTP_HDR_RAW) {
		TFW_STR_INIT(&ht->tbl[hid]);
	} else {
		if (hid < ht->off - 1)
			memmove(&ht->tbl[hid], &ht->tbl[hid + 1],
				ht->off - hid - 1);
		--ht->off;
	}

	return 0;
}

/**
 * Substitute header value.
 */
static int
__hdr_sub(TfwHttpMsg *hm, char *name, size_t n_len, char *val, size_t v_len,
	  int hid)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *orig_hdr = &ht->tbl[hid];
	TfwStr hdr = {
		.ptr = (TfwStr []){
			{ .ptr = name,	.len = n_len },
			{ .ptr = ": ",	.len = 2 },
			{ .ptr = val,	.len = v_len },
			{ .ptr = "\r\n", .len = 2 }
		},
		.len = n_len + v_len + 4,
		.flags = 4 << 8
	};

	if (!TFW_STR_DUP(orig_hdr) && hdr.len <= orig_hdr->len) {
		/* Rewrite the header in-place. */
		if (ss_skb_cutoff_data(&hm->msg.skb_list, orig_hdr,
				       orig_hdr->len - hdr.len, 2))
			return TFW_BLOCK;
		if (tfw_strcpy(orig_hdr, &hdr))
			return TFW_BLOCK;
		return 0;
	}

	/* Generic and slower path. */
	if (__hdr_del(hm, hid))
		return TFW_BLOCK;
	return __hdr_add(hm, &hdr, hid);
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
 * TODO accept TfwStr as header value.
 */
int
tfw_http_msg_hdr_xfrm(TfwHttpMsg *hm, char *name, size_t n_len,
		      char *val, size_t v_len, int hid, bool append)
{
	TfwHttpHdrTbl *ht = hm->h_tbl;
	TfwStr *orig_hdr;
	TfwStr new_hdr = {
		.ptr = (TfwStr []){
			{ .ptr = name,	.len = n_len },
			{ .ptr = ": ",	.len = 2 },
			{ .ptr = val,	.len = v_len },
			{ .ptr = "\r\n", .len = 2 }
		},
		.len = n_len + v_len + 4,
		.flags = 4 << TFW_STR_CN_SHIFT
	};

	BUG_ON(!val && v_len);

	/* Firstly, get original message header to transform. */
	if (hid < TFW_HTTP_HDR_RAW) {
		orig_hdr = &ht->tbl[hid];
		if (TFW_STR_EMPTY(orig_hdr) && !val)
			/* Not found, nothing to delete. */
			return -ENOENT;
	} else {
		hid = __hdr_lookup(hm, &new_hdr);
		if (hid == ht->off && !val)
			/* Not found, nothing to delete. */
			return -ENOENT;
		if (hid == ht->size)
			if (tfw_http_msg_grow_hdr_tbl(hm))
				return -ENOMEM;
		orig_hdr = &ht->tbl[hid];
		BUG_ON(!TFW_STR_EMPTY(orig_hdr));
	}

	if (unlikely(append && hid < TFW_HTTP_HDR_NONSINGULAR)) {
		TFW_WARN("Try to append to nonsingular header %d\n", hid);
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
		return __hdr_append(hm, orig_hdr, &hdr_app);
	}

	return __hdr_sub(hm, name, n_len, val, v_len, hid);
}

/**
 * Add a header, probably duplicated, without any checking of current headers.
 */
int
tfw_http_msg_hdr_add(TfwHttpMsg *hm, TfwStr *hdr)
{
	int hid;
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
		skb = ss_skb_alloc(min_t(size_t, len, SS_SKB_MAX_DATA_LEN));
		if (!skb)
			return -ENOMEM;
		ss_skb_queue_tail(&hm->msg.skb_list, skb);
	}

	return 0;
}

/*
 * Allocate an HTTP message of type @type and set it up with empty SKB
 * space of size @data_len for data writing. An iterator @it is set up
 * to support consecutive writes. This function is intended to work
 * together with tfw_http_msg_write() that uses the @it iterator.
 */
TfwHttpMsg *
tfw_http_msg_create(TfwMsgIter *it, int type, size_t data_len)
{
	TfwHttpMsg *hm;

	if (data_len == 0)
		return NULL;

	hm = tfw_http_msg_alloc(type);
	if (hm && __msg_alloc_skb_data(hm, data_len)) {
		tfw_http_msg_free(hm);
		return NULL;
	}

	it->skb = ss_skb_peek(&hm->msg.skb_list);
	it->frag = 0;

	BUG_ON(it->skb == NULL);
	BUG_ON(!skb_shinfo(it->skb)->nr_frags);

	return hm;
}

/*
 * Fill up an HTTP message @hm with data from string @data. An iterator
 * @it is used to support multiple calls to this functions after set up.
 * This function can only be called after a call to tfw_http_msg_setup().
 * It works only with empty SKB space prepared by tfw_http_msg_setup().
 * It should not be used under any other circumstances.
 */
int
tfw_http_msg_write(TfwMsgIter *it, TfwHttpMsg *hm, const TfwStr *data)
{
	const TfwStr *c;
	skb_frag_t *frag = &skb_shinfo(it->skb)->frags[it->frag];
	unsigned int c_off = 0, f_size, c_size, f_room, n_copy;

	TFW_STR_FOR_EACH_CHUNK(c, data, {
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
			/*
			 * Current SKB fragment has no more room available.
			 * Switch to next SKB fragment.
			 */
			frag = ss_skb_frag_next(&hm->msg.skb_list,
						&it->skb, &it->frag);
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
	});

	return 0;
}

void
tfw_http_conn_msg_unlink(TfwHttpMsg *m)
{
	if (m->conn && m->conn->msg == (TfwMsg *)m)
		m->conn->msg = NULL;
}

void
tfw_http_msg_free(TfwHttpMsg *m)
{
	TFW_DBG3("Free msg=%p\n", m);

	if (!m)
		return;

	tfw_http_conn_msg_unlink(m);

	while (1) {
		/*
		 * The SKBs are handed to Tempesta from the lower layer.
		 * Tempesta is responsible for releasing them.
		 */
		struct sk_buff *skb = ss_skb_dequeue(&m->msg.skb_list);
		if (!skb)
			break;
		TFW_DBG3("free skb %p: truesize=%d sk=%p, destructor=%p"
			 " users=%d type=%s\n",
			 skb, skb->truesize, skb->sk, skb->destructor,
			 atomic_read(&skb->users),
			 m->conn && TFW_CONN_TYPE(m->conn) & Conn_Clnt
			 ? "Conn_Clnt"
			 : m->conn && TFW_CONN_TYPE(m->conn) & Conn_Srv
			   ? "Conn_Srv" : "Unknown");
		kfree_skb(skb);
	}
	tfw_pool_destroy(m->pool);
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

	ss_skb_queue_head_init(&hm->msg.skb_list);

	hm->h_tbl = (TfwHttpHdrTbl *)tfw_pool_alloc(hm->pool, TFW_HHTBL_SZ(1));
	hm->h_tbl->size = __HHTBL_SZ(1);
	hm->h_tbl->off = TFW_HTTP_HDR_RAW;
	memset(hm->h_tbl->tbl, 0, __HHTBL_SZ(1) * sizeof(TfwStr));

	INIT_LIST_HEAD(&hm->msg.msg_list);

	return hm;
}

