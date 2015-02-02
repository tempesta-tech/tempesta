/**
 *		Tempesta FW
 *
 * HTTP processing.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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
#include <linux/highmem.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include "cache.h"
#include "classifier.h"
#include "gfsm.h"
#include "hash.h"
#include "http.h"
#include "http_msg.h"
#include "log.h"

#include "sync_socket.h"

TfwMsg *
tfw_http_conn_msg_alloc(TfwConnection *conn)
{
	TfwHttpMsg *hm = tfw_http_msg_alloc(TFW_CONN_TYPE(conn));
	if (unlikely(!hm))
		return NULL;

	hm->conn = conn;
	tfw_gfsm_state_init(&hm->msg.state, conn, TFW_HTTP_FSM_INIT);

	return (TfwMsg *)hm;
}

/**
 * TODO Initialize allocated Client structure by HTTP specific callbacks and FSM.
 */
static int
tfw_http_conn_init(TfwConnection *conn)
{
	return 0;
}

static void
tfw_http_conn_destruct(TfwConnection *conn)
{
	tfw_http_msg_free((TfwHttpMsg *)conn->msg);
}

/**
 * Create sibling for @msg message.
 * Siblings in HTTP are usually pipelined requests
 * which can share the same skbs.
 */
static TfwHttpMsg *
tfw_http_msg_create_sibling(TfwHttpMsg *hm, int type)
{
	TfwHttpMsg *shm;
	struct sk_buff *nskb, *skb;

	skb = ss_skb_peek_tail(&hm->msg.skb_list);
	BUG_ON(!skb);

	shm = tfw_http_msg_alloc(type);
	if (!shm)
		return NULL;

	/*
	 * The sibling is created for current (the last skb in skb_list
	 * - set the skb as a start for skb_list in @sm.
	 */
	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb) {
		tfw_http_msg_free(shm);
		return NULL;
	}
	ss_skb_queue_tail(&shm->msg.skb_list, nskb);

	shm->msg.prev = &hm->msg;
	/* Relink current connection msg to @hsm. */
	shm->conn = hm->conn;

	return shm;
}

/**
 * Set for all new just parsed headers pointers to last skb
 * (to which they belong).
 *
 * If some header name or value are splitted among number of skb's, then
 * hdr->skb points to the first skb and all other skbs are dereferenced
 * through skb->next. TODO The parser cares to set correct lengths for name
 * and value field which consists from few skb's.
 */
static void
tfw_http_establish_skb_hdrs(TfwHttpMsg *hm)
{
	int i;

	if (unlikely(!hm->h_tbl || !hm->h_tbl->size))
		return;

	for (i = 0; i < hm->h_tbl->size; ++i) {
		TfwHttpHdr *hdr = hm->h_tbl->tbl + i;
		if (hdr->skb)
			continue;
		if (!hdr->field.ptr)
			break;
		hdr->skb = hm->msg.skb_list.last;
	}
}

/**
 * Sometimes kernel gives bit more memory for skb than was requested
 * - use the extra memory if enough to place @n bytes or allocate
 * new linear data.
 * 
 * @return new pointer to @split.
 *
 * The main part of the function is borrowed from Linux pskb_expand_head().
 */
static void *
tfw_skb_get_room(struct sk_buff *skb, unsigned char *split, size_t n)
{
	int i;
	u8 *data;
	int size = skb_end_offset(skb) + n;
	long off = split - skb->head;
	gfp_t gfp_mask = GFP_ATOMIC;

	/* Quick path: we have some room. */
	if (skb->tail + n <= skb->end) {
		memmove(skb->head + off + n, skb->head + off,
			skb_tail_pointer(skb) - split);
		skb_put(skb, n);
		return split;
	}

	/* Ohh, we must copy... */
	if (skb_shared(skb))
		BUG();

	/*
	 * Probably we'll need more space to adjust other headers,
	 * so request more data.
	 */
	size = SKB_DATA_ALIGN(skb_end_offset(skb) + n * 4);

	if (skb_pfmemalloc(skb))
		gfp_mask |= __GFP_MEMALLOC;
	data = kmalloc(size + SKB_DATA_ALIGN(sizeof(struct skb_shared_info)),
		       gfp_mask);
	if (!data)
		goto nodata;
	size = SKB_WITH_OVERHEAD(ksize(data));

	/*
	 * Copy data before @split and after @split + @n to leave room
	 * to insert data.
	 */
	memcpy(data, skb->head, off);
	memcpy(data + off + n, skb->head + off, skb_tail_pointer(skb) - split);
	split = data + off;

	memcpy((struct skb_shared_info *)(data + size),
	       skb_shinfo(skb),
	       offsetof(struct skb_shared_info, frags[skb_shinfo(skb)->nr_frags]));

	if (skb_cloned(skb)) {
		if (skb_orphan_frags(skb, gfp_mask))
			goto nofrags;
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
			skb_frag_ref(skb, i);

		if (skb_has_frag_list(skb)) {
			struct sk_buff *list;
			skb_walk_frags(skb, list)
				skb_get(list);
		}

		/* skb_release_data() */
		if (!skb->cloned
		    || !atomic_sub_return(skb->nohdr
			    		  ? (1 << SKB_DATAREF_SHIFT) + 1
					  : 1,
					  &skb_shinfo(skb)->dataref))
		{
			if (skb_shinfo(skb)->nr_frags)
				for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
					skb_frag_unref(skb, i);

			if (skb_shinfo(skb)->tx_flags & SKBTX_DEV_ZEROCOPY) {
				struct ubuf_info *uarg;

				uarg = skb_shinfo(skb)->destructor_arg;
				if (uarg->callback)
					uarg->callback(uarg, true);
			}

			if (skb_has_frag_list(skb)) {
				kfree_skb_list(skb_shinfo(skb)->frag_list);
				skb_shinfo(skb)->frag_list = NULL;
			}

			if (skb->head_frag)
				put_page(virt_to_head_page(skb->head));
			else
				kfree(skb->head);
		}
	} else {
		if (skb->head_frag)
			put_page(virt_to_head_page(skb->head));
		else
			kfree(skb->head);
	}
	off = data - skb->head;

	skb->head	= data;
	skb->head_frag	= 0;
	skb->data	+= off;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->end	= size;
	off		= 0;
#else
	skb->end	= skb->head + size;
#endif
	skb->tail	+= off + n;
	skb->len	+= n;
	/* skb_headers_offset_update(skb, off) */
	skb->transport_header += off;
	skb->network_header   += off;
	if (skb_mac_header_was_set(skb))
		skb->mac_header += off;
	skb->inner_transport_header += off;
	skb->inner_network_header += off;
	skb->inner_mac_header += off;
	skb->cloned	= 0;
	skb->hdr_len	= 0;
	skb->nohdr	= 0;
	atomic_set(&skb_shinfo(skb)->dataref, 1);
	return split;

nofrags:
	kfree(data);
nodata:
	return NULL;
}

/**
 * Add @new_hdr as a last header just before the message body.
 */
static int
__hdr_add(const char *new_hdr, size_t nh_len, struct sk_buff *skb,
	  unsigned char *crlf)
{
	int i, dlen;
	struct sk_buff *frag_i;
	unsigned char *vaddr;

next_skb:
	dlen = skb_headlen(skb);
	vaddr = skb->data;

	/* Process linear data. */
	if (crlf >= vaddr && crlf < vaddr + dlen) {
		void *split = tfw_skb_get_room(skb, crlf, nh_len);
		if (!split)
			return TFW_BLOCK;
		memcpy(split, new_hdr, nh_len);
		return TFW_PASS;
	}

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = kmap_atomic(skb_frag_page(frag));
		dlen = skb_frag_size(frag);

		/* TODO do we need to process this? */
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		int r = __hdr_add(new_hdr, nh_len, frag_i, crlf);
		if (r == TFW_PASS)
			return r;
	}

	skb = skb->next;
	if (skb)
		goto next_skb;

	/* It seems not all data was received. */
	return TFW_BLOCK;
}

#define TFW_HTTP_HDR_ADD(hm, str)	__hdr_add(str "\r\n", sizeof(str) + 1, \
						  hm->msg.skb_list.first, \
						  hm->crlf)

static int
__hdr_delete(TfwStr *hdr, struct sk_buff *skb)
{
	int i, dlen, c = 0, r = TFW_PASS;
	struct sk_buff *frag_i;
	TfwStr *h = TFW_STR_CHUNK(hdr, 0);
	unsigned char *vaddr;

#define PROCESS_DATA(code)						\
do {									\
	unsigned char *p = h->ptr;					\
	if (p >= vaddr && p < vaddr + dlen) {				\
		if (p + h->len < vaddr + dlen) {			\
			/* The header is linear. */			\
			BUG_ON(hdr->flags & TFW_STR_COMPOUND);		\
			memmove(p, p + h->len, dlen - (p - vaddr) - h->len); \
			skb_trim(skb, skb->len - h->len);		\
			code;						\
			return TFW_PASS;				\
		} else {						\
			/* Header can't exceed data chunks boundary. */	\
			BUG_ON(p + h->len - vaddr - dlen);		\
			skb_trim(skb, skb->len - h->len);		\
			code;						\
			if (!(hdr->flags & TFW_STR_COMPOUND))		\
				return TFW_PASS;			\
			/* Compound header: process next chunk. */	\
			++c;						\
			h = TFW_STR_CHUNK(hdr, c);			\
			if (!h)						\
				return TFW_PASS;			\
		}							\
	}								\
} while (0)

next_skb:
	dlen = skb_headlen(skb);
	vaddr = skb->head;

	/* Process linear data. */
	PROCESS_DATA({});

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = kmap_atomic(skb_frag_page(frag));
		vaddr += frag->page_offset;
		dlen = skb_frag_size(frag);

		PROCESS_DATA({
				skb->data_len -= h->len;
				skb_frag_size_set(frag, dlen - h->len);
				kunmap_atomic(vaddr);
			});
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		TfwStr hdr2 = { .flags = hdr->flags };
		if (hdr->flags & TFW_STR_COMPOUND) {
			hdr2.len = hdr->len - c;
			hdr2.ptr = h;
		} else {
			hdr2.len = h->len;
			hdr2.ptr = h->ptr;
		}
		r = __hdr_delete(&hdr2, frag_i);
		if (r == TFW_PASS)
			return r;
	}

	skb = skb->next;
	if (skb)
		goto next_skb;

	/* It seems not all data was received. */
	return TFW_BLOCK;
#undef PROCESS_DATA
}

static int
__hdr_sub(TfwStr *hdr, const char *new_hdr, size_t nh_len, struct sk_buff *skb)
{
	int c, i, r, dlen, tot_hlen = 0;
	struct sk_buff *frag_i;
	TfwStr *h;
	unsigned char *vaddr, *p;

	for (h = TFW_STR_CHUNK(hdr, 0), c = 0; h; h = TFW_STR_CHUNK(hdr, ++c))
		tot_hlen += h->len;
	c = 0;
	h = TFW_STR_CHUNK(hdr, c);

next_skb:
	dlen = skb_headlen(skb);
	vaddr = skb->data;

	/* Process linear data. */
	p = h->ptr;
	if (p >= vaddr && p < vaddr + dlen) {
		int delta = nh_len - tot_hlen;
		if (tot_hlen < nh_len) {
			/* Make up for deficient room in skb linear data. */
			p = tfw_skb_get_room(skb, p, delta);
			if (!p)
				return TFW_BLOCK;
		}
		if (p + h->len < vaddr + dlen) {
			/* The header is linear. */
			BUG_ON(hdr->flags & TFW_STR_COMPOUND);
			memcpy(p, new_hdr, nh_len);
			if (h->len > nh_len) {
				/* Set SPs at the end of header. */
				memset(p + nh_len - 2, ' ',
				       h->len - nh_len);
				memcpy(p + h->len - 2, "\r\n", 2);
			}
			return TFW_PASS;
		} else {
			int n = min((size_t)h->len, nh_len);
			/* Header can't exceed data chunks boundary. */
			BUG_ON(p + h->len - vaddr - dlen);

			/* Replace current part of the header. */
			memcpy(p, new_hdr, n);

			/* Set SPs at the end of header. */
			if (h->len > nh_len) {
				memset(p + nh_len - 2, ' ',
				       h->len - nh_len);
				memcpy(p + h->len - 2, "\r\n", 2);
				return TFW_PASS;
			}

			new_hdr += n;
			nh_len -= n;
			tot_hlen -= n;

			/* Write the extra allocated room. */
			if (tot_hlen < nh_len)
				memcpy(p + n, new_hdr, delta);

			/* Move to next header chunk if exists. */
			if (!(hdr->flags & TFW_STR_COMPOUND))
				return TFW_PASS;
					++c;
			h = TFW_STR_CHUNK(hdr, c);
			if (!h)	
				return TFW_PASS;
		}
	}

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		vaddr = kmap_atomic(skb_frag_page(frag));
		dlen = skb_frag_size(frag);

		/*
		 * TODO do we need to process poaged data?
		 * It's easy to rewrite the header chunks if it starts at
		 * linear data and there we allocated extra room, but it's
		 * unclear how to allocate extra room if frags array is full.
		 */
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		TfwStr hdr2 = { .flags = hdr->flags };
		if (hdr->flags & TFW_STR_COMPOUND) {
			hdr2.len = hdr->len - c;
			hdr2.ptr = h;
		} else {
			hdr2.len = h->len;
			hdr2.ptr = h->ptr;
		}
		r = __hdr_sub(&hdr2, new_hdr, nh_len, frag_i);
		if (r == TFW_PASS)
			return r;
	}

	skb = skb->next;
	if (skb)
		goto next_skb;

	/* It seems not all data was received. */
	return TFW_BLOCK;
}

#define TFW_HTTP_HDR_SUB(hdr, str, skb)	__hdr_sub(hdr, str "\r\n",	\
						  sizeof(str) + 1, skb)

/**
 * Removes Connection header from HTTP message @msg if @conn_flg is zero,
 * and replace or set a new header value otherwise.
 *
 * Sometimes there is some extra space in skb (see ksize() in linux/mm/slab.c),
 * so in some cases we can place some additional data w/o memory allcations.
 *
 * skb's can be shared between number of HTTP messages. We don't copy skb if
 * it's shared - we modify skb's safely and shared skb is still owned by one
 * CPU.
 *
 * TODO handle generic headers adjustment.
 * The three cases are possible:
 *
 * 1. we need to delete the header - we just shift first or second
 *    (which is shorter) using skb pointers;
 *
 * 2. need to add a header - we add the header as last header shifting message
 *    body;
 *
 * 3. replace some of the headers - aggregate all current headers with the same
 *    name to one single header with comma separated fields (RFC 2616 4.2)
 *    shrinking unneccessary fields and adding the new fields at the end of
 *    the list;
 *    if the resulting header is shorter than sum of current headers, then we
 *    place SPs to avoid data movement;
 *    we need to move headers between the substituted headers with the same
 *    name and message body if the new header is longer than the sum of the
 *    cyrrent headers.
 */
static int
tfw_http_set_hdr_connection(TfwHttpMsg *hm, int conn_flg)
{
	int r = 0;
	unsigned int need_add = (hm->flags & conn_flg) ^ conn_flg;
	unsigned int need_del = (hm->flags & conn_flg)
				^ (hm->flags & __TFW_HTTP_CONN_MASK);
	TfwHttpHdr *ch = hm->h_tbl->tbl + TFW_HTTP_HDR_CONNECTION;

	/* Never call the function if no changes are required. */
	BUG_ON(!need_add && !need_del);

	/* Delete unnecessary headers. */
	if (unlikely(ch->field.flags & TFW_STR_COMPOUND2))
		/* Few Connection headers - looks suspicious. */
		return TFW_BLOCK;

	if (need_add && need_del) {
		/* Substitute the header. */
		switch (need_add) {
		case TFW_HTTP_CONN_CLOSE:
			r = TFW_HTTP_HDR_SUB(&ch->field,
					     "Connection: close",
					     ch->skb);
			break;
		case TFW_HTTP_CONN_KA:
			r = TFW_HTTP_HDR_SUB(&ch->field,
					     "Connection: keep-alive",
					     ch->skb);
			break;
		default:
			BUG();
		}
	}
	else if (need_add) {
		/* There is no Connection header, add one. */
		BUG_ON(ch->field.ptr);
		switch (need_add) {
		case TFW_HTTP_CONN_CLOSE:
			r = TFW_HTTP_HDR_ADD(hm, "Connection: close");
			break;
		case TFW_HTTP_CONN_KA:
			r = TFW_HTTP_HDR_ADD(hm, "Connection: keep-alive");
			break;
		default:
			BUG();
		}
	}
	else {
		/* Just delete the header. */
		r = __hdr_delete(&ch->field, ch->skb);
	}

	return r;
}

/**
 * Get @skb's source address and port as a string, e.g. "127.0.0.1", "::1".
 *
 * Only the source IP address is printed to @out_buf, and the TCP/SCTP port
 * is not printed. That is done because:
 *  - Less output bytes means more chance for fast path in __hdr_add().
 *  - RFC7239 says the port is optional.
 *  - Most proxy servers don't put it to the field.
 *  - Usually you get a random port of an outbound connection there,
 *    so the value is likely useless.
 * If at some point we will need the port, then the fix should be trivial:
 * just get it with tcp_hdr(skb)->src (or sctp_hdr() for SPDY).
 */
static char *
tfw_fmt_skb_src_addr(const struct sk_buff *skb, char *out_buf)
{
	const struct iphdr *ih4 = ip_hdr(skb);
	const struct ipv6hdr *ih6 = ipv6_hdr(skb);

	if (ih6->version == 6)
		return tfw_addr_fmt_v6(&ih6->saddr, 0, out_buf);

	return tfw_addr_fmt_v4(ih4->saddr, 0, out_buf);
}

static int
tfw_http_add_forwarded_for(TfwHttpMsg *m)
{
#define XFF_HDR "X-Forwarded-For: "
#define XFF_LEN (sizeof(XFF_HDR) - 1)

	struct sk_buff *skb;
	char *pos;
	int r, len;
	char buf[XFF_LEN + TFW_ADDR_STR_BUF_SIZE + 2] = XFF_HDR;

	skb = m->msg.skb_list.first;
	pos = buf + XFF_LEN;
	pos = tfw_fmt_skb_src_addr(skb, pos);

	*pos++ = '\r';
	*pos++ = '\n';
	len = (pos - buf);
	r = __hdr_add(buf, len, skb, m->crlf);

	if (r)
		TFW_ERR("can't add X-Forwarded-For header to msg: %p, "
			"buf: %*s", m, len, buf);
	else
		TFW_DBG("added X-Forwarded-For header: %*s\n", len, buf);

	return r;

#undef XFF_HDR
#undef XFF_LEN
}

static int
tfw_http_append_forwarded_for(TfwHttpMsg *m)
{
	TfwHttpHdr *hdr = &m->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
	struct sk_buff *skb;
	char *buf, *pos;
	int r, old_hdr_len, buf_size, new_hdr_len;

	skb = m->msg.skb_list.first;
	old_hdr_len = tfw_str_len(&hdr->field);
	buf_size = old_hdr_len + TFW_ADDR_STR_BUF_SIZE + sizeof(", \r\n");

	buf = tfw_pool_alloc(m->pool, buf_size);
	if (!buf)
		return TFW_BLOCK;

	tfw_str_to_cstr(&hdr->field, buf, buf_size);

	pos = buf + old_hdr_len;
	*pos++ = ',';
	*pos++ = ' ';
	BUG_ON(!skb);
	pos = tfw_fmt_skb_src_addr(skb, pos);
	*pos++ = '\r';
	*pos++ = '\n';

	new_hdr_len = (pos - buf);
	r = __hdr_sub(&hdr->field, buf, new_hdr_len, skb);

	if (r)
		TFW_ERR("can't replace X-Forwarded-For with: %.*s",
			new_hdr_len, buf);
	else
		TFW_DBG("re-placed X-Forwarded-For header: %.*s",
			new_hdr_len, buf);

	return r;
}

static int
tfw_http_add_or_append_forwarded_for(TfwHttpMsg *m)
{
	if (m->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR].field.len)
		return tfw_http_append_forwarded_for(m);

	return tfw_http_add_forwarded_for(m);
}

/**
 * Adjust the request before proxying it to real server.
 */
static int
tfw_http_adjust_req(TfwHttpReq *req)
{
	int r = 0;
	TfwHttpMsg *m = (TfwHttpMsg *)req;

	r = tfw_http_add_or_append_forwarded_for(m);
	if (r)
		return r;

	if ((m->flags & __TFW_HTTP_CONN_MASK) != TFW_HTTP_CONN_KA)
		r = tfw_http_set_hdr_connection(m, TFW_HTTP_CONN_KA);

	return r;
}

/**
 * Adjust the response before proxying it to real client.
 */
static int
tfw_http_adjust_resp(TfwHttpResp *resp)
{
	/*
	 * TODO adjust Connection header and all connection-token headers
	 * (e.g. Keep-Alive) according to our policy.
	 */
	(void)resp;

	return 0;
}

static void
tfw_http_req_cache_cb(TfwHttpReq *req, TfwHttpResp *resp, void *data)
{
	TfwSession *sess = data;

	if (resp) {
		/*
		 * We have prepared response, send it as is.
		 * TODO should we adjust it somehow?
		 */
		tfw_connection_send_cli(sess, (TfwMsg *)resp);
	} else {
		if (tfw_http_adjust_req(req))
			return;
		/* Send the request to appropriate server. */
		tfw_connection_send_srv(sess, (TfwMsg *)req);
	}
}

/**
 * @return number of processed bytes on success and negative value otherwise.
 */
static int
tfw_http_req_process(TfwConnection *conn, unsigned char *data, size_t len)
{
	int r = TFW_BLOCK;
	TfwHttpReq *req = (TfwHttpReq *)conn->msg;
	TfwSession *sess = conn->sess;

	BUG_ON(!req);
	BUG_ON(!sess);

	TFW_DBG("Received %lu client data bytes (%.*s) on socket (conn=%p)\n",
		len, (int)len, data, conn);

	/* Process pipelined requests in a loop. */
	while (1) {
		TfwHttpMsg *hm;
		int msg_off = req->parser.data_off;

		r = tfw_http_parse_req(req, data, len);

		req->msg.len += req->parser.data_off - msg_off;

		TFW_DBG("request parsed: len=%lu parsed=%d msg_len=%lu res=%d\n",
			len, req->parser.data_off, req->msg.len, r);

		switch (r) {
		default:
			TFW_ERR("bad HTTP parser request return code, %d\n", r);
			BUG();
		case TFW_BLOCK:
			TFW_DBG("Block bad HTTP request\n");
			goto block;
		case TFW_POSTPONE:
			tfw_http_establish_skb_hdrs((TfwHttpMsg *)req);
			r = tfw_gfsm_move(&req->msg.state,
					  TFW_HTTP_FSM_REQ_CHUNK, data, len);
			if (r == TFW_BLOCK)
				goto block;
			return TFW_POSTPONE;
		case TFW_PASS:
			/* Request is fully parsed, add it to the connection. */
			list_add_tail(&req->msg.pl_list, &sess->req_list);
			conn->msg = NULL;

			tfw_http_establish_skb_hdrs((TfwHttpMsg *)req);
			r = tfw_gfsm_move(&req->msg.state,
					  TFW_HTTP_FSM_REQ_MSG, data, len);
			TFW_DBG("GFSM return code %d\n", r);
			if (r == TFW_BLOCK)
				goto block;
			/* Fall through. */
		}

		/* The request is fully parsed, process it. */

		tfw_cache_req_process(req, tfw_http_req_cache_cb, sess);

		if (!req->parser.data_off || req->parser.data_off == len)
			/* There is no more pending data in skbs. */
			break;

		/* Pipelined requests: create new sibling message. */
		hm = tfw_http_msg_create_sibling((TfwHttpMsg *)req, Conn_Clnt);
		if (!hm)
			/* Bad... Let's wait little bit... */
			return TFW_POSTPONE;
		tfw_http_parser_msg_inherit((TfwHttpMsg *)req, hm);
		req = (TfwHttpReq *)hm;
	}

	return r;
block:
	return TFW_BLOCK;
}

/**
 * @return number of processed bytes on success and negative value otherwise.
 */
static int
tfw_http_resp_process(TfwConnection *conn, unsigned char *data, size_t len)
{
	int r = TFW_BLOCK;
	TfwHttpResp *resp = (TfwHttpResp *)conn->msg;
	TfwSession *sess = conn->sess;

	BUG_ON(!resp);
	BUG_ON(!sess);

	TFW_DBG("received %lu server data bytes (%.*s) on socket (conn=%p)\n",
		len, (int)len, data, conn);

	r = tfw_http_parse_resp(resp, data, len);

	resp->msg.len += resp->parser.data_off;

	TFW_DBG("response parsed: len=%lu parsed=%d res=%d\n",
		len, resp->parser.data_off, r);

	switch (r) {
	default:
		TFW_ERR("bad HTTP parser return code, %d\n", r);
		BUG();
	case TFW_BLOCK:
		TFW_DBG("Block bad HTTP response\n");
		goto block;
	case TFW_POSTPONE:
		tfw_http_establish_skb_hdrs((TfwHttpMsg *)resp);
		r = tfw_gfsm_move(&resp->msg.state, TFW_HTTP_FSM_RESP_CHUNK,
				  data, len);
		if (r == TFW_BLOCK)
			goto block;
		return TFW_POSTPONE;
	case TFW_PASS:
		tfw_http_establish_skb_hdrs((TfwHttpMsg *)resp);
		r = tfw_gfsm_move(&resp->msg.state, TFW_HTTP_FSM_RESP_MSG,
				  data, len);
		if (r == TFW_BLOCK)
			goto block;
		/* fall through */
	}

	/* The response is fully parsed, process it. */

	r = tfw_gfsm_move(&resp->msg.state, TFW_HTTP_FSM_LOCAL_RESP_FILTER,
			  data, len);
	if (r == TFW_PASS) {
		TfwHttpReq *req;

		if (tfw_http_adjust_resp(resp))
			goto block;

		/*
		 * Cache adjusted and filtered responses only.
		 * We get responses in the same order as requests,
		 * so we can just pop the first request.
		 */
		if (unlikely(list_empty(&sess->req_list))) {
			TFW_WARN("Response w/o request\n");
			goto block;
		}

		req = list_first_entry(&sess->req_list, TfwHttpReq, msg.pl_list);
		list_del(&req->msg.pl_list);

		/*
		 * Send the response to client before caching it.
		 * The cache frees the response.
		 */
		tfw_connection_send_cli(sess, (TfwMsg *)resp);

		tfw_cache_add(resp, req);
	}
	else if (r == TFW_BLOCK) {
		tfw_pool_free(resp->pool);
		conn->msg = NULL;
	}

	return r;
block:
	tfw_http_msg_free((TfwHttpMsg *)resp);
	return TFW_BLOCK;
}

/**
 * @return status (application logic decision) of the message processing.
 */
int
tfw_http_msg_process(void *conn, unsigned char *data, size_t len)
{
	TfwConnection *c = (TfwConnection *)conn;

	return (TFW_CONN_TYPE(c) & Conn_Clnt)
		? tfw_http_req_process(c, data, len)
		: tfw_http_resp_process(c, data, len);
}

/**
 * Calculate key of a HTTP request by hashing its URI and Host header.
 *
 * Requests with the same URI and Host are mapped to the same key with
 * high probability. Different keys may be calculated for the same Host and URI
 * when they consist of many chunks.
 */
unsigned long
tfw_http_req_key_calc(const TfwHttpReq *req)
{
	return (tfw_hash_str(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST].field) ^
		tfw_hash_str(&req->uri));
}
EXPORT_SYMBOL(tfw_http_req_key_calc);

static TfwConnHooks http_conn_hooks = {
	.conn_init	= tfw_http_conn_init,
	.conn_destruct	= tfw_http_conn_destruct,
	.conn_msg_alloc	= tfw_http_conn_msg_alloc,
};

int __init
tfw_http_init(void)
{
	int r = tfw_gfsm_register_fsm(TFW_FSM_HTTP, tfw_http_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&http_conn_hooks, TFW_FSM_HTTP);

	return 0;
}

void
tfw_http_exit(void)
{
}
