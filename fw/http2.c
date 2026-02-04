/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2025 Tempesta Technologies, Inc.
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
#undef DEBUG
#if DBG_HTTP2 > 0
#define DEBUG DBG_HTTP2
#endif

#include "connection.h"
#include "http.h"
#include "http2.h"
#include "http_frame.h"
#include "http_msg.h"

#define TFW_MAX_CLOSED_STREAMS          5

static struct kmem_cache *stream_sched_cache;

static int
tfw_h2_stream_sched_cache_create(void)
{
	stream_sched_cache = kmem_cache_create("tfw_stream_sched_cache",
					       sizeof(TfwStreamSchedEntry),
					       0, 0, NULL);
	if (!stream_sched_cache)
		return -ENOMEM;

	return 0;
}

static void
tfw_h2_stream_sched_cache_destroy(void)
{
	kmem_cache_destroy(stream_sched_cache);
}

/**
 * Usually client firstly send SETTINGS frame to a server, so:
 * - we don't have many streams to iterate over in this function
 *   (usually we have no streams at all).
 * - typically there is only one SETTINGS_INITIAL_WINDOW_SIZE
 *   frame is sent from a client side.
 */
static void
tfw_h2_apply_wnd_sz_change(TfwH2Ctx *ctx, long int delta)
{
	TfwConn *conn = (TfwConn *)ctx->conn;
	TfwStream *stream, *next;

	/*
	 * Order is no matter, use default funtion from the Linux kernel.
	 * According to RFC 9113 6.9.2
	 * When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver
	 * MUST adjust the size of all stream flow-control windows that it
	 * maintains by the difference between the new value and the old value.
	 * A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available
	 * space in a flow-control window to become negative.
	 */
	rbtree_postorder_for_each_entry_safe(stream, next,
					     &ctx->sched.streams, node) {
		TfwStreamState state = tfw_h2_get_stream_state(stream);
		bool was_blocked = !tfw_h2_is_ready_to_send(ctx);

		if (state == HTTP2_STREAM_OPENED ||
		    state == HTTP2_STREAM_REM_HALF_CLOSED) {
			stream->rem_wnd += delta;
			tfw_h2_stream_try_unblock(&ctx->sched, stream);
			if (was_blocked && tfw_h2_is_ready_to_send(ctx))
				sock_set_flag(conn->sk, SOCK_TEMPESTA_HAS_DATA);
		}
	}
}

static void
tfw_h2_apply_settings_entry(TfwH2Ctx *ctx, unsigned short id,
			    unsigned int val)
{
	TfwConn *conn = (TfwConn *)ctx->conn;
	TfwSettings *dest = &ctx->rsettings;
	long int delta;

	assert_spin_locked(&conn->sk->sk_lock.slock);

	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		dest->hdr_tbl_sz = min_t(unsigned int,
					 val, HPACK_ENC_TABLE_MAX_SIZE);
		tfw_hpack_set_rbuf_size(&ctx->hpack.enc_tbl, dest->hdr_tbl_sz);
		break;

	case HTTP2_SETTINGS_ENABLE_PUSH:
		BUG_ON(val > 1);
		dest->push = val;
		break;

	case HTTP2_SETTINGS_MAX_STREAMS:
		dest->max_streams = val;
		break;

	case HTTP2_SETTINGS_INIT_WND_SIZE:
		BUG_ON(val > MAX_WND_SIZE);
		delta = (long int)val - (long int)dest->wnd_sz;
		tfw_h2_apply_wnd_sz_change(ctx, delta);
		dest->wnd_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_FRAME_SIZE:
		BUG_ON(val < FRAME_DEF_LENGTH || val > FRAME_MAX_LENGTH);
		dest->max_frame_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_HDR_LIST_SIZE:
		dest->max_lhdr_sz = val;
		break;

	default:
		/*
		 * We should silently ignore unknown identifiers (see
		 * RFC 9113 section 6.5.2)
		 */
		break;
	}
}

int
tfw_h2_check_settings_entry(TfwH2Ctx *ctx, unsigned short id, unsigned int val)
{
	TfwConn *conn = (TfwConn *)ctx->conn;

	assert_spin_locked(&conn->sk->sk_lock.slock);

	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		break;

	case HTTP2_SETTINGS_ENABLE_PUSH:
		if (val > 1)
			return -EINVAL;
		break;

	case HTTP2_SETTINGS_MAX_STREAMS:
		break;

	case HTTP2_SETTINGS_INIT_WND_SIZE:
		if (val > MAX_WND_SIZE)
			return -EINVAL;
		break;

	case HTTP2_SETTINGS_MAX_FRAME_SIZE:
		if (val < FRAME_DEF_LENGTH || val > FRAME_MAX_LENGTH)
			return -EINVAL;
		break;

	case HTTP2_SETTINGS_MAX_HDR_LIST_SIZE:
		break;

	default:
		/*
		 * We should silently ignore unknown identifiers (see
		 * RFC 9113 section 6.5.2)
		 */
		break;
	}

	return 0;
}

void
tfw_h2_save_settings_entry(TfwH2Ctx *ctx, unsigned short id, unsigned int val)
{
	TfwConn *conn = (TfwConn *)ctx->conn;

	assert_spin_locked(&conn->sk->sk_lock.slock);

	if (id > 0 && id < _HTTP2_SETTINGS_MAX) {
		ctx->new_settings[id - 1] = val;
		__set_bit(id, ctx->settings_to_apply);
		__set_bit(HTTP2_SETTINGS_NEED_TO_APPLY,
			  ctx->settings_to_apply);
	}
}

void
tfw_h2_apply_new_settings(TfwH2Ctx *ctx)
{
	TfwConn *conn = (TfwConn *)ctx->conn;
	unsigned int id;

	assert_spin_locked(&conn->sk->sk_lock.slock);

	for (id = HTTP2_SETTINGS_TABLE_SIZE; id < _HTTP2_SETTINGS_MAX; id++) {
		if (test_bit(id, ctx->settings_to_apply)) {
			unsigned int val = ctx->new_settings[id - 1];
			tfw_h2_apply_settings_entry(ctx, id, val);
		}
	}
	clear_bit(HTTP2_SETTINGS_NEED_TO_APPLY, ctx->settings_to_apply);
}

int
tfw_h2_init(void)
{
	int r;

	r = tfw_h2_stream_cache_create();
	if (unlikely(r))
		return r;

	r = tfw_h2_stream_sched_cache_create();
	if (unlikely(r)) {
		tfw_h2_stream_cache_destroy();
		return r;
	}

	return 0;
}

void
tfw_h2_cleanup(void)
{
	tfw_h2_stream_sched_cache_destroy();
	tfw_h2_stream_cache_destroy();
}

static inline void
tfw_h2_context_init_sched_entry_list(TfwH2Ctx *ctx, TfwStreamSchedList *list)
{
	int i;

#define LIST_SZ_DFLT	\
	(PAGE_SIZE - sizeof(TfwH2Ctx)) / sizeof(TfwStreamSchedEntry)

	for (i = LIST_SZ_DFLT - 1; i >= 0; i--) {
		list->entries[i].owner = NULL;
		list->entries[i].next_free = ctx->sched.free_list;
		ctx->sched.free_list = &list->entries[i];
	}

#undef LIST_SZ_DFLT
}

TfwH2Ctx *
tfw_h2_context_alloc(void)
{
	struct page *page;

	/*
	 * Tempesta FW allocates the whole page for http2 context.
	 * and uses extra memory for streams schedulers for better
	 * memory locality. Tempesta FW preallocate only streams
	 * schedulers not the whole streams, because size of
	 * TfwStream structure is very big. There is no sence
	 * to preallocate only two streams (count of streams that
	 * can fit into the remaining memory on the page) and we
	 * can loose too much memory if we preallocate 10 -15
	 * streams.
	 */
	page = alloc_page(GFP_ATOMIC);
	if (!page)
		return NULL;
	return page_address(page);
}

void
tfw_h2_context_free(TfwH2Ctx *ctx)
{
	free_page((unsigned long)ctx);
}

int
tfw_h2_context_init(TfwH2Ctx *ctx, TfwH2Conn *conn)
{
	TfwStreamQueue *closed_streams = &ctx->closed_streams;
	TfwStreamQueue *idle_streams = &ctx->idle_streams;
	TfwSettings *lset = &ctx->lsettings;
	TfwSettings *rset = &ctx->rsettings;
	TfwStreamSchedList *list =
		(TfwStreamSchedList *)((char *)ctx + sizeof(TfwH2Ctx));

	BUG_ON(!conn || conn->h2 != ctx);
	bzero_fast(ctx, sizeof(*ctx) + sizeof(*list));

	ctx->state = HTTP2_RECV_CLI_START_SEQ;
	ctx->loc_wnd = DEF_WND_SIZE;
	ctx->rem_wnd = DEF_WND_SIZE;

	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&closed_streams->list);
	INIT_LIST_HEAD(&idle_streams->list);

	tfw_h2_init_stream_sched(&ctx->sched);
	tfw_h2_context_init_sched_entry_list(ctx, list);

	lset->hdr_tbl_sz = rset->hdr_tbl_sz = HPACK_TABLE_DEF_SIZE;
	lset->push = rset->push = 1;
	lset->max_streams = tfw_cli_max_concurrent_streams;
	rset->max_streams = 0xffffffff;
	lset->max_frame_sz = rset->max_frame_sz = FRAME_DEF_LENGTH;
	lset->max_lhdr_sz = max_header_list_size ?
		max_header_list_size : UINT_MAX;
	rset->max_lhdr_sz = UINT_MAX;

	lset->wnd_sz = DEF_WND_SIZE;
	rset->wnd_sz = DEF_WND_SIZE;
	ctx->conn = conn;

	return tfw_hpack_init(&ctx->hpack, ((TfwConn *)conn)->peer,
			      HPACK_TABLE_DEF_SIZE);
}

void
tfw_h2_context_clear(TfwH2Ctx *ctx)
{
	WARN_ON_ONCE(ctx->streams_num);
	/*
	 * Free POSTPONED SKBs. This is necessary when h2 context has
	 * postponed frames and connection closing initiated.
	 */
	ss_skb_queue_purge(&ctx->skb_head);
	tfw_hpack_clean(&ctx->hpack);
}


TfwStreamSchedEntry *
tfw_h2_alloc_stream_sched_entry(TfwH2Ctx *ctx)
{
	TfwStreamSchedEntry *entry;

	if (unlikely(!ctx->sched.free_list)) {
		/*
		 * If count of preallocate streams schedulers (56) is
		 * exceeded use standart kernel allocator. There is no
		 * sense to allocate the whole page for the new schedulers
		 * or use special cache for this purpose, because it is a
		 * very rare case (browsers usually open not more then
		 * 15 - 20 streams in parallel even if there are much
		 * more resourses to request). TfwStreamSchedEntry is
		 * small (64 bytes), so use special cache for allocation.
		 */ 
		entry = kmem_cache_alloc(stream_sched_cache,
					 GFP_ATOMIC | __GFP_ZERO);
	} else {
		entry = ctx->sched.free_list;
		BUG_ON(entry->owner);
		ctx->sched.free_list = entry->next_free;
	}

	return entry;
}

static inline bool
tfw_h2_stream_sched_is_dflt(TfwH2Ctx *ctx, TfwStreamSchedEntry *entry)
{
	char *begin = (char *)ctx + sizeof(TfwH2Ctx);
	char *end = (char *)ctx + PAGE_SIZE;
	char *p = (char *)entry;

	return p >= begin && p < end;
}

void
tfw_h2_free_stream_sched_entry(TfwH2Ctx *ctx, TfwStreamSchedEntry *entry)
{
	if (entry->owner) {
		entry->owner->sched = NULL;
		entry->owner = NULL;
	}

	if (likely(tfw_h2_stream_sched_is_dflt(ctx, entry))) {
		entry->next_free = ctx->sched.free_list;
		ctx->sched.free_list = entry;
	} else {
		kmem_cache_free(stream_sched_cache, entry);
	}
}

void
tfw_h2_conn_terminate_close(TfwH2Ctx *ctx, TfwH2Err err_code, bool close,
			    bool attack)
{
	TfwH2Conn *conn = ctx->conn;

	if (tfw_h2_send_goaway(ctx, err_code, attack) && close)
		tfw_connection_close((TfwConn *)conn, true);
}

/**
 * According to RFC 9113 section 5.1.1:
 * The first use of a new stream identifier implicitly closes all
 * streams in the "idle" state that might have been initiated by that
 * peer with a lower-valued stream identifier.
 */
void
tfw_h2_remove_idle_streams(TfwH2Ctx *ctx, unsigned int id)
{
	TfwStream *stream, *tmp;

	/*
	 * We add/remove idle streams on receive path
	 * so we don't need lock `ctx->lock` here.
	 */
	list_for_each_entry_safe(stream, tmp, &ctx->idle_streams.list, hcl_node)
	{
		if (id <= stream->id)
			break;

		tfw_h2_stream_del_from_queue_nolock(stream);
		tfw_h2_set_stream_state(stream, HTTP2_STREAM_CLOSED);
		tfw_h2_stream_add_closed(ctx, stream);
	}
}

void
tfw_h2_conn_streams_cleanup(TfwH2Ctx *ctx)
{
	TfwStream *cur, *next;
	TfwH2Conn *conn = ctx->conn;
	TfwStreamSched *sched = &ctx->sched;

	WARN_ON_ONCE(((TfwConn *)conn)->stream.msg);

	T_DBG3("%s: ctx [%p] conn %p sched %p\n", __func__, ctx, conn, sched);

	rbtree_postorder_for_each_entry_safe(cur, next, &sched->streams, node) {
		tfw_h2_stream_purge_all_and_free_response(cur);
		tfw_h2_stream_unlink_lock(ctx, cur);

		/* The streams tree is about to be destroyed and
		 * we don't want to trigger rebalancing.
		 * No further actions regarding streams dependencies/prio
		 * is required at this stage.
		 */
		tfw_h2_delete_stream(ctx, cur);
		--ctx->streams_num;
	}
	sched->streams = RB_ROOT;
}

void
tfw_h2_current_stream_remove(TfwH2Ctx *ctx)
{
	T_DBG3("%s: ctx [%p] ctx->cur_stream %p\n", __func__,
	       ctx, ctx->cur_stream);
	tfw_h2_stream_unlink_lock(ctx, ctx->cur_stream);
	tfw_h2_stream_clean(ctx, ctx->cur_stream);
	ctx->cur_stream = NULL;
}

/*
 * Send RST stream and move stream to the queue of closed streams.
 * When count of closed streams exceeded TFW_MAX_CLOSED_STREAMS,
 * closed streams will be removed from the memory.
 */
int
tfw_h2_current_stream_send_rst(TfwH2Ctx *ctx, int err_code)
{
	unsigned int stream_id = ctx->cur_stream->id;

	spin_lock(&ctx->lock);

	tfw_h2_stream_unlink_nolock(ctx, ctx->cur_stream);
	tfw_h2_stream_add_to_queue_nolock(&ctx->closed_streams,
					  ctx->cur_stream);

	spin_unlock(&ctx->lock);

	ctx->cur_stream = NULL;

	return tfw_h2_send_rst_stream(ctx, stream_id, err_code);
}

/*
 * Clean the queue of closed streams if its size has exceeded a certain
 * value.
 */
void
tfw_h2_closed_streams_shrink(TfwH2Ctx *ctx)
{
	TfwStream *cur;
	unsigned int max_streams = ctx->lsettings.max_streams;
	TfwStreamQueue *closed_streams = &ctx->closed_streams;

	T_DBG3("%s: ctx [%p] closed streams num %lu\n", __func__, ctx,
	       closed_streams->num);

	while (1) {
		spin_lock(&ctx->lock);

		if (closed_streams->num <= TFW_MAX_CLOSED_STREAMS
		    && (ctx->streams_num < max_streams
			|| !closed_streams->num)) {
			spin_unlock(&ctx->lock);
			break;
		}

		BUG_ON(list_empty(&closed_streams->list));
		cur = list_first_entry(&closed_streams->list, TfwStream,
				       hcl_node);
		tfw_h2_stream_unlink_nolock(ctx, cur);

		spin_unlock(&ctx->lock);

		T_DBG3("%s: ctx [%p] cur stream [%p]\n", __func__, ctx, cur);

		tfw_h2_stream_clean(ctx, cur);
	}
}

void
tfw_h2_check_current_stream_is_closed(TfwH2Ctx *ctx)
{
	BUG_ON(!ctx->cur_stream);

	T_DBG3("%s: strm [%p] id %u state %d(%s), streams_num %lu\n",
	       __func__, ctx->cur_stream, ctx->cur_stream->id,
	       tfw_h2_get_stream_state(ctx->cur_stream),
	       __h2_strm_st_n(ctx->cur_stream), ctx->streams_num);

	if (tfw_h2_stream_is_closed(ctx->cur_stream))
		tfw_h2_current_stream_remove(ctx);
}

TfwStream *
tfw_h2_find_not_closed_stream(TfwH2Ctx *ctx, unsigned int id, bool recv)
{
	TfwStream *stream;

	stream = tfw_h2_find_stream(&ctx->sched, id);
	return stream && !tfw_h2_stream_is_closed(stream) ? stream : NULL;
}

/*
 * Unlink request from corresponding stream (if linked).
 */
void
tfw_h2_req_unlink_stream(TfwHttpReq *req)
{
	TfwStream *stream;
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);

	spin_lock(&ctx->lock);

	stream = req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return;
	}

	req->stream = NULL;
	stream->msg = NULL;

	spin_unlock(&ctx->lock);
}

/*
 * Unlink request from corresponding stream (if linked),
 * send RST STREAM and add stream to closed queue.
 */
void
tfw_h2_req_unlink_and_close_stream(TfwHttpReq *req)
{
	TfwStream *stream;
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);

	spin_lock(&ctx->lock);

	stream = req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return;
	}

	req->stream = NULL;
	stream->msg = NULL;
	tfw_h2_set_stream_state(stream, HTTP2_STREAM_CLOSED);
	tfw_h2_stream_add_to_queue_nolock(&ctx->closed_streams, stream);

	spin_unlock(&ctx->lock);
}

static int
tfw_h2_hpack_encode_trailer_headers(TfwHttpResp *resp)
{
	TfwHttpHdrMap *map = resp->mit.map;
	TfwHttpHdrTbl *ht = resp->h_tbl;
	unsigned int i;
	int r = 0;

	/*
	 * TODO #2136: Remove this flag during reworking
	 * `tfw_http_msg_expand_from_pool` function. 
	 */
	__set_bit(TFW_HTTP_B_RESP_ENCODE_TRAILERS, resp->flags);

	for (i = map->trailer_idx; i < map->count; ++i) {
		unsigned short hid = map->index[i].idx;
		unsigned short d_num = map->index[i].d_idx;
		TfwStr *tgt = &ht->tbl[hid];

		if (TFW_STR_DUP(tgt))
			tgt = TFW_STR_CHUNK(tgt, d_num);

		if (WARN_ON_ONCE(!tgt
				 || TFW_STR_EMPTY(tgt)
				 || TFW_STR_DUP(tgt)))
		{
			r = -EINVAL;
			goto finish;
		}

		T_DBG3("%s: hid=%hu, d_num=%hu, nchunks=%u\n",
		       __func__, hid, d_num, ht->tbl[hid].nchunks);

		r = tfw_hpack_transform(resp, tgt);
		if (unlikely(r))
			goto finish;
	}

finish:
	clear_bit(TFW_HTTP_B_RESP_ENCODE_TRAILERS, resp->flags);
	return r;
}

int
tfw_h2_stream_xmit_prepare_resp(TfwStream *stream)
{
	TfwHttpResp *resp = stream->xmit.resp;
	unsigned char tls_type;
	unsigned int mark;
	int r = 0;

	BUG_ON(!resp || resp->msg.skb_head || !resp->req
	       || !resp->req->conn || !stream->xmit.skb_head);

	tls_type = skb_tfw_tls_type(stream->xmit.skb_head);
	mark = stream->xmit.skb_head->mark;
	swap(resp->msg.skb_head, stream->xmit.skb_head);

	r = tfw_h2_resp_encode_headers(resp);
	if (unlikely(r)) {
		T_WARN("Failed to encode headers");
		goto finish;
	}

	stream->xmit.h_len = resp->mit.acc_len;

	if (test_bit(TFW_HTTP_B_REQ_HEAD_TO_GET, resp->req->flags)
	    && !TFW_STR_EMPTY(&resp->body)) {
		/* Send only headers for HEAD method. */
		r = ss_skb_list_chop_head_tail(&resp->msg.skb_head, 0,
					       tfw_str_total_len(&resp->body)
					       + resp->trailers_len);
		if (unlikely(r))
			goto finish;
		resp->body.len = 0;
	} else {
		if (resp->trailers_len > 0) {
			TfwHttpTransIter *mit = &resp->mit;
			unsigned long acc = mit->acc_len;

			resp->iter.skb = resp->msg.skb_head->prev;
			resp->iter.frag =
				skb_shinfo(resp->iter.skb)->nr_frags - 1;
			tfw_http_msg_setup_transform_pool(mit, (TfwHttpMsg *)resp,
							  resp->pool);

			r = tfw_h2_hpack_encode_trailer_headers(resp);
			if (unlikely(r)) {
				T_WARN("Failed to encode trailers");
				goto finish;
			}
			stream->xmit.t_len = mit->acc_len - acc;
		}

		stream->xmit.b_len = TFW_HTTP_RESP_CUT_BODY_SZ(resp);
		/*
		 * Response is chunked encoded, but it is not a response
		 * on HEAD request.
		 */
		if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags)
		    && !test_bit(TFW_HTTP_B_VOID_BODY, resp->flags))
		{
			r = tfw_http_msg_cutoff_body_chunks(resp);
			if (unlikely(r)) {
				T_WARN("Failed to encode body");
				goto finish;
			}
		}
	}

finish:
	swap(stream->xmit.skb_head, resp->msg.skb_head);
	ss_skb_setup_head_of_list(stream->xmit.skb_head, mark, tls_type);

	return r;
}
ALLOW_ERROR_INJECTION(tfw_h2_stream_xmit_prepare_resp, ERRNO);

int
tfw_h2_entail_stream_skb(struct sock *sk, TfwH2Ctx *ctx, TfwStream *stream,
			 unsigned int *len, bool should_split)
{
	unsigned char tls_type = skb_tfw_tls_type(stream->xmit.skb_head);
	unsigned int mark = stream->xmit.skb_head->mark;
	struct sk_buff *skb, *split;
	int r = 0;

	BUG_ON(!TFW_SKB_CB(stream->xmit.skb_head)->is_head);
	while (*len) {
		skb = ss_skb_dequeue(&stream->xmit.skb_head);
		BUG_ON(!skb);

		if (unlikely(!skb->len)) {
			T_DBG3("[%d]: %s: drop skb=%px data_len=%u len=%u\n",
			       smp_processor_id(), __func__,
			       skb, skb->data_len, skb->len);
			ss_kfree_skb(skb);
			continue;
		}

		BUG_ON(!tls_type);
		BUG_ON(!skb->len);

		r = ss_skb_realloc_headroom(skb);
		if (unlikely(r)) {
			ss_skb_queue_head(&stream->xmit.skb_head, skb);
			return r;
		}

		if (skb->len > *len) {
			if (should_split) {
				split = ss_skb_split(skb, *len);
				if (!split) {
					ss_skb_queue_head(&stream->xmit.skb_head,
							  skb);
					r = -ENOMEM;
					break;
				}

				ss_skb_queue_head(&stream->xmit.skb_head, split);
			} else {
				ss_skb_queue_head(&stream->xmit.skb_head, skb);
				break;
			}
		}
		*len -= skb->len;
		ss_skb_tcp_entail(sk, skb, mark, tls_type);
	}

	/*
	 * We use tls_type and mark from skb_head when we entail data in
	 * socket write queue. So we should set tls_type and mark for the
	 * new skb_head.
	 */
	if (stream->xmit.skb_head
	    && !TFW_SKB_CB(stream->xmit.skb_head)->is_head) {
		ss_skb_setup_head_of_list(stream->xmit.skb_head, mark,
					  tls_type);
	}

	return r;
}
ALLOW_ERROR_INJECTION(tfw_h2_entail_stream_skb, ERRNO);

void
tfw_h2_conn_recv_finish(TfwConn *conn)
{
	struct sock *sk = conn->sk;
	TfwH2Ctx *ctx = tfw_h2_context_safe(conn);

	if (ctx && sock_flag(sk, SOCK_TEMPESTA_HAS_DATA)) {
		SS_IN_USE_PROTECT({
			tcp_push_pending_frames(sk);
		});
	}
}
