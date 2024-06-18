/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
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
		if (state == HTTP2_STREAM_OPENED ||
		    state == HTTP2_STREAM_REM_HALF_CLOSED) {
			stream->rem_wnd += delta;
			tfw_h2_stream_try_unblock(&ctx->sched, stream);
			if (stream->rem_wnd > 0) {
				sock_set_flag(((TfwConn *)conn)->sk,
					      SOCK_TEMPESTA_HAS_DATA);
			}
		}
	}
}

static void
tfw_h2_apply_settings_entry(TfwH2Ctx *ctx, unsigned short id,
			    unsigned int val)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwSettings *dest = &ctx->rsettings;
	long int delta;

	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);
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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	unsigned int id;

	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

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
	return tfw_h2_stream_cache_create();
}

void
tfw_h2_cleanup(void)
{
	tfw_h2_stream_cache_destroy();
}

int
tfw_h2_context_init(TfwH2Ctx *ctx)
{
	TfwStreamQueue *closed_streams = &ctx->closed_streams;
	TfwStreamQueue *idle_streams = &ctx->idle_streams;
	TfwSettings *lset = &ctx->lsettings;
	TfwSettings *rset = &ctx->rsettings;

	bzero_fast(ctx, sizeof(*ctx));

	ctx->state = HTTP2_RECV_CLI_START_SEQ;
	ctx->loc_wnd = DEF_WND_SIZE;
	ctx->rem_wnd = DEF_WND_SIZE;

	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&closed_streams->list);
	INIT_LIST_HEAD(&idle_streams->list);

	tfw_h2_init_stream_sched(&ctx->sched);

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

	return tfw_hpack_init(&ctx->hpack, HPACK_TABLE_DEF_SIZE);
}
ALLOW_ERROR_INJECTION(tfw_h2_context_init, ERRNO);

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

void
tfw_h2_conn_terminate_close(TfwH2Ctx *ctx, TfwH2Err err_code, bool close,
			    bool attack)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	if (tfw_h2_send_goaway(ctx, err_code, attack) && close) {
		if (attack)
			tfw_connection_close((TfwConn *)conn, true);
		else
			tfw_connection_shutdown((TfwConn *)conn, true);
	}
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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwStream *stream, *tmp;

	/*
	 * We add and remove streams from idle queue under
	 * socket lock.
	 */
	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

	list_for_each_entry_safe_reverse(stream, tmp, &ctx->idle_streams.list,
					 hcl_node)
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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwStreamSched *sched = &ctx->sched;

	WARN_ON_ONCE(((TfwConn *)conn)->stream.msg);

	T_DBG3("%s: ctx [%p] conn %p sched %p\n", __func__, ctx, conn, sched);

	tfw_h2_remove_idle_streams(ctx, UINT_MAX);

        rbtree_postorder_for_each_entry_safe(cur, next, &sched->streams, node) {
		tfw_h2_stream_purge_all_and_free_response(cur);
		tfw_h2_stream_unlink_lock(ctx, cur);

		/* The streams tree is about to be destroyed and
		 * we don't want to trigger rebalancing.
		 * No further actions regarding streams dependencies/prio
		 * is required at this stage.
		 */
		tfw_h2_delete_stream(cur);
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
 * Clean the queue of closed streams if its size has exceeded a certain
 * value.
 */
void
tfw_h2_closed_streams_shrink(TfwH2Ctx *ctx)
{
	TfwStream *cur;
	TfwStreamQueue *closed_streams = &ctx->closed_streams;

	T_DBG3("%s: ctx [%p] closed streams num %lu\n", __func__, ctx,
	       closed_streams->num);

	while (1) {
		spin_lock(&ctx->lock);

		if (closed_streams->num <= TFW_MAX_CLOSED_STREAMS) {
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
 * Get stream ID for upper layer to create frames info.
 */
unsigned int
tfw_h2_req_stream_id(TfwHttpReq *req)
{
	unsigned int id = 0;
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);

	spin_lock(&ctx->lock);

	if (req->stream)
		id = req->stream->id;

	spin_unlock(&ctx->lock);

	return id;
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
tfw_h2_req_unlink_stream_with_rst(TfwHttpReq *req)
{
	TfwStreamFsmRes r;
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

	r = tfw_h2_stream_fsm_ignore_err(ctx, stream, HTTP2_RST_STREAM, 0);
	WARN_ON_ONCE(r != STREAM_FSM_RES_OK && r != STREAM_FSM_RES_IGNORE);

	tfw_h2_stream_add_to_queue_nolock(&ctx->closed_streams, stream);

	spin_unlock(&ctx->lock);
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
	stream->xmit.b_len = TFW_HTTP_RESP_CUT_BODY_SZ(resp);
	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags))
		r = tfw_http_msg_cutoff_body_chunks(resp);

finish:
	swap(stream->xmit.skb_head, resp->msg.skb_head);
	ss_skb_setup_head_of_list(stream->xmit.skb_head, mark, tls_type);

	return r;
}

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
			kfree_skb(skb);
			continue;
		}

		BUG_ON(!tls_type);
		BUG_ON(!skb->len);

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
