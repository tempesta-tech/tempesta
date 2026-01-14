/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2025 Tempesta Technologies, Inc.
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
#include <linux/slab.h>

#undef DEBUG
#if DBG_HTTP_STREAM > 0
#define DEBUG DBG_HTTP_STREAM
#endif

#include "lib/log.h"
#include "http_frame.h"
#include "http.h"

#define HTTP2_DEF_WEIGHT	16

static struct kmem_cache *stream_cache;

int
tfw_h2_stream_cache_create(void)
{
	stream_cache = kmem_cache_create("tfw_stream_cache", sizeof(TfwStream),
					 0, 0, NULL);
	if (!stream_cache)
		return -ENOMEM;

	return 0;
}

void
tfw_h2_stream_cache_destroy(void)
{
	kmem_cache_destroy(stream_cache);
}

static inline void
tfw_h2_conn_reset_stream_on_close(TfwH2Ctx *ctx, TfwStream *stream)
{
	if (ctx->cur_send_headers == stream)
		ctx->cur_send_headers = NULL;
	if (ctx->cur_recv_headers == stream)
		ctx->cur_recv_headers = NULL;
}

static inline void
tfw_h2_stream_purge_all(TfwStream *stream)
{
	ss_skb_queue_purge(&stream->xmit.skb_head);
	ss_skb_queue_purge(&stream->xmit.postponed);
	stream->xmit.h_len = stream->xmit.b_len = stream->xmit.t_len = 0;
}

static void
tfw_h2_stop_stream(TfwStreamSched *sched, TfwStream *stream)
{
	TfwH2Ctx *ctx = container_of(sched, TfwH2Ctx, sched);

	/*
	 * Should be done before purging stream send queue,
	 * to correct adjusting count of active streams in
	 * the scheduler.
	 */
	tfw_h2_remove_stream_dep(sched, stream);
	tfw_h2_stream_purge_all_and_free_response(stream);

	tfw_h2_conn_reset_stream_on_close(ctx, stream);
	rb_erase(&stream->node, &sched->streams);
}

static inline void
tfw_h2_init_stream(TfwStream *stream, TfwStreamSchedEntry *entry,
		   unsigned int id, unsigned short weight,
		   long int loc_wnd, long int rem_wnd)
{
	RB_CLEAR_NODE(&stream->node);
	INIT_LIST_HEAD(&stream->sched_node);
	stream->sched_state = HTTP2_STREAM_SCHED_STATE_UNKNOWN;
	tfw_h2_init_stream_sched_entry(entry, stream);
	INIT_LIST_HEAD(&stream->hcl_node);
	spin_lock_init(&stream->st_lock);
	stream->id = id;
	stream->state = HTTP2_STREAM_IDLE;
	stream->loc_wnd = loc_wnd;
	stream->rem_wnd = rem_wnd;
	stream->weight = weight ? weight : HTTP2_DEF_WEIGHT;
}

static TfwStream *
tfw_h2_add_stream(TfwStreamSched *sched, TfwStreamSchedEntry *entry,
		  unsigned int id, unsigned short weight,
		  long int loc_wnd, long int rem_wnd)
{
	TfwStream *new_stream;
	struct rb_node **new = &sched->streams.rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		TfwStream *stream = rb_entry(*new, TfwStream, node);

		parent = *new;
		if (id < stream->id) {
			new = &parent->rb_left;
		} else if (id > stream->id) {
			new = &parent->rb_right;
		} else {
			WARN_ON_ONCE(1);
			return NULL;
		}
	}

	new_stream = kmem_cache_alloc(stream_cache, GFP_ATOMIC | __GFP_ZERO);
	if (unlikely(!new_stream))
		return NULL;

	tfw_h2_init_stream(new_stream, entry, id, weight, loc_wnd, rem_wnd);

	rb_link_node(&new_stream->node, parent, new);
	rb_insert_color(&new_stream->node, &sched->streams);

	return new_stream;
}
ALLOW_ERROR_INJECTION(tfw_h2_add_stream, NULL);

void
tfw_h2_stream_purge_send_queue(TfwStream *stream)
{
	unsigned long len = stream->xmit.h_len + stream->xmit.b_len +
		stream->xmit.t_len + stream->xmit.frame_length;
	struct sk_buff *skb;

	while (len) {
		skb = ss_skb_dequeue(&stream->xmit.skb_head);
		BUG_ON(!skb);

		len -= skb->len;
		ss_kfree_skb(skb);
	}
	stream->xmit.h_len = stream->xmit.b_len = stream->xmit.t_len
		= stream->xmit.frame_length = 0;
}

void
tfw_h2_stream_purge_all_and_free_response(TfwStream *stream)
{
	TfwHttpResp*resp = stream->xmit.resp;

	if (resp) {
		tfw_http_resp_pair_free_and_put_conn(resp);
		stream->xmit.resp = NULL;
	}
	tfw_h2_stream_purge_all(stream);
}

void
tfw_h2_stream_add_idle(TfwH2Ctx *ctx, TfwStream *idle)
{
	TfwStreamQueue *idle_streams = &ctx->idle_streams;
	TfwStream *cur;
	bool found = false;

	/*
	 * We add/remove idle streams on receive path
	 * so we don't need lock `ctx->lock` here.
	 * Found first idle stream with id less than new idle
	 * stream, then insert new stream before this stream.
	 */
	list_for_each_entry_reverse(cur, &idle_streams->list, hcl_node) {
		if (idle->id > cur->id) {
			found = true;
			break;
		}
	}

	if (found) {
		list_add(&idle->hcl_node, &cur->hcl_node);
		idle->queue = idle_streams;
		++idle->queue->num;
	} else {
		tfw_h2_stream_add_to_queue_nolock(idle_streams, idle);
	}

}

void
tfw_h2_stream_remove_idle(TfwH2Ctx *ctx, TfwStream *stream)
{
	/*
	 * We add/remove idle streams on receive path
	 * so we don't need lock `ctx->lock` here.
	 */
	tfw_h2_stream_del_from_queue_nolock(stream);
}

/*
 * Create a new stream and add it to the streams storage and to the dependency
 * tree. Note, that we do not need to protect the streams storage in @sched from
 * concurrent access, since all operations with it (adding, searching and
 * deletion) are done only in receiving flow of Frame layer.
 */
TfwStream *
tfw_h2_stream_create(TfwH2Ctx *ctx, unsigned int id)
{
	TfwStream *stream;
	TfwStreamSchedEntry *dep = NULL;
	TfwFramePri *pri = &ctx->priority;
	bool excl = pri->exclusive;
	TfwStreamSchedEntry *entry;

	T_DBG3("Create new stream (id %u weight %u exclusive %d),"
	       " which depends from stream with id %u,"
	       " ctx %px streams_num %lu\n", id, pri->weight,
	       pri->exclusive, pri->stream_id, ctx, ctx->streams_num);

	entry = tfw_h2_alloc_stream_sched_entry(ctx);
	if (!entry)
		return NULL;

	dep = tfw_h2_find_stream_dep(&ctx->sched, pri->stream_id);
	stream = tfw_h2_add_stream(&ctx->sched, entry, id, pri->weight,
				   ctx->lsettings.wnd_sz,
				   ctx->rsettings.wnd_sz);
	if (!stream) {
		tfw_h2_free_stream_sched_entry(ctx, entry);
		return NULL;
	}

	tfw_h2_add_stream_dep(&ctx->sched, stream, dep, excl);
	++ctx->streams_num;

	return stream;
}

void
tfw_h2_stream_clean(TfwH2Ctx *ctx, TfwStream *stream)
{
	T_DBG3("Stop and delete stream (id %u state %d(%s) weight %u)," 
	       " ctx %px streams num %lu\n", stream->id,
	       tfw_h2_get_stream_state(stream), __h2_strm_st_n(stream),
	       stream->weight, ctx, ctx->streams_num);
	tfw_h2_stop_stream(&ctx->sched, stream);
	tfw_h2_delete_stream(ctx, stream);
	--ctx->streams_num;
}

/*
 * Unlink the stream from a corresponding request (if linked) and from special
 * queue of closed streams (if it is contained there).
 *
 * NOTE: call to this procedure should be protected by special lock for
 * Stream linkage protection.
 */
void
tfw_h2_stream_unlink_nolock(TfwH2Ctx *ctx, TfwStream *stream)
{
	TfwHttpMsg *hmreq = (TfwHttpMsg *)stream->msg;

	tfw_h2_stream_del_from_queue_nolock(stream);

	if (hmreq) {
		hmreq->stream = NULL;
		stream->msg = NULL;
		/*
		 * If the request is linked with a stream, but not complete yet,
		 * it must be deleted right here to avoid leakage, because in
		 * this case it is not used anywhere yet. When request is
		 * assembled and complete, it will be removed (due to some
		 * processing error) in @tfw_http_req_process(), or in other
		 * cases controlled by server connection side (after adding to
		 * @fwd_queue): successful response sending, eviction etc.
		 */
		if (!test_bit(TFW_HTTP_B_FULLY_PARSED, hmreq->flags))
			tfw_http_conn_msg_free(hmreq);
	}
}

void
tfw_h2_stream_unlink_lock(TfwH2Ctx *ctx, TfwStream *stream)
{
	spin_lock(&ctx->lock);

	tfw_h2_stream_unlink_nolock(ctx, stream);

	spin_unlock(&ctx->lock);
}

void
tfw_h2_stream_add_closed(TfwH2Ctx *ctx, TfwStream *stream)
{
	spin_lock(&ctx->lock);
	tfw_h2_stream_add_to_queue_nolock(&ctx->closed_streams, stream);
	spin_unlock(&ctx->lock);
}

/*
 * Stream FSM processing during frames receipt (see RFC 7540 section
 * 5.1 for details).
 *
 * @stream - H2 stream to process
 * @type   - H2 frame type
 * @flags  - H2 frame flags
 * @send   - send or receive operation
 * @err	   - holds error, if any
 *
 * @return - Stream FSM exec status
 */
TfwStreamFsmRes
tfw_h2_stream_fsm(TfwH2Ctx *ctx, TfwStream *stream, unsigned char type,
		  unsigned char flags, bool send, TfwH2Err *err)
{
	TfwStreamFsmRes res = STREAM_FSM_RES_OK;
	TfwStreamState new_state;

/*
 * The next two macros checks RFC 9113 4.3:
 * Each field block is processed as a discrete unit. Field blocks MUST be
 * transmitted as a contiguous sequence of frames, with no interleaved
 * frames of any other type or from any other stream. The last frame in a
 * sequence of HEADERS or CONTINUATION frames has the END_HEADERS flag set.
 * The last frame in a sequence of PUSH_PROMISE or CONTINUATION frames has
 * the END_HEADERS flag set. This allows a field block to be logically
 * equivalent to a single frame.
 */
#define TFW_H2_FSM_STREAM_CHECK(ctx, stream, op)			\
do {									\
	if (ctx->cur_##op##_headers					\
	    && stream != ctx->cur_##op##_headers) { 			\
		*err = HTTP2_ECODE_PROTO;				\
		res = STREAM_FSM_RES_TERM_CONN;				\
		goto finish;						\
	}								\
} while(0)

#define TFW_H2_FSM_TYPE_CHECK(ctx, stream, op, type)			\
do {									\
	if ((ctx->cur_##op##_headers					\
	     && (type != HTTP2_CONTINUATION && type != HTTP2_RST_STREAM)) \
	    || (!ctx->cur_##op##_headers && type == HTTP2_CONTINUATION)) { \
		*err = HTTP2_ECODE_PROTO;				\
		res = STREAM_FSM_RES_TERM_CONN;				\
		goto finish;						\
	}								\
} while(0)

/* Helper macro to fit in 80 characters. */
#define SET_STATE(state)	tfw_h2_set_stream_state(stream, state)

	if (unlikely(!stream))
		return STREAM_FSM_RES_IGNORE;

	spin_lock(&stream->st_lock);

	T_DBG4("enter %s: %s strm [%p] state %d(%s) id %u, ftype %d(%s),"
	       " flags %x\n", __func__, send ? "SEND" : "RECV", stream,
	       tfw_h2_get_stream_state(stream), __h2_strm_st_n(stream),
	       stream->id, type, __h2_frm_type_n(type), flags);

	if (send) {
		TFW_H2_FSM_STREAM_CHECK(ctx, stream, send);
		TFW_H2_FSM_TYPE_CHECK(ctx, stream, send, type);
		/*
		 * Usually we would send HEADERS/CONTINUATION or DATA frames
		 * to the client when HTTP2_STREAM_REM_HALF_CLOSED state
		 * is passed, e.g. we have received END_STREAM flag from peer.
		 * However there might be the case when we can send a reply
		 * right away, not waiting for an entire request reception
		 * (RFC 9113 8.1).
		 * Consider this case:
		 *	     clnt			    srv
		 *	     ----			    ---
		 *	  [OPEN]
		 * SEND HEADERS (-END_STREAM) ->
		 * SEND DATA    (+END_STREAM) ->
		 *	  [HALF_CLOSED LOC]		  [OPEN]
		 *				>-   RECV HEADERS (-END_STREAM)
		 *					    |
		 *					    V
		 *				req is blocked by FRANG settings
		 *					    |
		 *					    V
		 *				<- SEND HEADERS (+END_STREAM)
		 *				   + close the stream/terminate
		 *				     connection
		 */
	} else {
		TFW_H2_FSM_STREAM_CHECK(ctx, stream, recv);
		TFW_H2_FSM_TYPE_CHECK(ctx, stream, recv, type);
	}

	switch (tfw_h2_get_stream_state(stream)) {
	case HTTP2_STREAM_IDLE:
		/* We don't processed sending headers for idle streams. */
		BUG_ON(send);

		/*
		 * RFC 9113 Section 6.4
		 *
		 * RST_STREAM frames MUST NOT be sent for a stream in the "idle"
		 * state. If a RST_STREAM frame identifying an idle stream is
		 * received, the recipient MUST treat this as a connection error
		 * of type PROTOCOL_ERROR.
		 */
		if (type == HTTP2_RST_STREAM) {
			*err = HTTP2_ECODE_PROTO;
			res = STREAM_FSM_RES_TERM_CONN;
			break;
		}

		if (type == HTTP2_HEADERS) {
			switch (flags
				& (HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM))
			{
			case HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM:
				SET_STATE(HTTP2_STREAM_REM_HALF_CLOSED);
				break;
			case HTTP2_F_END_HEADERS:
				SET_STATE(HTTP2_STREAM_OPENED);
				break;
			/*
			 * If END_HEADERS flag is not received, move stream
			 * into the states of waiting CONTINUATION frame.
			 */
			case HTTP2_F_END_STREAM:
				ctx->cur_recv_headers = stream;
				stream->state |=
					HTTP2_STREAM_RECV_END_OF_STREAM;
				SET_STATE(HTTP2_STREAM_OPENED);
				break;
			/*
			 * END_HEADERS and END_STREAM are not set. Next frame
			 * CONTINUATION expected.
			 */
			default:
				SET_STATE(HTTP2_STREAM_OPENED);
				ctx->cur_recv_headers = stream;
				break;
			}
		} else if (type != HTTP2_PRIORITY) {
			/*
			 * TODO receiving of HTTP2_PUSH_PROMISE switched stream
			 * to HTTP2_STREAM_REM_RESERVED state.
			 */
			*err = HTTP2_ECODE_PROTO;
			res = STREAM_FSM_RES_TERM_CONN;
		}

		break;

	case HTTP2_STREAM_LOC_RESERVED:
	case HTTP2_STREAM_REM_RESERVED:
		/*
		 * TODO: reserved states is not used for now, since client
		 * cannot push (RFC 7540 section 8.2), and Server Push on
		 * our side will be implemented in #1194.
		 */
		BUG();

	case HTTP2_STREAM_OPENED:
		if (type == HTTP2_RST_STREAM) {
			new_state = send
				? HTTP2_STREAM_LOC_CLOSED
				: HTTP2_STREAM_CLOSED;
			SET_STATE(new_state);
			break;
		}

		if (type == HTTP2_CONTINUATION) {
			/*
			 * Empty CONTINUATION frames without END_HEADERS flag
			 * are not prohibited by protocol specification. But
			 * there is no sense to process them. Just utilizes CPU
			 * without any effect, looks suspicious.
			 */
			TfwStream *snd_hdrs = send ? ctx->cur_send_headers
						   : ctx->cur_recv_headers;

			if (snd_hdrs && !(flags & HTTP2_F_END_HEADERS)
			    && ctx->plen == 0)
			{
				T_LOG("Empty CONTINUATION frame without END_HEADERS");
				*err = HTTP2_ECODE_PROTO;
				res = STREAM_FSM_RES_TERM_CONN;
				goto finish;
			}

			if (flags & HTTP2_F_END_HEADERS) {
				/*
				 * Headers are ended, next frame in the stream
				 * should be DATA frame.
				 */
				if (send) {
					ctx->cur_send_headers = NULL;
					if (tfw_h2_stream_is_eos_sent(stream)) {
						new_state =
							HTTP2_STREAM_LOC_HALF_CLOSED;
						SET_STATE(new_state);
					}
				} else {
					ctx->cur_recv_headers = NULL;
					if (tfw_h2_stream_is_eos_received(stream)) {
						new_state =
							HTTP2_STREAM_REM_HALF_CLOSED;
						SET_STATE(new_state);
					}
				}
			} else {
				if (send)
					ctx->cur_send_headers = stream;
				else
					ctx->cur_recv_headers = stream;
			}
			break;
		} else if (type == HTTP2_HEADERS) {
			/*
			 * Only trailer HEADERS block is allowed in this
			 * state.
			 */
			if (flags & HTTP2_F_END_HEADERS
			    && flags & HTTP2_F_END_STREAM)
			{
				if (send) {
					ctx->cur_send_headers = NULL;
					new_state =
						HTTP2_STREAM_LOC_HALF_CLOSED;
				} else {
					ctx->cur_recv_headers = NULL;
					stream->state |=
						HTTP2_STREAM_RECV_END_OF_STREAM;
					new_state =
						HTTP2_STREAM_REM_HALF_CLOSED;
				}
				SET_STATE(new_state);
			}
			else if (flags & HTTP2_F_END_STREAM) {
				/* Expected CONTINUATION in trailers.
				 *
				 * Don't set HTTP2_STREAM_REM/LOC_HALF_CLOSED
				 * because need to send/receive CONTINUATION
				 * frame.
				 */
				if (send) {
					ctx->cur_send_headers = stream;
					stream->state |=
						HTTP2_STREAM_SEND_END_OF_STREAM;
				} else {
					ctx->cur_recv_headers = stream;
					stream->state |=
						HTTP2_STREAM_RECV_END_OF_STREAM;
				}
			}
			else {
				if (send)
					ctx->cur_send_headers = stream;
				else
					ctx->cur_recv_headers = stream;
			}
			break;

		} else if (type == HTTP2_DATA) {
			/*
			 * Empty DATA frames without END_STREAM flag are not
			 * prohibited by protocol specification. But there is
			 * no sense to process them. Just utilizes CPU without
			 * any effect, looks suspicious.
			 */
			if (!ctx->plen
			    && !(ctx->hdr.flags & HTTP2_F_END_STREAM))
			{
				T_LOG("Empty DATA frame without END_STREAM");
				*err = HTTP2_ECODE_PROTO;
				res = STREAM_FSM_RES_TERM_CONN;
				goto finish;
			}

			if (flags & HTTP2_F_END_STREAM) {
				new_state = send
					? HTTP2_STREAM_LOC_HALF_CLOSED
					: HTTP2_STREAM_REM_HALF_CLOSED;
				SET_STATE(new_state);
			}
		}

		break;

	case HTTP2_STREAM_LOC_HALF_CLOSED:
		if (!send) {
			if (type == HTTP2_RST_STREAM) {
				SET_STATE(HTTP2_STREAM_CLOSED);
				break;
			}

			if (type == HTTP2_HEADERS
			    || type == HTTP2_CONTINUATION) {
				switch (flags
					& (HTTP2_F_END_HEADERS |
					   HTTP2_F_END_STREAM))
				{
				case HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM:
					ctx->cur_recv_headers = NULL;
					SET_STATE(HTTP2_STREAM_CLOSED);
					break;
				case HTTP2_F_END_HEADERS:
					/*
					 * Headers is ended, next frame in the
					 * stream should be DATA frame.
					 */
					ctx->cur_recv_headers = NULL;
					break;
				case HTTP2_F_END_STREAM:
					ctx->cur_recv_headers = stream;
					stream->state |=
						HTTP2_STREAM_RECV_END_OF_STREAM;
					break;
				default:
					ctx->cur_recv_headers = stream;
					break;
				}
			} else if (type == HTTP2_DATA) {
				if (flags & HTTP2_F_END_STREAM)
					SET_STATE(HTTP2_STREAM_CLOSED);
			}

			break;
		}

		/*
		 * TFC 9113 section 5.1:
		 * A stream that is in the "half-closed (local)"
		 * state cannot be used for sending frames other
		 * than WINDOW_UPDATE, PRIORITY, and RST_STREAM.
		 */
		if (type == HTTP2_RST_STREAM)
		{
			SET_STATE(HTTP2_STREAM_LOC_CLOSED);
		}
		else if (type != HTTP2_PRIORITY
			 && type != HTTP2_WINDOW_UPDATE) {
			res = STREAM_FSM_RES_IGNORE;
		}

		break;

	case HTTP2_STREAM_REM_HALF_CLOSED:
		if (send) {
			if (type == HTTP2_HEADERS ||
			    type == HTTP2_CONTINUATION) {
				switch (flags
					& (HTTP2_F_END_HEADERS |
					   HTTP2_F_END_STREAM))
				{
				/*
				 * RFC 9113 5.1 (half-closed (remote) state):
				 * A stream can transition from this state to
				 * "closed" by sending a frame with the
				 * END_STREAM flag set.
				 */
				case HTTP2_F_END_STREAM:
					ctx->cur_send_headers = stream;
					stream->state |=
						HTTP2_STREAM_SEND_END_OF_STREAM;
					break;
				case HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM:
					ctx->cur_send_headers = NULL;
					SET_STATE(HTTP2_STREAM_CLOSED);
					break;
				case HTTP2_F_END_HEADERS:
					/*
					 * Headers are ended, next frame in the
					 * stream should be DATA frame.
					 */
					ctx->cur_send_headers = NULL;
					break;

				default:
					ctx->cur_send_headers = stream;
					break;
				}
			} else if (type == HTTP2_DATA) {
				if (flags & HTTP2_F_END_STREAM)
					SET_STATE(HTTP2_STREAM_CLOSED);
			} else if (type == HTTP2_RST_STREAM) {
				SET_STATE(HTTP2_STREAM_CLOSED);
			}

			break;
		}

		/*
		 * RFC 9113 section 5.1 (half-closed (remote) state):
		 * If an endpoint receives additional frames, other
		 * than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for
		 * a stream that is in this state, it MUST respond
		 * with a stream error (Section 5.4.2) of type
		 * STREAM_CLOSED.
		 */
		if (type == HTTP2_RST_STREAM)
		{
			SET_STATE(HTTP2_STREAM_CLOSED);
		}
		else if (type != HTTP2_PRIORITY && type != HTTP2_WINDOW_UPDATE)
		{
			/*
			 * We always send RST_STREAM to the peer in this case;
			 * thus, the stream should be switched to the
			 * 'closed' state.
			 */
			SET_STATE(HTTP2_STREAM_CLOSED);
			*err = HTTP2_ECODE_CLOSED;
			res = STREAM_FSM_RES_TERM_STREAM;
		}

		break;

	/*
	 * This state is not described in RFC 9113, but it is necessary to
	 * implement handling of situation, when an endpoint sends RST_STREAM
	 * frame on a stream in the "open" or "half-closed (local)" state.
	 */
	case HTTP2_STREAM_LOC_CLOSED:
		if (send) {
			res = STREAM_FSM_RES_IGNORE;
			break;
		}

		/*
		 * RFC 9113 section 5.1:
		 * An endpoint that sends a RST_STREAM frame on a stream
		 * that is in the "open" or "half-closed (local)" state
		 * could receive any type of frame.
		 * An endpoint MUST minimally process and then discard
		 * any frames it receives in this state.
		 */
		if (type == HTTP2_RST_STREAM)
			SET_STATE(HTTP2_STREAM_CLOSED);
		else if (type != HTTP2_WINDOW_UPDATE)
			res = STREAM_FSM_RES_IGNORE;

		break;

	case HTTP2_STREAM_CLOSED:
		T_WARN("%s, stream fully closed: stream->id=%u, type=%hhu,"
		       " flags=0x%hhx\n", __func__, stream->id, type, flags);
		if (send) {
			res = STREAM_FSM_RES_IGNORE;
		} else {
			if (type != HTTP2_PRIORITY) {
				*err = HTTP2_ECODE_PROTO;
				res = STREAM_FSM_RES_TERM_CONN;
			}
		}

		break;
	default:
		BUG();
	}

finish:
	if (type == HTTP2_RST_STREAM || res == STREAM_FSM_RES_TERM_STREAM)
		tfw_h2_conn_reset_stream_on_close(ctx, stream);

	T_DBG4("exit %s: strm [%p] state %d(%s), res %d\n", __func__, stream,
	       tfw_h2_get_stream_state(stream), __h2_strm_st_n(stream), res);

	spin_unlock(&stream->st_lock);

	return res;

#undef SET_STATE
#undef TFW_H2_FSM_TYPE_CHECK
#undef TFW_H2_FSM_STREAM_CHECK
}

TfwStream *
tfw_h2_find_stream(TfwStreamSched *sched, unsigned int id)
{
	struct rb_node *node = sched->streams.rb_node;

	while (node) {
		TfwStream *stream = rb_entry(node, TfwStream, node);

		if (id < stream->id)
			node = node->rb_left;
		else if (id > stream->id)
			node = node->rb_right;
		else
			return stream;
	}

	return NULL;
}

void
tfw_h2_delete_stream(TfwH2Ctx *ctx, TfwStream *stream)
{
	BUG_ON(stream->xmit.resp || stream->xmit.skb_head);
	tfw_h2_free_stream_sched_entry(ctx, stream->sched);
	kmem_cache_free(stream_cache, stream);
}

void
tfw_h2_stream_skb_destructor(struct sk_buff *skb)
{
	TfwHttpResp *resp = (TfwHttpResp *)TFW_SKB_CB(skb)->opaque_data;

	TFW_SKB_CB(skb)->opaque_data = resp->req->conn->peer;
	ss_skb_dflt_destructor(skb);
	tfw_http_resp_pair_free_and_put_conn(resp);
}

int
tfw_h2_stream_init_for_xmit(TfwHttpResp *resp, TfwStreamXmitState state,
			    unsigned long h_len, unsigned long b_len)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(resp->req->conn);
	struct sk_buff *skb_head = resp->msg.skb_head;
	TfwStream *stream;

	spin_lock(&ctx->lock);

	stream = resp->req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return -EPIPE;
	}

	TFW_SKB_CB(skb_head)->on_send = tfw_h2_on_send_resp;
	TFW_SKB_CB(skb_head)->stream_id = stream->id;

	stream->xmit.resp = NULL;
	stream->xmit.skb_head = NULL;
	stream->xmit.h_len = h_len;
	stream->xmit.b_len = b_len;
	stream->xmit.t_len = 0;
	stream->xmit.state = state;
	stream->xmit.frame_length = 0;
	stream->xmit.is_blocked = false;

	spin_unlock(&ctx->lock);

	return 0;
}

int
tfw_h2_stream_init_t_len_for_xmit(TfwHttpResp *resp, unsigned long t_len)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(resp->req->conn);
	TfwStream *stream;

	spin_lock(&ctx->lock);

	stream = resp->req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return -EPIPE;
	}

	stream->xmit.t_len = t_len;

	spin_unlock(&ctx->lock);

	return 0;
}
