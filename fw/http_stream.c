/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2023 Tempesta Technologies, Inc.
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

static int
tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id, TfwStream **dep)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
	return 0;
}

static void
tfw_h2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream, TfwStream *dep,
		      bool excl)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}

static void
tfw_h2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}

static void
tfw_h2_stop_stream(TfwStreamSched *sched, TfwStream *stream)
{
	TfwH2Ctx *ctx = container_of(sched, TfwH2Ctx, sched);

	tf2_h2_conn_reset_stream_on_close(ctx, stream);
	tfw_h2_remove_stream_dep(sched, stream);
	rb_erase(&stream->node, &sched->streams);
}

static inline void
tfw_h2_init_stream(TfwStream *stream, unsigned int id, unsigned short weight,
		   long int loc_wnd, long int rem_wnd)
{
	RB_CLEAR_NODE(&stream->node);
	INIT_LIST_HEAD(&stream->hcl_node);
	spin_lock_init(&stream->st_lock);
	stream->id = id;
	stream->state = HTTP2_STREAM_OPENED;
	stream->loc_wnd = loc_wnd;
	stream->rem_wnd = rem_wnd;
	stream->weight = weight ? weight : HTTP2_DEF_WEIGHT;
}

static TfwStream *
tfw_h2_add_stream(TfwStreamSched *sched, unsigned int id, unsigned short weight,
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

	tfw_h2_init_stream(new_stream, id, weight, loc_wnd, rem_wnd);

	rb_link_node(&new_stream->node, parent, new);
	rb_insert_color(&new_stream->node, &sched->streams);

	return new_stream;
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
	TfwStream *stream, *dep = NULL;
	TfwFramePri *pri = &ctx->priority;
	bool excl = pri->exclusive;

	if (tfw_h2_find_stream_dep(&ctx->sched, pri->stream_id, &dep))
		return NULL;

	stream = tfw_h2_add_stream(&ctx->sched, id, pri->weight,
				   ctx->lsettings.wnd_sz,
				   ctx->rsettings.wnd_sz);
	if (!stream)
		return NULL;

	tfw_h2_add_stream_dep(&ctx->sched, stream, dep, excl);

	++ctx->streams_num;

	T_DBG3("%s: ctx [%p] (streams_num %lu, dep strm id %u, dep strm [%p], excl %u)\n"
	       "added strm [%p] id %u weight %u\n",
	       __func__, ctx, ctx->streams_num, pri->stream_id, dep, pri->exclusive,
	       stream, id, stream->weight);

	return stream;
}

void
tfw_h2_stream_clean(TfwH2Ctx *ctx, TfwStream *stream)
{
	T_DBG3("%s: strm [%p] id %u state %d(%s) weight %u, ctx "
	       "streams num %lu\n",  __func__, stream, stream->id,
	       tfw_h2_get_stream_state(stream), __h2_strm_st_n(stream),
	       stream->weight, ctx->streams_num);
	tfw_h2_stop_stream(&ctx->sched, stream);
	tfw_h2_delete_stream(stream);
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
 * Stream closing procedure: move the stream into special queue of closed
 * streams and send RST_STREAM frame to peer. This procedure is intended
 * for usage only in receiving flow of Framing layer, thus the stream is
 * definitely alive here and we need not any unlinking operations since
 * all the unlinking and cleaning work will be made later, during shrinking
 * the queue of closed streams; thus, we just move the stream into the
 * closed queue here.
 * We also reset the current stream of the H2 context here.
 */
int
tfw_h2_stream_close(TfwH2Ctx *ctx, unsigned int id, TfwStream **stream,
		    TfwH2Err err_code)
{
	if (stream && *stream) {
		T_DBG3("%s: ctx [%p] strm %p id %d err %u\n", __func__,
			ctx, *stream, id, err_code);
		tf2_h2_conn_reset_stream_on_close(ctx, *stream);
		if (tfw_h2_get_stream_state(*stream) >
		    HTTP2_STREAM_REM_HALF_CLOSED) {
			tfw_h2_stream_add_closed(ctx, *stream);
		} else {
			/*
			 * This function is always called after processing
			 * RST STREAM or stream error.
			 */
			BUG();
		}
		*stream = NULL;
	}

	return tfw_h2_send_rst_stream(ctx, id, err_code);
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
	if ((ctx->cur_##op##_headers && type != HTTP2_CONTINUATION)	\
	    || (!ctx->cur_##op##_headers && type == HTTP2_CONTINUATION)) { \
		*err = HTTP2_ECODE_PROTO;				\
		res = STREAM_FSM_RES_TERM_CONN;				\
		break;							\
	}								\
} while(0)

/* Helper macro to fit in 80 characters. */
#define SET_STATE(state)	tfw_h2_set_stream_state(stream, state)

	if (unlikely(!stream))
		return STREAM_FSM_RES_IGNORE;

	spin_lock(&stream->st_lock);

	T_DBG3("enter %s: %s strm [%p] state %d(%s) id %u, ftype %d(%s),"
	       " flags %x\n", __func__, send ? "SEND" : "RECV", stream,
	       tfw_h2_get_stream_state(stream), __h2_strm_st_n(stream),
	       stream->id, type, __h2_frm_type_n(type), flags);

	if (send) {
		TFW_H2_FSM_STREAM_CHECK(ctx, stream, send);
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
	}

	switch (tfw_h2_get_stream_state(stream)) {
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

		if (send) {
			TFW_H2_FSM_TYPE_CHECK(ctx, stream, send, type);
		} else {
			TFW_H2_FSM_TYPE_CHECK(ctx, stream, recv, type);
		}

		if (type == HTTP2_HEADERS || type == HTTP2_CONTINUATION) {
			switch (flags
				& (HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM))
			{
			case HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM:
				new_state = send
					? HTTP2_STREAM_LOC_HALF_CLOSED
					: HTTP2_STREAM_REM_HALF_CLOSED;
				SET_STATE(new_state);
				break;
			case HTTP2_F_END_HEADERS:
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

				break;
			/*
			 * If END_HEADERS flag is not received, move stream
			 * into the states of waiting CONTINUATION frame.
			 */
			case HTTP2_F_END_STREAM:
				if (send) {
					ctx->cur_send_headers = stream;
					stream->state |=
						HTTP2_STREAM_SEND_END_OF_STREAM;
				} else {
					ctx->cur_recv_headers = stream;
					stream->state |=
						HTTP2_STREAM_RECV_END_OF_STREAM;
				}

				break;
			default:
				if (send) {
					ctx->cur_send_headers = stream;
				} else {
					ctx->cur_recv_headers = stream;
				}

				break;
			}
		} else if (type == HTTP2_DATA) {
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

			TFW_H2_FSM_TYPE_CHECK(ctx, stream, recv, type);

			if (type == HTTP2_HEADERS
			    || type == HTTP2_CONTINUATION) {
				switch (flags
					& (HTTP2_F_END_HEADERS |
					   HTTP2_F_END_STREAM))
				{
				case HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM:
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
					SET_STATE(HTTP2_STREAM_CLOSED);
					ctx->cur_recv_headers = NULL;
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
			if (type == HTTP2_RST_STREAM
			    || flags & HTTP2_F_END_STREAM)
				SET_STATE(HTTP2_STREAM_REM_CLOSED);
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
			 * 'closed (remote)' state.
			 */
			SET_STATE(HTTP2_STREAM_REM_CLOSED);
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
		/*
		 * RFC 9113 section 5.1:
		 * An endpoint that sends a RST_STREAM frame on a stream
		 * that is in the "open" or "half-closed (local)" state
		 * could receive any type of frame.
		 */
		if (send) {
			res = STREAM_FSM_RES_IGNORE;
			break;
		}

		if (type == HTTP2_RST_STREAM)
			SET_STATE(HTTP2_STREAM_CLOSED);

		break;

	/*
	 * This state is not described in RFC 9113, but it is necessary to
	 * implement handling of situation when an endpoint that sends a
	 * frame with the END_STREAM flag set or a RST_STREAM frame might
	 * receive a WINDOW_UPDATE or RST_STREAM frame from its peer.
	 */
	case HTTP2_STREAM_REM_CLOSED:
		if (type == HTTP2_PRIORITY)
			break;

		if (send) {
			res = STREAM_FSM_RES_IGNORE;
			break;
		}

		if (type == HTTP2_RST_STREAM) {
			SET_STATE(HTTP2_STREAM_CLOSED);
			break;
		} else if (type == HTTP2_WINDOW_UPDATE)
			break;

		*err = HTTP2_ECODE_PROTO;
		res = STREAM_FSM_RES_TERM_CONN;

		break;

	case HTTP2_STREAM_CLOSED:
		T_WARN("%s, stream fully closed: stream->id=%u, type=%hhu,"
		       " flags=0x%hhx\n", __func__, stream->id, type, flags);
		if (send) {
			res = STREAM_FSM_RES_IGNORE;
			break;
		}
		/*
		 * In moment when the final 'closed' state is achieved, stream
		 * actually must be removed from stream's storage (and from
		 * memory), thus the receive execution flow must not reach this
		 * point.
		 */
		fallthrough;
	default:
		BUG();
	}

finish:
	T_DBG3("exit %s: strm [%p] state %d(%s), res %d\n", __func__, stream,
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
tfw_h2_delete_stream(TfwStream *stream)
{
	kmem_cache_free(stream_cache, stream);
}

void
tfw_h2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			 unsigned int new_dep, unsigned short new_weight,
			 bool excl)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}

int
tfw_h2_stream_init_for_xmit(TfwHttpReq *req, unsigned long h_len,
			    unsigned long b_len)
{
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);
	TfwStream *stream;

	spin_lock(&ctx->lock);

	stream = req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return -EPIPE;
	}

	stream->xmit.h_len = h_len;
	stream->xmit.b_len = b_len;
	tfw_h2_stream_xmit_reinit(&stream->xmit);

	spin_unlock(&ctx->lock);

	return 0;
}

TfwStreamFsmRes
tfw_h2_stream_send_process(TfwH2Ctx *ctx, TfwStream *stream, unsigned char type)
{
	TfwStreamFsmRes r;
	unsigned char flags = 0;

	BUG_ON(stream->xmit.h_len && stream->xmit.b_len);

	if (!stream->xmit.h_len && type != HTTP2_DATA)
		flags |= HTTP2_F_END_HEADERS;

	if (!stream->xmit.b_len)
		flags |= HTTP2_F_END_STREAM;

	if (!stream->xmit.t_len && type == HTTP2_TRAILER_HEADERS) {
		flags |= HTTP2_F_END_HEADERS;
		flags |= HTTP2_F_END_STREAM;
		type = HTTP2_DATA;
	}

	r = tfw_h2_stream_fsm_ignore_err(ctx, stream, type, flags);
	if (flags & HTTP2_F_END_STREAM
	    || (r && r != STREAM_FSM_RES_IGNORE))
		tfw_h2_stream_add_closed(ctx, stream);

	return r != STREAM_FSM_RES_IGNORE ? r : STREAM_FSM_RES_OK;
}
