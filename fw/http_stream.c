/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2022 Tempesta Technologies, Inc.
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
tfw_h2_stream_fsm(TfwStream *stream, unsigned char type, unsigned char flags,
		  bool send, TfwH2Err *err)
{
	TfwStreamFsmRes res = STREAM_FSM_RES_OK;

	if (unlikely(!stream))
		return STREAM_FSM_RES_IGNORE;

	spin_lock(&stream->st_lock);

	T_DBG3("enter %s: %s strm [%p] state %d(%s) id %u, ftype %d(%s), flags %x\n",
	       __func__, send ? "SEND" : "RECV", stream, stream->state,
	       __h2_strm_st_n(stream->state), stream->id, type, __h2_frm_type_n(type),
	       flags);

	if (send) {
		/*
		 * In the sending flow this FSM procedure intended only for
		 * HEADERS, DATA and RST_STREAM frames processing.
		 */
		BUG_ON(type != HTTP2_HEADERS && type != HTTP2_DATA
		       && type != HTTP2_RST_STREAM);
		/*
		 * Usually we would send HEADERS/CONTINUATION or DATA frames
		 * to the client when HTTP2_STREAM_REM_HALF_CLOSED state
		 * is passed, e.g. we have received END_STREAM flag from peer.
		 * However there might be the case when we can send a reply
		 * right away, not waiting for an entire request reception (RFC 9113 8.1).
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
		 *				   + close the stream/terminate connection
		 */
	}

	switch (stream->state) {
	case HTTP2_STREAM_LOC_RESERVED:
	case HTTP2_STREAM_REM_RESERVED:
		/*
		 * TODO: reserved states is not used for now, since client
		 * cannot push (RFC 7540 section 8.2), and Server Push on
		 * our side will be implemented in #1194.
		 */
		BUG();

	case HTTP2_STREAM_OPENED:
		/*
		 * In 'opened' state receiving of all frame types is allowed
		 * (in this implementation - except CONTINUATION frames, which
		 * are processed in special separate states). Receiving HEADERS
		 * frame with both END_HEADERS and END_STREAM flags (or DATA
		 * frame with END_STREAM flag) move stream into 'half-closed
		 * (remote)' state.
		 */
		if (type == HTTP2_HEADERS) {
			switch (flags
				& (HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM))
			{
			case HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM:
				stream->state = HTTP2_STREAM_REM_HALF_CLOSED;
				break;
			case HTTP2_F_END_HEADERS:
				/*
				 * Headers is ended, next frame in the stream
				 * should be DATA frame.
				 */
				break;
			/*
			 * If END_HEADERS flag is not received, move stream into
			 * the states of waiting CONTINUATION frame.
			 */
			case HTTP2_F_END_STREAM:
				stream->state = send
					? HTTP2_STREAM_LOC_CLOSED
					: HTTP2_STREAM_CONT_CLOSED;
				break;
			default:
				stream->state = HTTP2_STREAM_CONT;
				break;
			}
		}
		else if (type == HTTP2_DATA && (flags & HTTP2_F_END_STREAM)) {
			stream->state = HTTP2_STREAM_REM_HALF_CLOSED;
		}
		/*
		 * Received RST_STREAM frame immediately moves stream into the
		 * final 'closed' state, while the sent RST_STREAM moves stream
		 * into the intermediate 'locally closed' state.
		 */
		else if (type == HTTP2_RST_STREAM) {
			stream->state = send
				? HTTP2_STREAM_LOC_CLOSED
				: HTTP2_STREAM_CLOSED;
		}
		else if (type == HTTP2_CONTINUATION) {
			/*
			 * CONTINUATION frames are allowed only in stream's
			 * state specially intended for continuation awaiting
			 * (RFC 7540 section 6.10).
			 */
			*err = HTTP2_ECODE_PROTO;
			res = STREAM_FSM_RES_TERM_CONN;
		}

		break;

	case HTTP2_STREAM_CONT:
		if (send && type == HTTP2_RST_STREAM) {
			stream->state = HTTP2_STREAM_LOC_CLOSED;
			break;
		}
		/*
		 * Only CONTINUATION frames are allowed (after HEADERS or
		 * CONTINUATION frames) until frame with END_HEADERS flag will
		 * be received (see RFC 7540 section 6.2 for details).
		 */
		if (type != HTTP2_CONTINUATION) {
			*err = HTTP2_ECODE_PROTO;
			res = STREAM_FSM_RES_TERM_CONN;
			break;
		}
		/*
		 * Once END_HEADERS flag is received, move stream into standard
		 * processing state (see RFC 7540 section 6.10 for details).
		 */
		if (flags & HTTP2_F_END_HEADERS)
			stream->state = HTTP2_STREAM_OPENED;

		break;

	case HTTP2_STREAM_CONT_CLOSED:
		if (send && type == HTTP2_RST_STREAM) {
			stream->state = HTTP2_STREAM_LOC_CLOSED;
			break;
		}
		if (type != HTTP2_CONTINUATION) {
			*err = HTTP2_ECODE_PROTO;
			res = STREAM_FSM_RES_TERM_CONN;
			break;
		}
		/*
		 * If END_HEADERS flag arrived in this state, this means that
		 * END_STREAM flag had been already received earlier, and we
		 * must move stream into half-closed (remote) processing state
		 * (see RFC 7540 section 6.2 for details).
		 */
		if (flags & HTTP2_F_END_HEADERS)
			stream->state = HTTP2_STREAM_REM_HALF_CLOSED;

		break;

	case HTTP2_STREAM_LOC_CLOSED:
		/* All types of frames are allowed in this state. */
		if (type == HTTP2_RST_STREAM) {
			if (send) {
				res = STREAM_FSM_RES_IGNORE;
				break;
			}
			stream->state = HTTP2_STREAM_CLOSED;
		}

		break;

	case HTTP2_STREAM_REM_HALF_CLOSED:
		if (send) {
			if (type == HTTP2_RST_STREAM
			    || flags & HTTP2_F_END_STREAM)
				stream->state = HTTP2_STREAM_REM_CLOSED;
			break;
		}
		/*
		 * The only allowed received stream-related frames in 'half-closed
		 * (remote)' state are PRIORITY, RST_STREAM and WINDOW_UPDATE.
		 * If RST_STREAM frame is received in this state, the stream
		 * will be removed from stream's storage (i.e. moved into final
		 * 'closed' state).
		 */
		if (type == HTTP2_CONTINUATION) {
			*err = HTTP2_ECODE_PROTO;
			res = STREAM_FSM_RES_TERM_CONN;
			break;
		}

		if (type == HTTP2_RST_STREAM)
		{
			stream->state = HTTP2_STREAM_CLOSED;
		}
		else if (type != HTTP2_PRIORITY && type != HTTP2_WINDOW_UPDATE)
		{
			/*
			 * We always send RST_STREAM to the peer in this case;
			 * thus, the stream should be switched to the
			 * 'closed (remote)' state.
			 */
			stream->state = HTTP2_STREAM_REM_CLOSED;
			*err = HTTP2_ECODE_CLOSED;
			res = STREAM_FSM_RES_TERM_STREAM;
		}

		break;

	case HTTP2_STREAM_REM_CLOSED:
		/*
		 * Sending of HEADERS/DATA and RST_STREAM frames must be ignored
		 * in this state, since the state is in 'closed (remote)' state,
		 * i.e. either it had already been reset from our side, or the
		 * HEADERS/DATA with END_STREAM flag had already been sent from
		 * us. Receiving of RST_STREAM and WINDOW_UPDATE frames should
		 * also be ignored according to RFC 7540, section 5.1 ('closed'
		 * paragraph). Receiving of all other frames should be ignored
		 * as well (except PRIORITY frames which should be processed
		 * even for closed streams), since there is no sense to respond
		 * into already closed stream. Receiving of CONTINUATION frames
		 * is forbidden (RFC 7540 section 6.10 stated that connection
		 * must be closed in such case).
		 */
		if (type == HTTP2_PRIORITY)
			break;

		if (!send) {
			switch (type) {
			case HTTP2_WINDOW_UPDATE:
			case HTTP2_RST_STREAM:
				res = STREAM_FSM_RES_IGNORE;
				break;
			case HTTP2_HEADERS:
			case HTTP2_PUSH_PROMISE:
				/* RFC 9113, sec 5.1.1:
				 *
				 * The identifier of a newly established stream MUST be
				 * numerically greater than all streams that the initiating
				 * endpoint has opened or reserved. This governs streams that
				 * are opened using a HEADERS frame and streams that are
				 * reserved using PUSH_PROMISE. An endpoint that receives an
				 * unexpected stream identifier MUST respond with a connection
				 * error (Section 5.4.1) of type PROTOCOL_ERROR.
				 */
				res = STREAM_FSM_RES_TERM_CONN;
				*err = HTTP2_ECODE_PROTO;
				break;
			default:
				/* At this point we're likely being in a "half-closed (remote)"
				 * state with response being sent to the client. This means
				 * that we need to apply RFC 9113 rule from sec 5.1:
				 *
				 * If an endpoint receives additional frames, other than
				 * WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is
				 * in this state, it MUST respond with a stream error
				 * (Section 5.4.2) of type STREAM_CLOSED.
				 */
				res = STREAM_FSM_RES_TERM_CONN;
				*err = HTTP2_ECODE_CLOSED;
			}
		}

		break;

	case HTTP2_STREAM_CLOSED:
		T_DBG3("%s, stream fully closed: stream->id=%u, type=%hhu,"
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

	T_DBG3("exit %s: strm [%p] state %d(%s), res %d\n", __func__, stream,
	       stream->state, __h2_strm_st_n(stream->state), res);

	spin_unlock(&stream->st_lock);

	return res;
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

TfwStream *
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

void
tfw_h2_delete_stream(TfwStream *stream)
{
	kmem_cache_free(stream_cache, stream);
}

int
tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id, TfwStream **dep)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
	return 0;
}

void
tfw_h2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream, TfwStream *dep,
		      bool excl)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
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

static void
tfw_h2_remove_stream_dep(TfwStreamSched *sched, TfwStream *stream)
{
	/*
	 * TODO: implement dependency/priority logic (according to RFC 7540
	 * section 5.3) in context of #1196.
	 */
}

void
tfw_h2_stop_stream(TfwStreamSched *sched, TfwStream *stream)
{
	tfw_h2_remove_stream_dep(sched, stream);
	rb_erase(&stream->node, &sched->streams);
}
