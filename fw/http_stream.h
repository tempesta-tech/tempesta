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
#ifndef __HTTP_STREAM__
#define __HTTP_STREAM__

#include "http_stream_sched.h"
#include "msg.h"
#include "http_parser.h"
#include "lib/str.h"
#include "ss_skb.h"

/**
 * States for HTTP/2 streams processing.
 *
 * NOTE: there is no exact matching between these states and states from
 * RFC 7540 (section 5.1), since several intermediate states were added in
 * current implementation to handle some edge states which are not mentioned
 * explicitly in RFC (special kinds of closed state). Besides, there is no
 * explicit 'idle' state here, since in current implementation idle stream
 * is just a stream that has not been created yet.
 */
typedef enum {
	HTTP2_STREAM_IDLE,
	HTTP2_STREAM_LOC_RESERVED,
	HTTP2_STREAM_REM_RESERVED,
	HTTP2_STREAM_OPENED,
	HTTP2_STREAM_LOC_HALF_CLOSED,
	HTTP2_STREAM_REM_HALF_CLOSED,
	HTTP2_STREAM_LOC_CLOSED,
	HTTP2_STREAM_REM_CLOSED,
	HTTP2_STREAM_CLOSED
} TfwStreamState;

enum {
	HTTP2_STREAM_STATE_MASK = 0x7,
	HTTP2_STREAM_FLAGS_OFFSET = 0x3,
	HTTP2_STREAM_SEND_END_OF_STREAM = 0x1 << HTTP2_STREAM_FLAGS_OFFSET,
	HTTP2_STREAM_RECV_END_OF_STREAM = 0x2 << HTTP2_STREAM_FLAGS_OFFSET,
};

typedef enum {
	HTTP2_ENCODE_HEADERS,
	HTTP2_CUTOFF_BODY_CHUNKS,
	HTTP2_RELEASE_RESPONSE,
	HTTP2_ENCODE_HPACK_TBL_SIZE,
	HTTP2_MAKE_HEADERS_FRAMES,
	HTTP2_MAKE_CONTINUATION_FRAMES,
	HTTP2_MAKE_DATA_FRAMES,
	HTTP2_SEND_FRAME,
	HTTP2_MAKE_FRAMES_FINISH,
} TfwStreamXmitState;

static const char *__tfw_strm_st_names[] = {
	[HTTP2_STREAM_IDLE]		= "HTTP2_STREAM_IDLE",
	[HTTP2_STREAM_LOC_RESERVED]	= "HTTP2_STREAM_LOC_RESERVED",
	[HTTP2_STREAM_REM_RESERVED]	= "HTTP2_STREAM_REM_RESERVED",
	[HTTP2_STREAM_OPENED]	    	= "HTTP2_STREAM_OPENED",
	[HTTP2_STREAM_LOC_HALF_CLOSED]	= "HTTP2_STREAM_LOC_HALF_CLOSED",
	[HTTP2_STREAM_REM_HALF_CLOSED]	= "HTTP2_STREAM_REM_HALF_CLOSED",
	[HTTP2_STREAM_LOC_CLOSED]	= "HTTP2_STREAM_LOC_CLOSED",
	[HTTP2_STREAM_REM_CLOSED]	= "HTTP2_STREAM_REM_CLOSED",
	[HTTP2_STREAM_CLOSED]		= "HTTP2_STREAM_CLOSED",
};

/**
 * Final statuses of Stream FSM processing.
 */
typedef enum {
	STREAM_FSM_RES_OK,
	STREAM_FSM_RES_TERM_CONN,
	STREAM_FSM_RES_TERM_STREAM,
	STREAM_FSM_RES_IGNORE
} TfwStreamFsmRes;

/**
 * HTTP/2 error codes (RFC 7540 section 7). Used in RST_STREAM
 * and GOAWAY frames to report the reasons of the stream or
 * connection error.
 */
typedef enum {
	HTTP2_ECODE_NO_ERROR		= 0,
	HTTP2_ECODE_PROTO,
	HTTP2_ECODE_INTERNAL,
	HTTP2_ECODE_FLOW,
	HTTP2_ECODE_SETTINGS_TIMEOUT,
	HTTP2_ECODE_CLOSED,
	HTTP2_ECODE_SIZE,
	HTTP2_ECODE_REFUSED,
	HTTP2_ECODE_CANCEL,
	HTTP2_ECODE_COMPRESSION,
	HTTP2_ECODE_CONNECT,
	HTTP2_ECODE_ENHANCE_YOUR_CALM,
	HTTP2_ECODE_INADEQUATE_SECURITY,
	HTTP2_ECODE_HTTP_1_1_REQUIRED
} TfwH2Err;

/**
 * Last http2 response info, used to prepare frames
 * in `xmit` callbacks.
 *
 * @resp		- responce, that should be sent.
 * @skb_head		- head of skb list that must be sent.
 * @h_len		- length of headers in http2 response;
 * @b_len		- length of body in http2 response;
 * @mark		- mark of the resp skb_head;
 * @state		- type of operation should be made for this
 *			  stream (encoding headers or making frame
 *			  with appropriate type);
 * @frame_length	- length of current sending frame;
 * @tls_type		- tls type for skbs;
 * @is_blocked  	- stream is blocked, because of exceeding of
 *			  HTTP window;
 * @is_progressive	- stream has benefit from processing in parallel;
 */
typedef struct {
	TfwHttpResp		*resp;
	struct sk_buff		*skb_head;
	unsigned long		h_len;
	unsigned long		b_len;
	unsigned int		mark;
	TfwStreamXmitState	state;
	unsigned int		frame_length;
	unsigned char		tls_type;
	bool			is_blocked;
	bool			is_progressive;
} TfwHttpXmit;

/**
 * Limited queue for temporary storage of half-closed or pending half-closed
 * streams.
 * This structure provides the possibility of temporary existing in memory -
 * for streams which are in HTTP2_STREAM_LOC_CLOSED or HTTP2_STREAM_REM_CLOSED
 * states (see RFC 7540, section 5.1, the 'closed' paragraph). Note, that
 * streams in HTTP2_STREAM_CLOSED state are not stored in this queue and must
 * be removed right away.
 *
 * @list		- list of streams which are in closed state;
 * @num			- number of streams in the list;
 */
typedef struct {
	struct list_head	list;
	unsigned long		num;
} TfwStreamQueue;

typedef enum {
	HTTP2_STREAM_SCHED_STATE_UNKNOWN,
	HTTP2_STREAM_SCHED_STATE_BLOCKED,
	HTTP2_STREAM_SCHED_STATE_ACTIVE,
} TfwStreamSchedState;

/**
 * Representation of HTTP/2 stream entity.
 *
 * @node	- entry in per-connection storage of streams (red-black tree);
 * @sched_node	- entry in per-connection priority storage of active streams;
 * @sched	- scheduler for child streams;
 * sched_state	- state of stream in the per-connection scheduler;
 * @id		- stream ID;
 * @hcl_node	- entry in queue of half-closed or closed streams;
 * @st_lock	- spinlock to synchronize concurrent access to stream FSM;
 * @state	- stream's current state;
 * @loc_wnd	- stream's current flow controlled window;
 * @rem_wnd	- streams's current flow controlled window for remote client;
 * @msg		- message that is currently being processed;
 * @parser	- the state of message processing;
 * @queue	- queue of half-closed or closed streams or NULL;
 * @xmit	- last http2 response info, used in `xmit` callbacks;
 * @weight	- stream's priority weight;
 */
struct tfw_http_stream_t {
	struct rb_node		node;
	struct eb64_node	sched_node;
	TfwStreamSchedEntry	*sched;
	TfwStreamSchedState	sched_state;
	unsigned int		id;
	struct list_head	hcl_node;
	spinlock_t		st_lock;
	int			state;
	long int		loc_wnd;
	long int		rem_wnd;
	TfwMsg			*msg;
	TfwHttpParser		parser;
	TfwStreamQueue		*queue;
	TfwHttpXmit		xmit;
	unsigned short		weight;
};

typedef struct tfw_h2_ctx_t TfwH2Ctx;

int tfw_h2_stream_cache_create(void);
void tfw_h2_stream_cache_destroy(void);
TfwStreamFsmRes tfw_h2_stream_fsm(TfwH2Ctx *ctx, TfwStream *stream,
				  unsigned char type, unsigned char flags,
				  bool send, TfwH2Err *err);
TfwStream *tfw_h2_find_stream(TfwStreamSched *sched, unsigned int id);
TfwStream *tfw_h2_add_stream(TfwStreamSched *sched, TfwStreamState state,
			     unsigned int id, unsigned short weight,
			     long int loc_wnd, long int rem_wnd);
TfwStream *tfw_h2_stream_create(TfwH2Ctx *ctx, TfwStreamState state,
				unsigned int id);
void tfw_h2_stream_add_to_queue_nolock(TfwStreamQueue *queue,
				       TfwStream *stream);
void tfw_h2_stream_del_from_queue_nolock(TfwStream *stream);
void tfw_h2_stream_remove_idle(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_delete_stream(TfwStream *stream);
void tfw_h2_stream_clean(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_unlink_nolock(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_unlink(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_add_closed(TfwH2Ctx *ctx, TfwStream *stream);
TfwStreamFsmRes tfw_h2_stream_send_process(TfwH2Ctx *ctx, TfwStream *stream,
					   unsigned char type);

static inline TfwStreamState
tfw_h2_get_stream_state(TfwStream *stream)
{
	return stream->state & HTTP2_STREAM_STATE_MASK;
}

static inline void
tfw_h2_set_stream_state(TfwStream *stream, TfwStreamState state)
{
	stream->state &= ~HTTP2_STREAM_STATE_MASK;
	stream->state |= state;
}

static inline bool
tfw_h2_stream_is_eos_sent(TfwStream *stream)
{
	return stream->state & HTTP2_STREAM_SEND_END_OF_STREAM;
}

static inline bool
tfw_h2_stream_is_eos_received(TfwStream *stream)
{
	return stream->state & HTTP2_STREAM_RECV_END_OF_STREAM;
}

static inline const char *
__h2_strm_st_n(TfwStream *stream)
{
	return __tfw_strm_st_names[tfw_h2_get_stream_state(stream)];
}

static inline bool
tfw_h2_stream_is_active(TfwStream *stream)
{
	return stream->xmit.skb_head && !stream->xmit.is_blocked;
}

static inline void
tfw_h2_stream_try_unblock(TfwStreamSched *sched, TfwStream *stream)
{
	bool stream_was_blocked = stream->xmit.is_blocked;

	if (stream->rem_wnd > 0) {
		stream->xmit.is_blocked = false;
		if (stream->xmit.skb_head && stream_was_blocked)
			tfw_h2_sched_activate_stream(sched, stream);
	}
}

static inline void
tfw_h2_stream_init_for_xmit(TfwStream *stream, TfwStreamXmitState state,
			    unsigned long h_len, unsigned long b_len,
			    bool is_progressive)
{
	stream->xmit.resp = NULL;
	stream->xmit.skb_head = NULL;
	stream->xmit.h_len = h_len;
	stream->xmit.b_len = b_len;
	stream->xmit.state = state;
	stream->xmit.frame_length = 0;
	stream->xmit.is_blocked = false;
	stream->xmit.is_progressive = is_progressive;
}

static inline void
tfw_h2_stream_purge_send_queue(TfwStream *stream)
{
	ss_skb_queue_purge(&stream->xmit.skb_head);
	stream->xmit.h_len = stream->xmit.b_len = 0;
}

static inline bool
tfw_h2_strm_req_is_compl(TfwStream *stream)
{
	return tfw_h2_get_stream_state(stream) == HTTP2_STREAM_REM_HALF_CLOSED;
}

static inline bool
tfw_h2_stream_is_closed(TfwStream *stream)
{
	return tfw_h2_get_stream_state(stream) == HTTP2_STREAM_CLOSED;
}

static inline TfwStreamFsmRes
tfw_h2_stream_fsm_ignore_err(TfwH2Ctx *ctx, TfwStream *stream,
			     unsigned char type, unsigned char flags)
{
	TfwH2Err err;

	return tfw_h2_stream_fsm(ctx, stream, type, flags, true, &err);
}

static inline u64
tfw_h2_stream_default_deficit(TfwStream *stream)
{
	return 65536 / stream->weight;
}

static inline u64
tfw_h2_stream_recalc_deficit(TfwStream *stream)
{
	/*
	 * This function should be called only for streams,
	 * which were removed from scheduler.
	 */
	BUG_ON(stream->sched_node.node.leaf_p ||
	       stream->sched_state != HTTP2_STREAM_SCHED_STATE_UNKNOWN);
	/* deficit = last_deficit + constant / weight */
	return stream->sched_node.key + tfw_h2_stream_default_deficit(stream);
}

static inline bool
tfw_h2_stream_has_default_deficit(TfwStream *stream)
{
	return stream->sched_node.key == tfw_h2_stream_default_deficit(stream);
}

#endif /* __HTTP_STREAM__ */
