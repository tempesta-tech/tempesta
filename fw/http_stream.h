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

/**
 * States for HTTP/2 streams processing.
 *
 * NOTE: there is no exact matching between these states and states from
 * RFC 7540 (section 5.1), since several intermediate states were added in
 * current implementation to handle some edge states which are not mentioned
 * explicitly in RFC (e.g. additional continuation states, and special kinds
 * of closed state). Besides, there is no explicit 'idle' state here, since
 * in current implementation idle stream is just a stream that has not been
 * created yet.
 */
typedef enum {
	HTTP2_STREAM_IDLE,
	HTTP2_STREAM_LOC_RESERVED,
	HTTP2_STREAM_REM_RESERVED,
	HTTP2_STREAM_OPENED,
	HTTP2_STREAM_CONT,
	HTTP2_STREAM_CONT_CLOSED,
	HTTP2_STREAM_LOC_HALF_CLOSED,
	HTTP2_STREAM_REM_HALF_CLOSED,
	HTTP2_STREAM_LOC_CLOSED,
	HTTP2_STREAM_REM_CLOSED,
	HTTP2_STREAM_CLOSED
} TfwStreamState;

typedef enum {
	HTTP2_MAKE_HEADERS_FRAMES,
	HTTP2_MAKE_CONTINUATION_FRAMES,
	HTTP2_MAKE_DATA_FRAMES,
	HTTP2_MAKE_FRAMES_FINISH
} TfwStreamXmitState;

static const char *__tfw_strm_st_names[] = {
	[HTTP2_STREAM_IDLE]		= "HTTP2_STREAM_IDLE",
	[HTTP2_STREAM_LOC_RESERVED]	= "HTTP2_STREAM_LOC_RESERVED",
	[HTTP2_STREAM_REM_RESERVED]	= "HTTP2_STREAM_REM_RESERVED",
	[HTTP2_STREAM_OPENED]	    	= "HTTP2_STREAM_OPENED",
	[HTTP2_STREAM_CONT]	    	= "HTTP2_STREAM_CONT",
	[HTTP2_STREAM_CONT_CLOSED]  	= "HTTP2_STREAM_CONT_CLOSED",
	[HTTP2_STREAM_LOC_HALF_CLOSED]	= "HTTP2_STREAM_LOC_HALF_CLOSED",
	[HTTP2_STREAM_REM_HALF_CLOSED]	= "HTTP2_STREAM_REM_HALF_CLOSED",
	[HTTP2_STREAM_LOC_CLOSED]	= "HTTP2_STREAM_LOC_CLOSED",
	[HTTP2_STREAM_REM_CLOSED]	= "HTTP2_STREAM_REM_CLOSED",
	[HTTP2_STREAM_CLOSED]		= "HTTP2_STREAM_CLOSED",
};

static inline const char *
__h2_strm_st_n(TfwStreamState state)
{
	return __tfw_strm_st_names[state];
}

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
 * @skb_head		- head of skb list that must be sent.
 * @h_len		- length of headers in http2 response;
 * @b_len		- length of body in http2 response;
 * @state		- current stream xmit state (what type of
 * 			  frame should be made for this stream);
 * @is_blocked		- stream is blocked;
 */
typedef struct {
	struct sk_buff *skb_head;
	unsigned long h_len;
	unsigned long b_len;
	TfwStreamXmitState state;
	bool is_blocked;
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

/**
 * Representation of HTTP/2 stream entity.
 *
 * @node	- entry in per-connection storage of streams (red-black tree);
 * @link	- entry in per-connection priority storage;
 * @sched	- scheduler for child streams;
 * @hcl_node	- entry in queue of half-closed or closed streams;
 * @id		- stream ID;
 * @state	- stream's current state;
 * @st_lock	- spinlock to synchronize concurrent access to stream FSM;
 * @loc_wnd	- stream's current flow controlled window;
 * @rem_wnd	- streams's current flow controlled window for remote client;
 * @weight	- stream's priority weight;
 * @msg		- message that is currently being processed;
 * @parser	- the state of message processing;
 * @queue	- queue of half-closed or closed streams or NULL;
 * @xmit	- last http2 response info, used in `xmit` callbacks;
 */
struct tfw_http_stream_t {
	struct rb_node		node;
	TfwStreamSchedEntryLink link;
	TfwStreamSchedEntry	sched;
	struct list_head	hcl_node;
	unsigned int		id;
	int			state;
	spinlock_t		st_lock;
	long int		loc_wnd;
	long int		rem_wnd;
	unsigned short		weight;
	TfwMsg			*msg;
	TfwHttpParser		parser;
	TfwStreamQueue		*queue;
	TfwHttpXmit		xmit;
};

int tfw_h2_stream_cache_create(void);
void tfw_h2_stream_cache_destroy(void);
TfwStreamFsmRes tfw_h2_stream_fsm(TfwStream *stream, unsigned char type,
				  unsigned char flags, bool send,
				  TfwH2Err *err);
TfwStream *tfw_h2_find_stream(TfwStreamSched *sched, unsigned int id);
TfwStream *tfw_h2_add_stream(TfwStreamSched *sched, TfwStreamState state,
			     unsigned int id, unsigned short weight,
			     long int loc_wnd, long int rem_wnd);
void tfw_h2_delete_stream(TfwStream *stream);
void tfw_h2_stop_stream(TfwStreamSched *sched, TfwStream *stream);

static inline bool
tfw_h2_stream_is_active(TfwStream *stream)
{
	return stream->xmit.skb_head && !stream->xmit.is_blocked;
}

static inline void
tfw_h2_stream_try_unblock(TfwStream *stream)
{
	bool stream_was_blocked = stream->xmit.is_blocked;

	if (stream->rem_wnd > 0) {
		stream->xmit.is_blocked = false;
		if (stream->xmit.skb_head && stream_was_blocked)
			tfw_h2_sched_activate_stream(stream);
	}
}

static inline void
tfw_h2_stream_init_for_xmit(TfwStream *stream, unsigned long h_len,
			    unsigned long b_len)
{
	stream->xmit.skb_head = NULL;
	stream->xmit.h_len = h_len;
	stream->xmit.b_len = b_len;
	stream->xmit.state = HTTP2_MAKE_HEADERS_FRAMES;
	stream->xmit.is_blocked = false;
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
	return stream->state == HTTP2_STREAM_REM_HALF_CLOSED;
}

static inline bool
tfw_h2_stream_is_closed(TfwStream *stream)
{
	return stream->state == HTTP2_STREAM_CLOSED;
}

static inline TfwStreamFsmRes
tfw_h2_stream_fsm_ignore_err(TfwStream *stream, unsigned char type,
			     unsigned char flags)
{
	TfwH2Err err;

	return tfw_h2_stream_fsm(stream, type, flags, true, &err);
}

#endif /* __HTTP_STREAM__ */
