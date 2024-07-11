/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2024 Tempesta Technologies, Inc.
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

#include "msg.h"
#include "http_parser.h"
#include "http_stream_sched.h"
#include "lib/str.h"
#include "ss_skb.h"

/**
 * States for HTTP/2 streams processing.
 *
 * NOTE: there is no exact matching between these states and states from
 * RFC 7540 (section 5.1), since several intermediate states were added in
 * current implementation to handle some edge states which are not mentioned
 * explicitly in RFC (special kinds of closed state).
 */
typedef enum {
	HTTP2_STREAM_IDLE,
	HTTP2_STREAM_LOC_RESERVED,
	HTTP2_STREAM_REM_RESERVED,
	HTTP2_STREAM_OPENED,
	HTTP2_STREAM_LOC_HALF_CLOSED,
	HTTP2_STREAM_REM_HALF_CLOSED,
	HTTP2_STREAM_LOC_CLOSED,
	HTTP2_STREAM_CLOSED
} TfwStreamState;

enum {
	HTTP2_STREAM_STATE_MASK = 0xF,
	HTTP2_STREAM_FLAGS_OFFSET = 0x4,
	HTTP2_STREAM_SEND_END_OF_STREAM = 0x1 << HTTP2_STREAM_FLAGS_OFFSET,
	HTTP2_STREAM_RECV_END_OF_STREAM = 0x2 << HTTP2_STREAM_FLAGS_OFFSET,
};

/*
 * We use 4 bits for this state in TfwHttpXmit structure.
 * If you add some new state here, do not forget to increase
 * count of bits used for this state.
 */
typedef enum {
	HTTP2_ENCODE_HEADERS,
	HTTP2_RELEASE_RESPONSE,
	HTTP2_MAKE_HEADERS_FRAMES,
	HTTP2_MAKE_CONTINUATION_FRAMES,
	HTTP2_MAKE_DATA_FRAMES,
	HTTP2_MAKE_TRAILER_FRAMES,
	HTTP2_MAKE_TRAILER_CONTINUATION_FRAMES,
	HTTP2_SEND_FRAMES,
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
 * @resp		- responce, that should be sent;
 * @skb_head		- head of skb list that must be sent;
 * @postponed		- head of skb list that must be sent
 *			  after sending headers for this stream;
 * @h_len		- length of headers in http2 response;
 * @t_len		- length of trailer headers in http2 response;
 * @frame_length	- length of current sending frame, or 0
 *			  if we send some service frames (for
 *			  example RST STREAM after all pending data);
 * @b_len		- length of body in http2 response;
 * @is_blocked		- stream is blocked;
 * @state		- current stream xmit state (what type of
 * 			  frame should be made for this stream);
 */
typedef struct {
	TfwHttpResp 		*resp;
	struct sk_buff		*skb_head;
	struct sk_buff		*postponed;
	unsigned int		h_len;
	unsigned int		t_len;
	unsigned int		frame_length;
	u64			b_len : 60;
	u64			is_blocked : 1;
	u64			state : 4;
} TfwHttpXmit;

/**
 * Limited queue for temporary storage of idle or closed streams
 * This structure provides the possibility of temporary existing in memory -
 * for streams which are in HTTP2_STREAM_CLOSED state.
 *
 * @list		- list of streams;
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
 * sched_state	- state of stream in the per-connection scheduler;
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
	struct eb64_node	sched_node;
	TfwStreamSchedState	sched_state;
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

typedef struct tfw_h2_ctx_t TfwH2Ctx;

int tfw_h2_stream_cache_create(void);
void tfw_h2_stream_cache_destroy(void);
TfwStream *tfw_h2_stream_create(TfwH2Ctx *ctx, unsigned int id);
void tfw_h2_stream_remove_idle(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_clean(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_unlink_nolock(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_unlink_lock(TfwH2Ctx *ctx, TfwStream *stream);
TfwStreamFsmRes tfw_h2_stream_fsm(TfwH2Ctx *ctx, TfwStream *stream,
				  unsigned char type, unsigned char flags,
				  bool send, TfwH2Err *err);
TfwStream *tfw_h2_find_stream(TfwStreamSched *sched, unsigned int id);
void tfw_h2_delete_stream(TfwStream *stream);
int tfw_h2_stream_init_for_xmit(TfwHttpResp *resp, TfwStreamXmitState state,
				unsigned long h_len, unsigned long b_len);
void tfw_h2_stream_add_closed(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_add_idle(TfwH2Ctx *ctx, TfwStream *idle);
TfwStreamFsmRes tfw_h2_stream_send_process(TfwH2Ctx *ctx, TfwStream *stream,
					   unsigned char type);
void tfw_h2_stream_purge_send_queue(TfwStream *stream);
void tfw_h2_stream_purge_all_and_free_response(TfwStream *stream);

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
		if (stream->xmit.skb_head && stream_was_blocked) {
			sched->blocked_streams--;
			BUG_ON(sched->blocked_streams < 0);
			tfw_h2_sched_activate_stream(sched, stream);
		}
	}
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

/*
 * Add stream to queue.
 *
 * NOTE: call to this procedure should be protected by special lock for
 * Stream linkage protection.
 */
static inline void
tfw_h2_stream_add_to_queue_nolock(TfwStreamQueue *queue, TfwStream *stream)
{
	if (!list_empty(&stream->hcl_node))
		return;

	list_add_tail(&stream->hcl_node, &queue->list);
	stream->queue = queue;
	++stream->queue->num;
}

/*
 * Del stream from queue.
 *
 * NOTE: call to this procedure should be protected by special lock for
 * Stream linkage protection.
 */
static inline void
tfw_h2_stream_del_from_queue_nolock(TfwStream *stream)
{
	if(list_empty(&stream->hcl_node))
		return;

	BUG_ON(!stream->queue);
	BUG_ON(!stream->queue->num);

	list_del_init(&stream->hcl_node);
	--stream->queue->num;
	stream->queue = NULL;
}

static inline u64
tfw_h2_stream_default_deficit(TfwStream *stream)
{
	static const unsigned tbl[256] = {
		65536, 32768, 21845, 16384, 13107, 10922, 9362, 8192, 7281,
		6553, 5957, 5461, 5041, 4681, 4369, 4096, 3855, 3640, 3449,
		3276, 3120, 2978, 2849, 2730, 2621, 2520, 2427, 2340, 2259,
		2184, 2114, 2048, 1985, 1927, 1872, 1820, 1771, 1724, 1680,
		1638, 1598, 1560, 1524, 1489, 1456, 1424, 1394, 1365, 1337,
		1310, 1285, 1260, 1236, 1213, 1191, 1170, 1149, 1129, 1110,
		1092, 1074, 1057, 1040, 1024, 1008, 992, 978, 963, 949, 936,
		923, 910, 897, 885, 873, 862, 851, 840, 829, 819, 809, 799,
		789, 780, 771, 762, 753, 744, 736, 728, 720, 712, 704, 697,
		689, 682, 675, 668, 661, 655, 648, 642, 636, 630, 624, 618,
		612, 606, 601, 595, 590, 585, 579, 574, 569, 564, 560, 555,
		550, 546, 541, 537, 532, 528, 524, 520, 516, 512, 508, 504,
		500, 496, 492, 489, 485, 481, 478, 474, 471, 468, 464, 461,
		458, 455, 451, 448, 445, 442, 439, 436, 434, 431, 428, 425,
		422, 420, 417, 414, 412, 409, 407, 404, 402, 399, 397, 394,
		392, 390, 387, 385, 383, 381, 378, 376, 374, 372, 370, 368,
		366, 364, 362, 360, 358, 356, 354, 352, 350, 348, 346, 344,
		343, 341, 339, 337, 336, 334, 332, 330, 329, 327, 326, 324,
		322, 321, 319, 318, 316, 315, 313, 312, 310, 309, 307, 306,
		304, 303, 302, 300, 299, 297, 296, 295, 293, 292, 291, 289,
		288, 287, 286, 284, 283, 282, 281, 280, 278, 277, 276, 275,
		274, 273, 271, 270, 269, 268, 267, 266, 265, 264, 263, 262,
		261, 260, 259, 258, 257, 256
	};

	return tbl[stream->weight - 1];
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
