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

#include <linux/rbtree.h>

#include "msg.h"
#include "http_parser.h"
#include "lib/str.h"

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
	HTTP2_STREAM_STATE_MASK = 0xF,
	HTTP2_STREAM_FLAGS_OFFSET = 0x4,
	HTTP2_STREAM_SEND_END_OF_STREAM = 0x1 << HTTP2_STREAM_FLAGS_OFFSET,
	HTTP2_STREAM_RECV_END_OF_STREAM = 0x2 << HTTP2_STREAM_FLAGS_OFFSET,
};

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
 * @h_len		- length of headers in http2 response;
 * @b_len		- length of body in http2 response;
 * @__off		- offset to reinitialize processing context;
 * @processed		- count of bytes, processed during prepare xmit
 * 			  callback;
 * @nskbs		- count of skbs processed during prepare xmit callback;
 */
typedef struct {
	unsigned long h_len;
	unsigned long b_len;
	char __off[0];
	unsigned int processed;
	unsigned int nskbs;
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

/**
 * Scheduler for stream's processing distribution based on dependency/priority
 * values.
 * TODO: the structure is not completed yet and should be finished in context
 * of #1196.
 *
 * @streams	- root red-black tree entry for per-connection streams' storage;
 */
typedef struct {
	struct rb_root streams;
} TfwStreamSched;

typedef struct tfw_h2_ctx_t TfwH2Ctx;

int tfw_h2_stream_cache_create(void);
void tfw_h2_stream_cache_destroy(void);
TfwStream * tfw_h2_stream_create(TfwH2Ctx *ctx, unsigned int id);
void tfw_h2_stream_clean(TfwH2Ctx *ctx, TfwStream *stream);
int tfw_h2_stream_close(TfwH2Ctx *ctx, unsigned int id, TfwStream **stream,
			TfwH2Err err_code);
void tfw_h2_stream_unlink_nolock(TfwH2Ctx *ctx, TfwStream *stream);
void tfw_h2_stream_unlink_lock(TfwH2Ctx *ctx, TfwStream *stream);
TfwStreamFsmRes tfw_h2_stream_fsm(TfwH2Ctx *ctx, TfwStream *stream,
				  unsigned char type, unsigned char flags,
				  bool send, TfwH2Err *err);
TfwStream *tfw_h2_find_stream(TfwStreamSched *sched, unsigned int id);
void tfw_h2_delete_stream(TfwStream *stream);
void tfw_h2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			      unsigned int new_dep, unsigned short new_weight,
			      bool excl);
int tfw_h2_stream_init_for_xmit(TfwHttpReq *req, unsigned long h_len,
				unsigned long b_len);
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

static inline void
tfw_h2_stream_xmit_reinit(TfwHttpXmit *xmit)
{
	bzero_fast(xmit->__off, sizeof(*xmit) - offsetof(TfwHttpXmit, __off));
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

#endif /* __HTTP_STREAM__ */
