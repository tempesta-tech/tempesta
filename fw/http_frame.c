/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2021 Tempesta Technologies, Inc.
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
#if DBG_HTTP_FRAME > 0
#define DEBUG DBG_HTTP_FRAME
#endif

#include "lib/fsm.h"
#include "lib/str.h"
#include "procfs.h"
#include "http.h"
#include "http_frame.h"

#define FRAME_PREFACE_CLI_MAGIC		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define FRAME_PREFACE_CLI_MAGIC_LEN	24
#define FRAME_WND_UPDATE_SIZE		4
#define FRAME_RST_STREAM_SIZE		4
#define FRAME_PRIORITY_SIZE		5
#define FRAME_SETTINGS_ENTRY_SIZE	6
#define FRAME_PING_SIZE			8
#define FRAME_GOAWAY_SIZE		8

#define WND_INCREMENT_SIZE		4
#define SETTINGS_KEY_SIZE		2
#define SETTINGS_VAL_SIZE		4
#define STREAM_ID_SIZE			4
#define ERR_CODE_SIZE			4

#define MAX_WND_SIZE			((1U << 31) - 1)
#define DEF_WND_SIZE			((1U << 16) - 1)

#define TFW_MAX_CLOSED_STREAMS		5

/**
 * FSM states for HTTP/2 frames processing.
 */
typedef enum {
	HTTP2_RECV_FRAME_HEADER,
	HTTP2_RECV_CLI_START_SEQ,
	HTTP2_RECV_FIRST_SETTINGS,
	HTTP2_RECV_FRAME_PRIORITY,
	HTTP2_RECV_FRAME_WND_UPDATE,
	HTTP2_RECV_FRAME_PING,
	HTTP2_RECV_FRAME_RST_STREAM,
	HTTP2_RECV_FRAME_SETTINGS,
	HTTP2_RECV_FRAME_GOAWAY,
	HTTP2_RECV_FRAME_PADDED,
	HTTP2_RECV_HEADER_PRI,
	HTTP2_IGNORE_FRAME_DATA,
	__HTTP2_RECV_FRAME_APP,
	HTTP2_RECV_HEADER		= __HTTP2_RECV_FRAME_APP,
	HTTP2_RECV_CONT,
	HTTP2_RECV_DATA
} TfwFrameState;

/**
 * IDs for SETTINGS parameters of HTTP/2 connection (RFC 7540
 * section 6.5.2).
 */
typedef enum {
	HTTP2_SETTINGS_TABLE_SIZE	= 0x01,
	HTTP2_SETTINGS_ENABLE_PUSH,
	HTTP2_SETTINGS_MAX_STREAMS,
	HTTP2_SETTINGS_INIT_WND_SIZE,
	HTTP2_SETTINGS_MAX_FRAME_SIZE,
	HTTP2_SETTINGS_MAX_HDR_LIST_SIZE
} TfwSettingsId;

#define __FRAME_FSM_EXIT()						\
do {									\
	ctx->rlen = 0;							\
	T_FSM_EXIT();							\
} while (0)

#define FRAME_FSM_EXIT(ret)						\
do {									\
	r = ret;							\
	__FRAME_FSM_EXIT();						\
} while (0)

#define FRAME_FSM_FINISH()						\
	T_FSM_FINISH(r, ctx->state);					\
	*read += p - buf;

#define FRAME_FSM_MOVE(st)						\
do {									\
	WARN_ON_ONCE(p - buf > len);					\
	ctx->rlen = 0;							\
	T_FSM_MOVE(st,							\
		   if (unlikely(p - buf >= len)) {			\
			   __fsm_const_state = st;			\
			   T_FSM_EXIT();				\
		   });							\
} while (0)

#define FRAME_FSM_NEXT()						\
do {									\
	WARN_ON_ONCE(p - buf > len);					\
	ctx->rlen = 0;							\
	if (unlikely(p - buf >= len)) {					\
		__fsm_const_state = ctx->state;				\
		T_FSM_EXIT();						\
	}								\
	T_FSM_NEXT();							\
} while (0)

#define FRAME_FSM_READ_LAMBDA(to_read, lambda)				\
do {									\
	WARN_ON_ONCE(ctx->rlen >= (to_read));				\
	n = min_t(int, (to_read) - ctx->rlen, buf + len - p);		\
	lambda;								\
	p += n;								\
	ctx->rlen += n;							\
	if (unlikely(ctx->rlen < (to_read)))				\
		T_FSM_EXIT();						\
} while (0)

#define FRAME_FSM_READ_SRVC(to_read)					\
	BUG_ON((to_read) > sizeof(ctx->rbuf));				\
	FRAME_FSM_READ_LAMBDA(to_read, {				\
		memcpy_fast(ctx->rbuf + ctx->rlen, p, n);		\
	})

#define FRAME_FSM_READ(to_read)						\
	FRAME_FSM_READ_LAMBDA(to_read, { })

#define SET_TO_READ(ctx)						\
do {									\
	(ctx)->to_read = (ctx)->hdr.length;				\
	(ctx)->hdr.length = 0;						\
} while (0)

#define SET_TO_READ_VERIFY(ctx, next_state)				\
do {									\
	(ctx)->to_read = (ctx)->hdr.length;				\
	if ((ctx)->hdr.length) {					\
		(ctx)->state = next_state;				\
		(ctx)->hdr.length = 0;					\
	} else {							\
		(ctx)->state = HTTP2_IGNORE_FRAME_DATA;			\
	}								\
} while (0)

#define APP_FRAME(ctx)							\
	((ctx)->state >= __HTTP2_RECV_FRAME_APP)

#define STREAM_RECV_PROCESS(ctx, hdr)					\
({									\
	TfwStreamFsmRes res;						\
	TfwH2Err err = HTTP2_ECODE_NO_ERROR;				\
	BUG_ON(!(ctx)->cur_stream);					\
	if ((res = tfw_h2_stream_fsm((ctx)->cur_stream, (hdr)->type,	\
				     (hdr)->flags, false, &err)))	\
	{								\
		T_DBG3("stream recv processed: result=%d, state=%d, id=%u," \
		       " err=%d\n", res, (ctx)->cur_stream->state,	\
		       (ctx)->cur_stream->id, err);			\
		SET_TO_READ_VERIFY((ctx), HTTP2_IGNORE_FRAME_DATA);	\
		if (res == STREAM_FSM_RES_TERM_CONN) {			\
			tfw_h2_conn_terminate((ctx), err);		\
			return T_DROP;					\
		} else if (res == STREAM_FSM_RES_TERM_STREAM) {		\
			return tfw_h2_stream_close((ctx),		\
						   (hdr)->stream_id,	\
						   &(ctx)->cur_stream,	\
						   err);		\
		}							\
		return T_OK;						\
	}								\
})

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
	TfwClosedQueue *hclosed_streams = &ctx->hclosed_streams;
	TfwSettings *lset = &ctx->lsettings;
	TfwSettings *rset = &ctx->rsettings;

	bzero_fast(ctx, sizeof(*ctx));

	ctx->state = HTTP2_RECV_CLI_START_SEQ;
	ctx->loc_wnd = MAX_WND_SIZE;
	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&hclosed_streams->list);

	lset->hdr_tbl_sz = rset->hdr_tbl_sz = HPACK_TABLE_DEF_SIZE;
	lset->push = rset->push = 1;
	lset->max_streams = rset->max_streams = 0xffffffff;
	lset->max_frame_sz = rset->max_frame_sz = FRAME_DEF_LENGTH;
	lset->max_lhdr_sz = rset->max_lhdr_sz = UINT_MAX;
	/*
	 * We ignore client's window size until #498, so currently
	 * we set it to maximum allowed value.
	 */
	lset->wnd_sz = rset->wnd_sz = MAX_WND_SIZE;

	return tfw_hpack_init(&ctx->hpack, HPACK_TABLE_DEF_SIZE);
}

void
tfw_h2_context_clear(TfwH2Ctx *ctx)
{
	WARN_ON_ONCE(ctx->streams_num);
	tfw_hpack_clean(&ctx->hpack);
}

static inline void
tfw_h2_unpack_frame_header(TfwFrameHdr *hdr, const unsigned char *buf)
{
	hdr->length = ntohl(*(int *)buf) >> 8;
	hdr->type = buf[3];
	hdr->flags = buf[4];
	hdr->stream_id = ntohl(*(unsigned int *)&buf[5]) & FRAME_STREAM_ID_MASK;

	T_DBG3("%s: parsed, length=%d, stream_id=%u, type=%hhu, flags=0x%hhx\n",
	       __func__, hdr->length, hdr->stream_id, hdr->type, hdr->flags);
}

static inline void
tfw_h2_unpack_priority(TfwFramePri *pri, const unsigned char *buf)
{
	pri->stream_id = ntohl(*(unsigned int *)buf) & FRAME_STREAM_ID_MASK;
	pri->exclusive = (buf[0] & 0x80) > 0;
	pri->weight = buf[4] + 1;
}

/**
 * Prepare and send HTTP/2 frame to the client; @hdr must contain
 * the valid data to fill in the frame's header; @data may carry
 * additional data as frame's payload.
 *
 * NOTE: Caller must leave first chunk of @data unoccupied - to
 * provide the place for frame's header which will be packed and
 * written in this procedure.
 */
static int
__tfw_h2_send_frame(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data, bool close)
{
	int r;
	TfwMsgIter it;
	TfwMsg msg = {};
	unsigned char buf[FRAME_HEADER_SIZE];
	TfwStr *hdr_str = TFW_STR_CHUNK(data, 0);
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	BUG_ON(hdr_str->data);
	hdr_str->data = buf;
	hdr_str->len = FRAME_HEADER_SIZE;

	if (data != hdr_str)
		data->len += FRAME_HEADER_SIZE;

	tfw_h2_pack_frame_header(buf, hdr);

	T_DBG2("Preparing HTTP/2 message with %lu bytes data\n", data->len);

	msg.len = data->len;
	if ((r = tfw_msg_iter_setup(&it, &msg.skb_head, msg.len, 0)))
		goto err;

	if ((r = tfw_msg_write(&it, data)))
		goto err;

	if (close)
		msg.ss_flags |= SS_F_CONN_CLOSE;

	if ((r = tfw_connection_send((TfwConn *)conn, &msg)))
		goto err;
	/*
	 * We do not close client connection automatically here in case
	 * of failed sending, the caller must make such decision instead;
	 * thus, we should set Conn_Stop flag only if sending procedure
	 * was successful - to avoid hanged unclosed client connection.
	 */
	if (close)
		TFW_CONN_TYPE((TfwConn *)conn) |= Conn_Stop;

	return 0;

err:
	ss_skb_queue_purge(&msg.skb_head);
	return r;
}

static inline int
tfw_h2_send_frame(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data)
{
	return __tfw_h2_send_frame(ctx, hdr, data, false);
}

static inline int
tfw_h2_send_frame_close(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data)
{
	return __tfw_h2_send_frame(ctx, hdr, data, true);
}

static inline int
tfw_h2_send_ping(TfwH2Ctx *ctx)
{
	TfwStr data = {
		.chunks = (TfwStr []){
			{},
			{ .data = ctx->rbuf, .len = ctx->rlen }
		},
		.len = ctx->rlen,
		.nchunks = 2
	};
	TfwFrameHdr hdr = {
		.length = ctx->rlen,
		.stream_id = 0,
		.type = HTTP2_PING,
		.flags = HTTP2_F_ACK
	};

	WARN_ON_ONCE(ctx->rlen != FRAME_PING_SIZE);

	return tfw_h2_send_frame(ctx, &hdr, &data);

}

static inline int
tfw_h2_send_wnd_update(TfwH2Ctx *ctx, unsigned int id, unsigned int wnd_incr)
{
	unsigned char incr_buf[WND_INCREMENT_SIZE];
	TfwStr data = {
		.chunks = (TfwStr []){
			{},
			{ .data = incr_buf, .len = WND_INCREMENT_SIZE }
		},
		.len = WND_INCREMENT_SIZE,
		.nchunks = 2
	};
	TfwFrameHdr hdr = {
		.length = data.len,
		.stream_id = id,
		.type = HTTP2_WINDOW_UPDATE,
		.flags = 0
	};

	WARN_ON_ONCE((unsigned int)(wnd_incr & FRAME_RESERVED_BIT_MASK));

	*(unsigned int *)incr_buf = htonl(wnd_incr);

	return tfw_h2_send_frame(ctx, &hdr, &data);
}

static inline int
tfw_h2_send_settings_init(TfwH2Ctx *ctx)
{
	unsigned char key_buf[SETTINGS_KEY_SIZE];
	unsigned char val_buf[SETTINGS_VAL_SIZE];
	TfwStr data = {
		.chunks = (TfwStr []){
			{},
			{ .data = key_buf, .len = SETTINGS_KEY_SIZE },
			{ .data = val_buf, .len = SETTINGS_VAL_SIZE }
		},
		.len = SETTINGS_KEY_SIZE + SETTINGS_VAL_SIZE,
		.nchunks = 3
	};
	TfwFrameHdr hdr = {
		.length = data.len,
		.stream_id = 0,
		.type = HTTP2_SETTINGS,
		.flags = 0
	};

	BUILD_BUG_ON(SETTINGS_KEY_SIZE != sizeof(unsigned short)
		     || SETTINGS_VAL_SIZE != sizeof(unsigned int)
		     || SETTINGS_VAL_SIZE != sizeof(ctx->lsettings.wnd_sz));

	*(unsigned short *)key_buf = htons(HTTP2_SETTINGS_INIT_WND_SIZE);
	*(unsigned int *)val_buf = htonl(ctx->lsettings.wnd_sz);

	return tfw_h2_send_frame(ctx, &hdr, &data);
}

static inline int
tfw_h2_send_settings_ack(TfwH2Ctx *ctx)
{
	TfwStr data = {};
	TfwFrameHdr hdr = {
		.length = 0,
		.stream_id = 0,
		.type = HTTP2_SETTINGS,
		.flags = HTTP2_F_ACK
	};

	return tfw_h2_send_frame(ctx, &hdr, &data);
}

static inline int
tfw_h2_send_goaway(TfwH2Ctx *ctx, TfwH2Err err_code)
{
	unsigned char id_buf[STREAM_ID_SIZE];
	unsigned char err_buf[ERR_CODE_SIZE];
	TfwStr data = {
		.chunks = (TfwStr []){
			{},
			{ .data = id_buf, .len = STREAM_ID_SIZE },
			{ .data = err_buf, .len = ERR_CODE_SIZE }
		},
		.len = STREAM_ID_SIZE + ERR_CODE_SIZE,
		.nchunks = 3
	};
	TfwFrameHdr hdr = {
		.length = data.len,
		.stream_id = 0,
		.type = HTTP2_GOAWAY,
		.flags = 0
	};

	WARN_ON_ONCE((unsigned int)(ctx->lstream_id & FRAME_RESERVED_BIT_MASK));
	BUILD_BUG_ON(STREAM_ID_SIZE != sizeof(unsigned int)
		     || STREAM_ID_SIZE != sizeof(ctx->lstream_id)
		     || ERR_CODE_SIZE != sizeof(unsigned int)
		     || ERR_CODE_SIZE != sizeof(err_code));

	*(unsigned int *)id_buf = htonl(ctx->lstream_id);
	*(unsigned int *)err_buf = htonl(err_code);

	return tfw_h2_send_frame_close(ctx, &hdr, &data);
}

int
tfw_h2_send_rst_stream(TfwH2Ctx *ctx, unsigned int id, TfwH2Err err_code)
{
	unsigned char buf[ERR_CODE_SIZE];
	TfwStr data = {
		.chunks = (TfwStr []){
			{},
			{ .data = buf, .len = ERR_CODE_SIZE }
		},
		.len = ERR_CODE_SIZE,
		.nchunks = 2
	};
	TfwFrameHdr hdr = {
		.length = data.len,
		.stream_id = id,
		.type = HTTP2_RST_STREAM,
		.flags = 0
	};

	*(unsigned int *)buf = htonl(err_code);

	return tfw_h2_send_frame(ctx, &hdr, &data);
}

void
tfw_h2_conn_terminate_close(TfwH2Ctx *ctx, TfwH2Err err_code, bool close)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	if (tfw_h2_send_goaway(ctx, err_code) && close)
		tfw_connection_close((TfwConn *)conn, true);
}

static inline void
tfw_h2_conn_terminate(TfwH2Ctx *ctx, TfwH2Err err_code)
{
	tfw_h2_conn_terminate_close(ctx, err_code, false);
}

#define VERIFY_FRAME_SIZE(ctx)						\
do {									\
	if ((ctx)->hdr.length < 0) {					\
		tfw_h2_conn_terminate(ctx, HTTP2_ECODE_SIZE);		\
		return T_DROP;						\
	}								\
} while (0)

static inline int
tfw_h2_recv_priority(TfwH2Ctx *ctx)
{
	ctx->to_read = FRAME_PRIORITY_SIZE;
	ctx->hdr.length -= ctx->to_read;
	ctx->plen -= ctx->to_read;
	VERIFY_FRAME_SIZE(ctx);
	ctx->state = HTTP2_RECV_HEADER_PRI;
	return T_OK;
}

static inline int
tfw_h2_recv_padded(TfwH2Ctx *ctx)
{
	ctx->to_read = 1;
	ctx->hdr.length -= ctx->to_read;
	ctx->plen -= ctx->to_read;
	VERIFY_FRAME_SIZE(ctx);
	ctx->state = HTTP2_RECV_FRAME_PADDED;
	return T_OK;
}

static int
tfw_h2_headers_pri_process(TfwH2Ctx *ctx)
{
	TfwFramePri *pri = &ctx->priority;
	TfwFrameHdr *hdr = &ctx->hdr;

	BUG_ON(!(hdr->flags & HTTP2_F_PRIORITY));

	tfw_h2_unpack_priority(pri, ctx->rbuf);

	T_DBG3("%s: parsed, stream_id=%u, dep_stream_id=%u, weight=%hu,"
	       " excl=%hhu\n", __func__, hdr->stream_id, pri->stream_id,
	       pri->weight, pri->exclusive);

	ctx->data_off += FRAME_PRIORITY_SIZE;

	SET_TO_READ_VERIFY(ctx, HTTP2_RECV_HEADER);
	return T_OK;
}

/*
 * Create a new stream and add it to the streams storage and to the dependency
 * tree. Note, that we do not need to protect the streams storage in @sched from
 * concurrent access, since all operations with it (adding, searching and
 * deletion) are done only in receiving flow of Frame layer.
 */
static TfwStream *
tfw_h2_stream_create(TfwH2Ctx *ctx, unsigned int id)
{
	TfwStream *stream, *dep = NULL;
	TfwFramePri *pri = &ctx->priority;
	bool excl = pri->exclusive;

	if (tfw_h2_find_stream_dep(&ctx->sched, pri->stream_id, &dep))
		return NULL;

	stream = tfw_h2_add_stream(&ctx->sched, id, pri->weight,
				      ctx->lsettings.wnd_sz);
	if (!stream)
		return NULL;

	tfw_h2_add_stream_dep(&ctx->sched, stream, dep, excl);

	++ctx->streams_num;

	T_DBG3("%s: stream added, id=%u, stream=[%p] weight=%hu,"
	       " streams_num=%lu, dep_stream_id=%u, dep_stream=[%p],"
	       " excl=%hhu\n", __func__, id, stream, stream->weight,
	       ctx->streams_num, pri->stream_id, dep, pri->exclusive);

	return stream;
}

static inline void
tfw_h2_stream_clean(TfwH2Ctx *ctx, TfwStream *stream)
{
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
static void
__tfw_h2_stream_unlink(TfwH2Ctx *ctx, TfwStream *stream)
{
	TfwHttpMsg *hmreq = (TfwHttpMsg *)stream->msg;

	if (!list_empty(&stream->hcl_node)) {
		list_del_init(&stream->hcl_node);
		--ctx->hclosed_streams.num;
	}

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

static inline void
tfw_h2_stream_unlink(TfwH2Ctx *ctx, TfwStream *stream)
{
	spin_lock(&ctx->lock);

	__tfw_h2_stream_unlink(ctx, stream);

	spin_unlock(&ctx->lock);
}

static inline void
tfw_h2_current_stream_remove(TfwH2Ctx *ctx)
{
	tfw_h2_stream_unlink(ctx, ctx->cur_stream);
	tfw_h2_stream_clean(ctx, ctx->cur_stream);
	ctx->cur_stream = NULL;
}

void
tfw_h2_conn_streams_cleanup(TfwH2Ctx *ctx)
{
	TfwStream *cur, *next;
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwStreamSched *sched = &ctx->sched;

	WARN_ON_ONCE(((TfwConn *)conn)->stream.msg);

	rbtree_postorder_for_each_entry_safe(cur, next, &sched->streams, node) {
		tfw_h2_stream_unlink(ctx, cur);
		tfw_h2_stream_clean(ctx, cur);
	}
}

/*
 * Add stream to special queue of closed streams.
 *
 * NOTE: call to this procedure should be protected by special lock for
 * Stream linkage protection.
 */
static inline void
__tfw_h2_stream_add_closed(TfwClosedQueue *hclosed_streams, TfwStream *stream)
{
	if (!list_empty(&stream->hcl_node))
		return;

	list_add_tail(&stream->hcl_node, &hclosed_streams->list);
	++hclosed_streams->num;
}

static inline void
tfw_h2_stream_add_closed(TfwH2Ctx *ctx, TfwStream *stream)
{
	spin_lock(&ctx->lock);

	__tfw_h2_stream_add_closed(&ctx->hclosed_streams, stream);

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
 */
static int
tfw_h2_stream_close(TfwH2Ctx *ctx, unsigned int id, TfwStream **stream,
		    TfwH2Err err_code)
{
	if (stream && *stream) {
		tfw_h2_stream_add_closed(ctx, *stream);
		*stream = NULL;
	}

	return tfw_h2_send_rst_stream(ctx, id, err_code);
}

/*
 * Get stream ID for upper layer to create frames info.
 */
unsigned int
tfw_h2_stream_id(TfwHttpReq *req)
{
	unsigned int id = 0;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);

	spin_lock(&ctx->lock);

	if (req->stream)
		id = req->stream->id;

	spin_unlock(&ctx->lock);

	return id;
}

/*
 * Get stream ID for upper layer to prepare and send frame with response to
 * client, and process stream FSM for the frame (of type specified in @type
 * and with flags set in @flags). This procedure also unlinks request from
 * corresponding stream (if linked) and moves the stream to the queue of
 * closed streams (if it is not contained there yet).
 */
unsigned int
tfw_h2_stream_id_close(TfwHttpReq *req, unsigned char type,
		       unsigned char flags)
{
	TfwStream *stream;
	unsigned int id = 0;
	TfwH2Ctx *ctx = tfw_h2_context(req->conn);

	spin_lock(&ctx->lock);

	stream = req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return 0;
	}

	if (type < _HTTP2_UNDEFINED &&
	    !STREAM_SEND_PROCESS(stream, type, flags))
	{
		id = stream->id;
	}

	req->stream = NULL;
	stream->msg = NULL;

	__tfw_h2_stream_add_closed(&ctx->hclosed_streams, stream);

	spin_unlock(&ctx->lock);

	return id;
}

/*
 * Clean the queue of closed streams if its size has exceeded a certain
 * value.
 */
static void
tfw_h2_closed_streams_shrink(TfwH2Ctx *ctx)
{
	TfwStream *cur;
	unsigned int max_streams = ctx->lsettings.max_streams;
	TfwClosedQueue *hclosed_streams = &ctx->hclosed_streams;

	while (1)
	{
		spin_lock(&ctx->lock);

		if (hclosed_streams->num <= TFW_MAX_CLOSED_STREAMS
		    || (max_streams == ctx->streams_num
			&& hclosed_streams->num))
		{
			spin_unlock(&ctx->lock);
			break;
		}

		BUG_ON(list_empty(&hclosed_streams->list));
		cur = list_first_entry(&hclosed_streams->list, TfwStream,
				       hcl_node);
		__tfw_h2_stream_unlink(ctx, cur);

		spin_unlock(&ctx->lock);

		tfw_h2_stream_clean(ctx, cur);
	}
}

static inline void
tfw_h2_check_closed_stream(TfwH2Ctx *ctx)
{
	BUG_ON(!ctx->cur_stream);

	T_DBG3("%s: stream->id=%u, stream->state=%d, stream=[%p], streams_num="
	       "%lu\n", __func__, ctx->cur_stream->id, ctx->cur_stream->state,
	       ctx->cur_stream, ctx->streams_num);

	if (tfw_h2_stream_is_closed(ctx->cur_stream))
		tfw_h2_current_stream_remove(ctx);
}

static inline int
tfw_h2_stream_state_process(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	STREAM_RECV_PROCESS(ctx, hdr);

	tfw_h2_check_closed_stream(ctx);

	return T_OK;
}

static int
tfw_h2_headers_process(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	T_DBG3("%s: stream->id=%u, cur_stream=[%p]\n", __func__,
	       hdr->stream_id, ctx->cur_stream);
	/*
	 * Stream cannot depend on itself (see RFC 7540 section 5.1.2 for
	 * details).
	 */
	if (ctx->priority.stream_id == hdr->stream_id) {
		T_DBG("Invalid dependency: new stream with %u depends on"
		      " itself\n", hdr->stream_id);

		ctx->state = HTTP2_IGNORE_FRAME_DATA;

		if (!STREAM_SEND_PROCESS(ctx->cur_stream, HTTP2_RST_STREAM, 0))
			return tfw_h2_stream_close(ctx, hdr->stream_id,
						   &ctx->cur_stream,
						   HTTP2_ECODE_PROTO);
		return T_OK;
	}

	if (!ctx->cur_stream) {
		ctx->cur_stream = tfw_h2_stream_create(ctx, hdr->stream_id);
		if (!ctx->cur_stream)
			return T_DROP;
		ctx->lstream_id = hdr->stream_id;
	}
	/*
	 * Since the same received HEADERS frame can cause the stream to become
	 * 'open' (i.e. created) and right away become 'half-closed (remote)'
	 * (in case of both END_STREAM and END_HEADERS flags set in initial
	 * HEADERS frame), we should process its state here - when frame is
	 * fully received and new stream is created.
	 */
	return tfw_h2_stream_state_process(ctx);
}

static int
tfw_h2_wnd_update_process(TfwH2Ctx *ctx)
{
	unsigned int wnd_incr;
	TfwFrameHdr *hdr = &ctx->hdr;

	wnd_incr = ntohl(*(unsigned int *)ctx->rbuf) & ((1U << 31) - 1);
	if (wnd_incr) {
		/*
		 * TODO #498: apply new window size for entire connection or
		 * particular stream.
		 */
		return T_OK;
	}

	if (!ctx->cur_stream) {
		tfw_h2_conn_terminate(ctx, HTTP2_ECODE_PROTO);
		return T_DROP;
	}

	if (STREAM_SEND_PROCESS(ctx->cur_stream, HTTP2_RST_STREAM, 0))
		return T_OK;

	return tfw_h2_stream_close(ctx, hdr->stream_id, &ctx->cur_stream,
				   HTTP2_ECODE_PROTO);
}

static inline int
tfw_h2_priority_process(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwFramePri *pri = &ctx->priority;

	tfw_h2_unpack_priority(pri, ctx->rbuf);

	if (pri->stream_id != hdr->stream_id) {
		T_DBG3("%s: parsed, stream_id=%u, dep_stream_id=%u, weight=%hu,"
		       " excl=%hhu\n", __func__, hdr->stream_id, pri->stream_id,
		       pri->weight, pri->exclusive);

		tfw_h2_change_stream_dep(&ctx->sched, hdr->stream_id,
					 pri->stream_id, pri->weight,
					 pri->exclusive);
		return T_OK;
	}

	/*
	 * Stream cannot depend on itself (see RFC 7540 section 5.1.2 for
	 * details).
	 */
	T_DBG("Invalid dependency: new stream with %u depends on"
		      " itself\n", hdr->stream_id);

	if (STREAM_SEND_PROCESS(ctx->cur_stream, HTTP2_RST_STREAM, 0))
		return T_OK;

	return tfw_h2_stream_close(ctx, hdr->stream_id, &ctx->cur_stream,
				   HTTP2_ECODE_PROTO);
}

static inline void
tfw_h2_rst_stream_process(TfwH2Ctx *ctx)
{
	BUG_ON(!ctx->cur_stream);
	T_DBG3("%s: parsed, stream_id=%u, stream=[%p], err_code=%u\n",
	       __func__, ctx->hdr.stream_id, ctx->cur_stream,
	       ntohl(*(unsigned int *)ctx->rbuf));

	tfw_h2_current_stream_remove(ctx);
}

static int
tfw_h2_apply_settings_entry(TfwH2Ctx *ctx, unsigned short id,
			    unsigned int val)
{
	TfwSettings *dest = &ctx->rsettings;

	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		dest->hdr_tbl_sz = min_t(unsigned int,
					 val, HPACK_ENC_TABLE_MAX_SIZE);
		tfw_hpack_set_rbuf_size(&ctx->hpack.enc_tbl, dest->hdr_tbl_sz);
		break;

	case HTTP2_SETTINGS_ENABLE_PUSH:
		if (val > 1)
			return T_BAD;
		dest->push = val;
		break;

	case HTTP2_SETTINGS_MAX_STREAMS:
		dest->max_streams = val;
		break;

	case HTTP2_SETTINGS_INIT_WND_SIZE:
		if (val > MAX_WND_SIZE)
			return T_BAD;
		dest->wnd_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_FRAME_SIZE:
		if (val < FRAME_DEF_LENGTH || val > FRAME_MAX_LENGTH)
			return T_BAD;
		dest->max_frame_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_HDR_LIST_SIZE:
		dest->max_lhdr_sz = val;
		break;

	default:
		/*
		 * We should silently ignore unknown identifiers (see
		 * RFC 7540 section 6.5.2)
		 */
		return T_OK;
	}

	return T_OK;
}

static void
tfw_h2_settings_ack_process(TfwH2Ctx *ctx)
{
	T_DBG3("%s: parsed, stream_id=%u, flags=%hhu\n", __func__,
	       ctx->hdr.stream_id, ctx->hdr.flags);

	ctx->hpack.max_window = ctx->lsettings.hdr_tbl_sz;
	/*
	 * TODO: apply other local settings on ACK receiving.
	 */
}

static int
tfw_h2_settings_process(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	unsigned short id  = ntohs(*(unsigned short *)&ctx->rbuf[0]);
	unsigned int val = ntohl(*(unsigned int *)&ctx->rbuf[2]);

	T_DBG3("%s: entry parsed, id=%hu, val=%u\n", __func__, id, val);

	if (tfw_h2_apply_settings_entry(ctx, id, val))
		return T_BAD;

	ctx->to_read = hdr->length ? FRAME_SETTINGS_ENTRY_SIZE : 0;
	hdr->length -= ctx->to_read;

	return T_OK;
}

static int
tfw_h2_goaway_process(TfwH2Ctx *ctx)
{
	unsigned int last_id, err_code;

	last_id = ntohl(*(unsigned int *)ctx->rbuf) & FRAME_STREAM_ID_MASK;
	err_code = ntohl(*(unsigned int *)&ctx->rbuf[4]);

	T_DBG3("%s: parsed, last_id=%u, err_code=%u\n", __func__,
	       last_id, err_code);
	/*
	 * TODO: currently Tempesta FW does not initiate new streams in client
	 * connections, so for now we have nothing to do here, except
	 * continuation processing of existing streams until client will close
	 * TCP connection. But in context of #1194 (since Tempesta FW will be
	 * able to initiate new streams after PUSH_PROMISE implementation), we
	 * should close all streams initiated by our side with identifier
	 * higher than @last_id, and should not initiate new streams until
	 * connection will be closed (see RFC 7540 section 5.4.1 and section
	 * 6.8 for details).
	 */
	if (err_code)
		T_LOG("HTTP/2 connection is closed by client with error code:"
		      " %u, ID of last processed stream: %u\n", err_code,
		      last_id);
	SET_TO_READ(ctx);
	return T_OK;
}

static inline int
tfw_h2_first_settings_verify(TfwH2Ctx *ctx)
{
	int err_code = 0;
	TfwFrameHdr *hdr = &ctx->hdr;

	BUG_ON(ctx->to_read);

	tfw_h2_unpack_frame_header(hdr, ctx->rbuf);

	if (hdr->type != HTTP2_SETTINGS
	    || (hdr->flags & HTTP2_F_ACK)
	    || hdr->stream_id)
	{
		err_code = HTTP2_ECODE_PROTO;
	}

	if (hdr->length && (hdr->length % FRAME_SETTINGS_ENTRY_SIZE))
		err_code = HTTP2_ECODE_SIZE;

	if (err_code) {
		tfw_h2_conn_terminate(ctx, err_code);
		return T_DROP;
	}

	ctx->to_read = hdr->length ? FRAME_SETTINGS_ENTRY_SIZE : 0;
	hdr->length -= ctx->to_read;

	return T_OK;
}

static inline int
tfw_h2_stream_id_verify(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	if (ctx->cur_stream)
		return T_OK;
	/*
	 * If stream ID is not greater than last processed ID, there may be
	 * two reasons for that:
	 * 1. Stream has been created, processed, closed and removed by now;
	 * 2. Stream was never created and has been moved from idle to closed
	 *    without processing (see RFC 7540 section 5.1.1 for details).
	 *
	 * NOTE: in cases of sending RST_STREAM frame or END_STREAM flag, stream
	 * can be switched into special closed states: HTTP2_STREAM_LOC_CLOSED
	 * or HTTP2_STREAM_REM_CLOSED (which indicates that situation is possible
	 * when stream had been already closed on server side, but the client
	 * is not aware about that yet); according to RFC 7540, section 5.1
	 * ('closed' paragraph) - we should silently discard such stream, i.e.
	 * continue process entire HTTP/2 connection but ignore HEADERS,
	 * CONTINUATION and DATA frames from this stream (not pass upstairs);
	 * to achieve such behavior (to avoid removing of such closed streams
	 * right away), streams in these states are temporary stored in special
	 * queue @TfwClosedQueue.
	 */
	if (ctx->lstream_id >= hdr->stream_id) {
		T_DBG("Invalid ID of new stream: %u stream is"
		      " closed and removed, %u last initiated\n",
		      hdr->stream_id, ctx->lstream_id);
		return T_DROP;
	}
	/*
	 * Streams initiated by client must use odd-numbered
	 * identifiers (see RFC 7540 section 5.1.1 for details).
	 */
	if (!(hdr->stream_id & 0x1)) {
		T_DBG("Invalid ID of new stream: initiated by"
		      " server\n");
		return T_DROP;
	}

	return T_OK;
}

static inline int
tfw_h2_flow_control(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwStream *stream = ctx->cur_stream;
	TfwSettings *lset = &ctx->lsettings;

	BUG_ON(!stream);
	if (hdr->length > stream->loc_wnd)
		T_WARN("Stream flow control window exceeded: frame payload %d,"
		       " current window %u\n", hdr->length, stream->loc_wnd);

	if(hdr->length > ctx->loc_wnd)
		T_WARN("Connection flow control window exceeded: frame payload"
		       " %d, current window %u\n", hdr->length, ctx->loc_wnd);

	stream->loc_wnd -= hdr->length;
	ctx->loc_wnd -= hdr->length;

	if (stream->loc_wnd <= lset->wnd_sz / 2) {
		if( tfw_h2_send_wnd_update(ctx, stream->id,
					   lset->wnd_sz - stream->loc_wnd))
		{
			return T_DROP;
		}
		stream->loc_wnd = lset->wnd_sz;
	}


	if (ctx->loc_wnd <= MAX_WND_SIZE / 2) {
		if (tfw_h2_send_wnd_update(ctx, 0, MAX_WND_SIZE - ctx->loc_wnd))
		{
			return T_DROP;
		}
		ctx->loc_wnd = MAX_WND_SIZE;
	}

	return T_OK;
}

static int
tfw_h2_frame_pad_process(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	++ctx->data_off;
	ctx->padlen = ctx->rbuf[0];
	hdr->length -= ctx->padlen;
	VERIFY_FRAME_SIZE(ctx);

	if (!hdr->length) {
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		ctx->to_read = 0;
		return T_OK;
	}

	switch (hdr->type) {
	case HTTP2_DATA:
		ctx->state = HTTP2_RECV_DATA;
		break;

	case HTTP2_HEADERS:
		if (hdr->flags & HTTP2_F_PRIORITY)
			return tfw_h2_recv_priority(ctx);
		ctx->state = HTTP2_RECV_HEADER;
		break;

	default:
		/* Only DATA and HEADERS frames can be padded. */
		BUG();
	}

	SET_TO_READ(ctx);

	return T_OK;
}

/*
 * Initial processing of received frames: verification and handling of
 * frame header; also, stream states are processed here - during receiving
 * of stream-related frames (CONTINUATION, DATA, RST_STREAM, PRIORITY,
 * WINDOW_UPDATE). We do all that processing at the initial stage here,
 * since we should drop invalid frames/streams/connections as soon as
 * possible in order not to waste resources on their further processing.
 * The only exception is received HEADERS frame which state are processed
 * after full frame reception (see comments in @tfw_h2_headers_process()
 * procedure).
 */
static int
tfw_h2_frame_type_process(TfwH2Ctx *ctx)
{
	TfwH2Err err_code = HTTP2_ECODE_SIZE;
	TfwFrameHdr *hdr = &ctx->hdr;

	T_DBG3("%s: hdr->type=%hhu, ctx->state=%d\n", __func__, hdr->type,
	       ctx->state);

	if (unlikely(ctx->hdr.length > ctx->lsettings.max_frame_sz))
		goto conn_term;

	/*
	 * TODO: RFC 7540 Section 6.2:
	 * A HEADERS frame without the END_HEADERS flag set MUST be followed
	 * by a CONTINUATION frame for the same stream. A receiver MUST treat
	 * the receipt of any other type of frame or a frame on a different
	 * stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
	 */

	switch (hdr->type) {
	case HTTP2_DATA:
		if (!hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		/*
		 * DATA frames are not allowed for idle streams (see RFC 7540
		 * section 5.1 for details).
		 */
		if (hdr->stream_id > ctx->lstream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream = tfw_h2_find_stream(&ctx->sched,
							hdr->stream_id);
		/*
		 * If stream is removed, it had been closed before, so this is
		 * connection error (see RFC 7540 section 5.1).
		 */
		if (!ctx->cur_stream) {
			err_code = HTTP2_ECODE_CLOSED;
			goto conn_term;
		}

		if (tfw_h2_flow_control(ctx))
			return T_DROP;

		ctx->data_off = FRAME_HEADER_SIZE;
		ctx->plen = ctx->hdr.length;

		if (hdr->flags & HTTP2_F_PADDED)
			return tfw_h2_recv_padded(ctx);

		SET_TO_READ_VERIFY(ctx, HTTP2_RECV_DATA);
		return T_OK;

	case HTTP2_HEADERS:
		if (!hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream = tfw_h2_find_stream(&ctx->sched,
						     hdr->stream_id);
		if (tfw_h2_stream_id_verify(ctx)) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		/*
		 * Endpoints must not exceed the limit set by their peer for
		 * maximum number of concurrent streams (see RFC 7540 section
		 * 5.1.2 for details).
		 */
		if (!ctx->cur_stream) {
			unsigned int max_streams = ctx->lsettings.max_streams;

			WARN_ON_ONCE(max_streams < ctx->streams_num);
			tfw_h2_closed_streams_shrink(ctx);

			if (max_streams == ctx->streams_num) {
				T_DBG("Max streams number exceeded: %lu\n",
				      ctx->streams_num);
				SET_TO_READ_VERIFY(ctx, HTTP2_IGNORE_FRAME_DATA);
				return tfw_h2_send_rst_stream(ctx, hdr->stream_id,
							      HTTP2_ECODE_REFUSED);
			}
		}

		ctx->data_off = FRAME_HEADER_SIZE;
		ctx->plen = ctx->hdr.length;

		if (hdr->flags & HTTP2_F_PADDED)
			return tfw_h2_recv_padded(ctx);

		if (hdr->flags & HTTP2_F_PRIORITY)
			return tfw_h2_recv_priority(ctx);

		SET_TO_READ_VERIFY(ctx, HTTP2_RECV_HEADER);
		return T_OK;

	case HTTP2_PRIORITY:
		if (!hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream = tfw_h2_find_stream(&ctx->sched,
							hdr->stream_id);
		if (hdr->length != FRAME_PRIORITY_SIZE)
			goto conn_term;

		if (ctx->cur_stream)
			STREAM_RECV_PROCESS(ctx, hdr);

		ctx->state = HTTP2_RECV_FRAME_PRIORITY;
		SET_TO_READ(ctx);
		return T_OK;

	case HTTP2_WINDOW_UPDATE:
		if (hdr->length != FRAME_WND_UPDATE_SIZE)
			goto conn_term;
		/*
		 * WINDOW_UPDATE frame not allowed for idle streams (see RFC
		 * 7540 section 5.1 for details).
		 */
		if (hdr->stream_id > ctx->lstream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		if (hdr->stream_id) {
			ctx->cur_stream = tfw_h2_find_stream(&ctx->sched,
								hdr->stream_id);
			if (!ctx->cur_stream) {
				err_code = HTTP2_ECODE_CLOSED;
				goto conn_term;
			}

			STREAM_RECV_PROCESS(ctx, hdr);
		}

		ctx->state = HTTP2_RECV_FRAME_WND_UPDATE;
		SET_TO_READ(ctx);
		return T_OK;

	case HTTP2_SETTINGS:
		if (hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		if ((hdr->length % FRAME_SETTINGS_ENTRY_SIZE)
		    || ((hdr->flags & HTTP2_F_ACK)
			&& hdr->length > 0))
		{
			goto conn_term;
		}

		if (hdr->flags & HTTP2_F_ACK)
			tfw_h2_settings_ack_process(ctx);

		if (hdr->length) {
			ctx->state = HTTP2_RECV_FRAME_SETTINGS;
			ctx->to_read = FRAME_SETTINGS_ENTRY_SIZE;
			hdr->length -= ctx->to_read;
		} else {
			/*
			 * SETTINGS frame does not have any payload in
			 * this case, so frame is fully received now.
			 */
			ctx->to_read = 0;
		}

		return T_OK;

	case HTTP2_PUSH_PROMISE:
		/* Client cannot push (RFC 7540 section 8.2). */
		err_code = HTTP2_ECODE_PROTO;
		goto conn_term;

	case HTTP2_PING:
		if (hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		if (hdr->length != FRAME_PING_SIZE)
			goto conn_term;

		ctx->state = HTTP2_RECV_FRAME_PING;
		SET_TO_READ(ctx);
		return T_OK;

	case HTTP2_RST_STREAM:
		if (!hdr->stream_id)
		{
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		if (hdr->length != FRAME_RST_STREAM_SIZE)
			goto conn_term;
		/*
		 * RST_STREAM frames are not allowed for idle streams (see RFC
		 * 7540 section 5.1 and section 6.4 for details).
		 */
		if (hdr->stream_id > ctx->lstream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream = tfw_h2_find_stream(&ctx->sched,
							hdr->stream_id);
		if (!ctx->cur_stream) {
			err_code = HTTP2_ECODE_CLOSED;
			goto conn_term;
		}

		STREAM_RECV_PROCESS(ctx, hdr);

		ctx->state = HTTP2_RECV_FRAME_RST_STREAM;
		SET_TO_READ(ctx);
		return T_OK;

	case HTTP2_GOAWAY:
		if (hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		if (hdr->length < FRAME_GOAWAY_SIZE)
			goto conn_term;

		ctx->state = HTTP2_RECV_FRAME_GOAWAY;
		ctx->to_read = FRAME_GOAWAY_SIZE;
		hdr->length -= ctx->to_read;
		return T_OK;

	case HTTP2_CONTINUATION:
		if (!hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		/*
		 * CONTINUATION frames are not allowed for idle streams (see
		 * RFC 7540 section 5.1 and section 6.4 for details).
		 */
		if (hdr->stream_id > ctx->lstream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream = tfw_h2_find_stream(&ctx->sched,
							hdr->stream_id);
		if (!ctx->cur_stream) {
			err_code = HTTP2_ECODE_CLOSED;
			goto conn_term;
		}

		ctx->data_off = FRAME_HEADER_SIZE;
		ctx->plen = ctx->hdr.length;

		SET_TO_READ_VERIFY(ctx, HTTP2_RECV_CONT);
		return T_OK;

	default:
		/*
		 * Possible extension types of frames are not covered (yet) in
		 * this procedure. On current stage we just ignore such frames.
		 */
		T_DBG("HTTP/2: frame of unknown type '%u' received\n",
		      hdr->type);
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		SET_TO_READ(ctx);
		return T_OK;
	}

conn_term:
	BUG_ON(!err_code);
	tfw_h2_conn_terminate(ctx, err_code);
	return T_DROP;
}

/**
 * Main FSM for processing HTTP/2 frames.
 */
static int
tfw_h2_frame_recv(void *data, unsigned char *buf, size_t len,
		  unsigned int *read)
{
	int n, r = T_POSTPONE;
	unsigned char *p = buf;
	TfwH2Ctx *ctx = data;
	T_FSM_INIT(ctx->state, "HTTP/2 Frame Receive");

	T_FSM_START(ctx->state) {

	T_FSM_STATE(HTTP2_RECV_CLI_START_SEQ) {
		FRAME_FSM_READ_LAMBDA(FRAME_PREFACE_CLI_MAGIC_LEN, {
			if (memcmp_fast(FRAME_PREFACE_CLI_MAGIC + ctx->rlen,
					p, n))
			{
				T_DBG("Invalid client magic received,"
					 " connection must be dropped\n");
				FRAME_FSM_EXIT(T_DROP);
			}
		});

		if (tfw_h2_send_settings_init(ctx)
		    || tfw_h2_send_wnd_update(ctx, 0,
						 MAX_WND_SIZE - DEF_WND_SIZE))
		{
			FRAME_FSM_EXIT(T_DROP);
		}

		FRAME_FSM_MOVE(HTTP2_RECV_FIRST_SETTINGS);
	}

	T_FSM_STATE(HTTP2_RECV_FIRST_SETTINGS) {
		FRAME_FSM_READ_SRVC(FRAME_HEADER_SIZE);

		if (tfw_h2_first_settings_verify(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_RECV_FRAME_SETTINGS);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_HEADER) {
		FRAME_FSM_READ_SRVC(FRAME_HEADER_SIZE);

		tfw_h2_unpack_frame_header(&ctx->hdr, ctx->rbuf);

		if (tfw_h2_frame_type_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_NEXT();

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PADDED) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_h2_frame_pad_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_NEXT();

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PRIORITY) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_h2_priority_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_WND_UPDATE) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_h2_wnd_update_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PING) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (!(ctx->hdr.flags & HTTP2_F_ACK)
		    && tfw_h2_send_ping(ctx))
		{
			FRAME_FSM_EXIT(T_DROP);
		}

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_RST_STREAM) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		tfw_h2_rst_stream_process(ctx);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_SETTINGS) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_h2_settings_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_RECV_FRAME_SETTINGS);

		if (tfw_h2_send_settings_ack(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_GOAWAY) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_h2_goaway_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_IGNORE_FRAME_DATA);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_HEADER_PRI) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_h2_headers_pri_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_NEXT();

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_DATA) {
		FRAME_FSM_READ(ctx->to_read);

		if (tfw_h2_stream_state_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_HEADER) {
		FRAME_FSM_READ(ctx->to_read);

		if (tfw_h2_headers_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_CONT) {
		FRAME_FSM_READ(ctx->to_read);

		if (tfw_h2_stream_state_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_IGNORE_FRAME_DATA) {
		FRAME_FSM_READ(ctx->to_read);
		FRAME_FSM_EXIT(T_OK);
	}
	}

	FRAME_FSM_FINISH();

	return r;
}

/*
 * Re-initialization of HTTP/2 framing context. Due to passing frames to
 * upper level in per-skb granularity (not per-frame) and processing of
 * padded frames - we need to pass upstairs postponed frames too (only
 * app frames: HEADERS, DATA, CONTINUATION); thus, three situations can
 * appear during framing context initialization:
 * 1. For all service (non-app) frames and for fully received app frames
 *    without padding - context must be reset; in this case the @ctx->state
 *    field will be set to HTTP2_RECV_FRAME_HEADER state (since its value
 *    is zero), and processing of the next frame will start from this state;
 * 2. On fully received app frames with padding - context must not be reset
 *    and should be reinitialized to continue processing until all padding
 *    will be processed;
 * 3. On postponed app frames (with or without padding) - context must not
 *    be reinitialized at all and should be further processed until the
 *    frame will be fully received.
 */
static inline void
tfw_h2_context_reinit(TfwH2Ctx *ctx, bool postponed)
{
	if (!APP_FRAME(ctx) || (!postponed && !ctx->padlen)) {
		bzero_fast(ctx->__off,
			   sizeof(*ctx) - offsetof(TfwH2Ctx, __off));
		return;
	}
	if (!postponed && ctx->padlen) {
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		ctx->to_read = ctx->padlen;
		ctx->padlen = 0;
	}
}

int
tfw_h2_frame_process(void *c, TfwFsmData *data)
{
	int r;
	bool postponed;
	unsigned int parsed, unused;
	TfwFsmData data_up = {};
	TfwH2Ctx *h2 = tfw_h2_context(c);
	struct sk_buff *nskb = NULL, *skb = data->skb;

next_msg:
	postponed = false;
	ss_skb_queue_tail(&h2->skb_head, skb);
	parsed = 0;
	r = ss_skb_process(skb, tfw_h2_frame_recv, h2, &unused, &parsed);

	switch (r) {
	default:
		T_WARN("Unrecognized return code %d during HTTP/2 frame"
		       " receiving, drop frame\n", r);
		// fallthrough
	case T_DROP:
		T_DBG3("Drop invalid HTTP/2 frame\n");
		goto out;
	case T_POSTPONE:
		/*
		 * We don't collect all skbs for app frames and pass
		 * current skb to the upper level as soon as possible
		 * (after frame header is processed), including the
		 * postpone case. On the contrary, we accumulate all
		 * the skbs for the service frames, since for them we
		 * need not to pass any data upstairs; in this case
		 * all collected skbs are dropped at once when service
		 * frame fully received, processed and applied.
		 */
		if (APP_FRAME(h2)) {
			postponed = true;
			break;
		}

		return T_OK;
	case T_OK:
		T_DBG3("%s: parsed=%d skb->len=%u\n", __func__,
		       parsed, skb->len);
	}

	/*
	 * For fully received frames possibly there are other frames
	 * in the current @skb, so create an skb sibling with next
	 * frame and process it on the next iteration. This situation
	 * is excluded for postponed frames, since for them the value
	 * of @parsed must be always equal to the length of skb currently
	 * processed.
	 */
	if (parsed < skb->len) {
		nskb = ss_skb_split(skb, parsed);
		if (unlikely(!nskb)) {
			TFW_INC_STAT_BH(clnt.msgs_otherr);
			r = T_DROP;
			goto out;
		}
	}

	/*
	 * Before transferring the skb with app frame for further processing,
	 * certain service data should be separated from it (placed at the
	 * frame's beginning): frame header, optional pad length and optional
	 * priority data (the latter is for HEADERS frames only). Besides,
	 * DATA and HEADERS frames can contain some padding in the frame's
	 * tail, but we don't need to worry about that here since such padding
	 * is processed as service data, separately from app frame, and it
	 * will be just split into separate skb (above).
	 */
	if (APP_FRAME(h2)) {
		/* This chopping algorithm could be repleces with a call
		 * of ss_skb_list_chop_head_tail(). We refrain of it
		 * to proccess a special case !h2->skb_head below.
		 */
		while (unlikely(h2->skb_head->len <= h2->data_off)) {
			struct sk_buff *skb = ss_skb_dequeue(&h2->skb_head);
			h2->data_off -= skb->len;
			kfree_skb(skb);
			/*
			 * Special case when the frame is postponed just
			 * in the beginning of the app data, after all
			 * frame header fields processed.
			 */
			if (!h2->skb_head) {
				WARN_ON_ONCE(h2->data_off);
				return T_OK;
			}
		}
		/*
		 * The skb should be last here, since we do not accumulate
		 * skbs until full frame will be received.
		 */
		WARN_ON_ONCE(h2->skb_head != h2->skb_head->next);
		data_up.skb = h2->skb_head;
		if (ss_skb_chop_head_tail(NULL, data_up.skb, h2->data_off, 0))
		{
			r = T_DROP;
			kfree_skb(nskb);
			goto out;
		}
		h2->data_off = 0;
		h2->skb_head = data_up.skb->next = data_up.skb->prev = NULL;
		r = tfw_http_msg_process_generic(c, h2->cur_stream, &data_up);
		if (r == T_DROP) {
			kfree_skb(nskb);
			goto out;
		}
	} else {
		ss_skb_queue_purge(&h2->skb_head);
	}

	tfw_h2_context_reinit(h2, postponed);

	if (nskb) {
		skb = nskb;
		nskb = NULL;
		goto next_msg;
	}

out:
	ss_skb_queue_purge(&h2->skb_head);
	return r;
}
