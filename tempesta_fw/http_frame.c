/**
 *		Tempesta FW
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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

#if DBG_HTTP_FRAME == 0
#undef DEBUG
#endif
#include "lib/fsm.h"
#include "lib/str.h"
#include "procfs.h"
#include "http.h"
#include "http_frame.h"


#define FRAME_CLI_MAGIC			"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define FRAME_CLI_MAGIC_LEN		24
#define FRAME_WND_UPDATE_SIZE		4
#define FRAME_RST_STREAM_SIZE		4
#define FRAME_PRIORITY_SIZE		5
#define FRAME_SETTINGS_ENTRY_SIZE	6
#define FRAME_PING_SIZE			8
#define FRAME_GOAWAY_SIZE		8

#define FRAME_STREAM_ID_MASK		((1U << 31) - 1)

/* HTTP/2 frame types (RFC 7540 section 6).*/
typedef enum {
	HTTP2_DATA			= 0,
	HTTP2_HEADERS,
	HTTP2_PRIORITY,
	HTTP2_RST_STREAM,
	HTTP2_SETTINGS,
	HTTP2_PUSH_PROMISE,
	HTTP2_PING,
	HTTP2_GOAWAY,
	HTTP2_WINDOW_UPDATE,
	HTTP2_CONTINUATION
} TfwFrameType;

/*
 * HTTP/2 error codes (RFC 7540 section 7). Used in RST_STREAM
 * and GOAWAY frames to report the reasons of the stream or
 * connection error.
 */
typedef enum {
	FRAME_ECODE_NO_ERROR,
	FRAME_ECODE_PROTO,
	FRAME_ECODE_INTERNAL,
	FRAME_ECODE_FLOW_CONTROL,
	FRAME_ECODE_SETTINGS_TIMEOUT,
	FRAME_ECODE_STREAM_CLOSED,
	FRAME_ECODE_SIZE,
	FRAME_ECODE_REFUSED_STREAM,
	FRAME_ECODE_CANCEL,
	FRAME_ECODE_COMPRESSION,
	FRAME_ECODE_CONNECT,
	FRAME_ECODE_ENHANCE_YOUR_CALM,
	FRAME_ECODE_INADEQUATE_SECURITY,
	FRAME_ECODE_HTTP_1_1_REQUIRED
} TfwFrameErr;

/*
 * HTTP/2 frame flags. Can be specified in frame's header and
 * are specific to the particular frame types (RFC 7540 section
 * 4.1 and section 6).
 */
typedef enum {
	HTTP2_F_ACK			= 0x01,
	HTTP2_F_END_STREAM		= 0x01,
	HTTP2_F_END_HEADERS		= 0x04,
	HTTP2_F_PADDED			= 0x08,
	HTTP2_F_PRIORITY		= 0x20
} TfwFrameFlag;

/*
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

#define APP_FRAME(ctx)							\
	((ctx)->state >= __HTTP2_RECV_FRAME_APP)

#define PAYLOAD(ctx)							\
	((ctx)->state != HTTP2_RECV_FRAME_HEADER)

static inline void
tfw_http2_unpack_frame_header(TfwFrameHdr *hdr, const unsigned char *buf)
{
	hdr->length = ntohl(*(int *)buf) >> 8;
	hdr->type = buf[3];
	hdr->flags = buf[4];
	hdr->stream_id = ntohl(*(unsigned int *)&buf[5]) & FRAME_STREAM_ID_MASK;

	T_DBG3("%s: parsed, length=%d, stream_id=%u, type=%hhu, flags=0x%hhx\n",
	       __func__, hdr->length, hdr->stream_id, hdr->type, hdr->flags);
}

static inline void
tfw_http2_pack_frame_header(unsigned char *p, const TfwFrameHdr *hdr)
{
	*(unsigned int *)p = htonl((unsigned int)(hdr->length << 8));
	p += 3;
	*p++ = hdr->type;
	*p++ = hdr->flags;
	/*
	 * Stream id must occupy not more than 31 bit and reserved bit
	 * must be 0.
	 */
	WARN_ON_ONCE((unsigned int)(hdr->stream_id & ~FRAME_STREAM_ID_MASK));

	*(unsigned int *)p = htonl(hdr->stream_id);
}

static inline void
tfw_http2_unpack_priority(TfwFramePri *pri, const unsigned char *buf)
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
tfw_http2_send_frame(TfwHttp2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data)
{
	int r;
	TfwMsgIter it;
	TfwMsg msg = {};
	unsigned char buf[FRAME_HEADER_SIZE];
	TfwStr *hdr_str = TFW_STR_CHUNK(data, 0);

	BUG_ON(hdr_str->data);
	hdr_str->data = buf;
	hdr_str->len = FRAME_HEADER_SIZE;

	if (data != hdr_str)
		data->len += FRAME_HEADER_SIZE;

	tfw_http2_pack_frame_header(buf, hdr);

	T_DBG2("Preparing HTTP/2 message with %lu bytes data\n", data->len);

	msg.len = data->len;
	if ((r = tfw_msg_iter_setup(&it, &msg.skb_head, msg.len)))
		goto err;

	if ((r = tfw_msg_write(&it, data)))
		goto err;

	return tfw_connection_send(ctx->conn, &msg);;

err:
	ss_skb_queue_purge(&msg.skb_head);
	return r;
}

static inline int
tfw_http2_send_ping(TfwHttp2Ctx *ctx)
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

	return tfw_http2_send_frame(ctx, &hdr, &data);

}

static inline int
tfw_http2_send_settings(TfwHttp2Ctx *ctx, bool ack)
{
	TfwStr data = {};
	TfwFrameHdr hdr = {
		.length = 0,
		.stream_id = 0,
		.type = HTTP2_SETTINGS,
		.flags = ack ? HTTP2_F_ACK : 0
	};

	return tfw_http2_send_frame(ctx, &hdr, &data);
}

static int
tfw_http2_conn_terminate(TfwHttp2Ctx *ctx, int err_code)
{
	ctx->state = HTTP2_IGNORE_FRAME_DATA;
	/*
	 * TODO: send appropriately filled GOAWAY frame, set
	 * Conn_Stop flag for connection, and close it (possibly
	 * via SS_F_CONN_CLOSE flag).
	 */
	return 0;
}

#define VERIFY_FRAME_SIZE(ctx)						\
do {									\
	if ((ctx)->hdr.length <= 0)					\
		return tfw_http2_conn_terminate(ctx, FRAME_ECODE_SIZE);	\
} while (0)

static int
tfw_http2_stream_verify(TfwHttp2Ctx *ctx)
{
	int stream = ctx->hdr.stream_id;

	/*
	 * TODO: check of Stream existence and stream's current state;
	 * this function (and similar verification procedures) may have
	 * three results:
	 * 1. Continue normal frame receiving (if stream exists and is
	 *    in appropriate state);
	 * 2. Set 'ctx->state = HTTP2_IGNORE_FRAME_DATA' to skip current
	 *    frame's payload (if stream is in not appropriate state but
	 *    we can continue operate with current connection);
	 * 3. Set 'ctx->state = HTTP2_IGNORE_ALL' to skip current and all
	 *    incoming frames in future until connection will be closed
	 *    (if we cannot operate with current connection and it must be
	 *    closed); in this case @tfw_http2_connection_terminate() must
	 *    be called (below).
	 */

	if (!stream)
		return tfw_http2_conn_terminate(ctx, FRAME_ECODE_PROTO);

	return 0;
}

static inline int
tfw_http2_recv_priority(TfwHttp2Ctx *ctx)
{
	ctx->to_read = FRAME_PRIORITY_SIZE;
	ctx->hdr.length -= ctx->to_read;
	VERIFY_FRAME_SIZE(ctx);
	ctx->state = HTTP2_RECV_HEADER_PRI;
	return T_OK;
}

static int
tfw_http2_headers_pri_process(TfwHttp2Ctx *ctx)
{
	TfwFramePri *pri = &ctx->priority;
	TfwFrameHdr *hdr = &ctx->hdr;

	BUG_ON(!(hdr->flags & HTTP2_F_PRIORITY));

	tfw_http2_unpack_priority(pri, ctx->rbuf);

	if (tfw_http2_stream_verify(ctx))
		return T_BAD;
	if (ctx->state != HTTP2_IGNORE_FRAME_DATA) {
		ctx->data_off += FRAME_PRIORITY_SIZE;
		ctx->state = HTTP2_RECV_HEADER;
	}

	T_DBG3("%s: parsed, stream_id=%u, dep_stream_id=%u, weight=%hu,"
	       " excl=%hhu\n", __func__, hdr->stream_id, pri->stream_id,
	       pri->weight, pri->exclusive);

	SET_TO_READ(ctx);
	return T_OK;
}

static TfwStream *
tfw_http2_stream_create(TfwHttp2Ctx *ctx, unsigned int id)
{
	TfwStream *stream, *dep = NULL;
	TfwFramePri *pri = &ctx->priority;
	bool excl = pri->exclusive;

	stream = kzalloc(sizeof(TfwStream), GFP_ATOMIC);
	if (unlikely(!stream))
		return NULL;

	RB_CLEAR_NODE(&stream->node);
	stream->id = id;
	stream->state = HTTP2_STREAM_OPENED;
	stream->weight = pri->weight;

	if (tfw_http2_find_stream_dep(&ctx->sched, pri->stream_id, &dep))
		goto out_free;

	if (tfw_http2_add_stream(&ctx->sched, stream))
		goto out_free;

	tfw_http2_add_stream_dep(&ctx->sched, stream, dep, excl);

	++ctx->streams_num;

	T_DBG3("%s: stream added, id=%u, stream=[%p] weight=%hu,"
	       " streams_num=%lu, dep_stream_id=%u, dep_stream=[%p],"
	       " excl=%hhu\n", __func__, id, stream, stream->weight,
	       ctx->streams_num, pri->stream_id, dep, pri->exclusive);

	return stream;

out_free:
	kfree(stream);

	return NULL;
}

static inline void
tfw_http2_stream_delete(TfwHttp2Ctx *ctx, TfwStream *stream)
{

}

static int
tfw_http2_headers_process(TfwHttp2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwStream *stream = tfw_http2_find_stream(&ctx->sched, hdr->stream_id);

	T_DBG3("%s: stream_id=%u, stream=[%p]\n", __func__, hdr->stream_id,
	       stream);

	if (!stream) {
		/*
		 * Streams initiated by client must use odd-numbered identifiers
		 * (see RFC 7540 section 5.1.1).
		 */
		if (!(hdr->stream_id & 0x1)) {
			T_DBG("Invalid ID of new stream: initiated by server\n");
			goto term;
		}

		if (ctx->priority.stream_id == hdr->stream_id) {
			T_DBG("Invalid dependency: new stream with %u depends"
			      " on itself\n", ctx->priority.stream_id);
			goto term;
		}

		if (ctx->lstream_id >= hdr->stream_id) {
			T_DBG("Invalid ID of new stream: %u already in use, %u"
			      " last initiated\n", hdr->stream_id,
			      ctx->lstream_id);
			goto term;
		}

		if (ctx->lsettings.max_streams <= ctx->streams_num) {
			T_DBG("Max streams number exceeded: %lu\n", ctx->streams_num);
			goto term;
		}

		if (!(stream = tfw_http2_stream_create(ctx, hdr->stream_id)))
			return T_BAD;

		ctx->lstream_id = hdr->stream_id;

		return T_OK;
	}

	/*
	 * TODO: verification of stream's state is needed.
	 * NOTE: in some cases - if we haven't found the stream (since it had
	 * been closed and removed already) or if we have found the stream but
	 * it is in closed state) - this is the race condition (when stream
	 * had been closed on server side, but the client does not aware about
	 * that yet), and we should silently discard such stream, i.e. continue
	 * process entire HTTP/2 connection but ignore HEADERS, CONTINUATION and
	 * DATA frames from this stream (not pass upstairs); to achieve such
	 * behavior in case of already removed streams, perhaps we should store
	 * closed streams - for some predefined period of time or just limiting
	 * the amount of closed stored streams.
	 */

	return T_OK;

term:
	return tfw_http2_conn_terminate(ctx, FRAME_ECODE_PROTO);
}

static int
tfw_http2_cont_check(TfwHttp2Ctx *ctx)
{
	/*
	 * TODO: check END_HEADERS flag.
	 */
	return T_OK;
}

static int
tfw_http2_wnd_update_process(TfwHttp2Ctx *ctx)
{
	/*
	 * TODO: apply new window size for entire connection or
	 * particular stream; ignore until #498.
	 */
	return T_OK;
}

static inline void
tfw_http2_priority_process(TfwHttp2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwFramePri *pri = &ctx->priority;

	tfw_http2_unpack_priority(pri, ctx->rbuf);

	T_DBG3("%s: parsed, stream_id=%u, dep_stream_id=%u, weight=%hu,"
	       " excl=%hhu\n", __func__, hdr->stream_id, pri->stream_id,
	       pri->weight, pri->exclusive);

	tfw_http2_change_stream_dep(&ctx->sched, hdr->stream_id, pri->stream_id,
				    pri->weight, pri->exclusive);
}

static int
tfw_http2_rst_stream_process(TfwHttp2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwStream *stream = tfw_http2_find_stream(&ctx->sched, hdr->stream_id);

	/*
	 * TODO: see note in @tfw_http2_headers_process().
	 */
	if (!stream)
		return T_BAD;

	T_DBG3("%s: parsed, stream_id=%u, stream=[%p], err_code=%u\n", __func__,
	       hdr->stream_id, stream, ntohl(*(unsigned int *)ctx->rbuf));

	--ctx->streams_num;

	tfw_http2_remove_stream_dep(&ctx->sched, stream);
	tfw_http2_remove_stream(&ctx->sched, stream);

	kfree(stream);

	return T_OK;
}

static int
tfw_http2_apply_settings_entry(TfwSettings *dest, unsigned short id,
			       unsigned int val)
{
	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		dest->hdr_tbl_sz = val;
		break;

	case HTTP2_SETTINGS_ENABLE_PUSH:
		dest->push = val;
		break;

	case HTTP2_SETTINGS_MAX_STREAMS:
		dest->max_streams = val;
		break;

	case HTTP2_SETTINGS_INIT_WND_SIZE:
		dest->wnd_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_FRAME_SIZE:
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

	/*
	 * TODO: apply settings entry.
	 */
	return T_OK;
}

static void
tfw_http2_settings_ack_process(TfwHttp2Ctx *ctx)
{
	T_DBG3("%s: parsed, stream_id=%u, flags=%hhu\n", __func__,
	       ctx->hdr.stream_id, ctx->hdr.flags);
	/*
	 * TODO: apply settings ACK.
	 */
}

static int
tfw_http2_settings_process(TfwHttp2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;
	unsigned short id  = ntohs(*(unsigned short *)&ctx->rbuf[0]);
	unsigned int val = ntohl(*(unsigned int *)&ctx->rbuf[2]);

	T_DBG3("%s: entry parsed, id=%hu, val=%u\n", __func__, id, val);

	if (tfw_http2_apply_settings_entry(&ctx->rsettings, id, val))
		return T_BAD;

	ctx->to_read = hdr->length ? FRAME_SETTINGS_ENTRY_SIZE : 0;
	hdr->length -= ctx->to_read;

	return T_OK;
}

static int
tfw_http2_goaway_process(TfwHttp2Ctx *ctx)
{
	unsigned int err_code = ntohl(*(unsigned int *)&ctx->rbuf[4]);
	unsigned int last_id = ntohl(*(unsigned int *)ctx->rbuf) & FRAME_STREAM_ID_MASK;

	T_DBG3("%s: parsed, last_id=%u, err_code=%u\n", __func__,
	       last_id, err_code);
	/*
	 * TODO: close streams with @id greater than @last_id
	 */
	if (err_code)
		T_LOG("HTTP/2 connection is closed by client with error code:"
		      " %u, ID of last processed stream: %u\n", err_code,
		      last_id);
	SET_TO_READ(ctx);
	return T_OK;
}

static inline int
tfw_http2_first_settings_verify(TfwHttp2Ctx *ctx)
{
	int err_code = 0;
	TfwFrameHdr *hdr = &ctx->hdr;

	BUG_ON(ctx->to_read);

	tfw_http2_unpack_frame_header(hdr, ctx->rbuf);

	if (hdr->type != HTTP2_SETTINGS
	    || (hdr->flags & HTTP2_F_ACK)
	    || hdr->stream_id)
	{
		err_code = FRAME_ECODE_PROTO;
	}

	if (hdr->length && (hdr->length % FRAME_SETTINGS_ENTRY_SIZE))
		err_code = FRAME_ECODE_SIZE;

	if (err_code)
		return tfw_http2_conn_terminate(ctx, err_code);

	ctx->to_read = hdr->length ? FRAME_SETTINGS_ENTRY_SIZE : 0;
	hdr->length -= ctx->to_read;

	return T_OK;
}

static int
tfw_http2_frame_pad_process(TfwHttp2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	++ctx->data_off;
	ctx->padlen = ctx->rbuf[0];
	hdr->length -= ctx->padlen;
	VERIFY_FRAME_SIZE(ctx);

	switch (hdr->type) {
	case HTTP2_DATA:
		ctx->state = HTTP2_RECV_DATA;
		break;

	case HTTP2_HEADERS:
		if (hdr->flags & HTTP2_F_PRIORITY)
			return tfw_http2_recv_priority(ctx);
		ctx->state = HTTP2_RECV_HEADER;
		break;

	default:
		/* Only DATA and HEADERS frames can be padded. */
		BUG();
	}

	SET_TO_READ(ctx);

	return T_OK;
}


static int
tfw_http2_frame_type_process(TfwHttp2Ctx *ctx)
{
	int err_code = FRAME_ECODE_SIZE;
	TfwFrameHdr *hdr = &ctx->hdr;

	T_DBG3("%s: hdr->type=%hhu, ctx->state=%d\n", __func__, hdr->type,
	       ctx->state);

	switch (hdr->type) {
	case HTTP2_DATA:
		BUG_ON(PAYLOAD(ctx));
		if (!hdr->stream_id) {
			err_code = FRAME_ECODE_PROTO;
			goto out_term;
		}

		if (!hdr->length)
			goto out_term;

		ctx->data_off = FRAME_HEADER_SIZE;

		if (hdr->flags & HTTP2_F_PADDED) {
			ctx->to_read = 1;
			hdr->length -= ctx->to_read;
			VERIFY_FRAME_SIZE(ctx);
			ctx->state = HTTP2_RECV_FRAME_PADDED;
			return T_OK;
		}

		ctx->state = HTTP2_RECV_DATA;
		SET_TO_READ(ctx);
		return T_OK;

	case HTTP2_HEADERS:
		BUG_ON(PAYLOAD(ctx));
		if (!hdr->stream_id) {
			err_code = FRAME_ECODE_PROTO;
			goto out_term;
		}

		if (!hdr->length)
			goto out_term;

		ctx->data_off = FRAME_HEADER_SIZE;

		if (hdr->flags & HTTP2_F_PADDED) {
			ctx->to_read = 1;
			hdr->length -= ctx->to_read;
			VERIFY_FRAME_SIZE(ctx);
			ctx->state = HTTP2_RECV_FRAME_PADDED;
			return T_OK;
		}

		if (hdr->flags & HTTP2_F_PRIORITY)
			return tfw_http2_recv_priority(ctx);

		ctx->state = HTTP2_RECV_HEADER;

		SET_TO_READ(ctx);
		return T_OK;

	case HTTP2_PRIORITY:
		if (!PAYLOAD(ctx)) {
			if (!hdr->stream_id) {
				err_code = FRAME_ECODE_PROTO;
				goto out_term;
			}

			if (hdr->length != FRAME_PRIORITY_SIZE)
				goto out_term;

			if (tfw_http2_stream_verify(ctx))
				return T_BAD;
			if (ctx->state != HTTP2_IGNORE_FRAME_DATA)
				ctx->state = HTTP2_RECV_FRAME_SERVICE;

			SET_TO_READ(ctx);
			return T_OK;
		}

		tfw_http2_priority_process(ctx);
		return T_OK;

	case HTTP2_WINDOW_UPDATE:
		if (!PAYLOAD(ctx)) {
			if (hdr->length != FRAME_WND_UPDATE_SIZE)
				goto out_term;

			ctx->state = HTTP2_RECV_FRAME_SERVICE;
			SET_TO_READ(ctx);
			return T_OK;
		}

		return tfw_http2_wnd_update_process(ctx);

	case HTTP2_SETTINGS:
		BUG_ON(PAYLOAD(ctx));
		if (hdr->stream_id) {
			err_code = FRAME_ECODE_PROTO;
			goto out_term;
		}
		if ((hdr->length % FRAME_SETTINGS_ENTRY_SIZE)
		    || ((hdr->flags & HTTP2_F_ACK)
			&& hdr->length > 0))
		{
			goto out_term;
		}

		if (hdr->flags & HTTP2_F_ACK)
			tfw_http2_settings_ack_process(ctx);

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
		err_code = FRAME_ECODE_PROTO;
		goto out_term;

	case HTTP2_PING:
		if (!PAYLOAD(ctx)) {
			if (hdr->stream_id) {
				err_code = FRAME_ECODE_PROTO;
				goto out_term;
			}
			if (hdr->length != FRAME_PING_SIZE)
				goto out_term;

			ctx->state = HTTP2_RECV_FRAME_SERVICE;
			SET_TO_READ(ctx);
			return T_OK;
		}
		if (!(hdr->flags & HTTP2_F_ACK))
			return tfw_http2_send_ping(ctx);

		return T_OK;

	case HTTP2_RST_STREAM:
		if (!PAYLOAD(ctx)) {
			if (hdr->stream_id || ctx->lstream_id < hdr->stream_id)
			{
				err_code = FRAME_ECODE_PROTO;
				goto out_term;
			}
			if (hdr->length != FRAME_RST_STREAM_SIZE)
				goto out_term;

			ctx->state = HTTP2_RECV_FRAME_SERVICE;
			SET_TO_READ(ctx);
			return T_OK;
		}

		if (tfw_http2_rst_stream_process(ctx)) {
			err_code = FRAME_ECODE_PROTO;
			goto out_term;
		}

		return T_OK;

	case HTTP2_GOAWAY:
		BUG_ON(PAYLOAD(ctx));
		if (hdr->stream_id) {
			err_code = FRAME_ECODE_PROTO;
			goto out_term;
		}
		if (hdr->length < FRAME_GOAWAY_SIZE)
			goto out_term;

		ctx->state = HTTP2_RECV_FRAME_GOAWAY;
		ctx->to_read = FRAME_GOAWAY_SIZE;
		hdr->length -= ctx->to_read;
		return T_OK;

	case HTTP2_CONTINUATION:
		BUG_ON(PAYLOAD(ctx));
		if (tfw_http2_cont_check(ctx))
			return T_BAD;
		if (ctx->state != HTTP2_IGNORE_FRAME_DATA)
			ctx->state = HTTP2_RECV_CONT;

		ctx->data_off = FRAME_HEADER_SIZE;

		SET_TO_READ(ctx);
		return T_OK;

	default:
		/*
		 * Possible extension types of frames are not covered
		 * (yet) in this procedure. On current stage we just
		 * ignore such frames.
		 */
		T_DBG("HTTP/2: frame of unknown type '%u' received\n",
		      hdr->type);
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		SET_TO_READ(ctx);
		return T_OK;
	}

out_term:
	BUG_ON(!err_code);
	return tfw_http2_conn_terminate(ctx, err_code);
}

/**
 * Main FSM for processing HTTP/2 frames.
 */
static int
tfw_http2_frame_recv(void *data, unsigned char *buf, size_t len,
		     unsigned int *read)
{
	int n, r = T_POSTPONE;
	unsigned char *p = buf;
	TfwHttp2Ctx *ctx = data;
	T_FSM_INIT(ctx->state, "HTTP/2 Frame Receive");

	T_FSM_START(ctx->state) {

	T_FSM_STATE(HTTP2_RECV_CLI_START_SEQ) {
		FRAME_FSM_READ_LAMBDA(FRAME_CLI_MAGIC_LEN, {
			if (memcmp_fast(FRAME_CLI_MAGIC + ctx->rlen, p, n)) {
				T_DBG("Invalid client magic received,"
					 " connection must be dropped\n");
				FRAME_FSM_EXIT(T_DROP);
			}
		});
		if (tfw_http2_send_settings(ctx, false))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_MOVE(HTTP2_RECV_FIRST_SETTINGS);
	}

	T_FSM_STATE(HTTP2_RECV_FIRST_SETTINGS) {
		FRAME_FSM_READ_SRVC(FRAME_HEADER_SIZE);

		if (tfw_http2_first_settings_verify(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_RECV_FRAME_SETTINGS);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_HEADER) {
		FRAME_FSM_READ_SRVC(FRAME_HEADER_SIZE);

		tfw_http2_unpack_frame_header(&ctx->hdr, ctx->rbuf);

		if (tfw_http2_frame_type_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_NEXT();

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PADDED) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_http2_frame_pad_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_NEXT();
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_SERVICE) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_http2_frame_type_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_SETTINGS) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_http2_settings_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_RECV_FRAME_SETTINGS);

		if (tfw_http2_send_settings(ctx, true))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_GOAWAY) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_http2_goaway_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_IGNORE_FRAME_DATA);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_HEADER_PRI) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (tfw_http2_headers_pri_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_NEXT();
	}

	T_FSM_STATE(HTTP2_RECV_DATA) {
		FRAME_FSM_READ(ctx->to_read);
		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_HEADER) {
		FRAME_FSM_READ(ctx->to_read);

		if (tfw_http2_headers_process(ctx))
			FRAME_FSM_EXIT(T_DROP);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_CONT) {
		FRAME_FSM_READ(ctx->to_read);

		if ((r = tfw_http2_cont_check(ctx)))
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
 * 1. On fully received service (non-app) frames and fully received app
 *    frames without padding - context must be reset; in this case the
 *    @ctx->state field will be set to HTTP2_RECV_FRAME_HEADER state (since
 *    its value is zero), and processing of the next frame will start from
 *    this state;
 * 2. On fully received app frames with padding - context must not be
 *    reset and should be reinitialized to continue processing until all
 *    padding will be processed;
 * 3. On postponed app frames (with or without padding) - context must
 *    not be reinitialized at all and should be further processed until
 *    the frame will be fully received.
 */
static inline void
tfw_http2_context_reinit(TfwHttp2Ctx *ctx, bool postponed)
{
	if (!APP_FRAME(ctx) || (!postponed && !ctx->padlen)) {
		bzero_fast(ctx->__off,
			   sizeof(*ctx) - offsetof(TfwHttp2Ctx, __off));
		return;
	}
	if (!postponed && ctx->padlen) {
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		ctx->to_read = ctx->padlen;
		ctx->padlen = 0;
	}
}

int
tfw_http2_frame_process(void *c, TfwFsmData *data)
{
	int r;
	unsigned int unused, curr_tail;
	TfwFsmData data_up = {};
	TfwHttp2Ctx *h2 = tfw_http2_context(c);
	struct sk_buff *nskb = NULL, *skb = data->skb;
	unsigned int parsed = 0, off = data->off, tail = data->trail;

	BUG_ON(off >= skb->len);
	BUG_ON(tail >= skb->len);

next_msg:
	ss_skb_queue_tail(&h2->skb_head, skb);
	r = ss_skb_process(skb, off, tail, tfw_http2_frame_recv, h2, &unused,
			   &parsed);

	curr_tail = off + parsed + tail < skb->len ? 0 : tail;
	if (r >= T_POSTPONE && ss_skb_chop_head_tail(NULL, skb, off, curr_tail))
	{
		r = T_DROP;
		goto out;
	}

	switch (r) {
	default:
		T_WARN("Unrecognized return code %d during HTTP/2 frame"
		       " receiving, drop frame\n", r);
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
		if (!APP_FRAME(h2))
			return T_OK;

		break;
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
		data_up.off = h2->data_off;
		data_up.skb = h2->skb_head;
		h2->data_off = 0;
		h2->skb_head = NULL;
		r = tfw_http_msg_process_generic(c, &data_up);
		if (r == T_DROP) {
			kfree_skb(nskb);
			goto out;
		}
	} else {
		ss_skb_queue_purge(&h2->skb_head);
	}

	tfw_http2_context_reinit(h2, r == T_POSTPONE);

	if (nskb) {
		skb = nskb;
		nskb = NULL;
		off = 0;
		parsed = 0;
		goto next_msg;
	}

out:
	ss_skb_queue_purge(&h2->skb_head);
	return r;
}

void
tfw_http2_settings_init(TfwHttp2Ctx *ctx)
{
	TfwSettings *lset = &ctx->lsettings;
	TfwSettings *rset = &ctx->rsettings;

	lset->hdr_tbl_sz = rset->hdr_tbl_sz = 1 << 12;
	lset->push = rset->push = 1;
	lset->max_streams = rset->max_streams = 0xffffffff;
	lset->wnd_sz = rset->wnd_sz = (1 << 16) - 1;
	lset->max_frame_sz = rset->max_frame_sz = 1 << 14;
	lset->max_lhdr_sz = rset->max_lhdr_sz = UINT_MAX;
}
