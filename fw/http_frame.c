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
#undef DEBUG
#if DBG_HTTP_FRAME > 0
#define DEBUG DBG_HTTP_FRAME
#endif

#include "lib/fsm.h"
#include "lib/str.h"
#include "procfs.h"
#include "http.h"
#include "http2.h"
#include "http_frame.h"
#include "http_msg.h"
#include "tcp.h"

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

#define PING_FRAME_RATE_LIMIT		100
#define SETTINGS_FRAME_RATE_LIMIT	5
#define RST_FRAME_RATE_LIMIT		5
#define PRIORITY_FRAME_RATE_LIMIT	30

#define TFW_H2_CTRL_FRAME_RATE_LIMIT(name, limit)			\
static inline bool							\
tfw_h2_##name##_frame_rate_limit(TfwH2Ctx *ctx)				\
{									\
	unsigned long ts = jiffies * FRANG_FREQ / HZ;			\
	int i = ts % FRANG_FREQ;					\
	unsigned int sum = 0;						\
									\
	if (ctx->stat[i].ts != ts) {					\
		ctx->stat[i].ts = ts;					\
		ctx->stat[i].name##_cnt = 0;				\
	}								\
	ctx->stat[i].name##_cnt++;					\
									\
	for (i = 0; i < FRANG_FREQ; i++)				\
		if (frang_time_in_frame(ts, ctx->stat[i].ts))		\
			sum += ctx->stat[i].name##_cnt;			\
	if (unlikely(sum > limit * ctrl_frame_rate_mul)) {		\
		TFW_INC_STAT_BH(clnt.name##_frame_exceeded);		\
		return false;						\
	}								\
									\
	return true;							\
}

TFW_H2_CTRL_FRAME_RATE_LIMIT(ping, PING_FRAME_RATE_LIMIT);
TFW_H2_CTRL_FRAME_RATE_LIMIT(settings, SETTINGS_FRAME_RATE_LIMIT);
TFW_H2_CTRL_FRAME_RATE_LIMIT(rst, RST_FRAME_RATE_LIMIT);
TFW_H2_CTRL_FRAME_RATE_LIMIT(priority, PRIORITY_FRAME_RATE_LIMIT);

typedef enum {
	TFW_FRAME_DEFAULT,
	TFW_FRAME_SHUTDOWN,
	TFW_FRAME_CLOSE
} TfwCloseType;

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

/*
 * This macro is used to account the amount
 * of payload still needed to be processed for a particular
 * http/2 frame when frame header has been fully read.
 * @to_read is initially set equal to the length of
 * the frame payload and decreases as we process
 * more sk_buff's and/or fragments.
 */
#define FRAME_FSM_READ_PYLD()						\
do {									\
	WARN_ON_ONCE(ctx->rlen > ctx->to_read);				\
	n = min_t(int, ctx->to_read - ctx->rlen, buf + len - p);	\
	p += n;								\
	ctx->rlen += n;							\
	ctx->to_read -= ctx->rlen;					\
} while (0)

#define SET_TO_READ(ctx)						\
do {									\
	(ctx)->to_read = (ctx)->hdr.length;				\
	(ctx)->hdr.length = 0;						\
} while (0)

#define SET_TO_READ_VERIFY(ctx, next_state)				\
do {									\
	if ((ctx)->hdr.length) {					\
		SET_TO_READ(ctx);                                       \
		(ctx)->state = next_state;				\
	} else {							\
		(ctx)->state = HTTP2_IGNORE_FRAME_DATA;			\
	}								\
} while (0)

#define APP_FRAME(ctx)							\
	((ctx)->state >= __HTTP2_RECV_FRAME_APP)

#define STREAM_RECV_PROCESS(ctx, hdr)					\
({									\
	TfwStreamFsmRes res;						\
	TfwStreamState s;						\
	TfwH2Err err = HTTP2_ECODE_NO_ERROR;				\
	BUG_ON(!(ctx)->cur_stream);					\
	if ((res = tfw_h2_stream_fsm((ctx), (ctx)->cur_stream, (hdr)->type, \
				     (hdr)->flags, false, &err)))	\
	{								\
		s = tfw_h2_get_stream_state((ctx)->cur_stream);		\
		T_DBG3("stream recv processed: result=%d, state=%d, id=%u," \
		       " err=%d\n", res, s, (ctx)->cur_stream->id, err); \
		SET_TO_READ_VERIFY((ctx), HTTP2_IGNORE_FRAME_DATA);	\
		if (res == STREAM_FSM_RES_TERM_CONN) {			\
			tfw_h2_conn_terminate((ctx), err);		\
			return T_BAD;					\
		} else if (res == STREAM_FSM_RES_TERM_STREAM) {		\
			WARN_ON_ONCE(hdr->stream_id != ctx->cur_stream->id); \
			return tfw_h2_current_stream_send_rst((ctx), err); \
		}							\
		return T_OK;						\
	}								\
})

static inline void
tfw_h2_unpack_priority(TfwFramePri *pri, const unsigned char *buf)
{
	pri->stream_id = ntohl(*(unsigned int *)buf) & FRAME_STREAM_ID_MASK;
	pri->exclusive = (buf[0] & 0x80) > 0;
	pri->weight = buf[4] + 1;
}

/**
 * The flags indicate that an appropriate SETTINGS parameter is waited for an
 * update.
 */
static const unsigned char
ctx_new_settings_flags[] = {
	[HTTP2_SETTINGS_TABLE_SIZE]		= 0x01,
	[HTTP2_SETTINGS_ENABLE_PUSH]		= 0x02,
	[HTTP2_SETTINGS_MAX_STREAMS]		= 0x04,
	[HTTP2_SETTINGS_INIT_WND_SIZE]		= 0x08,
	[HTTP2_SETTINGS_MAX_FRAME_SIZE] 	= 0x10,
	[HTTP2_SETTINGS_MAX_HDR_LIST_SIZE]	= 0x20
};

static void
tfw_h2_on_tcp_entail_ack(void *conn, struct sk_buff *skb_head)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);

	if (test_bit(HTTP2_SETTINGS_NEED_TO_APPLY, ctx->settings_to_apply))
		tfw_h2_apply_new_settings(ctx);
}

static int
tfw_h2_on_send_goaway(void *conn, struct sk_buff **skb_head)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);

	if (ctx->error && ctx->error->xmit.skb_head) {
		ss_skb_queue_splice(&ctx->error->xmit.skb_head, skb_head);
	} else if (ctx->cur_send_headers) {
		/*
		 * Other frames (from any stream) MUST NOT occur between
		 * the HEADERS frame and any CONTINUATION frames that might
		 * follow. Send goaway later.
		 */
		ctx->error = ctx->cur_send_headers;
		ss_skb_queue_splice(&ctx->error->xmit.skb_head, skb_head);
	}

	return 0;
}

static int
tfw_h2_on_send_rst_stream(void *conn, struct sk_buff **skb_head)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);
	unsigned int stream_id = TFW_SKB_CB(*skb_head)->stream_id;
	TfwStream *stream;

	stream = tfw_h2_find_not_closed_stream(ctx, stream_id, false);

	/*
	 * Send RST STREAM after all pending data otherwise directly push it
	 * to socket write queue.
	 * Stream can not exist in case when we send RST stream because a
	 * remote peer exceeded max_concurrent_streams limit.
	 */
	if (stream && stream->xmit.skb_head) {
		ss_skb_queue_splice(&stream->xmit.skb_head, skb_head);
	} else if (ctx->cur_send_headers) {
		ss_skb_queue_splice(&ctx->cur_send_headers->xmit.postponed,
				    skb_head);
	}

	return 0;
}

static int
tfw_h2_on_send_dflt(void *conn, struct sk_buff **skb_head)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);

	if (ctx->cur_send_headers) {
		ss_skb_queue_splice(&ctx->cur_send_headers->xmit.postponed,
				    skb_head);
	}

	return 0;
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
__tfw_h2_send_frame(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data,
		    TfwCloseType type)
{
	int r;
	TfwMsgIter it;
	TfwMsg msg = {};
	unsigned char buf[FRAME_HEADER_SIZE];
	TfwStr *hdr_str = TFW_STR_CHUNK(data, 0);
	TfwConn *conn = (TfwConn *)ctx->conn;

	BUG_ON(hdr_str->data);
	hdr_str->data = buf;
	hdr_str->len = FRAME_HEADER_SIZE;

	if (data != hdr_str)
		data->len += FRAME_HEADER_SIZE;

	tfw_h2_pack_frame_header(buf, hdr);

	T_DBG2("Preparing HTTP/2 message with %lu bytes data\n", data->len);

	msg.len = data->len;
	if ((r = tfw_msg_iter_setup(&it, conn->sk, &msg.skb_head, msg.len)))
		goto err;

	if ((r = tfw_msg_iter_write(&it, data)))
		goto err;

	switch (type) {
	case TFW_FRAME_CLOSE:
		msg.ss_flags |= __SS_F_FORCE;
		fallthrough;
	case TFW_FRAME_SHUTDOWN:
		msg.ss_flags |= SS_F_CONN_CLOSE;
		break;
	default:
		break;
	}

	if (hdr->type == HTTP2_GOAWAY) {
		TFW_SKB_CB(msg.skb_head)->on_send = tfw_h2_on_send_goaway;
	} else if (hdr->type == HTTP2_RST_STREAM) {
		TFW_SKB_CB(msg.skb_head)->on_send = tfw_h2_on_send_rst_stream;
		TFW_SKB_CB(msg.skb_head)->stream_id = hdr->stream_id;
	} else {
		TFW_SKB_CB(msg.skb_head)->on_send = tfw_h2_on_send_dflt;
	}

	if (hdr->type == HTTP2_SETTINGS && hdr->flags == HTTP2_F_ACK) {
		TFW_SKB_CB(msg.skb_head)->on_tcp_entail =
			tfw_h2_on_tcp_entail_ack;
	}

	if ((r = tfw_connection_send(conn, &msg)))
		goto err;
	/*
	 * We do not close client connection automatically here in case
	 * of failed sending, the caller must make such decision instead;
	 * thus, we should set Conn_Stop flag only if sending procedure
	 * was successful - to avoid hanged unclosed client connection.
	 */
	if (type == TFW_FRAME_CLOSE || type == TFW_FRAME_SHUTDOWN)
		TFW_CONN_TYPE(conn) |= Conn_Stop;

	return 0;

err:
	ss_skb_queue_purge(&msg.skb_head);
	return r;
}

static inline int
tfw_h2_send_frame(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data)
{
	return __tfw_h2_send_frame(ctx, hdr, data, 0);
}

static inline int
tfw_h2_send_frame_shutdown(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data)
{
	return __tfw_h2_send_frame(ctx, hdr, data, TFW_FRAME_SHUTDOWN);
}

static inline int
tfw_h2_send_frame_close(TfwH2Ctx *ctx, TfwFrameHdr *hdr, TfwStr *data)
{
	return __tfw_h2_send_frame(ctx, hdr, data, TFW_FRAME_CLOSE);
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
	struct {
		unsigned short key;
		unsigned int value;
	} __attribute__((packed)) field[4];

	const unsigned int required_fields = 3;

	TfwStr data = {
		.chunks = (TfwStr []){
			{},
			{
				.data = (unsigned char *)field,
				.len = required_fields * sizeof(field[0])
			},
			{},
		},
		.len = required_fields * sizeof(field[0]),
		.nchunks = 2
	};
	TfwFrameHdr hdr = {
		.length = data.len,
		.stream_id = 0,
		.type = HTTP2_SETTINGS,
		.flags = 0
	};

	BUILD_BUG_ON(SETTINGS_KEY_SIZE != sizeof(unsigned short)
		     || SETTINGS_VAL_SIZE != sizeof(unsigned int));

	field[0].key   = htons(HTTP2_SETTINGS_TABLE_SIZE);
	field[0].value = htonl(HPACK_ENC_TABLE_MAX_SIZE);
	__set_bit(_HTTP2_SETTINGS_MAX - 1 + HTTP2_SETTINGS_TABLE_SIZE,
		  ctx->settings_to_apply);

	BUILD_BUG_ON(SETTINGS_VAL_SIZE != sizeof(ctx->lsettings.wnd_sz));
	field[1].key   = htons(HTTP2_SETTINGS_INIT_WND_SIZE);
	field[1].value = htonl(ctx->lsettings.wnd_sz);
	__set_bit(_HTTP2_SETTINGS_MAX -1 + HTTP2_SETTINGS_INIT_WND_SIZE,
		  ctx->settings_to_apply);

	field[2].key   = htons(HTTP2_SETTINGS_MAX_STREAMS);
	field[2].value = htonl(ctx->lsettings.max_streams);

	if (ctx->lsettings.max_lhdr_sz != UINT_MAX) {
		field[required_fields].key =
			htons(HTTP2_SETTINGS_MAX_HDR_LIST_SIZE);
		field[required_fields].value =
			htonl(ctx->lsettings.max_lhdr_sz);
		__set_bit(_HTTP2_SETTINGS_MAX - 1 +
			  HTTP2_SETTINGS_MAX_HDR_LIST_SIZE,
			  ctx->settings_to_apply);
		data.chunks[1].len += sizeof(field[0]);
		hdr.length += sizeof(field[0]);
	}

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

int
tfw_h2_send_goaway(TfwH2Ctx *ctx, TfwH2Err err_code, bool attack)
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

	return attack ? tfw_h2_send_frame_close(ctx, &hdr, &data) :
		tfw_h2_send_frame_shutdown(ctx, &hdr, &data);
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

	if (unlikely(!tfw_h2_rst_frame_rate_limit(ctx)))
		return T_BLOCK_WITH_RST;

	if (tfw_h2_send_frame(ctx, &hdr, &data))
		return T_BAD;

	return T_OK;
}

static inline void
tfw_h2_conn_terminate(TfwH2Ctx *ctx, TfwH2Err err_code)
{
	tfw_h2_conn_terminate_close(ctx, err_code, false, false);
}

#define VERIFY_FRAME_SIZE(ctx)						\
do {									\
	if ((ctx)->hdr.length < 0) {					\
		tfw_h2_conn_terminate(ctx, HTTP2_ECODE_SIZE);		\
		return -EINVAL;						\
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

static inline int
tfw_h2_current_stream_state_process(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	STREAM_RECV_PROCESS(ctx, hdr);

	tfw_h2_check_current_stream_is_closed(ctx);

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
	ctx->lstream_id = hdr->stream_id;
	if (ctx->priority.stream_id == hdr->stream_id) {
		T_DBG("Invalid dependency: new stream with %u depends on"
		      " itself\n", hdr->stream_id);

		ctx->state = HTTP2_IGNORE_FRAME_DATA;

		if (likely(!ctx->cur_stream)) {
			return tfw_h2_send_rst_stream(ctx, hdr->stream_id,
						      HTTP2_ECODE_PROTO);
		}

		WARN_ON_ONCE(hdr->stream_id != ctx->cur_stream->id);
		return tfw_h2_current_stream_send_rst(ctx, HTTP2_ECODE_PROTO);
	}

	if (likely(!ctx->cur_stream)) {
		ctx->cur_stream = tfw_h2_stream_create(ctx, hdr->stream_id);
		if (!ctx->cur_stream)
			return -ENOMEM;
	} else if (ctx->cur_stream->state == HTTP2_STREAM_IDLE) {
		tfw_h2_stream_remove_idle(ctx, ctx->cur_stream);
	}
	/*
	 * Since the same received HEADERS frame can cause the stream to become
	 * 'open' (i.e. created) and right away become 'half-closed (remote)'
	 * (in case of both END_STREAM and END_HEADERS flags set in initial
	 * HEADERS frame), we should process its state here - when frame is
	 * fully received and new stream is created.
	 */
	return tfw_h2_current_stream_state_process(ctx);
}

static int
tfw_h2_increment_wnd_sz(long int *window, unsigned int wnd_incr)
{
	long int new_window = *window + wnd_incr;
	/*
	 * According to RFC 9113 6.9.1
	 * A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets.
	 * If a sender receives a WINDOW_UPDATE that causes a flow-control
	 * window to exceed this maximum, it MUST terminate either the stream
	 * or the connection, as appropriate. For streams, the sender sends a
	 * RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the
	 * connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR
	 * is sent.
	 */
	if (new_window > MAX_WND_SIZE)
		return -EINVAL;
	*window = new_window;
	return 0;
}

static int
tfw_h2_wnd_update_process(TfwH2Ctx *ctx)
{
	unsigned int wnd_incr;
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwH2Err err_code = HTTP2_ECODE_PROTO;

	wnd_incr = ntohl(*(unsigned int *)ctx->rbuf) & ((1U << 31) - 1);
	if (wnd_incr) {
		TfwH2Conn *conn = ctx->conn;
		struct sock *sk = ((TfwConn *)conn)->sk;
		long int *window = ctx->cur_stream ?
			&ctx->cur_stream->rem_wnd : &ctx->rem_wnd;
		bool was_blocked = !tfw_h2_is_ready_to_send(ctx);

		if (tfw_h2_increment_wnd_sz(window, wnd_incr)) {
			err_code = HTTP2_ECODE_FLOW;
			goto fail;
		}

		if (ctx->cur_stream)
			tfw_h2_stream_try_unblock(&ctx->sched, ctx->cur_stream);

		if (was_blocked && tfw_h2_is_ready_to_send(ctx))
			sock_set_flag(sk, SOCK_TEMPESTA_HAS_DATA);

		return T_OK;
	}

fail:
	if (!ctx->cur_stream) {
		tfw_h2_conn_terminate(ctx, err_code);
		return -EPIPE;
	}

	if (tfw_h2_stream_fsm_ignore_err(ctx, ctx->cur_stream,
					 HTTP2_RST_STREAM, 0))
		return -EPERM;

	WARN_ON_ONCE(hdr->stream_id != ctx->cur_stream->id);
	return tfw_h2_current_stream_send_rst(ctx, err_code);
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

	if (ctx->cur_stream->state == HTTP2_STREAM_IDLE) {
		/*
		 * According to RFC 9113 we should response with stream
		 * error of type PROTOCOL ERROR here, but we can't send
		 * RST_STREAM for idle stream.
		 * RFC 9113 doesn't describe this case, so terminate
		 * connection.
		 */
		tfw_h2_conn_terminate(ctx, HTTP2_ECODE_PROTO);
		return T_BAD;
	}

	/*
	 * Stream cannot depend on itself (see RFC 7540 section 5.1.2 for
	 * details).
	 */
	T_DBG("Invalid dependency: new stream with %u depends on itself\n",
	      hdr->stream_id);

	if (tfw_h2_stream_fsm_ignore_err(ctx, ctx->cur_stream,
					 HTTP2_RST_STREAM, 0))
		return -EPERM;

	WARN_ON_ONCE(hdr->stream_id != ctx->cur_stream->id);
	return tfw_h2_current_stream_send_rst(ctx, HTTP2_ECODE_PROTO);
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

static void
tfw_h2_settings_ack_process(TfwH2Ctx *ctx)
{
	T_DBG3("%s: parsed, stream_id=%u, flags=%hhu\n", __func__,
	       ctx->hdr.stream_id, ctx->hdr.flags);

	if (test_bit(_HTTP2_SETTINGS_MAX - 1 + HTTP2_SETTINGS_TABLE_SIZE,
		     ctx->settings_to_apply))
	{
		ctx->hpack.max_window = ctx->lsettings.hdr_tbl_sz;
		ctx->hpack.dec_tbl.wnd_update = true;
		clear_bit(_HTTP2_SETTINGS_MAX -1 + HTTP2_SETTINGS_TABLE_SIZE,
			  ctx->settings_to_apply);
	}
}

static int
tfw_h2_settings_process(TfwH2Ctx *ctx)
{
	int r;
	TfwFrameHdr *hdr = &ctx->hdr;
	unsigned short id  = ntohs(*(unsigned short *)&ctx->rbuf[0]);
	unsigned int val = ntohl(*(unsigned int *)&ctx->rbuf[2]);

	T_DBG3("%s: entry parsed, id=%hu, val=%u\n", __func__, id, val);

	if ((r = tfw_h2_check_settings_entry(ctx, id, val)))
		return r;

	tfw_h2_save_settings_entry(ctx, id, val);

	ctx->to_read = hdr->length ? FRAME_SETTINGS_ENTRY_SIZE : 0;
	hdr->length -= ctx->to_read;

	return 0;
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
		T_DBG("HTTP/2 connection is closed by client with error code:"
		      " %u, ID of last processed stream: %u\n", err_code,
		      last_id);
	SET_TO_READ(ctx);
	return 0;
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
		return -EINVAL;
	}

	ctx->to_read = hdr->length ? FRAME_SETTINGS_ENTRY_SIZE : 0;
	hdr->length -= ctx->to_read;

	return 0;
}

static inline int
tfw_h2_current_stream_id_verify(TfwH2Ctx *ctx)
{
	TfwFrameHdr *hdr = &ctx->hdr;

	if (ctx->cur_stream)
		return 0;
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
	 * queue @TfwStreamQueue.
	 */
	if (ctx->lstream_id >= hdr->stream_id) {
		T_DBG("Invalid ID of new stream: %u stream is"
		      " closed and removed, %u last initiated\n",
		      hdr->stream_id, ctx->lstream_id);
		return -EINVAL;
	}
	/*
	 * Streams initiated by client must use odd-numbered
	 * identifiers (see RFC 7540 section 5.1.1 for details).
	 */
	if (!(hdr->stream_id & 0x1)) {
		T_DBG("Invalid ID of new stream: initiated by"
		      " server\n");
		return -EINVAL;
	}

	return 0;
}

static inline int
tfw_h2_flow_control(TfwH2Ctx *ctx)
{
	int r;
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwStream *stream = ctx->cur_stream;
	TfwSettings *lset = &ctx->lsettings;

	BUG_ON(!stream);
	if (hdr->length > stream->loc_wnd)
		T_WARN("Stream flow control window exceeded: frame payload %d,"
		       " current window %ld\n", hdr->length, stream->loc_wnd);

	if(hdr->length > ctx->loc_wnd)
		T_WARN("Connection flow control window exceeded: frame payload"
		       " %d, current window %ld\n", hdr->length, ctx->loc_wnd);

	stream->loc_wnd -= hdr->length;
	ctx->loc_wnd -= hdr->length;

	if (stream->loc_wnd <= lset->wnd_sz / 2) {
		if((r = tfw_h2_send_wnd_update(ctx, stream->id,
					       lset->wnd_sz - stream->loc_wnd)))
		{
			return r;
		}
		stream->loc_wnd = lset->wnd_sz;
	}


	if (ctx->loc_wnd <= DEF_WND_SIZE / 2) {
		if ((r = tfw_h2_send_wnd_update(ctx, 0,
						DEF_WND_SIZE - ctx->loc_wnd)))
		{
			return r;
		}
		ctx->loc_wnd = DEF_WND_SIZE;
	}

	return 0;
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
		return 0;
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

	return 0;
}

static inline unsigned int
tfw_h2_calc_min_to_send(struct sock *sk, TfwH2Ctx *ctx, unsigned int mss_now)
{
	/* Empirically chosen value. */
	const unsigned int min_to_send_dflt = 512;
	unsigned int min_to_send;

	/*
	 * Tempesta FW avoid to send frame if the size of frame
	 * is less than 512 bytes, except when mtu is small or http2
	 * initial window is less than 1024 bytes (client usually sends
	 * window update frame with a size equal to a half of initial
	 * window).
	 */
	min_to_send = min3(min_to_send_dflt, mss_now - TLS_MAX_OVERHEAD,
			   ctx->rsettings.wnd_sz >> 1);

	return min_to_send;
}

static inline bool
tfw_h2_wnd_update_rate_limit(TfwH2Ctx *ctx)
{
	struct sock *sk = ((TfwConn *)ctx->conn)->sk;
	int size, mss_now;
	unsigned int min_to_send;

	/*
	 * We allow to send not more than six WINDOW_UPDATE
	 * frames for one DATA frame by default. We also allow
	 * to send not more than one WINDOW_UPDATE frame for each
	 * minimum count of bytes allowed to send for Tempesta FW
	 * (We do it to prevent data dribble attack). We also allow
	 * to send at least `max_streams` WINDOW_UPDATE frames to
	 * cover the case when client initiate connection with zero
	 * window.
	 */
	if (++ctx->wnd_update_cnt < ctx->lsettings.max_streams)
		return true;

	if (unlikely(ctx->wnd_update_cnt >
		     ctx->data_frames_sent * 6 * wnd_update_frame_rate_mul)) {
		TFW_INC_STAT_BH(clnt.wnd_update_frame_exceeded);
		return false;
	}

	mss_now = tcp_send_mss(sk, &size, MSG_DONTWAIT);
	min_to_send = tfw_h2_calc_min_to_send(sk, ctx, mss_now);

	if (unlikely(ctx->wnd_update_cnt >
		     (ctx->data_bytes_sent / min_to_send) *
		     wnd_update_frame_rate_mul))
	{
		TFW_INC_STAT_BH(clnt.wnd_update_frame_exceeded);
		return false;
	}

	return true;
}

static inline bool
tfw_h2_ctrl_frame_limit(TfwH2Ctx *ctx, TfwFrameType hdr_type)
{
	switch (hdr_type) {
	case HTTP2_PRIORITY:
		if (unlikely(!tfw_h2_priority_frame_rate_limit(ctx)))
			return false;

		break;
	case HTTP2_RST_STREAM:
		if (unlikely(!tfw_h2_rst_frame_rate_limit(ctx)))
			return false;

		break;

		break;
	case HTTP2_SETTINGS:
		if (unlikely(!tfw_h2_settings_frame_rate_limit(ctx)))
			return false;

		break;
	case HTTP2_PING:
		if (unlikely(!tfw_h2_ping_frame_rate_limit(ctx)))
			return false;

		break;
	case HTTP2_WINDOW_UPDATE:
		if (unlikely(!tfw_h2_wnd_update_rate_limit(ctx)))
			return false;

		break;
	default:
		break;
	}

	return true;		
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
	int r;
	TfwH2Err err_code = HTTP2_ECODE_SIZE;
	TfwFrameHdr *hdr = &ctx->hdr;
	TfwFrameType hdr_type =
		(hdr->type <= _HTTP2_UNDEFINED ? hdr->type : _HTTP2_UNDEFINED);

#define VERIFY_MAX_CONCURRENT_STREAMS(ctx, ACTION)			\
do {									\
	unsigned int max_streams = ctx->lsettings.max_streams;		\
									\
	tfw_h2_closed_streams_shrink(ctx);				\
									\
	if (max_streams == ctx->streams_num) {				\
		T_DBG("Max streams number exceeded: %lu\n",		\
		      ctx->streams_num);				\
		TFW_INC_STAT_BH(clnt.streams_num_exceeded);		\
		SET_TO_READ_VERIFY(ctx, HTTP2_IGNORE_FRAME_DATA);	\
		ACTION;							\
	}								\
} while(0)

	T_DBG3("%s: hdr->type %u(%s), ctx->state %u\n", __func__, hdr_type,
	       __h2_frm_type_n(hdr_type), ctx->state);

	if (unlikely(ctx->hdr.length > ctx->lsettings.max_frame_sz))
		goto conn_term;

	if (unlikely(!tfw_h2_ctrl_frame_limit(ctx, hdr_type)))
		return T_BLOCK_WITH_RST; 

	/*
	 * TODO: RFC 7540 Section 6.2:
	 * A HEADERS frame without the END_HEADERS flag set MUST be followed
	 * by a CONTINUATION frame for the same stream. A receiver MUST treat
	 * the receipt of any other type of frame or a frame on a different
	 * stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
	 */

	switch (hdr_type) {
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

		ctx->cur_stream =
			tfw_h2_find_not_closed_stream(ctx, hdr->stream_id,
						      true);
		/*
		 * If stream is removed, it had been closed before, so this is
		 * connection error (see RFC 7540 section 5.1).
		 */
		if (!ctx->cur_stream) {
			err_code = HTTP2_ECODE_CLOSED;
			goto conn_term;
		}

		if ((r = tfw_h2_flow_control(ctx)))
			return r;

		ctx->data_off = FRAME_HEADER_SIZE;
		ctx->plen = ctx->hdr.length;

		if (hdr->flags & HTTP2_F_PADDED)
			return tfw_h2_recv_padded(ctx);

		ctx->state = HTTP2_RECV_DATA;
		SET_TO_READ(ctx);

		return 0;

	case HTTP2_HEADERS:
		if (!hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream =
			tfw_h2_find_not_closed_stream(ctx, hdr->stream_id,
						      true);
		if (tfw_h2_current_stream_id_verify(ctx)) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		tfw_h2_remove_idle_streams(ctx, hdr->stream_id);

		/*
		 * Endpoints must not exceed the limit set by their peer for
		 * maximum number of concurrent streams (see RFC 7540 section
		 * 5.1.2 for details).
		 */
		if (!ctx->cur_stream)
			VERIFY_MAX_CONCURRENT_STREAMS(ctx, {
				return tfw_h2_send_rst_stream(ctx, hdr->stream_id,
							      HTTP2_ECODE_REFUSED);
			});

		ctx->data_off = FRAME_HEADER_SIZE;
		ctx->plen = ctx->hdr.length;

		if (hdr->flags & HTTP2_F_PADDED)
			return tfw_h2_recv_padded(ctx);

		if (hdr->flags & HTTP2_F_PRIORITY)
			return tfw_h2_recv_priority(ctx);

		ctx->state = HTTP2_RECV_HEADER;
		SET_TO_READ(ctx);

		return 0;

	case HTTP2_PRIORITY:
		if (!hdr->stream_id) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}

		ctx->cur_stream =
			tfw_h2_find_stream(&ctx->sched, hdr->stream_id);
		if (hdr->length != FRAME_PRIORITY_SIZE)
			goto conn_term;

		if (ctx->cur_stream) {
			STREAM_RECV_PROCESS(ctx, hdr);
			ctx->state = HTTP2_RECV_FRAME_PRIORITY;
		} else if (hdr->stream_id > ctx->lstream_id) {
			VERIFY_MAX_CONCURRENT_STREAMS(ctx, {
				err_code = HTTP2_ECODE_PROTO;
				goto conn_term;
			});
			/*
			 * According to RFC 9113 section 6.3:
			 * Priority frame can be sent in any stream state,
			 * including idle or closed streams.
			 */
			ctx->cur_stream =
				tfw_h2_stream_create(ctx, hdr->stream_id);
			if (!ctx->cur_stream)
				return -ENOMEM;

			tfw_h2_stream_add_idle(ctx, ctx->cur_stream);
			STREAM_RECV_PROCESS(ctx, hdr);
			ctx->state = HTTP2_RECV_FRAME_PRIORITY;
		} else {
			/*
			 * According to RFC 9113 section 5.1:
			 * PRIORITY frames are allowed in the `closed` state,
			 * but if the stream was already removed from memory,
			 * just ignore this frame.
			 */
			ctx->state = HTTP2_IGNORE_FRAME_DATA;
		}

		SET_TO_READ(ctx);
		return 0;

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
			ctx->cur_stream =
				tfw_h2_find_not_closed_stream(ctx,
							      hdr->stream_id,
							      true);
			if (ctx->cur_stream) {
				STREAM_RECV_PROCESS(ctx, hdr);
				ctx->state = HTTP2_RECV_FRAME_WND_UPDATE;
			} else {
				/*
				 * According to RFC 9113 section 5.1:
				 * An endpoint that sends a frame with the
				 * END_STREAM flag set or a RST_STREAM frame
				 * might receive a WINDOW_UPDATE or RST_STREAM
				 * frame from its peer in the time before the
				 * peer receives and processes the frame that
				 * closes the stream.
				 * But if the stream was moved to closed queue
				 * or was already removed from memory, just
				 * ignore this frame.
				 */
				ctx->state = HTTP2_IGNORE_FRAME_DATA;
			}
		} else {
			ctx->state = HTTP2_RECV_FRAME_WND_UPDATE;
		}

		SET_TO_READ(ctx);
		return 0;

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

		return 0;

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
		return 0;

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

		ctx->cur_stream =
			tfw_h2_find_not_closed_stream(ctx, hdr->stream_id,
						      true);
		if (ctx->cur_stream) {
			STREAM_RECV_PROCESS(ctx, hdr);
			ctx->state = HTTP2_RECV_FRAME_RST_STREAM;
		} else {
			/*
			 * According to RFC 9113 section 5.1:
			 * An endpoint that sends a frame with the END_STREAM
			 * flag set or a RST_STREAM frame might receive a
			 * WINDOW_UPDATE or RST_STREAM frame from its peer in
			 * the time before the peer receives and processes the
			 * frame that closes the stream.
			 * But if the stream was moved to closed queue or was
			 * already removed from memory, just ignore this frame.
			 */
			ctx->state = HTTP2_IGNORE_FRAME_DATA;
		}

		SET_TO_READ(ctx);
		return 0;

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
		return 0;

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

		ctx->cur_stream =
			tfw_h2_find_not_closed_stream(ctx, hdr->stream_id,
						      true);
		if (!ctx->cur_stream) {
			err_code = HTTP2_ECODE_CLOSED;
			goto conn_term;
		}

		ctx->data_off = FRAME_HEADER_SIZE;
		ctx->plen = ctx->hdr.length;

		SET_TO_READ(ctx);
		ctx->state = HTTP2_RECV_CONT;
		return 0;

	default:
		/*
		 * Possible extension types of frames are not covered (yet) in
		 * this procedure. On current stage we just ignore such frames.
		 */
		T_DBG("HTTP/2: frame of unknown type '%u' received\n",
		      hdr_type);
		/*
		 * According RFC 9113 5.5.
		 * Implementations MUST ignore unknown or unsupported values
		 * in all extensible protocol elements. Implementations MUST
		 * discard frames that have unknown or unsupported types.
		 * This means that any of these extension points can be safely
		 * used by extensions without prior arrangement or negotiation.
		 * However, extension frames that appear in the middle of a
		 * field block (Section 4.3) are not permitted; these MUST be
		 * treated as a connection error (Section 5.4.1) of type
		 * PROTOCOL_ERROR.
		 */
		if (ctx->cur_recv_headers) {
			err_code = HTTP2_ECODE_PROTO;
			goto conn_term;
		}
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		SET_TO_READ(ctx);
		return 0;
	}

conn_term:
	BUG_ON(!err_code);
	tfw_h2_conn_terminate(ctx, err_code);
	return -EINVAL;

#undef VERIFY_MAX_CONCURRENT_STREAMS
}

/**
 * Main FSM for processing HTTP/2 frames.
 */
static int
tfw_h2_frame_recv(void *data, unsigned char *buf, unsigned int len,
		  unsigned int *read)
{
	int n, ret, r = T_POSTPONE;
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
				FRAME_FSM_EXIT(T_BAD);
			}
		});

		if ((ret = tfw_h2_send_settings_init(ctx)))
			FRAME_FSM_EXIT(ret);

		FRAME_FSM_MOVE(HTTP2_RECV_FIRST_SETTINGS);
	}

	T_FSM_STATE(HTTP2_RECV_FIRST_SETTINGS) {
		FRAME_FSM_READ_SRVC(FRAME_HEADER_SIZE);

		if ((ret = tfw_h2_first_settings_verify(ctx)))
			FRAME_FSM_EXIT(ret);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_RECV_FRAME_SETTINGS);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_HEADER) {
		FRAME_FSM_READ_SRVC(FRAME_HEADER_SIZE);

		tfw_h2_unpack_frame_header(&ctx->hdr, ctx->rbuf);

		if ((ret = tfw_h2_frame_type_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (ctx->to_read) {
			FRAME_FSM_NEXT();
		} else if (ctx->state != HTTP2_IGNORE_FRAME_DATA &&
			   (ctx->hdr.type == HTTP2_HEADERS ||
			    ctx->hdr.type == HTTP2_CONTINUATION ||
			    ctx->hdr.type == HTTP2_DATA))
		{
			/*
			 * HEADERS, CONTINUATION and DATA are allowed to have
			 * empty payload.
			 */
			ctx->rlen = 0;
			T_FSM_NEXT();
		}

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PADDED) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if ((ret = tfw_h2_frame_pad_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (ctx->to_read)
			FRAME_FSM_NEXT();

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PRIORITY) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if ((ret = tfw_h2_priority_process(ctx)))
			FRAME_FSM_EXIT(ret);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_WND_UPDATE) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if ((ret = tfw_h2_wnd_update_process(ctx)))
			FRAME_FSM_EXIT(ret);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_PING) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if (!(ctx->hdr.flags & HTTP2_F_ACK)
		    && (ret = tfw_h2_send_ping(ctx)))
		{
			FRAME_FSM_EXIT(ret);
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

		if ((ret = tfw_h2_settings_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_RECV_FRAME_SETTINGS);

		if ((ret = tfw_h2_send_settings_ack(ctx)))
			FRAME_FSM_EXIT(ret);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_FRAME_GOAWAY) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if ((ret = tfw_h2_goaway_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (ctx->to_read)
			FRAME_FSM_MOVE(HTTP2_IGNORE_FRAME_DATA);

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_HEADER_PRI) {
		FRAME_FSM_READ_SRVC(ctx->to_read);

		if ((ret = tfw_h2_headers_pri_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (ctx->to_read)
			FRAME_FSM_NEXT();

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_DATA) {
		FRAME_FSM_READ_PYLD();

		if ((ret = tfw_h2_current_stream_state_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (unlikely(ctx->state == HTTP2_IGNORE_FRAME_DATA))
			__fsm_const_state = ctx->state;

		if (unlikely(ctx->to_read)) {
			if (unlikely(ctx->state == HTTP2_IGNORE_FRAME_DATA))
				FRAME_FSM_MOVE(HTTP2_IGNORE_FRAME_DATA);
			else
				FRAME_FSM_MOVE(HTTP2_RECV_APP_DATA_POST);
		}

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_HEADER) {
		FRAME_FSM_READ_PYLD();

		if ((ret = tfw_h2_headers_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (unlikely(ctx->state == HTTP2_IGNORE_FRAME_DATA))
			__fsm_const_state = ctx->state;

		if (unlikely(ctx->to_read)) {
			if (unlikely(ctx->state == HTTP2_IGNORE_FRAME_DATA))
				FRAME_FSM_MOVE(HTTP2_IGNORE_FRAME_DATA);
			else
				FRAME_FSM_MOVE(HTTP2_RECV_APP_DATA_POST);
		}

		FRAME_FSM_EXIT(T_OK);
	}

	T_FSM_STATE(HTTP2_RECV_CONT) {
		FRAME_FSM_READ_PYLD();

		if ((ret = tfw_h2_current_stream_state_process(ctx)))
			FRAME_FSM_EXIT(ret);

		if (unlikely(ctx->state == HTTP2_IGNORE_FRAME_DATA))
			__fsm_const_state = ctx->state;

		if (unlikely(ctx->to_read)) {
			if (unlikely(ctx->state == HTTP2_IGNORE_FRAME_DATA))
				FRAME_FSM_MOVE(HTTP2_IGNORE_FRAME_DATA);
			else
				FRAME_FSM_MOVE(HTTP2_RECV_APP_DATA_POST);
		}

		FRAME_FSM_EXIT(T_OK);
	}

	/* This is the special state intended to handle edge cases
	 * when H2 frame crosses sk_buff boundary and/or fragment boundary
	 */
	T_FSM_STATE(HTTP2_RECV_APP_DATA_POST) {
		FRAME_FSM_READ_PYLD();

		if (ctx->to_read)
			FRAME_FSM_EXIT(T_POSTPONE);

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

static bool
tfw_h2_allowed_empty_frame(TfwH2Ctx *ctx)
{
	unsigned char flags = ctx->hdr.flags;
	TfwFrameType type = ctx->hdr.type;

	if (ctx->plen)
		return false;

	/* Allow empty DATA frame only with END_STREAM flag. */
	if (type == HTTP2_DATA && flags & HTTP2_F_END_STREAM)
		return true;

	/* Allow empty CONTINUATION frame only with END_HEADERS flag. */
	if (type == HTTP2_CONTINUATION && flags & HTTP2_F_END_HEADERS)
		return true;

	/*
	 * Allow here empty HEADERS frame, invalid frames will be dropped
	 * before parsing (case when invalid HEADERS in trailer).
	 */
	if (type == HTTP2_HEADERS)
		return true;

	return false;
}

int
tfw_h2_frame_process(TfwConn *c, struct sk_buff *skb, struct sk_buff **next)
{
	int r;
	bool postponed;
	unsigned int parsed, unused;
	TfwH2Ctx *h2 = tfw_h2_context_unsafe(c);
	struct sk_buff *nskb = NULL;

next_msg:
	postponed = false;
	ss_skb_queue_tail(&h2->skb_head, skb);
	parsed = 0;
	r = ss_skb_process(skb, tfw_h2_frame_recv, h2, &unused, &parsed);

	switch (r) {
	default:
		/*
		 * T_BLOCK is error code for high level modules (like frang),
		 * here we should deal with error code, which accurately
		 * determine further closing behavior.
		 * T_DROP is error code, which is returned when connection
		 * should be alive, but if we can't process frame, we should
		 * close the connection.
		 */
		WARN_ON_ONCE(r == T_BLOCK || r == T_DROP);
		fallthrough;
	case T_BAD:
		r = T_BAD;
		fallthrough;
	case T_BLOCK_WITH_FIN:
	case T_BLOCK_WITH_RST:
		T_DBG3("Drop invalid HTTP/2 frame and close connection\n");
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
			r = -ENOMEM;
			goto out;
		}
	}

	 if (unlikely(!h2->cur_stream))
		 goto purge;

	/*
	 * Before transferring the skb with app frame for further processing,
	 * certain service data should be separated from it (placed at the
	 * frame's beginning): frame header, optional pad length and optional
	 * priority data (the latter is for HEADERS frames only). Besides,
	 * DATA and HEADERS frames can contain some padding in the frame's
	 * tail, but we don't need to worry about that here since such padding
	 * is processed as service data, separately from app frame, and it
	 * will be just split into separate skb (above).
	 *
	 * While traversing the H2 frame FSM for 'non-service' frame types,
	 * we should always end up with the correct stream,
	 * e.g. @h2->cur_stream != NULL.
	 * If an error occurs somewhere along the way, all the actions required
	 * to handle it (e.g sending RST stream frame) should have already happened
	 * by the time we get here. We shouldn't submit the data to the
	 * upper level for the actual HTTP parsing.
	 */
	if (APP_FRAME(h2) && h2->plen) {
		struct sk_buff *pskb;

		/* This chopping algorithm could be replaced with a call
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
		pskb = h2->skb_head;
		if ((r = ss_skb_chop_head_tail(NULL, pskb,
					       h2->data_off, 0))) {
			kfree_skb(nskb);
			goto out;
		}
		h2->data_off = 0;
		h2->skb_head = pskb->next = pskb->prev = NULL;
		r = tfw_http_msg_process_generic(c, h2->cur_stream, pskb, next);
		/* TODO #1490: Check this place, when working on the task. */
		if (r && r != T_DROP) {
			WARN_ON_ONCE(r == T_POSTPONE);
			kfree_skb(nskb);
			goto out;
		}
	}
	else if (unlikely(tfw_h2_allowed_empty_frame(h2))) {
		/*
		 * Process empty frames.
		 */
		struct sk_buff *pskb, *end = h2->skb_head->prev;

		/*
		 * Free all SKBs in queue except the last. The last one
		 * will be passed to message processing function.
		 */
		while (unlikely(h2->skb_head != end)) {
			pskb = ss_skb_dequeue(&h2->skb_head);
			h2->data_off -= pskb->len;
			kfree_skb(pskb);
		}

		pskb = h2->skb_head;
		h2->skb_head = pskb->next = pskb->prev = NULL;
		h2->data_off = 0;
		/* The skb will not be parsed, just flags will be checked. */
		r = tfw_http_msg_process_generic(c, h2->cur_stream, pskb, next);
		/* TODO #1490: Check this place, when working on the task. */
		if (r && r != T_DROP) {
			WARN_ON_ONCE(r == T_POSTPONE);
			kfree_skb(nskb);
			goto out;
		}
	}
	else {
purge:
		h2->data_off = 0;
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
	if (r && r != T_POSTPONE && r != T_DROP)
		tfw_h2_context_reinit(h2, false);
	return r;

#undef TFW_H2_CONN_PROCESS_RESULT
}

static inline unsigned int
tfw_h2_calc_frame_length(TfwH2Ctx *ctx, TfwStream *stream, TfwFrameType type,
			 unsigned int len, unsigned int max_len)
{
	unsigned int length;

	length = min3(ctx->rsettings.max_frame_sz, len, max_len);
	if (type == HTTP2_DATA) {
		length = min3(length, (unsigned int)ctx->rem_wnd,
			      (unsigned int)stream->rem_wnd);
	}

	return length;
}

static inline char
tfw_h2_calc_frame_flags(TfwStream *stream, TfwFrameType type,
			bool trailers)
{
	unsigned char flags = 0;

	if (!stream->xmit.b_len && !stream->xmit.t_len
	    && (type == HTTP2_HEADERS || type == HTTP2_DATA)
	    && !tfw_h2_stream_is_eos_sent(stream))
		flags |= HTTP2_F_END_STREAM;

	if (!stream->xmit.b_len && stream->xmit.t_len
	    && type == HTTP2_HEADERS && trailers)
		flags |= HTTP2_F_END_STREAM;

	if (!stream->xmit.h_len && type != HTTP2_DATA && !trailers)
		flags |= HTTP2_F_END_HEADERS;

	if (!stream->xmit.t_len && type != HTTP2_DATA && trailers)
		flags |= HTTP2_F_END_HEADERS;

	return flags;
}

static inline int
tfw_h2_insert_frame_header(struct sock *sk, TfwH2Ctx *ctx, TfwStream *stream,
			   TfwFrameType type, unsigned int frame_length)
{
	TfwFrameHdr frame_hdr = {};
	bool trailers = false;
	char *data;
	int r = 0;

	/*
	 * Very unlikely case, when skb_head and one or more next skbs
	 * are empty because of transformation during making HEADERS.
	 */
	if (type == HTTP2_CONTINUATION || type == HTTP2_DATA
	    || !stream->xmit.h_len) {
		struct sk_buff *skb = stream->xmit.skb_head;

		while (skb && unlikely(!skb->len)) {
			ss_skb_unlink(&stream->xmit.skb_head, skb);
			kfree_skb(skb);
			skb = stream->xmit.skb_head;
		}
	}

	data = ss_skb_data_ptr_by_offset(stream->xmit.skb_head,
					 stream->xmit.frame_length);
	BUG_ON(!data);

	if (type == HTTP2_CONTINUATION || type == HTTP2_DATA) {
		TfwStr dst = {};
		unsigned int _;

		r = ss_skb_get_room_w_frag(stream->xmit.skb_head,
					   stream->xmit.skb_head,
					   data, FRAME_HEADER_SIZE,
					   &dst, &_);
		if (unlikely(r))
			return r;

		data = dst.data;
	}

	if (type == HTTP2_DATA) {
		ctx->rem_wnd -= frame_length;
		ctx->data_bytes_sent += frame_length;
		stream->rem_wnd -= frame_length;
		stream->xmit.b_len -= frame_length;
	} else if (stream->xmit.h_len) {
		stream->xmit.h_len -= frame_length;
	} else if (stream->xmit.t_len) {
		stream->xmit.t_len -= frame_length;
		trailers = true;
	}

	frame_hdr.length = frame_length;
	frame_hdr.stream_id = stream->id;
	frame_hdr.type = type;
	frame_hdr.flags = tfw_h2_calc_frame_flags(stream, type, trailers);
	tfw_h2_pack_frame_header(data, &frame_hdr);

	stream->xmit.frame_length += frame_length + FRAME_HEADER_SIZE;
	switch (tfw_h2_stream_fsm_ignore_err(ctx, stream, type,
					     frame_hdr.flags))
	{
	case STREAM_FSM_RES_OK:
		break;
	case STREAM_FSM_RES_IGNORE:
		fallthrough;
	case STREAM_FSM_RES_TERM_STREAM:
		/* Send previosly successfully prepared frames if exist. */
		stream->xmit.frame_length -= frame_length + FRAME_HEADER_SIZE;
		if (stream->xmit.frame_length) {
			r = tfw_h2_entail_stream_skb(sk, ctx, stream,
						     &stream->xmit.frame_length,
						     true);
		}
		stream->xmit.frame_length += frame_length + FRAME_HEADER_SIZE;
		/*
		 * Purge stream send queue, but leave postponed
		 * skbs and rst stream/goaway/tls alert if exist.
		 */
		tfw_h2_stream_purge_send_queue(stream);
		return r;
	case STREAM_FSM_RES_TERM_CONN:
		return -EPIPE;
	}

	return r;
}

static int
tfw_h2_stream_xmit_process(struct sock *sk, TfwH2Ctx *ctx, TfwStream *stream,
			   bool stream_is_exclusive, unsigned int mss_now,
			   unsigned long *snd_wnd, bool *stop)
{
	int r = 0;
	TfwFrameType frame_type;
	unsigned int frame_length;
	bool is_trailer_cont = false;
	unsigned int min_to_send = tfw_h2_calc_min_to_send(sk, ctx, mss_now);
	T_FSM_INIT(stream->xmit.state, "HTTP/2 make frames");

#define ADJUST_BLOCKED_STREAMS_AND_EXIT(len, type)			\
do {									\
	/*								\
	 * If Tempesta FW stop to make frames, because of exceeded	\
	 * stream->rem_wnd, mark such stream as blocked.		\
	 */								\
	BUG_ON(stream->xmit.is_blocked);				\
	stream->xmit.is_blocked =					\
		(type == HTTP2_DATA && stream->rem_wnd <= len);		\
	ctx->sched.blocked_streams += stream->xmit.is_blocked;		\
	*stop = true;							\
	T_FSM_EXIT();							\
} while(0)

#define CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE(type, len)			\
do {									\
	unsigned int max_len;						\
	unsigned int min_len;						\
									\
	if (*snd_wnd <= FRAME_HEADER_SIZE + TLS_MAX_OVERHEAD) {		\
		*stop = true;						\
		T_FSM_EXIT();						\
	}								\
	max_len = min(TLS_MAX_PAYLOAD_SIZE, *snd_wnd - TLS_MAX_OVERHEAD); \
	max_len -= FRAME_HEADER_SIZE;					\
	min_len = min(min_to_send, (unsigned int)len);			\
	frame_length = tfw_h2_calc_frame_length(ctx, stream, type, len,	\
						max_len); 		\
	/*								\
	 * If the lenght of data to send is less then `min_to_send`	\
	 * use it as a minimum bytes to send.				\
	 */								\
	if (frame_length < min_len)					\
		ADJUST_BLOCKED_STREAMS_AND_EXIT(min_len, type);		\
	frame_type = type;						\
} while(0)

#define FRAME_XMIT_FSM_NEXT(frame_length, state)			\
do {									\
	*snd_wnd -= frame_length;					\
	T_FSM_JMP(state);						\
} while(0)

	T_FSM_START(stream->xmit.state) {

	T_FSM_STATE(HTTP2_ENCODE_HEADERS) {
		r = tfw_h2_stream_xmit_prepare_resp(stream);
		fallthrough;
	}

	T_FSM_STATE(HTTP2_RELEASE_RESPONSE) {
		TfwHttpResp *resp = stream->xmit.resp;

		BUG_ON(!resp || !resp->req || !resp->req->conn);
		tfw_http_resp_pair_free_and_put_conn(resp);
		stream->xmit.resp = NULL;
		/* Error during headers encoding. */
		if (unlikely(r))
			return r;
		fallthrough;
	}

	T_FSM_STATE(HTTP2_MAKE_HEADERS_FRAMES) {
		CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE(HTTP2_HEADERS,
						     stream->xmit.h_len);
		if (unlikely(ctx->hpack.enc_tbl.wnd_changed)) {
			r = tfw_hpack_enc_tbl_write_sz(&ctx->hpack.enc_tbl,
						       stream);
			if (unlikely(r < 0)) {
				T_WARN("Failed to encode hpack dynamic"
				       "table size %d", r);
				return r;
			}
		}

		r = tfw_h2_insert_frame_header(sk, ctx, stream, frame_type,
					       frame_length);
		if (unlikely(r)) {
			T_WARN("Failed to make headers frame %d", r);
			return r;
		}

		FRAME_XMIT_FSM_NEXT(frame_length, HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_MAKE_CONTINUATION_FRAMES) {
		CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE(HTTP2_CONTINUATION,
						     stream->xmit.h_len);
		r = tfw_h2_insert_frame_header(sk, ctx, stream, frame_type,
					       frame_length);
		if (unlikely(r)) {
			T_WARN("Failed to make continuation frame %d", r);
			return r;
		}

		FRAME_XMIT_FSM_NEXT(frame_length, HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_MAKE_DATA_FRAMES) {
		if (unlikely(ctx->rem_wnd <= 0 || stream->rem_wnd <= 0))
			ADJUST_BLOCKED_STREAMS_AND_EXIT(0, HTTP2_DATA);

		CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE(HTTP2_DATA,
						     stream->xmit.b_len);
		r = tfw_h2_insert_frame_header(sk, ctx, stream, frame_type,
					       frame_length);
		if (unlikely (r)) {
			T_WARN("Failed to make data frame %d", r);
			return r;
		}

		ctx->data_frames_sent++;
		FRAME_XMIT_FSM_NEXT(frame_length, HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_MAKE_TRAILER_FRAMES) {
		is_trailer_cont = true;
		CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE(HTTP2_HEADERS,
						     stream->xmit.t_len);
		r = tfw_h2_insert_frame_header(sk, ctx, stream, frame_type,
					       frame_length);
		if (unlikely(r)) {
			T_WARN("Failed to make trail headers frame %d", r);
			return r;
		}

		FRAME_XMIT_FSM_NEXT(frame_length, HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_MAKE_TRAILER_CONTINUATION_FRAMES) {
		is_trailer_cont = true;
		CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE(HTTP2_CONTINUATION,
						     stream->xmit.t_len);
		r = tfw_h2_insert_frame_header(sk, ctx, stream, frame_type,
					       frame_length);
		if (unlikely(r)) {
			T_WARN("Failed to make trail continuation frame %d", r);
			return r;
		}

		FRAME_XMIT_FSM_NEXT(frame_length, HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_SEND_FRAMES) {
		if (likely(stream->xmit.frame_length)) {
			r =  tfw_h2_entail_stream_skb(sk, ctx, stream,
						      &stream->xmit.frame_length,
						      false);
			if (unlikely(r)) {
				T_WARN("Failed to send frame %d", r);
				return r;
			}
		}

		if (stream->xmit.h_len) {
			T_FSM_JMP(HTTP2_MAKE_CONTINUATION_FRAMES);
		} else {
			if (stream->xmit.postponed
			    && !stream->xmit.frame_length
			    && !ctx->cur_send_headers) {
				struct sk_buff **postponed =
					&stream->xmit.postponed;

				r = ss_skb_tcp_entail_list(sk, postponed);
				if (unlikely(r)) {
					T_WARN("Failed to send postponed"
					       " frames %d", r);
					return r;
				}
			}
			if (stream->xmit.b_len) {
				T_FSM_JMP(HTTP2_MAKE_DATA_FRAMES);
			} else if (stream->xmit.t_len) {
				if (likely(!is_trailer_cont)) {
					T_FSM_JMP(HTTP2_MAKE_TRAILER_FRAMES);
				} else {
					T_FSM_JMP(HTTP2_MAKE_TRAILER_CONTINUATION_FRAMES);
				}
			} else {
				fallthrough;
			}
		}
	}

	T_FSM_STATE(HTTP2_MAKE_FRAMES_FINISH) {
		BUG_ON(stream->xmit.resp);
		/*
		 * skb_head is not empty because RST stream or
		 * GOAWAY and TLS ALERT are pending until error
		 * response is sent.
		 */
		if (unlikely(stream->xmit.skb_head)) {
			r = ss_skb_tcp_entail_list(sk, &stream->xmit.skb_head);
			if (unlikely(r)) {
				T_WARN("Failed to send postponed"
				       " frames %d", r);
				return r;
			}
		}
		if (stream == ctx->error)
			ctx->error = NULL;
		/*
		 * Don't put exclusive streams in closed queue it
		 * will be immediately deleted in the caller function.
		 */
		if (!stream_is_exclusive)
			tfw_h2_stream_add_closed(ctx, stream);
		T_FSM_EXIT();
	}

	}

	T_FSM_FINISH(r, stream->xmit.state);

	if (stream->xmit.frame_length) {
		r = tfw_h2_entail_stream_skb(sk, ctx, stream,
					     &stream->xmit.frame_length,
					     true);
		if (unlikely(r)) {
			T_WARN("Failed to send frame %d", r);
			return r;
		}
		if (stream->xmit.postponed && !ctx->cur_send_headers) {
			struct sk_buff **postponed =
				&stream->xmit.postponed;

			r = ss_skb_tcp_entail_list(sk, postponed);
			if (unlikely(r)) {
				T_WARN("Failed to send postponed"
				       " frames %d", r);
				return r;
			}
		}
	}

	return r;

#undef FRAME_XMIT_FSM_NEXT
#undef CALC_FRAME_LENGTH_AND_SET_FRAME_TYPE
#undef ADJUST_BLOCKED_STREAMS_AND_EXIT
}

int
tfw_h2_make_frames(struct sock *sk, TfwH2Ctx *ctx, unsigned int mss_now)
{
	TfwStreamSched *sched = &ctx->sched;
	unsigned long snd_wnd = tfw_tcp_calc_snd_wnd(sk, mss_now);
	bool stop = false;
	int r = 0;
	TfwStream *stream;

	while (sched->root.active_cnt) {
		bool stream_is_exclusive;

		if (ctx->cur_send_headers) {
			stream = ctx->cur_send_headers;
			/*
			 * Stream can't be blocked during sending
			 * headers frames and this pointer should be
			 * zeroed if client close this stream.
			 */
			BUG_ON(!tfw_h2_stream_is_active(stream));
		} else if (ctx->error && tfw_h2_stream_is_active(ctx->error)) {
			stream = ctx->error;
			/*
			 * If we send error response we stop to send any data
			 * from other streams, so we either sent all error
			 * response or blocked by window size.
			*/
			stop = true;
		} else {
			stream = tfw_h2_sched_get_most_prio_stream(sched);
		}

		/*
		 * If root scheduler is active we always can find
		 * active stream.
		 */
		BUG_ON(!stream);
		stream_is_exclusive = tfw_h2_stream_is_exclusive(stream);
		r = tfw_h2_stream_xmit_process(sk, ctx, stream,
					       stream_is_exclusive, mss_now,
					       &snd_wnd, &stop);

		if (!tfw_h2_stream_is_active(stream)) {
			tfw_h2_sched_deactivate_stream(sched, stream);
			if (!stream->xmit.skb_head) {
				/*
				 * Remove exclusive stream after sending all
				 * pending data.
				 */
				if (stream_is_exclusive) {
					tfw_h2_stream_clean(ctx, stream);
				} else {
					TfwStreamSchedEntry *parent =
						stream->sched->parent;

					tfw_h2_stream_sched_reinsert(sched,
								     stream,
								     parent);
				}

			}
		}

		if (stop || r)
			break;
	}

	return r;
}
