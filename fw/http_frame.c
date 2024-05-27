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
#undef DEBUG
#if DBG_HTTP_FRAME > 0
#define DEBUG DBG_HTTP_FRAME
#endif

#include "lib/fsm.h"
#include "lib/str.h"
#include "procfs.h"
#include "http.h"
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
	HTTP2_RECV_DATA,
	HTTP2_RECV_APP_DATA_POST
} TfwFrameState;

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
			ctx->cur_stream = NULL;				\
			return tfw_h2_send_rst_stream((ctx),		\
						      (hdr)->stream_id,	\
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
	TfwStreamQueue *closed_streams = &ctx->closed_streams;
	TfwStreamQueue *idle_streams = &ctx->idle_streams;
	TfwSettings *lset = &ctx->lsettings;
	TfwSettings *rset = &ctx->rsettings;

	bzero_fast(ctx, sizeof(*ctx));

	ctx->state = HTTP2_RECV_CLI_START_SEQ;
	ctx->loc_wnd = DEF_WND_SIZE;
	ctx->rem_wnd = DEF_WND_SIZE;

	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&closed_streams->list);
	INIT_LIST_HEAD(&idle_streams->list);

	tfw_h2_init_stream_sched(&ctx->sched);

	lset->hdr_tbl_sz = rset->hdr_tbl_sz = HPACK_TABLE_DEF_SIZE;
	lset->push = rset->push = 1;
	lset->max_streams = tfw_cli_max_concurrent_streams;
	rset->max_streams = 0xffffffff;
	lset->max_frame_sz = rset->max_frame_sz = FRAME_DEF_LENGTH;
	lset->max_lhdr_sz = max_header_list_size ?
		max_header_list_size : UINT_MAX;
	rset->max_lhdr_sz = UINT_MAX;

	lset->wnd_sz = DEF_WND_SIZE;
	rset->wnd_sz = DEF_WND_SIZE;

	return tfw_hpack_init(&ctx->hpack, HPACK_TABLE_DEF_SIZE);
}
ALLOW_ERROR_INJECTION(tfw_h2_context_init, ERRNO);

void
tfw_h2_context_clear(TfwH2Ctx *ctx)
{
	WARN_ON_ONCE(ctx->streams_num);
	/*
	 * Free POSTPONED SKBs. This is necessary when h2 context has
	 * postponed frames and connection closing initiated.
	 */
	ss_skb_queue_purge(&ctx->skb_head);
	tfw_hpack_clean(&ctx->hpack);
}

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

/**
 * Usually client firstly send SETTINGS frame to a server, so:
 * - we don't have many streams to iterate over in this function
 *   (usually we have no streams at all).
 * - typically there is only one SETTINGS_INITIAL_WINDOW_SIZE
 *   frame is sent from a client side.
 */
static void
tfw_h2_apply_wnd_sz_change(TfwH2Ctx *ctx, long int delta)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwStream *stream, *next;

	/*
	 * Order is no matter, use default funtion from the Linux kernel.
	 * According to RFC 9113 6.9.2
	 * When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver
	 * MUST adjust the size of all stream flow-control windows that it
	 * maintains by the difference between the new value and the old value.
	 * A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available
	 * space in a flow-control window to become negative.
	 */
	rbtree_postorder_for_each_entry_safe(stream, next,
					     &ctx->sched.streams, node) {
		TfwStreamState state = tfw_h2_get_stream_state(stream);
		if (state == HTTP2_STREAM_OPENED ||
		    state == HTTP2_STREAM_REM_HALF_CLOSED) {
			stream->rem_wnd += delta;
			tfw_h2_stream_try_unblock(&ctx->sched, stream);
			if (stream->rem_wnd > 0) {
				sock_set_flag(((TfwConn *)conn)->sk,
					      SOCK_TEMPESTA_HAS_DATA);
			}
		}
	}
}

static void
tfw_h2_apply_settings_entry(TfwH2Ctx *ctx, unsigned short id,
			    unsigned int val)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwSettings *dest = &ctx->rsettings;
	long int delta;

	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);
		dest->hdr_tbl_sz = min_t(unsigned int,
					 val, HPACK_ENC_TABLE_MAX_SIZE);
		tfw_hpack_set_rbuf_size(&ctx->hpack.enc_tbl, dest->hdr_tbl_sz);
		break;

	case HTTP2_SETTINGS_ENABLE_PUSH:
		BUG_ON(val > 1);
		dest->push = val;
		break;

	case HTTP2_SETTINGS_MAX_STREAMS:
		dest->max_streams = val;
		break;

	case HTTP2_SETTINGS_INIT_WND_SIZE:
		BUG_ON(val > MAX_WND_SIZE);
		delta = (long int)val - (long int)dest->wnd_sz;
		tfw_h2_apply_wnd_sz_change(ctx, delta);
		dest->wnd_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_FRAME_SIZE:
		BUG_ON(val < FRAME_DEF_LENGTH || val > FRAME_MAX_LENGTH);
		dest->max_frame_sz = val;
		break;

	case HTTP2_SETTINGS_MAX_HDR_LIST_SIZE:
		dest->max_lhdr_sz = val;
		break;

	default:
		/*
		 * We should silently ignore unknown identifiers (see
		 * RFC 9113 section 6.5.2)
		 */
		break;
	}
}

static int
tfw_h2_check_settings_entry(TfwH2Ctx *ctx, unsigned short id, unsigned int val)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

	switch (id) {
	case HTTP2_SETTINGS_TABLE_SIZE:
		break;

	case HTTP2_SETTINGS_ENABLE_PUSH:
		if (val > 1)
			return -EINVAL;
		break;

	case HTTP2_SETTINGS_MAX_STREAMS:
		break;

	case HTTP2_SETTINGS_INIT_WND_SIZE:
		if (val > MAX_WND_SIZE)
			return -EINVAL;
		break;

	case HTTP2_SETTINGS_MAX_FRAME_SIZE:
		if (val < FRAME_DEF_LENGTH || val > FRAME_MAX_LENGTH)
			return -EINVAL;
		break;

	case HTTP2_SETTINGS_MAX_HDR_LIST_SIZE:
		break;

	default:
		/*
		 * We should silently ignore unknown identifiers (see
		 * RFC 9113 section 6.5.2)
		 */
		break;
	}

	return 0;
}

static void
tfw_h2_save_settings_entry(TfwH2Ctx *ctx, unsigned short id, unsigned int val)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

	if (id > 0 && id < _HTTP2_SETTINGS_MAX) {
		ctx->new_settings[id] = val;
		ctx->new_settings[0] |= ctx_new_settings_flags[id];
	}
}

static void
tfw_h2_apply_new_settings(TfwH2Ctx *ctx)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	unsigned int id;

	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

	for (id = HTTP2_SETTINGS_TABLE_SIZE; id < _HTTP2_SETTINGS_MAX; id++) {
		if (ctx->new_settings[0] & ctx_new_settings_flags[id]) {
			unsigned int val = ctx->new_settings[id];
			tfw_h2_apply_settings_entry(ctx, id, val);
		}
	}
	ctx->new_settings[0] = 0;
}

static int
tfw_h2_do_send_ack(void *conn, struct sk_buff **skb_head, int flags)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);

	/*
	 * First new_settings entry is used to save settings
	 * which were acked.
	 */
	if (ctx->new_settings[0])
		tfw_h2_apply_new_settings(ctx);
	return 0;
}

static int
tfw_h2_do_send_goaway(void *conn, struct sk_buff **skb_head, int flags)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);
	unsigned char tls_type = flags & SS_F_ENCRYPT ?
		SS_SKB_F2TYPE(flags) : 0;

	if (tls_type)
		skb_set_tfw_tls_type(*skb_head, tls_type);
	swap(ctx->goaway, *skb_head);
	sock_set_flag(((TfwConn *)conn)->sk, SOCK_TEMPESTA_HAS_DATA);
	return 0;
}

static int
tfw_h2_do_send_rst_stream(void *conn, struct sk_buff **skb_head, int flags)
{
	TfwH2Ctx *ctx = tfw_h2_context_unsafe((TfwConn *)conn);
	struct tfw_skb_cb *tfw_cb = TFW_SKB_CB(*skb_head);
	unsigned char tls_type = flags & SS_F_ENCRYPT ?
		SS_SKB_F2TYPE(flags) : 0;
	TfwStream *stream;

	if (tls_type)
		skb_set_tfw_tls_type(*skb_head, tls_type);
	stream = tfw_h2_find_not_closed_stream(ctx, tfw_cb->stream_id, false);

	/*
	 * Send RST STREAM after all pending data otherwise directly push it
	 * to socket write queue.
	 * Stream can not exist in case when we send RST stream because a
	 * remote peer exceeded max_concurrent_streams limit.
	 */
	if (stream && stream->xmit.skb_head) {
		swap(stream->xmit.rst_stream, *skb_head);
		sock_set_flag(((TfwConn *)conn)->sk, SOCK_TEMPESTA_HAS_DATA);
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

	if (hdr->type == HTTP2_SETTINGS && hdr->flags == HTTP2_F_ACK) {
		TFW_SKB_CB(msg.skb_head)->do_send = tfw_h2_do_send_ack;
	} else if (hdr->type == HTTP2_GOAWAY) {
		TFW_SKB_CB(msg.skb_head)->do_send = tfw_h2_do_send_goaway;
	} else if (hdr->type == HTTP2_RST_STREAM) {
		TFW_SKB_CB(msg.skb_head)->do_send = tfw_h2_do_send_rst_stream;
		TFW_SKB_CB(msg.skb_head)->stream_id = hdr->stream_id;
	}

	if ((r = tfw_connection_send((TfwConn *)conn, &msg)))
		goto err;
	/*
	 * We do not close client connection automatically here in case
	 * of failed sending, the caller must make such decision instead;
	 * thus, we should set Conn_Stop flag only if sending procedure
	 * was successful - to avoid hanged unclosed client connection.
	 */
	if (type == TFW_FRAME_CLOSE || type == TFW_FRAME_SHUTDOWN)
		TFW_CONN_TYPE((TfwConn *)conn) |= Conn_Stop;

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
	ctx->sent_settings[HTTP2_SETTINGS_TABLE_SIZE] = true;

	BUILD_BUG_ON(SETTINGS_VAL_SIZE != sizeof(ctx->lsettings.wnd_sz));
	field[1].key   = htons(HTTP2_SETTINGS_INIT_WND_SIZE);
	field[1].value = htonl(ctx->lsettings.wnd_sz);
	ctx->sent_settings[HTTP2_SETTINGS_INIT_WND_SIZE] = true;

	field[2].key   = htons(HTTP2_SETTINGS_MAX_STREAMS);
	field[2].value = htonl(ctx->lsettings.max_streams);

	if (ctx->lsettings.max_lhdr_sz != UINT_MAX) {
		field[required_fields].key =
			htons(HTTP2_SETTINGS_MAX_HDR_LIST_SIZE);
		field[required_fields].value =
			htonl(ctx->lsettings.max_lhdr_sz);
		ctx->sent_settings[HTTP2_SETTINGS_MAX_HDR_LIST_SIZE] = true;
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

static inline int
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

	return tfw_h2_send_frame(ctx, &hdr, &data);
}

void
tfw_h2_conn_terminate_close(TfwH2Ctx *ctx, TfwH2Err err_code, bool close,
			    bool attack)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

	if (tfw_h2_send_goaway(ctx, err_code, attack) && close) {
		if (attack)
			tfw_connection_close((TfwConn *)conn, true);
		else
			tfw_connection_shutdown((TfwConn *)conn, true);
	}
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

static inline void
tfw_h2_current_stream_remove(TfwH2Ctx *ctx)
{
	T_DBG3("%s: ctx [%p] ctx->cur_stream %p\n", __func__, ctx, ctx->cur_stream);
	tfw_h2_stream_unlink_lock(ctx, ctx->cur_stream);
	tfw_h2_stream_clean(ctx, ctx->cur_stream);
	ctx->cur_stream = NULL;
}

/**
 * According to RFC 9113 section 5.1.1:
 * The first use of a new stream identifier implicitly closes all
 * streams in the "idle" state that might have been initiated by that
 * peer with a lower-valued stream identifier.
 */
static void
tfw_h2_remove_idle_streams(TfwH2Ctx *ctx, unsigned int id)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwStream *stream, *tmp;

	/*
	 * We add and remove streams from idle queue under
	 * socket lock.
	 */
	assert_spin_locked(&((TfwConn *)conn)->sk->sk_lock.slock);

	list_for_each_entry_safe_reverse(stream, tmp, &ctx->idle_streams.list,
					 hcl_node)
	{
		if (id <= stream->id)
			break;

		tfw_h2_stream_del_from_queue_nolock(stream);
		tfw_h2_set_stream_state(stream, HTTP2_STREAM_CLOSED);
		tfw_h2_stream_add_closed(ctx, stream);
	}
}

void
tfw_h2_conn_streams_cleanup(TfwH2Ctx *ctx)
{
	TfwStream *cur, *next;
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	TfwStreamSched *sched = &ctx->sched;

	WARN_ON_ONCE(((TfwConn *)conn)->stream.msg);

	T_DBG3("%s: ctx [%p] conn %p sched %p\n", __func__, ctx, conn, sched);

	tfw_h2_remove_idle_streams(ctx, UINT_MAX);

	rbtree_postorder_for_each_entry_safe(cur, next, &sched->streams, node) {
		tfw_h2_stream_purge_send_queue_and_free_response(cur);
		tfw_h2_stream_unlink_lock(ctx, cur);

		/* The streams tree is about to be destroyed and
		 * we don't want to trigger rebalancing.
		 * No further actions regarding streams dependencies/prio
		 * is required at this stage.
		 */
		tfw_h2_delete_stream(cur);
		--ctx->streams_num;
	}
	sched->streams = RB_ROOT;
}

/*
 * Get stream ID for upper layer to create frames info.
 */
unsigned int
tfw_h2_req_stream_id(TfwHttpReq *req)
{
	unsigned int id = 0;
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);

	spin_lock(&ctx->lock);

	if (req->stream)
		id = req->stream->id;

	spin_unlock(&ctx->lock);

	return id;
}

/*
 * Unlink request from corresponding stream (if linked).
 */
void
tfw_h2_req_unlink_stream(TfwHttpReq *req)
{
	TfwStream *stream;
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);

	spin_lock(&ctx->lock);

	stream = req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return;
	}

	req->stream = NULL;
	stream->msg = NULL;

	spin_unlock(&ctx->lock);
}

/*
 * Unlink request from corresponding stream (if linked),
 * send RST STREAM and add stream to closed queue.
 */
void
tfw_h2_req_unlink_stream_with_rst(TfwHttpReq *req)
{
	TfwStreamFsmRes r;
	TfwStream *stream;
	TfwH2Ctx *ctx = tfw_h2_context_unsafe(req->conn);

	spin_lock(&ctx->lock);

	stream = req->stream;
	if (!stream) {
		spin_unlock(&ctx->lock);
		return;
	}

	req->stream = NULL;
	stream->msg = NULL;

	r = tfw_h2_stream_fsm_ignore_err(ctx, stream, HTTP2_RST_STREAM, 0);
	WARN_ON_ONCE(r != STREAM_FSM_RES_OK && r != STREAM_FSM_RES_IGNORE);

	tfw_h2_stream_add_to_queue_nolock(&ctx->closed_streams, stream);

	spin_unlock(&ctx->lock);
}

/*
 * Clean the queue of closed streams if its size has exceeded a certain
 * value.
 */
static void
tfw_h2_closed_streams_shrink(TfwH2Ctx *ctx)
{
	TfwStream *cur;
	TfwStreamQueue *closed_streams = &ctx->closed_streams;

	T_DBG3("%s: ctx [%p] closed streams num %lu\n", __func__, ctx,
	       closed_streams->num);

	while (1) {
		spin_lock(&ctx->lock);

		if (closed_streams->num <= TFW_MAX_CLOSED_STREAMS) {
			spin_unlock(&ctx->lock);
			break;
		}

		BUG_ON(list_empty(&closed_streams->list));
		cur = list_first_entry(&closed_streams->list, TfwStream,
				       hcl_node);
		tfw_h2_stream_unlink_nolock(ctx, cur);

		spin_unlock(&ctx->lock);

		T_DBG3("%s: ctx [%p] cur stream [%p]\n", __func__, ctx, cur);

		tfw_h2_stream_clean(ctx, cur);
	}
}

static inline void
tfw_h2_check_closed_stream(TfwH2Ctx *ctx)
{
	BUG_ON(!ctx->cur_stream);

	T_DBG3("%s: strm [%p] id %u state %d(%s), streams_num %lu\n",
	       __func__, ctx->cur_stream, ctx->cur_stream->id,
	       tfw_h2_get_stream_state(ctx->cur_stream),
	       __h2_strm_st_n(ctx->cur_stream), ctx->streams_num);

	if (tfw_h2_stream_is_closed(ctx->cur_stream))
		tfw_h2_current_stream_remove(ctx);
}

static inline int
tfw_h2_current_stream_state_process(TfwH2Ctx *ctx)
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

		if (tfw_h2_stream_fsm_ignore_err(ctx, ctx->cur_stream,
						 HTTP2_RST_STREAM, 0))
			return -EPERM;

		ctx->cur_stream = NULL;
		return tfw_h2_send_rst_stream(ctx, hdr->stream_id,
					      HTTP2_ECODE_PROTO);
	}

	if (!ctx->cur_stream) {
		ctx->cur_stream = tfw_h2_stream_create(ctx, hdr->stream_id);
		if (!ctx->cur_stream)
			return -ENOMEM;
		ctx->lstream_id = hdr->stream_id;
	} else if (ctx->cur_stream->state == HTTP2_STREAM_IDLE) {
		tfw_h2_stream_remove_idle(ctx, ctx->cur_stream);
		ctx->lstream_id = hdr->stream_id;
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
		TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
		long int *window = ctx->cur_stream ?
			&ctx->cur_stream->rem_wnd : &ctx->rem_wnd;

		if (tfw_h2_increment_wnd_sz(window, wnd_incr)) {
			err_code = HTTP2_ECODE_FLOW;
			goto fail;
		}

		if (ctx->cur_stream)
			tfw_h2_stream_try_unblock(&ctx->sched, ctx->cur_stream);

		if (*window > 0) {
			if (tfw_h2_stream_sched_is_active(&ctx->sched.root)) {
				sock_set_flag(((TfwConn *)conn)->sk,
					       SOCK_TEMPESTA_HAS_DATA);
				tcp_push_pending_frames(((TfwConn *)conn)->sk);
			}
		}

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

	ctx->cur_stream = NULL;
	return tfw_h2_send_rst_stream(ctx, hdr->stream_id,
				      err_code);
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
	T_DBG("Invalid dependency: new stream with %u depends on"
		      " itself\n", hdr->stream_id);

	if (tfw_h2_stream_fsm_ignore_err(ctx, ctx->cur_stream,
					 HTTP2_RST_STREAM, 0))
		return -EPERM;

	ctx->cur_stream = NULL;
	return tfw_h2_send_rst_stream(ctx, hdr->stream_id,
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

static void
tfw_h2_settings_ack_process(TfwH2Ctx *ctx)
{
	T_DBG3("%s: parsed, stream_id=%u, flags=%hhu\n", __func__,
	       ctx->hdr.stream_id, ctx->hdr.flags);

	if (ctx->sent_settings[HTTP2_SETTINGS_TABLE_SIZE]) {
		ctx->hpack.max_window = ctx->lsettings.hdr_tbl_sz;
		ctx->hpack.dec_tbl.wnd_update = true;
		ctx->sent_settings[HTTP2_SETTINGS_TABLE_SIZE] = false;
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
		T_LOG("HTTP/2 connection is closed by client with error code:"
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
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);

#define VERIFY_MAX_CONCURRENT_STREAMS(ctx, ACTION)			\
do {									\
	unsigned int max_streams = ctx->lsettings.max_streams;		\
									\
	tfw_h2_closed_streams_shrink(ctx);				\
									\
	if (max_streams == ctx->streams_num) {				\
		T_WARN("Max streams number exceeded: %lu\n",		\
		       ctx->streams_num);				\
		SET_TO_READ_VERIFY(ctx, HTTP2_IGNORE_FRAME_DATA);	\
		ACTION;							\
	}								\
} while(0)

	T_DBG3("%s: hdr->type %u(%s), ctx->state %u\n", __func__, hdr_type,
	       __h2_frm_type_n(hdr_type), ctx->state);

	if ((TFW_CONN_TYPE((TfwConn *)conn) & Conn_Stop)
	    && hdr_type != HTTP2_WINDOW_UPDATE) {
		T_DBG3("Drop %s frame, because connection is closing",
		       __h2_frm_type_n(hdr_type));
		ctx->state = HTTP2_IGNORE_FRAME_DATA;
		SET_TO_READ(ctx);
		return 0;
	}

	if (unlikely(ctx->hdr.length > ctx->lsettings.max_frame_sz))
		goto conn_term;

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
		 */
		BUG_ON(r == T_BLOCK);
		fallthrough;
	case T_DROP:
	case T_BAD:
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
}

static inline unsigned int
tfw_h2_calc_frame_length(TfwH2Ctx *ctx, TfwStream *stream, TfwFrameType type,
			 unsigned int len, unsigned int snd_wnd)
{
	unsigned int length;

	length = min3(ctx->rsettings.max_frame_sz, len, snd_wnd);
	if (type == HTTP2_DATA) {
		length = min3(length, (unsigned int)ctx->rem_wnd,
			      (unsigned int)stream->rem_wnd);
	}

	return length;
}

static inline char
tf2_h2_calc_frame_flags(TfwStream *stream, TfwFrameType type)
{
	switch (type) {
	case HTTP2_HEADERS:
		return stream->xmit.h_len ?
			(stream->xmit.b_len ? 0 : HTTP2_F_END_STREAM) :
			(stream->xmit.b_len ? HTTP2_F_END_HEADERS :
			 HTTP2_F_END_HEADERS | HTTP2_F_END_STREAM);
	case HTTP2_CONTINUATION:
		return stream->xmit.h_len ? 0 : HTTP2_F_END_HEADERS;
	case HTTP2_DATA:
		return stream->xmit.b_len ? 0 : HTTP2_F_END_STREAM;
	default:
		BUG();
	};

	return 0;
}

static inline int
tfw_h2_entail_stream_skb(TfwH2Ctx *ctx, TfwStream *stream, unsigned int *len)
{
	TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
	struct sock *sk = ((TfwConn *)conn)->sk;
	unsigned char tls_type = skb_tfw_tls_type(stream->xmit.skb_head);
	unsigned int mark = stream->xmit.skb_head->mark;
	struct sk_buff *skb, *split;
	int r = 0;

	while (*len) {
		skb = ss_skb_dequeue(&stream->xmit.skb_head);
		BUG_ON(!skb);

		if (unlikely(!skb->len)) {
			T_DBG3("[%d]: %s: drop skb=%px data_len=%u len=%u\n",
			       smp_processor_id(), __func__,
			       skb, skb->data_len, skb->len);
			kfree_skb(skb);
			continue;
		}

		BUG_ON(!tls_type);
		BUG_ON(!skb->len);

		if (skb->len > *len) {
			split = ss_skb_split(skb, *len);
			if (!split) {
				ss_skb_queue_head(&stream->xmit.skb_head, skb);
				r = -ENOMEM;
				break;
			}

			ss_skb_queue_head(&stream->xmit.skb_head, split);
		}
		*len -= skb->len;
		ss_skb_entail(sk, skb, mark, tls_type);
	}

	/*
	 * We use tls_type and mark from skb_head when we entail data in
	 * socket write queue. So we should set tls_type and mark for the
	 * new skb_head.
	 */
	if (stream->xmit.skb_head) {
		skb_set_tfw_tls_type(stream->xmit.skb_head, tls_type);
		stream->xmit.skb_head->mark = mark;
	}

	return r;
}

static inline int
tfw_h2_insert_frame_header(TfwH2Ctx *ctx, TfwStream *stream, TfwFrameType type,
			   unsigned long *snd_wnd, unsigned long *len)
{
	TfwMsgIter it = {
		.skb_head = stream->xmit.skb_head,
		.skb = stream->xmit.skb_head,
		.frag = -1
	};
	unsigned char buf[FRAME_HEADER_SIZE];
	const TfwStr frame_hdr_str = { .data = buf, .len = sizeof(buf)};
	TfwFrameHdr frame_hdr = {};
	unsigned char tls_type = skb_tfw_tls_type(stream->xmit.skb_head);
	unsigned int mark = stream->xmit.skb_head->mark;
	unsigned int length;
	char *data;
	int r;

	if (unlikely(type == HTTP2_DATA
		     && skb_headlen(stream->xmit.skb_head)))
	{
		if ((r = tfw_http_msg_linear_transform(&it)))
			return r;
		stream->xmit.skb_head = it.skb_head;
	}

	data = ss_skb_data_ptr_by_offset(stream->xmit.skb_head, 0);
	if(unlikely(!data))
		data = stream->xmit.skb_head->data;

	if (type == HTTP2_CONTINUATION || type == HTTP2_DATA) {
		it.skb = it.skb_head = stream->xmit.skb_head;
		if ((r = tfw_http_msg_insert(&it, &data, &frame_hdr_str)))
			return r;
		stream->xmit.skb_head = it.skb_head;
	}

	/*
	 * Set tls_type and mark, because skb_head could be changed
	 * during previous operations.
	 */
	skb_set_tfw_tls_type(stream->xmit.skb_head, tls_type);
	stream->xmit.skb_head->mark = mark;

	length = tfw_h2_calc_frame_length(ctx, stream, type, *len, *snd_wnd);
	*len -= length;
	if (type == HTTP2_DATA) {
		ctx->rem_wnd -= length;
		stream->rem_wnd -= length;
	}

	frame_hdr.length = length;
	frame_hdr.stream_id = stream->id;
	frame_hdr.type = type;
	frame_hdr.flags = tf2_h2_calc_frame_flags(stream, type);

	tfw_h2_pack_frame_header(data, &frame_hdr);

	switch (tfw_h2_stream_send_process(ctx, stream, type)) {
	case STREAM_FSM_RES_OK:
	case STREAM_FSM_RES_IGNORE:
		break;
	case STREAM_FSM_RES_TERM_STREAM:
		tfw_h2_stream_purge_send_queue(stream);
		return 0;
	case STREAM_FSM_RES_TERM_CONN:
		return -EPIPE;
	}

	*snd_wnd -= length;
	stream->xmit.frame_length = length + FRAME_HEADER_SIZE;
	return 0;
}

static int
tfw_h2_stream_xmit_prepare_resp(TfwStream *stream)
{
	TfwHttpResp *resp = stream->xmit.resp;
	unsigned char tls_type;
	unsigned int mark;
	int r = 0;

	BUG_ON(!resp || resp->msg.skb_head || !resp->req
	       || !resp->req->conn || !stream->xmit.skb_head);

	tls_type = skb_tfw_tls_type(stream->xmit.skb_head);
	mark = stream->xmit.skb_head->mark;
	swap(resp->msg.skb_head, stream->xmit.skb_head);

	r = tfw_h2_resp_encode_headers(resp);
	if (unlikely(r)) {
		T_WARN("Failed to encode headers");
		goto finish;
	}

	stream->xmit.h_len = resp->mit.acc_len;
	stream->xmit.b_len = TFW_HTTP_RESP_CUT_BODY_SZ(resp);
	if (test_bit(TFW_HTTP_B_CHUNKED, resp->flags))
		r = tfw_http_msg_cutoff_body_chunks(resp);

finish:
	swap(stream->xmit.skb_head, resp->msg.skb_head);
	skb_set_tfw_tls_type(stream->xmit.skb_head, tls_type);
	stream->xmit.skb_head->mark = mark;

	return r;
}

static int
tfw_h2_stream_xmit_process(TfwH2Ctx *ctx, TfwStream *stream,
			   unsigned long *snd_wnd)
{
	int r = 0;
	TfwFrameType frame_type;
	unsigned long tmp_snd_wnd = ULONG_MAX;
	T_FSM_INIT(stream->xmit.state, "HTTP/2 make frames");

#define ADJUST_SND_WND(snd_wnd, type)					\
do {									\
	if (snd_wnd <= FRAME_HEADER_SIZE)				\
		T_FSM_EXIT();						\
	snd_wnd -= FRAME_HEADER_SIZE;					\
	frame_type = type;						\
} while(0)

/*
 * We can't break making headers because of exceeding available window,
 * bytes since there is a chance that some other frames will be sent in
 * between sending headers. This is prohibited by RFC and leads to
 * connection closing by client. So we adjust window in temporary variable
 * and recalculate window when we start making DATA frames or when we finish
 * making frames for current stream.
 */
#define ADJUST_TMP_SND_WND(stream, tmp_snd_wnd)				\
do {									\
	if (!stream->xmit.h_len) {					\
		unsigned long delta = ULONG_MAX - tmp_snd_wnd;		\
		*snd_wnd = (*snd_wnd > delta ?				\
			*snd_wnd - delta : 0);				\
		tmp_snd_wnd = ULONG_MAX;				\
	}								\
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
		ADJUST_SND_WND(tmp_snd_wnd, HTTP2_HEADERS);
		if (unlikely(ctx->hpack.enc_tbl.wnd_changed)) {
			r = tfw_hpack_enc_tbl_write_sz(&ctx->hpack.enc_tbl,
						       stream);
			if (unlikely(r < 0)) {
				T_WARN("Failed to encode hpack dynamic"
				       "table size %d", r);
				return r;
			}
		}

		r = tfw_h2_insert_frame_header(ctx, stream, frame_type,
					       &tmp_snd_wnd,
					       &stream->xmit.h_len);
		if (unlikely(r)) {
			T_WARN("Failed to make headers frame %d", r);
			return r;
		}

		ADJUST_TMP_SND_WND(stream, tmp_snd_wnd);
		T_FSM_JMP(HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_MAKE_CONTINUATION_FRAMES) {
		ADJUST_SND_WND(tmp_snd_wnd, HTTP2_CONTINUATION);
		r = tfw_h2_insert_frame_header(ctx, stream, frame_type,
					       &tmp_snd_wnd,
					       &stream->xmit.h_len);
		if (unlikely(r)) {
			T_WARN("Failed to make continuation frame %d", r);
			return r;
		}

		ADJUST_TMP_SND_WND(stream, tmp_snd_wnd);
		T_FSM_JMP(HTTP2_SEND_FRAMES);
	}

	T_FSM_STATE(HTTP2_MAKE_DATA_FRAMES) {
		if (ctx->rem_wnd <= 0 || stream->rem_wnd <= 0) {
			ctx->sched.blocked_streams +=
				(stream->rem_wnd <= 0
				 && !stream->xmit.is_blocked);
			stream->xmit.is_blocked = stream->rem_wnd <= 0;
			T_FSM_EXIT();
		}

		ADJUST_SND_WND(*snd_wnd, HTTP2_DATA);
		r = tfw_h2_insert_frame_header(ctx, stream, frame_type,
					       snd_wnd, &stream->xmit.b_len);
		if (unlikely (r)) {
			T_WARN("Failed to make data frame %d", r);
			return r;
		}

		fallthrough;
	}

	T_FSM_STATE(HTTP2_SEND_FRAMES) {
		if (stream->xmit.frame_length) {
			unsigned int *len = &stream->xmit.frame_length;
			r =  tfw_h2_entail_stream_skb(ctx, stream, len);
			if (unlikely(r)) {
				T_WARN("Failed to send frame %d", r);
				return r;
			}
		} else if (stream->xmit.rst_stream) {
			TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
			struct sock *sk = ((TfwConn *)conn)->sk;
			unsigned char tls_type =
				skb_tfw_tls_type(stream->xmit.rst_stream);

			ss_skb_head_entail(sk, &stream->xmit.rst_stream,
					   stream->xmit.rst_stream->mark,
					   tls_type);
		}

		if (stream->xmit.h_len) {
			T_FSM_JMP(HTTP2_MAKE_CONTINUATION_FRAMES);
		} else if (stream->xmit.b_len) {
			T_FSM_JMP(HTTP2_MAKE_DATA_FRAMES);
		} else if (stream->xmit.rst_stream) {
			T_FSM_JMP(HTTP2_SEND_FRAMES);
		} else {
			T_FSM_JMP(HTTP2_MAKE_FRAMES_FINISH);
		}
	}

	T_FSM_STATE(HTTP2_MAKE_FRAMES_FINISH) {
		BUG_ON(stream->xmit.resp);

		ss_skb_queue_purge(&stream->xmit.skb_head);
		tfw_h2_stream_add_closed(ctx, stream);
		T_FSM_EXIT();
	}

	}

	T_FSM_FINISH(r, stream->xmit.state);

	return r;

#undef ADJUST_TMP_SND_WND
#undef ADJUST_SND_WND
}

int
tfw_h2_make_frames(TfwH2Ctx *ctx, unsigned long snd_wnd,
		   bool *data_is_available)
{
	TfwStreamSched *sched = &ctx->sched;
	TfwStreamSchedEntry *parent;
	TfwStream *stream;
	u64 deficit;
	int r = 0;

	while (tfw_h2_stream_sched_is_active(&sched->root)
	       && snd_wnd > FRAME_HEADER_SIZE && ctx->rem_wnd > 0 && !r)
	{
		stream = tfw_h2_sched_stream_dequeue(sched, &parent);
		/*
		 * If root scheduler is active we always can find
		 * active stream.
		 */
		BUG_ON(!stream);
		r = tfw_h2_stream_xmit_process(ctx, stream, &snd_wnd);

		deficit = tfw_h2_stream_recalc_deficit(stream);
		tfw_h2_sched_stream_enqueue(sched, stream, parent,
					    deficit);
	}

	*data_is_available =
		tfw_h2_stream_sched_is_active(&sched->root) && ctx->rem_wnd;

	if ((!(*data_is_available) && !ctx->sched.blocked_streams)) {
		TfwH2Conn *conn = container_of(ctx, TfwH2Conn, h2);
		struct sock *sk = ((TfwConn *)conn)->sk;

		/*
		 * First send goaway, then tls_alert and then TCP
		 * shutdown.
		 */
		if (ctx->goaway) {
			ss_skb_head_entail(sk, &ctx->goaway,
					   ctx->goaway->mark,
					   skb_tfw_tls_type(ctx->goaway));
		}
		if (ctx->tls_alert) {
			ss_skb_head_entail(sk, &ctx->tls_alert,
					   ctx->tls_alert->mark,
					   skb_tfw_tls_type(ctx->tls_alert));
		}
		if (SS_CONN_TYPE(((TfwConn *)conn)->sk) & Conn_Shutdown)
			tcp_shutdown(((TfwConn *)conn)->sk, SEND_SHUTDOWN);
	}

	return (tfw_h2_stream_sched_is_active(&sched->root) ||
		ctx->sched.blocked_streams) ? 1 : 0;
}

TfwStream *
tfw_h2_find_not_closed_stream(TfwH2Ctx *ctx, unsigned int id, bool recv)
{
	TfwStream *stream;

	stream = tfw_h2_find_stream(&ctx->sched, id);
	return stream && !tfw_h2_stream_is_closed(stream) ? stream : NULL;
}
