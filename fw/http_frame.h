/**
 *		Tempesta FW
 *
 * Copyright (C) 2022-2025 Tempesta Technologies, Inc.
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
#ifndef __HTTP_FRAME__
#define __HTTP_FRAME__

#include "gfsm.h"
#include "http_stream.h"
#include "hpack.h"

/* RFC 7540 Section 4.1 frame header constants. */
#define FRAME_HEADER_SIZE		9
#define FRAME_STREAM_ID_MASK		((1U << 31) - 1)
#define FRAME_RESERVED_BIT_MASK		(~FRAME_STREAM_ID_MASK)
#define FRAME_MAX_LENGTH		((1U << 24) - 1)
#define FRAME_DEF_LENGTH		(16384)

/**
 * HTTP/2 frame types (RFC 7540 section 6).
 */
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
	HTTP2_CONTINUATION,
	_HTTP2_UNDEFINED
} TfwFrameType;

/**
 * IDs for SETTINGS parameters of HTTP/2 connection (RFC 7540
 * section 6.5.2).
 */
typedef enum {
	HTTP2_SETTINGS_NEED_TO_APPLY	= 0x00,
	HTTP2_SETTINGS_TABLE_SIZE	= 0x01,
	HTTP2_SETTINGS_ENABLE_PUSH,
	HTTP2_SETTINGS_MAX_STREAMS,
	HTTP2_SETTINGS_INIT_WND_SIZE,
	HTTP2_SETTINGS_MAX_FRAME_SIZE,
	HTTP2_SETTINGS_MAX_HDR_LIST_SIZE,
	_HTTP2_SETTINGS_MAX
} TfwSettingsId;

static const char *__tfw_h2_frm_names[] = {
	[HTTP2_DATA]	      = "DATA",
	[HTTP2_HEADERS]	      = "HEADERS",
	[HTTP2_PRIORITY]      = "PRIORITY",
	[HTTP2_RST_STREAM]    = "RST_STREAM",
	[HTTP2_SETTINGS]      = "SETTINGS",
	[HTTP2_PUSH_PROMISE]  = "PUSH_PROMISE",
	[HTTP2_PING]	      = "PING",
	[HTTP2_GOAWAY]	      = "GOAWAY",
	[HTTP2_WINDOW_UPDATE] = "WINDOW_UPDATE",
	[HTTP2_CONTINUATION]  = "CONTINUATION",
	[_HTTP2_UNDEFINED]    = "< UNDEF >",
};

static inline const char *
__h2_frm_type_n(TfwFrameType f_type)
{
	return __tfw_h2_frm_names[f_type];
}

/**
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

/**
 * Unpacked header data of currently processed frame (RFC 7540 section
 * 4.1). Reserved bit is not present here since it has no any semantic
 * value for now and should be always ignored.
 *
 * @length		- the frame's payload length;
 * @stream_id		- id of current stream (which frame is processed);
 * @type		- the type of frame being processed;
 * @flags		- frame's flags;
 */
typedef struct {
	int		length;
	unsigned int	stream_id;
	TfwFrameType	type;
	unsigned char	flags;
} TfwFrameHdr;

/**
 * Unpacked data from priority payload of frames (RFC 7540 section 6.2
 * and section 6.3).
 *
 * @stream_id		- id for the stream that the current stream depends on;
 * @weight		- stream's priority weight;
 * @exclusive		- flag indicating exclusive stream dependency;
 */
typedef struct {
	unsigned int	stream_id;
	unsigned short	weight;
	unsigned char	exclusive;
} TfwFramePri;

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

#define MAX_WND_SIZE			((1U << 31) - 1)
#define DEF_WND_SIZE			((1U << 16) - 1)

typedef struct tfw_h2_conn_t TfwH2Conn;

int tfw_h2_frame_process(TfwConn *c, struct sk_buff *skb,
			 struct sk_buff **next);
int tfw_h2_send_rst_stream(TfwH2Ctx *ctx, unsigned int id, TfwH2Err err_code);
int tfw_h2_send_goaway(TfwH2Ctx *ctx, TfwH2Err err_code, bool attack);
int tfw_h2_make_frames(struct sock *sk, TfwH2Ctx *ctx, unsigned int mss_now,
		       unsigned long snd_wnd);

static inline void
tfw_h2_pack_frame_header(unsigned char *p, const TfwFrameHdr *hdr)
{
	*(unsigned int *)p = htonl((unsigned int)(hdr->length << 8));
	p += 3;
	*p++ = hdr->type;
	*p++ = hdr->flags;
	/*
	 * Stream id must occupy not more than 31 bit and reserved bit
	 * must be 0.
	 */
	WARN_ON_ONCE((unsigned int)(hdr->stream_id & FRAME_RESERVED_BIT_MASK));

	*(unsigned int *)p = htonl(hdr->stream_id);
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

#endif /* __HTTP_FRAME__ */
