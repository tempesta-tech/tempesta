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
#ifndef __HTTP_FRAME__
#define __HTTP_FRAME__

#include "connection.h"
#include "http_stream.h"

#define FRAME_HEADER_SIZE		9

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
	HTTP2_CONTINUATION
} TfwFrameType;

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
 * @length	- the frame's payload length;
 * @stream_id	- id of current stream (which frame is processed);
 * @type	- the type of frame being processed;
 * @flags	- frame's flags;
 */
typedef struct {
	int		length;
	unsigned int	stream_id;
	unsigned char	type;
	unsigned char	flags;
} TfwFrameHdr;

/**
 * Unpacked data from priority payload of frames (RFC 7540 section 6.2
 * and section 6.3).
 *
 * @stream_id	- id for the stream that the current stream depends on;
 * @weight	- stream's priority weight;
 * @exclusive	- flag indicating exclusive stream dependency;
 */
typedef struct {
	unsigned int	stream_id;
	unsigned short	weight;
	unsigned char	exclusive;
} TfwFramePri;

/**
 * Representation of SETTINGS parameters for HTTP/2 connection (RFC 7540
 * section 6.5.2).
 *
 * @hdr_tbl_sz		- maximum size of the endpoint's header compression
 *			  table used to decode header blocks;
 * @push		- enable/disable indicator for server push;
 * @max_streams		- maximum number of streams that the endpoint will
 *			  allow;
 * @wnd_sz		- endpoint's initial window size for stream-level
 *			  flow control;
 * @max_frame_sz	- size of the largest frame payload the endpoint wish
 *			  to receive;
 * @max_lhdr_sz		- maximum size of header list the endpoint prepared
 *			  to accept;
 */
typedef struct {
	unsigned int hdr_tbl_sz;
	unsigned int push;
	unsigned int max_streams;
	unsigned int wnd_sz;
	unsigned int max_frame_sz;
	unsigned int max_lhdr_sz;
} TfwSettings;

/**
 * Context for HTTP/2 frames processing.
 *
 * @conn	- pointer to corresponding connection instance;
 * @lsettings	- local settings for HTTP/2 connection;
 * @rsettings	- settings for HTTP/2 connection received from the remote
 *		  endpoint;
 * @streams_num	- number of the streams initiated by client;
 * @sched	- streams' priority scheduler;
 * @lstream_id	- ID of last stream initiated by client and processed on the
 *		  server side;
 * @loc_wnd	- connection's current flow controlled window;
 * @__off	- offset to reinitialize processing context;
 * @skb_head	- collected list of processed skbs containing HTTP/2 frames;
 * @cur_stream	- found stream for the frame currently being processed;
 * @priority	- unpacked data from priority part of payload of processed
 *		  HEADERS or PRIORITY frames;
 * @hdr		- unpacked data from header of currently processed frame;
 * @state	- current FSM state of HTTP/2 processing context;
 * @to_read	- indicates how much data of HTTP/2 frame should
 *		  be read on next FSM @state;
 * @rlen	- length of accumulated data in @rbuf;
 * @rbuf	- buffer for data accumulation from frames headers and
 *		  payloads (for service frames) during frames processing;
 * @padlen	- length of current frame's padding (if exists);
 * @data_off	- offset of app data in HEADERS, CONTINUATION and DATA
 *		  frames (after all service payloads);
 */
struct tfw_http2_ctx_t {
	TfwConn		*conn;
	TfwSettings	lsettings;
	TfwSettings	rsettings;
	unsigned long	streams_num;
	TfwStreamSched	sched;
	unsigned int	lstream_id;
	unsigned int	loc_wnd;
	char		__off[0];
	struct sk_buff	*skb_head;
	TfwStream	*cur_stream;
	TfwFramePri	priority;
	TfwFrameHdr	hdr;
	int		state;
	int		to_read;
	int		rlen;
	unsigned char	rbuf[FRAME_HEADER_SIZE];
	unsigned char	padlen;
	unsigned char	data_off;
};

int tfw_http2_frame_process(void *c, TfwFsmData *data);
void tfw_http2_init(TfwHttp2Ctx *ctx);

#endif /* __HTTP_FRAME__ */
