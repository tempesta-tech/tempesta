/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2025 Tempesta Technologies, Inc.
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
#ifndef __HTTP2__
#define __HTTP2__

#include "http_frame.h"
#include "http_limits.h"

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
 * Control frame statistics.
 *
 * @ping_cnt		- Amount of ping frames in a time;
 * @settings_cnt	- Amount of settings frames in a time;
 * @rst_cnt		- Amount of rst stream frames in a time;
 * @priority_cnt	- Amount of priority frames in a time;
 * @ts			- Control frame time in seconds.
 */
typedef struct {
	unsigned int	ping_cnt;
	unsigned int	settings_cnt;	
	unsigned int	rst_cnt;
	unsigned int	priority_cnt;
	unsigned int	ts;
} CtrlFrameStat;

typedef struct tfw_conn_t TfwConn;

/**
 * Context for HTTP/2 frames processing.
 *
 * @lock		- spinlock to protect stream-request linkage;
 * @lsettings		- local settings for HTTP/2 connection;
 * @rsettings		- settings for HTTP/2 connection received from the
 *			  remote endpoint;
 * @lstream_id		- ID of last stream initiated by client and processed
 *			  on the server side;
 * @streams_num		- number of the streams initiated by client;
 * @sched		- streams priority scheduler;
 * @closed_streams	- queue of closed streams (in HTTP2_STREAM_CLOSED or
 *			  HTTP2_STREAM_REM_CLOSED state), which are waiting
 *			  for removal;
 * @idle_streams	- queue of idle streams (in HTTP2_STREAM_IDLE) state;
 * @loc_wnd		- connection's current flow controlled window;
 * @rem_wnd		- remote peer current flow controlled window;
 * @hpack		- HPACK context, used in processing of
 *			  HEADERS/CONTINUATION frames;
 * @cur_send_headers	- stream for which we have already started sending
 *			  headers, but have not yet sent the END_HEADERS flag;
 * @cur_recv_headers	- stream for which we have already started receiving
 *			  headers, but have not yet received the END_HEADERS
 *			  flag;
 * @error		- the stream where the error occurred;
 * @new_settings	- new settings to apply when ack is pushed to socket
 *			  write queue;
 * @settings_to_apply	- bitmap to save what settings we should apply. first
 *			  bit is used to fast check that we should apply new
 *			  settings. 1 - _HTTP2_SETTINGS_MAX - 1 bits are used
 *			  to save what @new_settings should be applyed. bits
 *			  from _HTTP2_SETTINGS_MAX are used to save what
 *			  settings we sent to the client;
 * @conn		- pointer to h2 connection of this context;
 * @stat		- ping and settings frames reception history;
 * @wnd_update_cnt	- count of received window update frames;
 * @data_bytes_sent	- count of sent data bytes;
 * @data_frames_sent	- count of sent data frames;
 * @__off		- offset to reinitialize processing context;
 * @skb_head		- collected list of processed skbs containing HTTP/2
 *			  frames;
 * @cur_stream		- found stream for the frame currently being processed;
 * @priority		- unpacked data from priority part of payload of
 *			  processed HEADERS or PRIORITY frames;
 * @hdr			- unpacked data from header of currently processed
 *			  frame;
 * @plen		- payload length of currently processed frame
 *			  (HEADERS/CONTINUATION/DATA frames);
 * @state		- current FSM state of HTTP/2 processing context;
 * @to_read		- indicates how much data of HTTP/2 frame should
 *			  be read on next FSM @state;
 * @rlen		- length of accumulated data in @rbuf
 *			  or length of the payload read in current FSM state;
 * @rbuf		- buffer for data accumulation from frames headers and
 *			  payloads (for service frames) during frames
 *			  processing;
 * @padlen		- length of current frame's padding (if exists);
 * @data_off		- offset of app data in HEADERS, CONTINUATION and DATA
 *			  frames (after all service payloads);
 *
 * NOTE: we can keep HPACK context in general connection-wide HTTP/2 context
 * (instead of separate HPACK context for each stream), since frames from other
 * streams cannot occur between the HEADERS/CONTINUATION frames of particular
 * stream (RFC 7540, sections 6.2, 6.10, 8.1).
 */
typedef struct tfw_h2_ctx_t {
	spinlock_t      lock;
	TfwSettings     lsettings;
	TfwSettings     rsettings;
	unsigned int    lstream_id;
	unsigned long   streams_num;
	TfwStreamSched  sched;
	TfwStreamQueue  closed_streams;
	TfwStreamQueue  idle_streams;
	long int        loc_wnd;
	long int        rem_wnd;
	TfwHPack        hpack;
	TfwStream       *cur_send_headers;
	TfwStream       *cur_recv_headers;
	TfwStream       *error;
	unsigned int    new_settings[_HTTP2_SETTINGS_MAX - 1];
	DECLARE_BITMAP  (settings_to_apply, 2 * _HTTP2_SETTINGS_MAX - 1);
	TfwH2Conn	*conn;
	CtrlFrameStat	stat[FRANG_FREQ];
	unsigned long	wnd_update_cnt;
	unsigned long	data_frames_sent;
	unsigned long	data_bytes_sent;
	char            __off[0];
	struct sk_buff  *skb_head;
	TfwStream       *cur_stream;
	TfwFramePri     priority;
	TfwFrameHdr     hdr;
	unsigned int    plen;
	int             state;
	int             to_read;
	int             rlen;
	unsigned char   rbuf[FRAME_HEADER_SIZE];
	unsigned char   padlen;
	unsigned char   data_off;
} TfwH2Ctx;

int tfw_h2_init(void);
void tfw_h2_cleanup(void);
TfwH2Ctx *tfw_h2_context_alloc(void);
void tfw_h2_context_free(TfwH2Ctx *ctx);
int tfw_h2_context_init(TfwH2Ctx *ctx, TfwH2Conn *conn);
void tfw_h2_context_clear(TfwH2Ctx *ctx);
int tfw_h2_check_settings_entry(TfwH2Ctx *ctx, unsigned short id,
				unsigned int val);
void tfw_h2_save_settings_entry(TfwH2Ctx *ctx, unsigned short id,
				unsigned int val);
void tfw_h2_apply_new_settings(TfwH2Ctx *ctx);
void tfw_h2_conn_terminate_close(TfwH2Ctx *ctx, TfwH2Err err_code, bool close,
				 bool attack);
void tfw_h2_conn_streams_cleanup(TfwH2Ctx *ctx);
void tfw_h2_current_stream_remove(TfwH2Ctx *ctx);
int tfw_h2_current_stream_send_rst(TfwH2Ctx *ctx, int err_code);
void tfw_h2_remove_idle_streams(TfwH2Ctx *ctx, unsigned int id);
void tfw_h2_closed_streams_shrink(TfwH2Ctx *ctx);
void tfw_h2_check_current_stream_is_closed(TfwH2Ctx *ctx);
TfwStream *tfw_h2_find_not_closed_stream(TfwH2Ctx *ctx, unsigned int id,
					 bool recv);
void tfw_h2_req_unlink_stream(TfwHttpReq *req);
void tfw_h2_req_unlink_and_close_stream(TfwHttpReq *req);
int tfw_h2_stream_xmit_prepare_resp(TfwStream *stream);
int tfw_h2_entail_stream_skb(struct sock *sk, TfwH2Ctx *ctx, TfwStream *stream,
			     unsigned int *len, bool should_split);
TfwStreamSchedEntry *tfw_h2_alloc_stream_sched_entry(TfwH2Ctx *ctx);
void tfw_h2_free_stream_sched_entry(TfwH2Ctx *ctx, TfwStreamSchedEntry *entry);
void tfw_h2_conn_recv_finish(TfwConn *conn);

static inline bool
tfw_h2_is_ready_to_send(TfwH2Ctx *ctx)
{
	return ctx->sched.root.active_cnt && ctx->rem_wnd;
}

static inline bool
tfw_h2_conn_or_stream_wnd_is_exceeded(TfwH2Ctx *ctx, TfwStream *stream)
{
	return ctx->rem_wnd <= 0 || stream->rem_wnd <= 0;
}

#endif /* __HTTP2__ */
