/**
 *		Tempesta FW
 *
 * HTTP/2 (RFC-7540) protocol API.
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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

#ifndef HTTP2_H
#define HTTP2_H

#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "../http.h"
#include "errors.h"
#include "buffers.h"
#include "subs.h"
#include "hash.h"
#include "hpack.h"

typedef unsigned int HStreamId;

/* Basic states: */

enum {
	HTTP2_State_Preface = 0x10,
	HTTP2_State_Ready,
	HTTP2_State_Flags,
	HTTP2_State_StreamId,
	HTTP2_State_Skip,
	HTTP2_State_Close
};

/* Frame header states: */

enum {
	HTTP2_Frame_DATA = 0x0,
	HTTP2_Frame_HEADERS = 0x1,
	HTTP2_Frame_PRIORITY = 0x2,
	HTTP2_Frame_PST_STEAM = 0x3,
	HTTP2_Frame_SETTINGS = 0x4,
	HTTP2_Frame_PUSH_PROMISE = 0x5,
	HTTP2_Frame_PING = 0x6,
	HTTP2_Frame_GOAWAY = 0x7,
	HTTP2_Frame_WINDOW_UPDATE = 0x8,
	HTTP2_Frame_CONTINUATION = 0x9,
	HTTP2_Frame_Unknown
};

/* Additional states: */

enum {
	HTTP2_Frame_DATA_Payload = 0x20,
	HTTP2_Frame_HEADERS_Priority,
	HTTP2_Frame_HEADERS_Payload
};

/* HTTP/2 frame-related flags: */

enum {
	HTTP2_Flags_Settings_Ack = 0x01,
	HTTP2_Flags_End_Stream = 0x01,
	HTTP2_Flags_End_Headers = 0x04,
	HTTP2_Flags_Padded = 0x08,
	HTTP2_Flags_Priority = 0x20
};

/* Stream states: */

enum {
	HStream_State_Idle = 0,
	HStream_State_Open,
	HStream_State_Closed,
	HStream_State_Reserved,
	HStream_State_Half_Closed
};

/* id:	   Stream identifier.	      */
/* parent: Parent stream identifier.  */
/* state:  Stream state.	      */
/* weight: Stream weight.	      */
/* window: Current congestion window. */
/* error:  Error code.		      */
/* out:    Output buffer.	      */
/* pool:   Memory pool. 	      */

typedef struct HTTP2 HTTP2;

typedef struct {
	HStreamId id;
	HStreamId parent;
	unsigned int state;
	unsigned int weight;
	unsigned int window;
	unsigned int error;
	HTTP2Output out;
	TfwPool *pool;
	HTTP2 *http;
} HStream;

/* HTTP/2 settings, as decribed in the RFC-7540: */

enum {
	SETTINGS_HEADER_TABLE_SIZE = 0x1,
	SETTINGS_ENABLE_PUSH = 0x2,
	SETTINGS_MAX_CONCURRENT_STREAMS = 0x3,
	SETTINGS_INITIAL_WINDOW_SIZE = 0x4,
	SETTINGS_MAX_FRAME_SIZE = 0x5,
	SETTINGS_MAX_HEADER_LIST_SIZE = 0x6,
	SETTINGS_UNKNOWN
};

/* state:     Current state.		   */
/* frame:     Current frame type.	   */
/* length:    Current frame length.	   */
/* flags:     Current frame flags.	   */
/* stream:    Current stream.		   */
/* window:    Current congestion window    */
/*	      (for all streams).	   */
/* padding:   Padding length.		   */
/* is_client: Non-zero if HTTP2 object	   */
/*	      created by the client.	   */
/* pool:      Memory pool.		   */
/* hp:	      HPack decoder.		   */
/* hp_out:    HPack encoder.		   */
/* sub:       Sub-allocator for stream	   */
/*	      descriptors.		   */
/* streams:   Hash-table of streams.	   */
/* settings:  HTTP/2 protocol settings, as */
/*	      specified in the RFC-7540.   */
/* output:    Output buffer.		   */

struct HTTP2 {
	unsigned char state;
	unsigned char frame;
	unsigned char flags;
	uint32_t length;
	HStream * stream;
	unsigned char padding;
	uint32_t window;
	TfwPool * pool;
	HPack * hp;
	HPack * hp_out;
	Sub *sub;
	Hash *streams;
	uint32_t settings[6];
	HTTP2Output output;
};

void http2_decode(HTTP2 * __restrict http,
		  HTTP2Input * __restrict source,
		  uintptr_t n, unsigned int *__restrict rc);

unsigned int http2_close(HTTP2 * __restrict http, unsigned int rc);

unsigned int http2_send_header(HTTP2 * __restrict hp,
			       const HStreamId stream,
			       const HTTP2Field * __restrict source,
			       uintptr_t n);

unsigned int http2_send_data(HTTP2 * __restrict hp,
			     const HStreamId stream,
			     const TfwStr * __restrict data);

HTTP2 *http2_new(unsigned char is_encoder, TfwPool * __restrict pool);

void http2_free(HTTP2 * __restrict hp);

void http2_init(TfwPool * __restrict pool);

void http2_shutdown(void);

#endif
