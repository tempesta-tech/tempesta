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

typedef ufast HStreamId;

enum {
	HTTP2_State_Ready = 0,
	HTTP2_State_Length,
	HTTP2_State_Type,
	HTTP2_State_Flags,
	HTTP2_State_StreamId,
	HTTP2_State_Pad_Length,
	HTTP2_State_Data,
	HTTP2_State_Padding,
	HTTP2_State_Weight,
	HTTP2_State_Error_Code,
	HTTP2_State_Id,
	HTTP2_State_Value,
	HTTP2_State_Window_Size
};

enum {
	HTTP2_Type_DATA = 0x0,
	HTTP2_Type_HEADERS = 0x1,
	HTTP2_Type_PRIORITY = 0x2,
	HTTP2_Type_PST_STEAM = 0x3,
	HTTP2_Type_SETTINGS = 0x4,
	HTTP2_Type_PUSH_PROMISE = 0x5,
	HTTP2_Type_PING = 0x6,
	HTTP2_Type_GOAWAY = 0x7,
	HTTP2_Type_WINDOW_UPDATE = 0x8,
	HTTP2_Type_CONTINUATION = 0x9
};

#define HTTP2_State_Mask 15

enum {
	HStream_State_Idle = 0,
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

typedef struct {
	HStreamId id;
	HStreamId parent;
	ufast state;
	ufast weight;
	ufast window;
	ufast error;
	HTTP2Output out;
	TfwPool *pool;
} HStream;

/* state:  Current state.			  */
/* frame:  Current frame type.			  */
/* shift:  Current shift (used when integer	  */
/*	   decoding interrupted due to absence	  */
/*	   of the next fragment).		  */
/* saved:  Current integer value (see above).	  */
/* window: Current congestion window (for all	  */
/*	   streams).				  */
/* pool:   Memory pool. 			  */
/* hp:	   HPack encoder/decoder.		  */
/* sub:    Sub-allocator for HStream descriptors. */
/* hash:   Hash-table for HStream descriptors.	  */

typedef struct {
	ufast state;
	ufast frame;
	ufast shift;
	uwide saved;
	uwide window;
	TfwPool *pool;
	HPack *hp;
	Sub *sub;
	Hash *hash;
} HTTP2;

ufast http2_decode(HTTP2 * __restrict http,
		   HTTP2Input * __restrict source, uwide n);

ufast http2_send_header(HTTP2 * __restrict hp,
			const HStreamId stream,
			const HTTP2Field * __restrict source, uwide n);

ufast http2_send_data(HTTP2 * __restrict hp,
		      const HStreamId stream, const TfwStr * __restrict data);

HTTP2 *http2_new(byte is_encoder, TfwPool * __restrict pool);

void http2_free(HTTP2 * __restrict hp);

void http2_init(TfwPool * __restrict pool);

void http2_shutdown(void);

#endif
