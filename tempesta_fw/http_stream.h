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
#ifndef __HTTP_STREAM__
#define __HTTP_STREAM__

#include <linux/rbtree.h>

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
 * Representation of HTTP/2 stream entity.
 *
 * @node	- entry in per-connection storage of streams (red-black tree);
 * @id		- stream ID;
 * @state	- stream's current state;
 * @loc_wnd	- stream's current flow controlled window;
 * @weight	- stream's priority weight;
 */
typedef struct {
	struct rb_node		node;
	unsigned int		id;
	int			state;
	unsigned int		loc_wnd;
	unsigned short		weight;
} TfwStream;

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

int tfw_h2_stream_cache_create(void);
void tfw_h2_stream_cache_destroy(void);
TfwStreamFsmRes tfw_h2_stream_fsm(TfwStream *stream, unsigned char type,
				  unsigned char flags, TfwH2Err *err);
bool tfw_h2_stream_is_closed(TfwStream *stream);
TfwStream *tfw_h2_find_stream(TfwStreamSched *sched, unsigned int id);
TfwStream *tfw_h2_add_stream(TfwStreamSched *sched, unsigned int id,
			     unsigned short weight, unsigned int wnd);
void tfw_h2_streams_cleanup(TfwStreamSched *sched);
int tfw_h2_find_stream_dep(TfwStreamSched *sched, unsigned int id,
			   TfwStream **dep);
void tfw_h2_add_stream_dep(TfwStreamSched *sched, TfwStream *stream,
			   TfwStream *dep, bool excl);
void tfw_h2_change_stream_dep(TfwStreamSched *sched, unsigned int stream_id,
			      unsigned int new_dep, unsigned short new_weight,
			      bool excl);
void tfw_h2_stop_stream(TfwStreamSched *sched, TfwStream **stream);

#endif /* __HTTP_STREAM__ */
