/**
 *		Tempesta FW
 *
 * HTTP/2 bufferization helpers for fragment-based parser.
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

#ifndef BUFFERS_H
#define BUFFERS_H

#include "common.h"

typedef struct HTTP2Buffer HTTP2Buffer;

typedef const uchar * http2_buffer_get (HTTP2Buffer * __restrict const p, uwide * __restrict length);
typedef const uchar * http2_buffer_next (HTTP2Buffer * __restrict const p, uwide * __restrict length);

struct HTTP2Buffer {
   http2_buffer_next *next;
   http2_buffer_get  *get;
   void 	     *fragment;
   const uchar	     *current;
   uwide	      n;
   uwide	      total;
};

void http2_buffer_init	(HTTP2Buffer * __restrict const p, void * fragment, uwide offset, uwide total);
void http2_buffer_shift (HTTP2Buffer * __restrict const p, const uchar * current);

#endif
