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

#ifndef HTTP2_API_H
#define HTTP2_API_H

#include "../pool.h"
#include "../str.h"
#include "../http.h"

typedef struct HTTP2 HTTP2;
typedef struct HStream HStream;

/* ------------------------------------------------------------------ */

HTTP2 *http2_api_new(TfwPool * pool, void *user);

void http2_api_close(HTTP2 * http);

void http2_api_destroy(HTTP2 * http);

typedef TfwHttpReq *http2_api_on_close(HTTP2 * http, void *user);

void http2_api_set_on_close(HTTP2 * http, http2_on_close * handler);

/* ------------------------------------------------------------------ */

typedef TfwHttpReq *http2_api_new_stream(HTTP2 * http,
					 HStream * stream, void *user);

void http2_set_new_stream(HTTP2 * http, http2_new_stream * handler);

typedef unsigned int
 http2_api_close_stream(HTTP2 * http, HStream * stream, TfwHttpReq * user);

void http2_api_set_close_stream(HTTP2 * http, http2_close_stream * handler);

typedef unsigned int
 http2_api_headers(HTTP2 * http, HStream * stream, TfwHttpReq * user);

void http2_api_set_headers(HTTP2 * http, http2_headers * handler);

typedef unsigned int

http2_api_data(HTTP2 * http,
	       HStream * stream, TfwHttpReq * user, TfwStr * new_data);

void http2_api_set_data(HTTP2 * http, http2_data * handler);

/* ------------------------------------------------------------------ */

typedef unsigned int
 http2_api_consumed(HTTP2 * http, TfwStr * fragment, void *user);

void http2_api_set_consumed(HTTP2 * http, http2_consumed * handler);

void http2_api_received(HTTP2 * http, TfwStr * data, void *user);

/* ------------------------------------------------------------------ */

typedef void *http2_api_allocate(void *user, unsigned int length);

typedef void
 http2_api_free(void *user, void *buffer, unsigned int length);

void http2_api_set_allocate(HTTP2 * http, http2_allocate * handler);

void http2_api_set_free(HTTP2 * http, http2_free * handler);

typedef unsigned int
 http2_api_send(void *user, void *buffer, unsigned int length);

void http2_api_set_send(HTTP2 * http, http2_send * handler);

/* ------------------------------------------------------------------ */

#endif
