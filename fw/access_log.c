/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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
#include "access_log.h"
#include "connection.h"
#include "server.h"
#include "http.h"
#include "lib/common.h"

static bool access_log_enabled = false;

/* Use small buffer because printk won't display strings longer that ~1000 bytes */
#define ACCESS_LOG_BUF_SIZE 990
static DEFINE_PER_CPU_ALIGNED(char[ACCESS_LOG_BUF_SIZE], access_log_buf);

/** Build string consists of chunks that belong to the header value.
 * If header value is empty, then it returns "-" to be nginx-like.
 *
 * @param http_version is TFW_HTTP_VER_xx enum
 * @param line is the request line from TfwHttpReq::h_tbl */
static TfwStr
get_http_header_value(char http_version, TfwStr *line)
{
	TfwStr result;
	size_t len = line->len;
	TfwStr *chunk = line->chunks, *end = chunk + line->nchunks;
	static TfwStr empty_hdr = TFW_STR_STRING("-");

	if (http_version >= TFW_HTTP_VER_09 && http_version <= TFW_HTTP_VER_11) {

		/* Should never get plain string from parser */
		if (TFW_STR_PLAIN(line))
			return TFW_STR_EMPTY(line) ? empty_hdr : *line;

		/* Skip over until ':' marker */
		for (; chunk < end; chunk++) {
			len -= chunk->len;
			if (chunk->len == 1 && *chunk->data == ':')
				break;
		}
		if (chunk == end)
			return empty_hdr;
		chunk++;

		/* Skip possible whitespace blocks */
		while (chunk < end && (chunk->flags & TFW_STR_OWS) != 0) {
			len -= chunk->len;
			chunk++;
		}
	} else {
		/* skip over chunks until HDR_VALUE one */
		while (chunk < end && (chunk->flags & TFW_STR_HDR_VALUE) == 0) {
			len -= chunk->len;
			chunk++;
		}
	}

	if (chunk == end)
		return empty_hdr;

	TFW_STR_INIT(&result);
	result.len = len;
	result.chunks = chunk;
	result.nchunks = end - chunk;
	return result;
}


static inline size_t
append_to_cstr_bounded(char *p, char *end, TfwStr *s,
		unsigned remaining, unsigned reserve)
{
	ssize_t limit, n;
	if (s == NULL)
		return 0;

	limit = (end - p) / remaining - reserve;
	if (limit <= 0)
		return 0;

	n = tfw_str_to_cstr(s, p, limit);
	if (n + 1 == limit && n >= 3) {
		p[n - 3] = '.';
		p[n - 2] = '.';
		p[n - 1] = '.';
	}
	p += n;

	return n;
}


void
do_access_log(TfwHttpResp *resp)
{
	do_access_log_req(resp->req, resp->status, resp->content_length);
}


void
do_access_log_req(TfwHttpReq *req, int status, unsigned long content_length)
{
	char *buf = this_cpu_ptr(access_log_buf);
	char *p = buf, *end = p + ACCESS_LOG_BUF_SIZE;

	if (!access_log_enabled)
		return;

#define CONCAT_TFW_STR(s, remaining, reserve)                      \
	p += append_to_cstr_bounded(p, end, s, remaining, reserve)
#define CONCAT_HDR(hdr_id, remaining, reserve) do {                \
                TfwStr hdr = get_http_header_value(req->version,   \
				req->h_tbl->tbl + hdr_id);         \
                CONCAT_TFW_STR(&hdr, remaining, reserve);          \
	} while (0)
#define CONCAT_PRINTF(fmt, ...) do {                               \
		p += snprintf(p, end - p, fmt, ##__VA_ARGS__);     \
		if (p >= end) goto overflow;                       \
	} while (0)
#define CONCAT_STR(str) do {                                       \
		if (p + sizeof(str) >= end) goto overflow;         \
		memcpy(p, str, sizeof(str) - 1);                   \
		p += sizeof(str) - 1;                              \
	} while (0)

	if (req)
		TODO_LOG_CONN(req);
	/* Resp->conn is NULL if invalid response had been received */
	if (req->conn && req->conn->peer)
		p = tfw_addr_fmt(&req->conn->peer->addr, TFW_NO_PORT, p);
	else
		CONCAT_STR("-");

	CONCAT_STR(" \"");
	if (req->vhost != NULL && !TFW_STR_EMPTY(&req->vhost->name))
		CONCAT_TFW_STR(&req->vhost->name, 3, 40);
	else
		CONCAT_STR("-");
#define CONCAT_CASE_STR(x, str) case x: CONCAT_STR(str); break

#define CONCAT_CASE_STR_XX(x, str) CONCAT_CASE_STR(x, XX(str))
	switch (req->method) {
#define XX(str) "\" \"" str " "
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_COPY,       "COPY");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_DELETE,     "DELETE");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_GET,        "GET");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_HEAD,       "HEAD");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_LOCK,       "LOCK");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_MKCOL,      "MKCOL");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_MOVE,       "MOVE");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_OPTIONS,    "OPTIONS");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_PATCH,      "PATCH");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_POST,       "POST");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_PROPFIND,   "PROPFIND");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_PROPPATCH,  "PROPPATCH");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_PUT,        "PUT");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_TRACE,      "TRACE");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_UNLOCK,     "UNLOCK");
	CONCAT_CASE_STR_XX(TFW_HTTP_METH_PURGE,      "PURGE");
	default: CONCAT_STR("-");
#undef XX
	}
	if (!TFW_STR_EMPTY(&req->uri_path))
		CONCAT_TFW_STR(&req->uri_path, 3,
			       8 + 2 + 10 + 1 + 20 + 2 + 3 + 1);
	else
		CONCAT_STR("-");
	switch (req->version) {
#define XX(str) " " str
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_09, "HTTP/0.9");
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_10, "HTTP/1.0");
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_11, "HTTP/1.1");
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_20, "HTTP/2.0");
#undef XX
	default: CONCAT_STR("-");
	}

	CONCAT_PRINTF("\" %d %lu \"", status, content_length);
	CONCAT_HDR(TFW_HTTP_HDR_REFERER, 2, 3 + 1);
	CONCAT_STR("\" \"");
	CONCAT_HDR(TFW_HTTP_HDR_USER_AGENT, 1, 1);
	CONCAT_STR("\"");

overflow:
	*(p < end ? p : end - 1) = 0;
	pr_info("%s\n", buf);
#undef CONCAT_CASE_STR_XX
#undef CONCAT_CASE_STR
#undef CONCAT_STR
#undef CONCAT_PRINTF
#undef CONCAT_HDR
#undef CONCAT_TFW_STR
}

static TfwCfgSpec tfw_http_specs[] = {
	{
		.name = "access_log",
		.deflt = "off",
		.handler = tfw_cfg_set_bool,
		.dest = &access_log_enabled,
		.allow_none = true,
		.allow_repeat = true,
	},
	{ 0 }
};

TfwMod tfw_access_log_mod  = {
	.name	= "access_log",
	.specs	= tfw_http_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_access_log_init(void)
{
	tfw_mod_register(&tfw_access_log_mod);
	return 0;
}

void
tfw_access_log_exit(void)
{
	tfw_mod_unregister(&tfw_access_log_mod);
}
