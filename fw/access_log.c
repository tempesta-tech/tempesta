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
#include "connection.h"
#include "server.h"
#include "http.h"
#include "lib/common.h"
#include <linux/timekeeping.h>

static bool access_log_enabled = false;

/** Build string consists of chunks that belong to the header value.
 * @param http_version is TFW_HTTP_VER_xx enum
 * @param line is the request line from TfwHttpReq::h_tbl */
static TfwStr
get_http_header_value(char http_version, TfwStr *line)
{
	WARN_ONCE(TFW_STR_PLAIN(line), "Got plain string from parser");
	if (TFW_STR_PLAIN(line))
		return *line;
	if (http_version >= TFW_HTTP_VER_09 && http_version <= TFW_HTTP_VER_11) {
		TfwStr result;
		TfwStr *chunk = line->chunks, *end = chunk + line->nchunks;
		for (; chunk < end; chunk++) {
			if (chunk->len == 1 && *chunk->data == ':')
				break;
		}
		if (chunk == end)
			return TFW_STR_STRING("");
		chunk++;
		while (chunk < end && (chunk->flags & TFW_STR_OWS) != 0)
			chunk++;
		if (chunk == end)
			return TFW_STR_STRING("");
		TFW_STR_INIT(&result);
		result.chunks = chunk;
		result.nchunks = end - chunk;
		return result;
	} else {
		WARN_ONCE(true, "HTTP/2.0 not handled yet");
		return *line;
	}
}

void tfw_str_info(TfwStr *str) {
	unsigned i = 0;
	const TfwStr *s, *end;
	pr_info("======================== %ld bytes, %d chunks", str->len, str->nchunks);
	TFW_STR_FOR_EACH_CHUNK(s, str, end) {
		pr_info("         chunk %d => %02x, len = %d, [%.*s]", i, s->flags, (int)s->len, (int)s->len, s->data);
		i++;
	}

}

void
do_access_log(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	// TODO: make it larger and per-cpu statically allocated
	char buf[1024], *p = buf, *end = buf + sizeof(buf);

#define CONCAT_TFW_STR(s) do {                               \
		if ((s) != NULL) {                           \
                        p += tfw_str_to_cstr(s, p, end - p); \
			if (p + 1 >= end) goto overflow;     \
		}                                            \
	} while (0)
#define CONCAT_HDR(hdr_id) do {                                  \
                TfwStr hdr = get_http_header_value(req->version, \
				req->h_tbl->tbl + hdr_id);       \
                CONCAT_TFW_STR(&hdr);                            \
	} while (0)
#define CONCAT_PRINTF(fmt, ...) do {                           \
		p += snprintf(p, end - p, fmt, ##__VA_ARGS__); \
		if (p >= end) goto overflow;                   \
	} while (0)
#define CONCAT_STR(str) do {                               \
		if (p + sizeof(str) >= end) goto overflow; \
		memcpy(p, str, sizeof(str) - 1);           \
		p += sizeof(str) - 1;                      \
	} while (0)

	/* Resp->conn is NULL if invalid response had been received */
	if (resp->conn && resp->conn->peer)
		p = tfw_addr_fmt(&resp->conn->peer->addr, TFW_NO_PORT, p);
	else
		CONCAT_STR("0.0.0.0");
	do {
		struct tm t;
		static const char months[12][4] = {
			"Jan", "Feb", "Mar",
			"Apr", "May", "Jun",
			"Jul", "Aug", "Sep",
			"Oct", "Nov", "Dec"
		};
		time64_t now =ktime_get_real_seconds();
		time64_to_tm(now, 0, &t);
		CONCAT_PRINTF(" [%d/%s/%ld:%02d:%02d:%02d +0000] \"",
			      t.tm_mday, months[t.tm_mon], 1900 + t.tm_year,
			      t.tm_hour, t.tm_min, t.tm_sec);
	} while (0);
	if (req->vhost != NULL)
		CONCAT_TFW_STR(&req->vhost->name);
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
	default: CONCAT_STR("UNKNOWN");
#undef XX
	}
	CONCAT_TFW_STR(&req->uri_path);

	switch (req->version) {
#define XX(str) " " str
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_09, "HTTP/0.9");
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_10, "HTTP/1.0");
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_11, "HTTP/1.1");
	CONCAT_CASE_STR_XX(TFW_HTTP_VER_20, "HTTP/2.0");
#undef XX
	default: CONCAT_STR("INVALID");
	}

	CONCAT_PRINTF("\" %d %lu \"", (int)resp->status, resp->content_length);
	CONCAT_HDR(TFW_HTTP_HDR_REFERER);
	CONCAT_STR("\" \"");
	CONCAT_HDR(TFW_HTTP_HDR_USER_AGENT);
	CONCAT_STR("\"");
overflow:
	*(p < end ? p : buf + sizeof(buf) - 1) = 0;
	pr_info("%s", buf);
	tfw_str_info(req->h_tbl->tbl + TFW_HTTP_HDR_COOKIE);
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
