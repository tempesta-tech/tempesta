/**
 *		Tempesta FW
 *
 * Copyright (C) 2022 Tempesta Technologies, Inc.
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

/* This thing describes access log format.
 * - FIXED => fixed string, passed as is
 * - UNTRUNCATABLE => this expression will never be truncated
 * - TRUNCATABLE => this expression will be truncated if it does not fit
 *   log buffer
 *
 * If you add new UNTRUNCATABLE/TRUNCATABLE field don't forget to also
 * set appropriate variable/array value in do_access_log_req()
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 ! Adding TRUNCATABLE field will compile !
 !  but won't work without changing the  !
 !       code that fills its value       !
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define ACCESS_LOG_LINE(FIXED, UNTRUNCATABLE, TRUNCATABLE) \
	FIXED(__BNR)                                       \
	UNTRUNCATABLE(client_ip)                           \
	FIXED(" \"")                                       \
	UNTRUNCATABLE(vhost)                               \
	FIXED("\" \"")                                     \
	UNTRUNCATABLE(method)                              \
	FIXED(" ")                                         \
	TRUNCATABLE(uri)                                   \
	FIXED(" ")                                         \
	UNTRUNCATABLE(version)                             \
	FIXED("\" ")                                       \
	UNTRUNCATABLE(status)                              \
	FIXED(" ")                                         \
	UNTRUNCATABLE(content_length)                      \
	FIXED(" \"")                                       \
	TRUNCATABLE(referer)                               \
	FIXED("\" \"")                                     \
	TRUNCATABLE(user_agent)                            \
	FIXED("\"")

static bool access_log_enabled = false;

/* Use small buffer because printk won't display strings longer that ~1000 bytes */
#define ACCESS_LOG_BUF_SIZE 960
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

	switch (http_version) {
	case TFW_HTTP_VER_09:
	case TFW_HTTP_VER_10:
	case TFW_HTTP_VER_11:
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
		break;
	case TFW_HTTP_VER_20:
		/* skip over chunks until HDR_VALUE one */
		while (chunk < end && (chunk->flags & TFW_STR_HDR_VALUE) == 0) {
			len -= chunk->len;
			chunk++;
		}
		break;
	default:
		return empty_hdr;
	}

	if (chunk == end)
		return empty_hdr;

	TFW_STR_INIT(&result);
	result.len = len;
	result.chunks = chunk;
	result.nchunks = end - chunk;
	return result;
}


/* Helpers for const=>name conversions for http methods and versions */
static const struct {
#	define MAX_HTTP_METHOD_NAME_LEN	10
	char name[MAX_HTTP_METHOD_NAME_LEN];
	u8 len;
} http_methods[] = {
#define STR_METHOD(name) [TFW_HTTP_METH_ ## name] = { #name, sizeof(#name) - 1 }
	STR_METHOD(COPY),
	STR_METHOD(DELETE),
	STR_METHOD(GET),
	STR_METHOD(HEAD),
	STR_METHOD(LOCK),
	STR_METHOD(MKCOL),
	STR_METHOD(MOVE),
	STR_METHOD(OPTIONS),
	STR_METHOD(PATCH),
	STR_METHOD(POST),
	STR_METHOD(PROPFIND),
	STR_METHOD(PROPPATCH),
	STR_METHOD(PUT),
	STR_METHOD(TRACE),
	STR_METHOD(UNLOCK),
	STR_METHOD(PURGE),
#undef STR_METHOD
};

static const struct {
#	define MAX_HTTP_VERSION_LEN 9
	char name[MAX_HTTP_VERSION_LEN];
	u8 len;
} http_versions[] = {
#define STR_VERSION(ver, name) [ver] = { name, sizeof(name) - 1 }
	STR_VERSION(TFW_HTTP_VER_09, "HTTP/0.9"),
	STR_VERSION(TFW_HTTP_VER_10, "HTTP/1.0"),
	STR_VERSION(TFW_HTTP_VER_11, "HTTP/1.1"),
	STR_VERSION(TFW_HTTP_VER_20, "HTTP/2.0"),
#undef STR_VERSION
};

enum {
#define IGNORE(...)
#define ENUM(id) idx_ ## id,
	ACCESS_LOG_LINE(IGNORE, IGNORE, ENUM)
#undef ENUM
#undef IGNORE
	TRUNCATABLE_FIELDS_COUNT
};

/**
 * Copies string to buffer if it is not plain. Returns pointer to the
 * first unused character in the "planar" buffer.
 */
static inline char*
make_plain(char *p, char *end, TfwStr *src, BasicStr *dst)
{
	if (TFW_STR_PLAIN(src)) {
		dst->data = src->data;
		dst->len = src->len;
		return p;
	} /* protect from BUG_ON in tfw_str_to_cstr */
	else if (p < end) {
		dst->len = tfw_str_to_cstr(src, p, end - p);
		dst->data = p;
		return p + dst->len;
	} else {
		dst->data = "";
		dst->len = 0;
		return p;
	}
}

/**
 * Truncates truncatable fields if needed.
 */
static void
process_truncated(TfwStr *in, BasicStr *out, char *p, char *end,
		  unsigned used_chars)
{
	unsigned i;
	unsigned total_len = 0;
	unsigned truncated_count = 0;
	unsigned max_untruncated_len, buf_avail;
	
	if (unlikely(used_chars >= ACCESS_LOG_BUF_SIZE))
		goto no_buffer_space;
	
	/* Compute total length of all strings that can be truncated */
	for (i = 0; i < TRUNCATABLE_FIELDS_COUNT; i++)
		total_len += in[i].len;
	
	/* Check if we're on happy path: all strings fit */
	if (likely(total_len + used_chars < ACCESS_LOG_BUF_SIZE)) {
		for (i = 0; i < TRUNCATABLE_FIELDS_COUNT; i++)
			p = make_plain(p, end, in + i, out + i);
		return;
	}
	
	/* Unhappy path: evenly distribute available buffer space across all
	 * strings that do not fit */
	buf_avail = (ACCESS_LOG_BUF_SIZE - used_chars);
	/* This division by constant usually gets optimized by compiler with
	 * multiplication/shifts */
	max_untruncated_len = buf_avail / TRUNCATABLE_FIELDS_COUNT;
	
	for (i = 0; i < TRUNCATABLE_FIELDS_COUNT; i++) {
		/* we loose some chars due to string "less than", but
		 * tfw_str_to_cstr accounts terminating NUL to total buffer
		 * length and would truncate strings anyways */
		if (in[i].len < max_untruncated_len)
			total_len -= in[i].len;
		else
			truncated_count++;
	}
	
	max_untruncated_len = buf_avail / truncated_count;
	if (max_untruncated_len < sizeof("..."))
		goto no_buffer_space;

	/* Now tuncate/plainarize strings */
	for (i = 0; i < TRUNCATABLE_FIELDS_COUNT; i++) {
		if (in[i].len < max_untruncated_len) {
			p = make_plain(p, end, in + i, out + i);
		} else {
			/* we need only part of the string + "...", so
			 * we have to enforce string copy */
			out[i].data = p;
			out[i].len = max_untruncated_len;
			tfw_str_to_cstr(in + i, p, max_untruncated_len);
			memcpy_fast(p + max_untruncated_len - 3,
			            "...", sizeof("...") - 1);
			p += max_untruncated_len;
		}
	}
	return;

no_buffer_space:
	/* We're getting here only if untruncatable/fixed fields are
	 * ACCESS_LOG_BUF_SIZE or above bytes length.
	 * In this extreme case the best we can do is just */
	for (i = 0; i < TRUNCATABLE_FIELDS_COUNT; i++) {
		out[i].data = "";
		out[i].len = 0;
	}
}

void
do_access_log_req(TfwHttpReq *req, int resp_status, unsigned long resp_content_length)
{
	char *buf = this_cpu_ptr(access_log_buf);
	char *p = buf, *end = buf + ACCESS_LOG_BUF_SIZE;
	BasicStr client_ip, vhost, method, version;
	/* These fields are only here to hold estimation of appropriate fields
	 * length in characters */
	BasicStr status, content_length;
	BasicStr missing = { "-", 1 };
	TfwStr truncated_in[TRUNCATABLE_FIELDS_COUNT];
	BasicStr truncated_out[TRUNCATABLE_FIELDS_COUNT];

	/* Check if logging is enabled */
	if (!access_log_enabled)
		return;
	
	/* client_ip
	 *
	 * this BUG_ON would only trigger if
	 * ACCESS_LOG_BUF_SIZE < TFW_ADDR_STR_BUF_SIZE
	 * which should be always false */
	BUG_ON(end - p < TFW_ADDR_STR_BUF_SIZE);
#define FMT_client_ip "%.*s"
#define ARG_client_ip , (int)client_ip.len, client_ip.data
	if (req->conn && req->conn->peer) {
		client_ip.data = p;
		p = tfw_addr_fmt(&req->conn->peer->addr, TFW_NO_PORT, p);
		client_ip.len = p - client_ip.data;
	} else {
		client_ip = missing;
	}

	/* vhost */
#define FMT_vhost "%.*s"
#define ARG_vhost , (int)vhost.len, vhost.data
	vhost = req->vhost && req->vhost->name.len ? req->vhost->name : missing;

	/* method */
#define FMT_method "%.*s"
#define ARG_method , (int)method.len, method.data
	if (req->method < sizeof(http_methods) / sizeof(*http_methods)
	    && http_methods[req->method].len != 0)
	{
		method.data = (char *)http_methods[req->method].name;
		method.len = http_methods[req->method].len;
	} else {
		method = missing;
	}

	/* http version */
#define FMT_version "%.*s"
#define ARG_version , (int)version.len, version.data
	if (req->version < sizeof(http_versions) / sizeof(*http_versions)
	    && http_versions[req->version].len != 0)
	{
		version.data = (char *)http_versions[req->version].name;
		version.len = http_versions[req->version].len;
	} else {
		version = missing;
	}
	
	/* status, content_length */
	/* NOTE: we only roughly estimate lengths of numbers, leaving final
	 * transformation to printk. This has some side-effects like string
	 * will be truncated while being smaller that destination buffer, but
	 * that would do for a while */
#define FMT_status "%d"
#define ARG_status , resp_status
#define FMT_content_length "%lu"
#define ARG_content_length , resp_content_length
	status.data = "";
	status.len = 10; /* len(str(2**32)) */
	content_length.data = "";
	content_length.len = 20; /* len(str(2**64)) */
	
	/* Process truncated fields */
	truncated_in[idx_uri] = req->uri_path;
#define ADD_HDR(id, tfw_hdr_id)                                        \
		truncated_in[id] = get_http_header_value(req->version, \
				req->h_tbl->tbl + tfw_hdr_id);
	ADD_HDR(idx_referer, TFW_HTTP_HDR_REFERER);
	ADD_HDR(idx_user_agent, TFW_HTTP_HDR_USER_AGENT);
	
	/* Now we calculate first estimation of
	 * "maximum allowed truncated string length" */
#define ESTIMATE_FIXED(str) + (sizeof(str) - 1)
#define ESTIMATE_UNTRUNCATABLE(id) + id.len
#define ESTIMATE_TRUNCATABLE(id)
	process_truncated(truncated_in, truncated_out, p, end,
			ACCESS_LOG_LINE(ESTIMATE_FIXED, ESTIMATE_UNTRUNCATABLE,
					ESTIMATE_TRUNCATABLE));

	/* Use macro to build format string */
#define FMT_FIXED(str) str
#define FMT_UNTRUNCATABLE(id) FMT_ ## id
#define FMT_TRUNCATABLE(id) "%.*s"
#define ARG_FIXED(str)
#define ARG_UNTRUNCATABLE(id) ARG_ ## id
#define ARG_TRUNCATABLE(id) , (int)truncated_out[idx_ ## id].len, \
		truncated_out[idx_ ## id].data
	/* Calling pr_info(ACCESS_LOG_LINE...) directly won't work because
	 * preprocessor would treat whole expression as a single argument,
	 * so we need additional level of macro expansion. */
#define DO_PR_INFO(...) pr_info(__VA_ARGS__)
	DO_PR_INFO(
		ACCESS_LOG_LINE(FMT_FIXED, FMT_UNTRUNCATABLE, FMT_TRUNCATABLE) "\n"
		ACCESS_LOG_LINE(ARG_FIXED, ARG_UNTRUNCATABLE, ARG_TRUNCATABLE)
	);

	/* Undefine all locally defined macros.
	 * You can use following oneliner to regenerate this list
	 * sed -nre '/^do_access_log_req/,/^\}/{s@^#[[:space:]]*define[[:space:]]*([^([:space:]]+).*@#undef \1@p}' fw/access_log.c | tac
	 */
#undef DO_PR_INFO
#undef ARG_TRUNCATABLE
#undef ARG_UNTRUNCATABLE
#undef ARG_FIXED
#undef FMT_TRUNCATABLE
#undef FMT_UNTRUNCATABLE
#undef FMT_FIXED
#undef ESTIMATE_TRUNCATABLE
#undef ESTIMATE_UNTRUNCATABLE
#undef ESTIMATE_FIXED
#undef ADD_HDR
#undef ARG_content_length
#undef FMT_content_length
#undef ARG_status
#undef FMT_status
#undef ARG_version
#undef FMT_version
#undef ARG_method
#undef FMT_method
#undef ARG_vhost
#undef FMT_vhost
#undef ARG_client_ip
#undef FMT_client_ip
}

void
do_access_log(TfwHttpResp *resp)
{
	do_access_log_req(resp->req, resp->status, resp->content_length);
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
