/**
 *		Tempesta FW
 *
 * Copyright (C) 2022-2026 Tempesta Technologies, Inc.
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
#include "event_log.h"
#include "connection.h"
#include "server.h"
#include "http.h"
#include "mmap_buffer.h"
#include "lib/common.h"

#include <linux/jiffies.h>

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
#define ACCESS_LOG_LINE(FIXED, UNTRUNCATABLE, TRUNCATABLE)	\
	FIXED(__BNR)						\
	UNTRUNCATABLE(client_ip)				\
	FIXED(" \"")						\
	UNTRUNCATABLE(vhost)					\
	FIXED("\" \"")						\
	TRUNCATABLE(method)					\
	FIXED(" ")						\
	TRUNCATABLE(uri)					\
	FIXED(" ")						\
	UNTRUNCATABLE(version)					\
	FIXED("\" ")						\
	UNTRUNCATABLE(status)					\
	FIXED(" ")						\
	UNTRUNCATABLE(content_length)				\
	FIXED(" \"")						\
	TRUNCATABLE(referer)					\
	FIXED("\" \"")						\
	TRUNCATABLE(user_agent)					\
	FIXED("\" \"")						\
	UNTRUNCATABLE(tf_tls)					\
	FIXED("\" \"")						\
	UNTRUNCATABLE(tf_http)					\
	FIXED("\"")

#define MMAP_LOG_PATH "tempesta_mmap_log"

int access_log_type = ACCESS_LOG_OFF;
static TfwMmapBufferHolder *mmap_buffer;

/* Use small buffer because printk won't display strings longer that ~1000 bytes */
#define ACCESS_LOG_BUF_SIZE 960
static DEFINE_PER_CPU_ALIGNED(char[ACCESS_LOG_BUF_SIZE], access_log_buf);
static DEFINE_PER_CPU_ALIGNED(u64, mmap_log_dropped);
static long mmap_log_buffer_size;

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

/**
 * The set of fnctions to write data into the buffer.
 *
 * There are two groups of types: fixed-size and dynamic-size.
 * Fixed-size types are copied directly into the buffer in the order defined
 * by the record structure.
 * Dynamic-size types consist of two parts: a 16-bit length field and a body
 * with a maximum length of 16 bits. The length is written first, followed by
 * the body.
 *
 * To write into the buffer fixed-size type use pre-defined helpers
 * tfw_log_write_(typename), or if necessary define the new one using
 * DEFINE_TYPED_LOG_WRITE/DEFINE_TYPED_LOG_WRITE_ALIAS macros. For dynamic-size
 * type such as string use tfw_log_write_bin() and tfw_log_write_tfwstr_as_bin()
 * for TfwStr. Each serialized type MUST have its own helper function. The
 * helper does not enforce the argument's exact type at compile time but its
 * type-specific name documents the serialization schema at each call site.
 *
 * Some types may have a different type from defined bu the record, for instance,
 * struct TlsTft is a struct with few fileds, but defined as unsigned long by the
 * record type TFW_MMAP_LOG_TYPE_ACCESS. To write such type into the buffer
 * we define aliased helper using DEFINE_TYPED_LOG_WRITE_ALIAS, to have
 * compile-time check ensures that type struct TlsTft has the size of unsigned
 * long.
 */

/*
 * Define helper to write data into the buffer. The @name must contain the name
 * of the type, explicitly define the type. For instance, helper for unsigned
 * short must include the word ushort in its name, resulting in tfw_log_write_ushort.
 */
#define DEFINE_TYPED_LOG_WRITE(name, type)					\
	__DEFINE_TYPED_LOG_WRITE(name, type, {})

/*
 * The same as DEFINE_TYPED_LOG_WRITE but add compile-time check ensures that
 * written type has the same size as defined by record type. See example in
 * the description to this function set.
 */
#define DEFINE_TYPED_LOG_WRITE_ALIAS(name, underlying_type, type)		\
	__DEFINE_TYPED_LOG_WRITE(name, type, {					\
		BUILD_BUG_ON(sizeof(type) != sizeof(underlying_type));		\
	})

#define __DEFINE_TYPED_LOG_WRITE(name, type, type_assert)                       \
static inline __must_check int							\
tfw_log_write_##name(char **buff, type val, unsigned int *room_size)		\
{										\
	type_assert;								\
	if (unlikely(*room_size < sizeof(type)))				\
		return -ENOSPC;							\
	*(type *)(*buff) = val;							\
	*buff += sizeof(type);							\
	*room_size -= sizeof(type);						\
	return 0;								\
}

static inline __must_check int
tfw_log_write_bin(char **buff, const void *data, size_t size,
		  unsigned int *room_size)
{
	TfwLogFieldLen data_len = min_t(size_t, size,
					TFW_EVENT_LOG_MAX_BIN_LEN);
	unsigned int total_len = data_len + sizeof(data_len);

	if (unlikely(*room_size < total_len))
		return -ENOSPC;

	/* Write size of the data. */
	*(TfwLogFieldLen *)(*buff) = data_len;
	*buff += sizeof(data_len);

	memcpy_fast(*buff, data, data_len);
	*buff += data_len;
	*room_size -= total_len;

	return 0;
}

static inline __must_check int
tfw_log_write_tfwstr_as_bin(char **buff, const TfwStr *str,
			    unsigned int *room_size)
{
	const TfwStr *c, *end;
	TfwLogFieldLen len = min_t(size_t, str->len, TFW_EVENT_LOG_MAX_BIN_LEN);

	if (unlikely(*room_size < len + sizeof(len)))
		return -ENOSPC;

	/* Write size of the data. */
	*(TfwLogFieldLen *)(*buff) = len;
	*buff += sizeof(len);
	*room_size -= sizeof(len);

	TFW_STR_FOR_EACH_CHUNK(c, str, end) {
		TfwLogFieldLen cur_len = min_t(size_t, len, c->len);

		memcpy_fast(*buff, c->data, cur_len);
		*buff += cur_len;
		len -= cur_len;
		*room_size -= cur_len;
	}

	return 0;
}

DEFINE_TYPED_LOG_WRITE(uchar, u8)
DEFINE_TYPED_LOG_WRITE(ushort, u16)
DEFINE_TYPED_LOG_WRITE(uint, u32)
DEFINE_TYPED_LOG_WRITE(ulong, u64)
DEFINE_TYPED_LOG_WRITE(ipv6, struct in6_addr)
DEFINE_TYPED_LOG_WRITE_ALIAS(tft_as_ulong, unsigned long, TlsTft)
DEFINE_TYPED_LOG_WRITE_ALIAS(tfh_as_ulong, unsigned long, HttpTfh)

/*
 * Use these aliases when only the serialized width of fixed-size data matters.
 * They do not enforce whether the argument is signed or unsigned.
 */
#define tfw_log_write_8bit tfw_log_write_uchar
#define tfw_log_write_16bit tfw_log_write_ushort
#define tfw_log_write_32bit tfw_log_write_uint
#define tfw_log_write_64bit tfw_log_write_ulong

static inline __must_check int
tfw_log_vwrite_bin(char **buff, unsigned int *room_size, const char *fmt,
		   va_list args)
{
	unsigned long long num;
	unsigned char type = FORMAT_TYPE_NONE;
	int precision;
	TfwLogFieldLen *size = (TfwLogFieldLen *)(*buff);

	if (unlikely(*room_size < sizeof(TfwLogFieldLen)))
		return -ENOSPC;

	*size = 0;
	*buff += sizeof(TfwLogFieldLen);
	*room_size -= sizeof(TfwLogFieldLen);

	while (*fmt) {
		int read = format_decode(fmt, &type, &precision);

		fmt += read;

		switch (type) {
		case FORMAT_TYPE_INVALID:
			goto drop;
		case FORMAT_TYPE_UBYTE:
		case FORMAT_TYPE_BYTE:
		case FORMAT_TYPE_CHAR:
			unsigned char c = (unsigned char)va_arg(args, int);

			if (tfw_log_write_8bit(buff, c, room_size))
				goto drop;
			*size += sizeof(char);
			break;
		case FORMAT_TYPE_STR:
			char *str = va_arg(args, char *);
			TfwLogFieldLen max_len = TFW_EVENT_LOG_MAX_BIN_LEN -
				sizeof(TfwLogFieldLen);
			size_t len;

			/*
			 * Handle %.*s format and regular null-terminated
			 * string.
			 */
			len = precision > -1 ? precision : strlen(str);

			if (len > max_len)
				return -EINVAL;

			if (unlikely(*room_size < len + sizeof(TfwLogFieldLen)))
				return -ENOSPC;

			/* Write size of the data. */
			*(TfwLogFieldLen *)(*buff) = len;
			*buff += sizeof(TfwLogFieldLen);

			memcpy_fast(*buff, str, len);
			*buff += len;
			*room_size -= len + sizeof(TfwLogFieldLen);
			*size += len + sizeof(TfwLogFieldLen);
			break;
		case FORMAT_TYPE_ULONG:
		case FORMAT_TYPE_LONG:
			num = va_arg(args, long);
			if (tfw_log_write_64bit(buff, num, room_size))
				goto drop;
			*size += sizeof(unsigned long);
			break;
		case FORMAT_TYPE_USHORT:
		case FORMAT_TYPE_SHORT:
			num = (short) va_arg(args, int);

			if (tfw_log_write_16bit(buff, num, room_size))
				goto drop;
			*size += sizeof(short);
			break;
		case FORMAT_TYPE_UINT:
		case FORMAT_TYPE_INT:
			num = (int) va_arg(args, int);
			if (tfw_log_write_32bit(buff, num, room_size))
				goto drop;
			*size += sizeof(unsigned int);
			break;
		case FORMAT_TYPE_PRECISION:
			precision = (int) va_arg(args, int);
			break;
		default:
			WARN_ONCE(1, "Unsupported pattern for binary field\n");
			goto drop;
		}
	}

	return 0;

drop:
	return -1;
}

static void
do_access_log_req_mmap(TfwHttpReq *req, u16 resp_status,
		       u64 resp_content_length)
{
	u64 *dropped = this_cpu_ptr(&mmap_log_dropped), dropped_tmp;
	TfwBinLogEvent *event;
	unsigned int room_size, resp_time;
	TfwStr referer, ua;
	char *data, *p;
	struct timespec64 ts;
	TlsTft *tls_tft = TFW_CONN_TLS(req->conn) ?
		&tfw_tls_context(req->conn)->sess.tft : NULL;

	room_size = tfw_mmap_buffer_get_room(mmap_buffer, &data);
	if (room_size < sizeof(TfwBinLogEvent))
		goto drop;

	room_size -= sizeof(TfwBinLogEvent);

	event = (TfwBinLogEvent *)data;
	p = data + sizeof(TfwBinLogEvent);

	tfw_current_timestamp_ts64(&ts);
	event->timestamp = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
	event->type = TFW_MMAP_LOG_TYPE_ACCESS;
	/* Enable all the fields */
	event->fields = TFW_MMAP_LOG_ENABLE_ALL_FIELDS(TFW_MMAP_LOG_MAX);

	if (tfw_log_write_ipv6(&p, req->conn->peer->addr.sin6_addr, &room_size))
		goto drop;
	if (tfw_log_write_uchar(&p, req->method, &room_size))
		goto drop;
	if (tfw_log_write_uchar(&p, req->version, &room_size))
		goto drop;
	if (tfw_log_write_ushort(&p, resp_status, &room_size))
		goto drop;
	if (tfw_log_write_ulong(&p, resp_content_length, &room_size))
		goto drop;
	resp_time = jiffies_to_msecs(jiffies - req->jrxtstamp);
	if (tfw_log_write_uint(&p, resp_time, &room_size))
		goto drop;

	if (req->vhost && req->vhost->name.len) {
		if (tfw_log_write_bin(&p, req->vhost->name.data,
				      req->vhost->name.len,
				      &room_size))
			goto drop;
	} else {
		TFW_MMAP_LOG_FIELD_RESET(event, TFW_MMAP_LOG_VHOST);
	}

	if (tfw_log_write_tfwstr_as_bin(&p, &req->uri_path, &room_size))
		goto drop;

	referer = get_http_header_value(req->version,
					req->h_tbl->tbl + TFW_HTTP_HDR_REFERER);
	if (tfw_log_write_tfwstr_as_bin(&p, &referer, &room_size))
		goto drop;

	ua = get_http_header_value(req->version,
				   req->h_tbl->tbl + TFW_HTTP_HDR_USER_AGENT);
	if (tfw_log_write_tfwstr_as_bin(&p, &ua, &room_size))
		goto drop;

	if (tls_tft) {
		if (tfw_log_write_tft_as_ulong(&p, *tls_tft, &room_size))
			goto drop;
	} else {
		TFW_MMAP_LOG_FIELD_RESET(event, TFW_MMAP_LOG_TFT);
	}

	if (tfw_log_write_tfh_as_ulong(&p, req->tfh, &room_size))
		goto drop;

	if (*dropped) {
		if (tfw_log_write_ulong(&p, *dropped, &room_size))
			goto drop;
		/* Save dropped to restore if commit failed. */
		dropped_tmp = *dropped;
		*dropped = 0;
	} else {
		TFW_MMAP_LOG_FIELD_RESET(event, TFW_MMAP_LOG_DROPPED);
	}

	if (tfw_mmap_buffer_commit(mmap_buffer, p - data) != 0) {
		T_DBG("Incorrect data size at commit: %ld", p - data);
		*dropped = dropped_tmp;
		goto drop;
	}

	return;

drop:
	++*dropped;
}

void
_log_security_event(TfwLogEventType event_type, TfwEventParams params,
		    const TfwAddr *addr, unsigned short local_port,
		    bool ip_block, const char *fmt,
		    ...)
{
	u64 *dropped = this_cpu_ptr(&mmap_log_dropped), dropped_tmp = 0;
	TfwBinLogEvent *event;
	unsigned int room_size;
	char *data, *p;
	struct timespec64 ts;
	va_list args;
	int r;

	room_size = tfw_mmap_buffer_get_room(mmap_buffer, &data);
	if (room_size < sizeof(TfwBinLogEvent))
		goto drop;

	room_size -= sizeof(TfwBinLogEvent);

	event = (TfwBinLogEvent *)data;
	p = data + sizeof(TfwBinLogEvent);

	tfw_current_timestamp_ts64(&ts);
	event->timestamp = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
	event->type = params.type;
	/* Enable all the fields */
	event->fields = params.fields_max;

	/* Client address */
	r = tfw_log_write_ipv6(&p, addr->sin6_addr, &room_size);
	if (unlikely(r))
		goto drop;

	/* Client port */
	r = tfw_log_write_ushort(&p, ntohs(addr->sin6_port), &room_size);
	if (unlikely(r))
		goto drop;

	/* Local port */
	r = tfw_log_write_ushort(&p, ntohs(local_port), &room_size);
	if (unlikely(r))
		goto drop;

	/* Event type */
	r = tfw_log_write_ushort(&p, event_type, &room_size);
	if (unlikely(r))
		goto drop;

	if (!fmt) {
		TFW_MMAP_LOG_FIELD_RESET(event, params.body_field);
	} else {
		/* Event body */
		va_start(args, fmt);
		r = tfw_log_vwrite_bin(&p, &room_size, fmt, args);
		va_end(args);
		if (r)
			goto drop;
	}

	/* IP block */
	r = tfw_log_write_uchar(&p, ip_block, &room_size);
	if (unlikely(r))
		goto drop;

	/* Dropped events */
	if (*dropped) {
		r = tfw_log_write_ulong(&p, *dropped, &room_size);
		if (unlikely(r))
			goto drop;
		/* Save dropped to restore if commit failed. */
		dropped_tmp = *dropped;
		*dropped = 0;
	} else {
		TFW_MMAP_LOG_FIELD_RESET(event, params.dropped_field);
	}

	if (tfw_mmap_buffer_commit(mmap_buffer, p - data) != 0) {
		T_DBG("Incorrect data size at commit: %ld", p - data);
		*dropped = dropped_tmp;
		goto drop;
	}

	return;

drop:
	++*dropped;
}

static void
do_access_log_req_dmesg(TfwHttpReq *req, int resp_status,
			unsigned long resp_content_length)
{
	char *buf = this_cpu_ptr(access_log_buf);
	char *p = buf, *end = buf + ACCESS_LOG_BUF_SIZE;
	BasicStr client_ip, vhost, version;
	/* These fields are only here to hold estimation of appropriate fields
	 * length in characters */
	BasicStr status, content_length, tf_tls, tf_http;
	BasicStr missing = { "-", 1 };
	TfwStr truncated_in[TRUNCATABLE_FIELDS_COUNT];
	BasicStr truncated_out[TRUNCATABLE_FIELDS_COUNT];
	TlsTft *tls_tft = TFW_CONN_TLS(req->conn) ?
		&tfw_tls_context(req->conn)->sess.tft : NULL;

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

	if (!TFW_MSG_H2(req))
		truncated_in[idx_method] = req->h_tbl->tbl[TFW_HTTP_METHOD];
	else
		ADD_HDR(idx_method, TFW_HTTP_METHOD);

	ADD_HDR(idx_referer, TFW_HTTP_HDR_REFERER);
	ADD_HDR(idx_user_agent, TFW_HTTP_HDR_USER_AGENT);

#define FMT_tf_tls "tft=%llx"
#define ARG_tf_tls , (tls_tft ? *(u64 *)tls_tft : 0)
	tf_tls.data = "";
	tf_tls.len = 16;
#define FMT_tf_http "tfh=%llx"
#define ARG_tf_http , (*(u64 *)&req->tfh)
	tf_http.data = "";
	tf_http.len = 16;

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
	 * sed -nre '/^do_access_log_req/,/^\}/{s@^#[[:space:]]*define[[:space:]]*([^([:space:]]+).*@#undef \1@p}' fw/event_log.c | tac
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
#undef ARG_vhost
#undef FMT_vhost
#undef ARG_client_ip
#undef FMT_client_ip
#undef FMT_tf_tls
#undef ARG_tf_tls
#undef FMT_tf_http
#undef ARG_tf_http
}

void
do_access_log_req(TfwHttpReq *req, int resp_status,
		  unsigned long resp_content_length)
{
	if (access_log_type & ACCESS_LOG_MMAP)
		do_access_log_req_mmap(req, (u16)resp_status, resp_content_length);

	if (access_log_type & ACCESS_LOG_DMESG)
		do_access_log_req_dmesg(req, resp_status, resp_content_length);
}

void
do_access_log(TfwHttpResp *resp)
{
	do_access_log_req(resp->req, resp->status,
			  resp->content_length ? :
			  TFW_HTTP_RESP_CUT_BODY_SZ(resp));
}

static int
cfg_access_log_set(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int i;
	const char *val;
	bool off = false;

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (strcasecmp(val, "off") == 0) {
			off = true;
		} else if (strcasecmp(val, "dmesg") == 0) {
#ifndef DEBUG
			T_WARN("Using the access log via `dmesg` has significant performance"
			       " overhead and may lead to kernel hangs under high loa\n");
#endif
			access_log_type |= ACCESS_LOG_DMESG;
		} else if (strcasecmp(val, "mmap") == 0) {
			access_log_type |= ACCESS_LOG_MMAP;
		} else {
			T_ERR_NL("invalid access_log value: '%s'\n", val);
			return -EINVAL;
		}
	}

	if (off && access_log_type != ACCESS_LOG_OFF) {
		T_ERR_NL("access_log 'off' value should be the only value\n");
		return -EINVAL;
	}

	return 0;
}

static int
tfw_event_log_start(void)
{
	int cpu;

	BUILD_BUG_ON(TFW_EVENT_LOG_MAX_BIN_LEN > 65535);
	if (!(access_log_type & ACCESS_LOG_MMAP) || mmap_buffer)
		return 0;

	mmap_buffer = tfw_mmap_buffer_create(MMAP_LOG_PATH, mmap_log_buffer_size);

	for_each_online_cpu(cpu) {
		u64 *dropped = per_cpu_ptr(&mmap_log_dropped, cpu);
		*dropped = 0;
	}

	return mmap_buffer ? 0 : -EINVAL;
}

static void
tfw_event_log_stop(void)
{
	tfw_mmap_buffer_free(mmap_buffer);
	mmap_buffer = NULL;
}

static TfwCfgSpec tfw_http_specs[] = {
	{
		.name = "access_log",
		.deflt = NULL,
		.handler = cfg_access_log_set,
		.allow_none = true,
		.allow_repeat = true,
	},
	{
		.name = "mmap_log_buffer_size",
		.deflt = "1M",
		.handler = tfw_cfg_set_mem,
		.dest = &mmap_log_buffer_size,
		.spec_ext = &(TfwCfgSpecMem) {
			.multiple_of = "4K",
			.range = { TFW_MMAP_BUFFER_MIN_SIZE_STR,
				   TFW_MMAP_BUFFER_MAX_SIZE_STR },
		}
	},
	{ 0 }
};

TfwMod tfw_event_log_mod  = {
	.name	= "event_log",
	.specs	= tfw_http_specs,
	.start	= tfw_event_log_start,
	.stop	= tfw_event_log_stop,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_event_log_init(void)
{
	tfw_mod_register(&tfw_event_log_mod);
	return 0;
}

void
tfw_event_log_exit(void)
{
	tfw_mod_unregister(&tfw_event_log_mod);
}
