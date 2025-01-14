/**
 *		Tempesta FW
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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
#ifndef __LIB_JA5_H__
#define __LIB_JA5_H__

#include <linux/compiler.h>

/**
 * Different constants for HTTP ja5 hash calculation.
 */
enum {
	TFW_HTTP_JA5H_HTTP_REQ = 0,
	TFW_HTTP_JA5H_HTTP2_REQ = 1,
	TFW_JA5_HASH_CALC_PRIME = 11,
	TFW_HTTP_JA5H_COOKIE_MAX = 31,
	TFW_HTTP_JA5H_HEADERS_MAX = 63
};

/**
 * Description of HTTP ja5 hash structure.
 * @padding	- padding up to 3 bytes;
 * @has_referer	- has Refer;
 * @headers_num	- number of headers (all bits set for 63
 *		  and more headers);
 * @cookie_num 	- number of Cookie values (all bits set for 31
 *		  and more cookies, within one or several headers);
 * @method	- HTTP method (tfw_http_meth_t value)
 * @version	- version (http1 or http2);
 * @summ	- sum * 11 + header, where header is an 'id'
 *		  if 'id' < TFW_HTTP_HDR_RAW or 4 or less bytes
 *		  (depending on how many bytes available) value
 *		  (header name or header name + value if name is
 *		  less then 4 bytes);
 */
typedef struct {
	unsigned int	padding:6;
	unsigned int	has_referer:1;
	unsigned int	headers_num:6;
	unsigned int	cookie_num:5;
	unsigned int	method:5;
	unsigned int	version:1;
	unsigned int	summ;
} HttpJa5h;

/**
 * JA5t TLS client fingerprint
 *
 * @alpn - chosen ALPN id
 * @has_unknown_alpn - has client sent unknown alpn value
 * @vhost_found - requested vhost presence flag
 * @is_abbreviated - is it going to be resumed session
 * @is_tls1_3 - is tls1.3 flag
 * @cipher_suite_hash - hash of the client cipher suites set
 * @extension_type_hash - hash of the client extensions set
 * @elliptic_curve_hash - hash of the client elliptic curves set
 */
typedef struct {
	unsigned char alpn:3;
	unsigned char has_unknown_alpn:1;
	unsigned char vhost_found:1;
	unsigned char is_abbreviated:1;
	unsigned char is_tls1_3:1;
	unsigned short cipher_suite_hash;
	unsigned short extension_type_hash;
	unsigned short elliptic_curve_hash;
} TlsJa5t;

#define HTTP_JA5H_CALC_NUM(val, max, num)				\
	({								\
		typeof(max) x = (val) < (max) ? (val) + (num) : (val);	\
		x;							\
	})

#define HTTP_JA5H_REQ_CALC_NUM(req, name, max, num)			\
	(req)->ja5h.name##_num =					\
		HTTP_JA5H_CALC_NUM(((req)->ja5h.name##_num), max, num)

#define COMPUTE_JA5_ACCHASH(hash, field)	\
do {						\
	(hash) *= TFW_JA5_HASH_CALC_PRIME;	\
	(hash) += (field);			\
} while (0)

#endif /* __LIB_JA5_H__ */
