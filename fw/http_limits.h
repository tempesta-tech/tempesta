/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __HTTP_LIMITS__
#define __HTTP_LIMITS__

#include <linux/in6.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tempesta_fw.h"
#include "http_types.h"
#include "tls.h"

/*
 * ------------------------------------------------------------------------
 *	Generic classifier interface.
 * ------------------------------------------------------------------------
 */

/* Size of classifier private client accounting data. */
#if defined(CONFIG_DEBUG_LOCK_ALLOC) || defined (CONFIG_DEBUG_SPINLOCK)
#define TFW_CLASSIFIER_ACCSZ	512
#else
#define TFW_CLASSIFIER_ACCSZ	264
#endif

typedef struct { char _[TFW_CLASSIFIER_ACCSZ]; } TfwClassifierPrvt;

/* We account users with FRANG_FREQ frequency per second. */
#define FRANG_FREQ	8

void tfw_classifier_add_inport(__be16 port);
void tfw_classifier_remove_inport(__be16 port);
void tfw_classifier_cleanup_inport(void);
void tfw_classify_conn_close(struct sock *sk);

/*
 * ------------------------------------------------------------------------
 *	Frang (static http limits classifier) configuration interface.
 * ------------------------------------------------------------------------
 */

/**
 * Response code block setting
 *
 * @codes	- Response code bitmap;
 * @limit	- Quantity of allowed responses in a time frame;
 * @tf		- Time frame in seconds;
 */
typedef struct {
	DECLARE_BITMAP(codes, 512);
	unsigned short	limit;
	unsigned short	tf;
} FrangHttpRespCodeBlock;

/**
 * Single allowed Content-Type value.
 * @str			- pointer to allowed value;
 * @len			- The pre-computed strlen(@str);
 */
typedef struct {
	char		*str;
	size_t		len;
} FrangCtVal;

/**
 * Variable-sized array of allowed Content-Type values. It's allocated by single
 * memory piece to keep all the data as close as possible.
 * @alloc_sz		- Full size of the structure;
 * @vals		- Variable array of allowed values;
 * @data		- Variable sized data area where @vals points to.
 *
 * Basically that will look like:
 *   [@vals                                   ][@data               ]
 *   [FrangCtVal, FrangCtVal, FrangCtVal, NULL][str1\0\str2\0\str3\0]
 *           +         +         +              ^      ^      ^
 *           |         |         |              |      |      |
 *           +----------------------------------+      |      |
 *                     |         |                     |      |
 *                     +-------------------------------+      |
 *                               |                            |
 *                               +----------------------------+
 */
typedef struct {
	size_t		alloc_sz;
	FrangCtVal	*vals;
	char		*data;
} FrangCtVals;

/**
 * Global Frang limits. As a request is received, it's not possible to determine
 * its target vhost or/and location until all the headers are parsed. Thus some
 * limits can't be redefined for vhost or location and can exist only as
 * unique top-level limits.
 *
 * @clnt_hdr_timeout	- Maximum time to receive the full headers set,
 *			  in jiffies;
 * @clnt_body_timeout	- Maximum time to receive the full body, in jiffies;
 * @req_rate		- Maximum requests per second over all the
 *			  connections from the single client;
 * @req_burst		- Allowed request rate burst;
 * @conn_rate		- Maximum new connections per second from the same
 *			  client;
 * @conn_burst		- Allowed connection rate burst;
 * @conn_max		- Maximum number of allowed concurrent connections;
 * @tls_new_conn_rate	- Maximum new tls connections with full handshakes per
 *			  second from the same client;
 * @tls_new_conn_burst	- New tls connections burst;
 * @tls_incomplete_conn_rate - Maximum rate of uncompleted tls connections;
 * @http_hchunk_cnt	- Maximum number of chunks in header part;
 * @http_bchunk_cnt	- Maximum number of chunks in body part;
 * @http_hdr_len	- Maximum HTTP header length;
 * @http_hdr_cnt	- Maximum number of headers;
 * @conn_rate_tf	- Time frame in which @conn_rate and @conn_burst are
 *                        calculated;
 * @req_rate_tf		- Time frame in which @req_rate and @req_burst are
 *                        calculated;
 * @ip_block		- Block clients by IP address if set, if not - just
 *			  close the client connection.
 *
 * Zero value means unlimited value.
 */
struct frang_global_cfg_t {
	unsigned long		clnt_hdr_timeout;
	unsigned long		clnt_body_timeout;
	unsigned int		req_rate;
	unsigned int		req_burst;
	unsigned int		conn_rate;
	unsigned int		conn_burst;
	unsigned int		conn_max;

	unsigned int		tls_new_conn_rate;
	unsigned int		tls_new_conn_burst;
	unsigned int		tls_incomplete_conn_rate;

	unsigned int		http_hchunk_cnt;
	unsigned int		http_bchunk_cnt;
	unsigned int		http_hdr_len;
	unsigned int		http_hdr_cnt;

	unsigned short		conn_rate_tf;
	unsigned short		req_rate_tf;

	bool			ip_block;
};

/**
 * Vhost and location specific Frang limits. As soon as full headers set is
 * received, it's possible to determine target vhost and location. The structure
 * contains full effective set of limits for chosen vhost and location.
 *
 * @http_methods_mask	- Allowed HTTP request methods;
 * @http_body_len	- Maximum body size;
 * @http_uri_len	- Maximum allowed URI len;
 * @http_ct_vals	- Allowed 'Content-Type:' values;
 * @http_ct_vals_sz	- Size of @http_ct_vals member;
 * @http_resp_code_block - Response status codes and maximum number of each
 *			   code before client connection is closed.
 * @http_ct_required	- Header 'Content-Type:' is required;
 * @http_strict_host_checking - Enforce equality of absolute_uri,
 *			  Host and :authority;
 * @http_trailer_split  - Allow the same header appear in both
 *			  request header part and chunked trailer part;
 * @http_method_override - Allow method override in request headers.
 */
struct frang_vhost_cfg_t {
	unsigned long		http_methods_mask;
	unsigned long		http_body_len;
	unsigned int		http_uri_len;

	FrangCtVals		*http_ct_vals;
	FrangHttpRespCodeBlock	*http_resp_code_block;

	bool			http_ct_required;
	bool			http_strict_host_checking;
	bool			http_trailer_split;
	bool			http_method_override;
};

int frang_tls_handler(TlsCtx *tls, int state);
int frang_sticky_cookie_handler(TfwHttpReq *req);
bool frang_req_is_whitelisted(TfwHttpReq *req);
int frang_http_hdr_limit(TfwHttpReq *req, unsigned int new_hdr_len);

static inline int
frang_time_in_frame(const unsigned long tcur, const unsigned long tprev)
{
	return tprev + FRANG_FREQ > tcur;
}

#endif /* __HTTP_LIMITS__ */
