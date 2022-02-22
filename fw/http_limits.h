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
#include "connection.h"

/*
 * ------------------------------------------------------------------------
 *	Generic classifier interface.
 * ------------------------------------------------------------------------
 */

/* Size of classifier private client accounting data. */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
#define TFW_CLASSIFIER_ACCSZ	512
#else
#define TFW_CLASSIFIER_ACCSZ	264
#endif

typedef struct { char _[TFW_CLASSIFIER_ACCSZ]; } TfwClassifierPrvt;

/*
 * Classification module handler.
 *
 * TODO:
 * -- modules should have possibility to register number of classifier callbacks,
 *    so store the callback in fixed size array, so we can quickly determine which
 *    callbacks (if either) we need to call.
 */
typedef struct {
	char	*name;
	/*
	 * Classify a client on network L3 layer.
	 */
	int	(*classify_ipv4)(struct sk_buff *skb);
	int	(*classify_ipv6)(struct sk_buff *skb);
	/*
	 * Classify TCP segments.
	 */
	int	(*classify_tcp)(struct tcphdr *th);
	/*
	 * Called when a new client connection is established (many TCP SYNs
	 * can precede an established connection, so it's more efficient to
	 * handle events for established and closed.
	 */
	int	(*classify_conn_estab)(struct sock *sk);
	/*
	 * Called when a client connection closed.
	 */
	void	(*classify_conn_close)(struct sock *sk);
	/*
	 * TODO called on retransmits to client (e.g. SYN+ACK or data).
	 */
	int	(*classify_tcp_timer_retrans)(void);
	/*
	 * TODO called on sending TCP keep alive segments.
	 */
	int	(*classify_tcp_timer_keepalive)(void);
	/*
	 * TODO called when we choose our window size to report to client.
	 */
	int	(*classify_tcp_window)(void);
	/*
	 * TODO called when peer reported zero window, so we can't send data
	 * and must send TCP zero window probing segments.
	 */
	int	(*classify_tcp_zwp)(void);
} TfwClassifier;

void tfw_classifier_add_inport(__be16 port);
void tfw_classifier_cleanup_inport(void);

void tfw_classify_shrink(void);

int tfw_classify_ipv4(struct sk_buff *skb);
int tfw_classify_ipv6(struct sk_buff *skb);

extern void tfw_classifier_register(TfwClassifier *mod);
extern void tfw_classifier_unregister(void);

/*
 * ------------------------------------------------------------------------
 *	Frang (static http limits classifier) configuration interface.
 * ------------------------------------------------------------------------
 */

/* We account users with FRANG_FREQ frequency per second. */
#define FRANG_FREQ	8

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

	bool			ip_block;
};

/**
 * Vhost and location specific Frang limits. As soon as full headers set is
 * received, it's possible to determine target vhost and location. The structure
 * contains full effective set of limits for chosen vhost and location.
 *
 * @http_methods_mask	- Allowed HTTP request methods;
 * @http_uri_len	- Maximum allowed URI len;
 * @http_field_len	- Maximum HTTP header length;
 * @http_body_len	- Maximum body size;
 * @http_hdr_cnt	- Maximum number of headers;
 * @http_ct_vals	- Allowed 'Content-Type:' values;
 * @http_ct_vals_sz	- Size of @http_ct_vals member;
 * @http_resp_code_block - Response status codes and maximum number of each
 *			   code before client connection is closed.
 * @http_ct_required	- Header 'Content-Type:' is required;
 * @http_host_required	- Header 'Host:' is required;
 * @http_method_override - Allow method override in request headers.
 */
struct frang_vhost_cfg_t {
	unsigned long		http_methods_mask;
	unsigned long		http_body_len;
	unsigned int		http_uri_len;
	unsigned int		http_field_len;
	unsigned int		http_hdr_cnt;

	FrangCtVals		*http_ct_vals;
	FrangHttpRespCodeBlock	*http_resp_code_block;

	bool			http_ct_required;
	bool			http_host_required;
	bool			http_trailer_split;
	bool			http_method_override;
};

int frang_tls_handler(TlsCtx *tls, int state);

#endif /* __HTTP_LIMITS__ */
