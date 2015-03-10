/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle external (fron-end) traffic.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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

/*
 * TODO:
 * -- block/drop HTTP requests if they decided as malicious by a classifier
 *    (application firewall);
 * -- how do we send the buffers? By GSO (what is the maximum size which
 *    GSO can process)? How do we send buffer with size N if client reported
 *    only M (M < N) bytes in window (recalculate checksum or just wait)?
 *    See tcp_sendmsg(), tcp_write_xmit()
 */

#include <linux/net.h>
#include <net/inet_sock.h>

#include "tempesta_fw.h"
#include "cfg.h"
#include "connection.h"
#include "filter.h"
#include "http.h"
#include "log.h"

#include "sync_socket.h"

#define LISTEN_SOCK_BACKLOG_LEN 1024
#define LISTEN_SOCKS_MAX 8

static struct socket *listen_socks[LISTEN_SOCKS_MAX];
static unsigned int listen_socks_n = 0;

static SsProto protos[LISTEN_SOCKS_MAX];

#define FOR_EACH_SOCK(sock, i) \
	for (i = 0;  (sock = listen_socks[i], i < listen_socks_n);  ++i)

/**
 * Parse IP address, create a socket and bind it with the address,
 * but not yet start listening.
 */
static int
add_listen_sock(TfwAddr *addr)
{
	int r;
	SsProto *proto;
	struct socket *s;

	if (listen_socks_n == ARRAY_SIZE(listen_socks)) {
		TFW_ERR("maximum number of listen sockets (%d) is reached\n",
			listen_socks_n);
		return -ENOBUFS;
	}

	r = sock_create_kern(addr->sa.sa_family, SOCK_STREAM, IPPROTO_TCP, &s);
	if (r) {
		TFW_ERR("can't create socket (err: %d)\n", r);
		return r;
	}

	inet_sk(s->sk)->freebind = 1;
	s->sk->sk_reuse = 1;
	r = s->ops->bind(s, &addr->sa, tfw_addr_sa_len(addr));
	if (r) {
		TFW_ERR_ADDR("can't bind to", addr);
		sock_release(s);
		return r;
	}

	/**
	 * TODO: If multiprotocol support is required, then here we must have
	 * information for which protocol we're establishing the new listener.
	 * e.g.: listen 127.0.0.1:80 proto=http;
	 */
	proto = &protos[listen_socks_n];
	proto->type = TFW_FSM_HTTP;
	BUG_ON(proto->listener);
	ss_tcp_set_listen(s, proto);
	TFW_DBG("created front-end socket: sk=%p\n", s->sk);

	BUG_ON(listen_socks[listen_socks_n]);
	listen_socks[listen_socks_n] = s;
	++listen_socks_n;

	return 0;
}

static int
start_listen_socks(void)
{
	struct socket *sock;
	int i, r;

	FOR_EACH_SOCK(sock, i) {
		/* TODO adjust /proc/sys/net/core/somaxconn */
		TFW_DBG("start listening on socket: sk=%p\n", sock->sk);
		r = sock->ops->listen(sock, LISTEN_SOCK_BACKLOG_LEN);
		if (r) {
			TFW_ERR("can't listen on front-end socket sk=%p (%d)\n",
				sock->sk, r);
			return r;
		}
	}

	return 0;
}

static void
stop_listen_socks(void)
{
	struct socket *sock;
	int i;

	FOR_EACH_SOCK(sock, i) {
		TFW_DBG("release front-end socket: sk=%p\n", sock->sk);
		sock_release(sock);
	}

	memset(listen_socks, 0, sizeof(listen_socks));
	memset(protos, 0, sizeof(protos));
	listen_socks_n = 0;
}

static int
handle_listen_cfg_entry(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	int port;
	TfwAddr addr;
	const char *in_str;

	r = tfw_cfg_check_single_val(ce);
	if (r)
		goto parse_err;

	/* Try both:
	 *  a single port without IP address (e.g. "listen 8081"),
	 *  and a full IP address (e.g. "listen 127.0.0.1:8081").
	 */
	in_str = ce->vals[0];
	r = tfw_cfg_parse_int(in_str, &port);
	if (!r) {
		r = tfw_cfg_check_range(port, 0, 65535);
		if (r)
			goto parse_err;

		/* For single port, use 0.0.0.0:port (IPv4, but not IPv6). */
		addr.v4.sin_family = AF_INET;
		addr.v4.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.v4.sin_port = htons(port);
	} else {
		r = tfw_addr_pton(in_str, &addr);
		if (r)
			goto parse_err;
	}

	r = add_listen_sock(&addr);
	return r;

parse_err:
	TFW_ERR("can't parse 'listen' value: '%s'\n", in_str);
	return -EINVAL;
}

TfwCfgMod tfw_sock_frontend_cfg_mod  = {
	.name	= "sock_frontend",
	.start	= start_listen_socks,
	.stop	= stop_listen_socks,
	.specs	= (TfwCfgSpec[]){
		{
			"listen", "80",
			handle_listen_cfg_entry,
			.allow_repeat = true
		},
		{}
	}
};
