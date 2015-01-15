/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle external (fron-end) traffic.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include "cfg.h"
#include "connection.h"
#include "filter.h"
#include "http.h"
#include "log.h"
#include "sync_socket.h"
#include "tempesta.h"

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
add_listen_sock(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwAddr addr;
	const char *addr_str;
	struct socket *s;
	int r;

	if (listen_socks_n == ARRAY_SIZE(listen_socks)) {
		TFW_ERR("maximum number of listen sockets (%d) is reached",
			listen_socks_n);
		return -ENOBUFS;
	}

	r = tfw_cfg_check_single_val(ce);
	if (r) {
		TFW_ERR("invalid syntax\n");
		return r;
	}

	addr_str = ce->vals[0];
	r = tfw_inet_pton(addr_str, &addr);
	if (r) {
		TFW_ERR("can't parse IP address: '%s'\n", ce->vals[0]);
		return r;
	}

	r = sock_create_kern(addr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP, &s);
	if (r) {
		TFW_ERR("Can't create socket (err: %d)\n", r);
		return r;
	}

	inet_sk(s->sk)->freebind = 1;
	s->sk->sk_reuse = 1;
	r = s->ops->bind(s, &addr.sa, tfw_addr_sa_len(&addr));
	if (r) {
		TFW_ERR("can't bind to address: '%s'\n", addr_str);
		sock_release(s);
		return r;
	}

	TFW_DBG("Created frontend socket %p\n", s->sk);

	BUG_ON(listen_socks_n >= ARRAY_SIZE(protos));
	BUG_ON(listen_socks[listen_socks_n]);
	listen_socks[listen_socks_n] = s;
	++listen_socks_n;

	return 0;
}

static int
start_listen_socks(void)
{
	SsProto *proto;
	struct socket *sock;
	int i, r;

	FOR_EACH_SOCK(sock, i) {
		/*
		 * TODO If multiprotocol support is required, then here we must
		 * have information for which protocol we're establishing
		 * the new listener. So TfwAddrCfg must be extended with
		 * protocol information (e.g. HTTP enum value).
		 */
		proto = &protos[i];
		proto->type = TFW_FSM_HTTP;

		BUG_ON(proto->listener);

		ss_tcp_set_listen(sock, proto);
		TFW_DBG("Created listening socket %p\n", sock->sk);

		/* TODO adjust /proc/sys/net/core/somaxconn */
		r = sock->ops->listen(sock, LISTEN_SOCK_BACKLOG_LEN);
		if (r) {
			TFW_ERR("Can't listen on front-end socket (%d)\n", r);
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
		kernel_sock_shutdown(sock, SHUT_RDWR);
	}
}

static void
release_listen_socks(void)
{
	struct socket *sock;
	int i;

	FOR_EACH_SOCK(sock, i) {
		sock_release(sock);
	}

	memset(listen_socks, 0, sizeof(listen_socks));
	memset(protos, 0, sizeof(protos));
	listen_socks_n = 0;
}

TfwCfgMod tfw_mod_sock_frontend  = {
	.name = "sock_frontend",
	.start   = start_listen_socks,
	.stop    = stop_listen_socks,
	.cleanup = release_listen_socks,
	.specs = (TfwCfgSpec[]){
		{
			"listen", ":80",
			add_listen_sock,
			.allow_repeat = true
		},
		{}
	}
};
