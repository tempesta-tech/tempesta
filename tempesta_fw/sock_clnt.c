/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle client traffic.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include "addr.h"
#include "cfg.h"
#include "classifier.h"
#include "connection.h"
#include "filter.h"
#include "http.h"
#include "log.h"
#include "client.h"

#include "sync_socket.h"

#define LISTEN_SOCK_BACKLOG_LEN 1024
#define LISTEN_SOCKS_MAX 8

static struct sock *listen_socks[LISTEN_SOCKS_MAX];
static unsigned int listen_socks_n = 0;

static struct socket sock_holders[LISTEN_SOCKS_MAX];
static SsProto protos[LISTEN_SOCKS_MAX];

#define FOR_EACH_SOCK(sk, i) \
	for (i = 0;  (sk = listen_socks[i], i < listen_socks_n);  ++i)

SsHooks ss_client_hooks;

/**
 * Parse IP address, create a socket and bind it with the address,
 * but not yet start listening.
 */
static int
add_listen_sock(TfwAddr *addr, int type)
{
	int r;
	struct sock *sk;
	struct socket *sk_sock;

	if (listen_socks_n == ARRAY_SIZE(listen_socks)) {
		TFW_ERR("maximum number of listen sockets (%d) is reached\n",
			listen_socks_n);
		return -ENOBUFS;
	}
	protos[listen_socks_n].sock = &sock_holders[listen_socks_n];
	sk_sock = protos[listen_socks_n].sock;

	r = ss_sock_create(addr->sa.sa_family,
			   SOCK_STREAM, IPPROTO_TCP, sk_sock, &sk);
	if (r) {
		TFW_ERR("can't create socket (err: %d)\n", r);
		return r;
	}
	ss_set_proto(sk, &protos[listen_socks_n], type, &ss_client_hooks);
	ss_set_listener(sk);
	ss_tcp_set_listen(sk);

	inet_sk(sk)->freebind = 1;
	sk->sk_reuse = 1;
	r = ss_bind(sk, &addr->sa, tfw_addr_sa_len(addr));
	if (r) {
		TFW_ERR_ADDR("can't bind to", addr);
		sock_release(sk_sock);
		return r;
	}

	TFW_DBG("created front-end socket: sk=%p\n", sk);

	BUG_ON(listen_socks[listen_socks_n]);
	listen_socks[listen_socks_n] = sk;
	++listen_socks_n;

	return 0;
}

static int
tfw_client_connect_complete(struct sock *sk)
{
	TfwClient *cli;
	TfwConnection *conn;

	/* Classify the connection before any resource allocations. */
	if (tfw_classify_conn_estab(sk) == TFW_BLOCK)
		return -EPERM;

	/*
	 * TODO: currently there is one to one socket-client
	 * mapping, which isn't appropriate since a client can
	 * have more than one socket with the server.
	 *
	 * We have to lookup the client by the socket and create
	 * a new one only if it's really new.
	 */
	cli = tfw_create_client();
	if (!cli) {
		TFW_ERR("Can't allocate a new client");
		ss_close(sk);
		return -EINVAL;
	}

	conn = tfw_connection_new(sk, Conn_Clnt, tfw_destroy_client);
	if (!conn) {
		TFW_ERR("Cannot create new client connection\n");
		tfw_destroy_client(sk);
	}

	/* Make sure we don't refer to parent's socket holder */
	conn->proto.sock = NULL;

	cli->sock = sk;
	conn->peer = (TfwPeer *)cli;
	ss_set_callbacks(sk);

	TFW_DBG("New client socket %p (state=%u)\n", sk, sk->sk_state);

	return 0;
}

static int
tfw_client_connection_close(struct sock *sk)
{
	TfwConnection *conn = sk->sk_user_data;

	TFW_DBG("Closing client socket %p, conn=%p\n", sk, conn);
	/*
	 * Classify the connection closing while all data structures
	 * are alive.
	 */
	if (tfw_classify_conn_close(sk) == TFW_BLOCK)
		return -EPERM;
	tfw_connection_close(sk);

	return 0;
}

static int
start_listen_socks(void)
{
	struct sock *sk;
	int i, r;

	FOR_EACH_SOCK(sk, i) {
		/* TODO adjust /proc/sys/net/core/somaxconn */
		TFW_DBG("start listening on socket: sk=%p\n", sk);
		r = ss_listen(sk, LISTEN_SOCK_BACKLOG_LEN);
		if (r) {
			TFW_ERR("can't listen on front-end socket sk=%p (%d)\n",
				sk, r);
			return r;
		}
	}

	return 0;
}

static void
stop_listen_socks(void)
{
	struct socket *sk_sock;
	int i;

	for (i = 0;  (sk_sock = &sock_holders[i], i < listen_socks_n);  ++i) {
		TFW_DBG("release front-end socket: sk=%p\n", listen_socks[i]);
		sock_release(sk_sock);
	}

	memset(listen_socks, 0, sizeof(listen_socks));
	memset(sock_holders, 0, sizeof(sock_holders));
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

	/* TODO Issue #82: pass parsed protocol instead of hardcoded HTTP. */
	r = add_listen_sock(&addr, TFW_FSM_HTTP);
	return r;

parse_err:
	TFW_ERR("can't parse 'listen' value: '%s'\n", in_str);
	return -EINVAL;
}

SsHooks ss_client_hooks = {
	.connection_new		= tfw_client_connect_complete,
	.connection_drop	= tfw_client_connection_close,
	.connection_close	= tfw_client_connection_close,
	.connection_recv	= tfw_connection_recv,
	.put_skb_to_msg		= tfw_connection_put_skb_to_msg,
	.postpone_skb		= tfw_connection_postpone_skb,
};

TfwCfgMod tfw_sock_client_cfg_mod  = {
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
