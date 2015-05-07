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
#include "cfg.h"
#include "classifier.h"
#include "client.h"
#include "connection.h"
#include "filter.h"
#include "log.h"
#include "sync_socket.h"
#include "tempesta_fw.h"

/*
 * ------------------------------------------------------------------------
 *	Client socket handling.
 * ------------------------------------------------------------------------
 */

static struct kmem_cache *tfw_cli_conn_cache;

static TfwConnection *
tfw_cli_conn_alloc(void)
{
	TfwConnection *conn;

	conn = kmem_cache_alloc(tfw_cli_conn_cache, GFP_ATOMIC);
	if (!conn)
		return NULL;

	tfw_connection_init(conn);

	return conn;
}

static void
tfw_cli_conn_free(TfwConnection *conn)
{
	tfw_connection_validate_cleanup(conn);
	kmem_cache_free(tfw_cli_conn_cache, conn);
}

/**
 * This hook is called when a new client connection is established.
 */
static int
tfw_sock_clnt_new(struct sock *sk)
{
	int r;
	TfwClient *cli;
	TfwConnection *conn;
	SsProto *listen_sock_proto;

	TFW_DBG("new client socket: sk=%p, state=%u\n", sk, sk->sk_state);

	/* The new sk->sk_user_data points to the TfwListenSock of the parent
	 * listening socket. We set it to NULL here to prevent other functions
	 * from referencing the TfwListenSock while a new TfwConnection object
	 * is not yet allocated/initialized. */
	listen_sock_proto = sk->sk_user_data;
	sk->sk_user_data = NULL;

	/* Classify the connection before any resource allocations. */
	r = tfw_classify_conn_estab(sk);
	if (r) {
		TFW_DBG("new client socket is blocked by the classifier: "
			"sk=%p, r=%d\n", sk, r);
		goto err_classify;

	}

	cli = tfw_client_obtain(sk);
	if (!cli) {
		TFW_ERR("can't obtain a client for the new socket\n");
		r = -ENOENT;
		goto err_cli_obtain;
	}

	conn = tfw_cli_conn_alloc();
	if (!conn) {
		TFW_ERR("can't allocate a new client connection\n");
		r = -ENOMEM;
		goto err_conn_alloc;
	}

	ss_proto_inherit(listen_sock_proto, &conn->proto, Conn_Clnt);
	tfw_connection_link_sk(conn, sk);
	tfw_connection_link_peer(conn, (TfwPeer *)cli);

	r = tfw_connection_new(conn);
	if (r) {
		TFW_ERR("conn_init() hook returned error\n");
		goto err_conn_init;
	}

	TFW_DBG("new client socket is accepted: sk=%p, conn=%p, cli=%p\n",
		sk, conn, cli);
	return 0;

err_conn_init:
	tfw_connection_unlink_peer(conn);
	tfw_connection_unlink_sk(conn);
	tfw_cli_conn_free(conn);
err_conn_alloc:
	tfw_client_put(cli);
err_cli_obtain:
	tfw_classify_conn_close(sk);
err_classify:
	return r;
}

static int
tfw_sock_clnt_drop(struct sock *sk)
{
	int r;
	TfwConnection *conn = sk->sk_user_data;
	TfwClient *cli = (TfwClient *)conn->peer;

	TFW_DBG("close client socket: sk=%p, conn=%p, cli=%p\n", sk, conn, cli);

	if (!sk->sk_user_data)
		return 0;

	/* Classify the connection closing while all resources are alive. */
	/* FIXME: here we call tfw_classify_conn_close() while these resources
	 * are alive, but in tfw_sock_clnt_new() we call it when resources are
	 * freed (or not yet allocated). */
	r = tfw_classify_conn_close(sk);

	tfw_connection_unlink_peer(conn);
	tfw_connection_unlink_sk(conn);
	tfw_cli_conn_free(conn);
	tfw_client_put(cli);

	return r;
}

static const SsHooks tfw_sock_clnt_ss_hooks = {
	.connection_new		= tfw_sock_clnt_new,
	.connection_drop	= tfw_sock_clnt_drop,
	.connection_recv	= tfw_connection_recv,
	.put_skb_to_msg		= tfw_connection_put_skb_to_msg,
	.postpone_skb		= tfw_connection_postpone_skb,
};

/*
 * ------------------------------------------------------------------------
 *	Listening socket handling.
 * ------------------------------------------------------------------------
 */

#define TFW_LISTEN_SOCK_BACKLOG_LEN 	1024

/**
 * The listening socket representation.
 * One such structure corresponds to one "listen" configuration entry.
 *
 * @sk		- The underlying networking representation.
 * @list	- An entry in the tfw_listen_socks list.
 * @addr	- The IP address specified in the configuration.
 */
typedef struct {
	struct sock		*sk;
	struct list_head	list;
	TfwAddr			addr;
} TfwListenSock;

/**
 * The list of all existing TfwListenSock structures.
 *
 * The list is filled when Tempesta FW is started and emptied when it is
 * stopped, and not changed in between. Therefore, no locking is required.
 */
static LIST_HEAD(tfw_listen_socks);

/**
 * Allocate a new TfwListenSock and add it to the global list of sockets.
 * Don't open a socket now, just save the configuration data.
 * The socket is opened later in tfw_listen_sock_start().
 *
 * @type is the SsProto->type.
 */
static int
tfw_listen_sock_add(const TfwAddr *addr, int type)
{
	TfwListenSock *ls;

	ls = kzalloc(sizeof(*ls), GFP_KERNEL);
	if (!ls)
		return -ENOMEM;

	ls->addr = *addr;

	list_add(&ls->list, &tfw_listen_socks);

	/* Port is placed at the same offset in sockaddr_in and sockaddr_in6. */
	tfw_filter_add_inport(addr->v4.sin_port);

	return 0;
}

static void
tfw_listen_sock_del_all(void)
{
	TfwListenSock *ls, *tmp;

	BUG_ON(list_empty(&tfw_listen_socks));

	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks, list) {
		BUG_ON(ls->sk);
		kfree(ls);
	}

	INIT_LIST_HEAD(&tfw_listen_socks);
}

/**
 * Start listening on a socket.
 * Create a new socket in @ls->sk that listens the @ls->addr.
 * This is similar to a classic socket()/bind()/listen() sequence.
 */
static int
tfw_listen_sock_start(TfwListenSock *ls)
{
	int r;
	struct sock *sk;
	TfwAddr *addr = &ls->addr;

	r = ss_sock_create(addr->family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r) {
		TFW_ERR("can't create listening socket (err: %d)\n", r);
		return r;
	}

	/* Link the new socket and TfwListenSock
	 * That must be done before ss_set_listen() that uses SsProto. */
	ls->sk = sk;
	sk->sk_user_data = ls;

	/* For listening sockets we do ss_set_listen() instead of
	 * ss_set_callbacks(). */
	ss_set_listen(sk);

	inet_sk(sk)->freebind = 1;
	sk->sk_reuse = 1;
	r = ss_bind(sk, &addr->sa, tfw_addr_sa_len(addr));
	if (r) {
		TFW_ERR_ADDR("can't bind to", addr);
		ss_release(sk);
		return r;
	}

	/* TODO adjust /proc/sys/net/core/somaxconn */
	TFW_DBG("start listening on socket: sk=%p\n", sk);
	r = ss_listen(sk, TFW_LISTEN_SOCK_BACKLOG_LEN);
	if (r) {
		TFW_ERR("can't listen on front-end socket sk=%p (%d)\n", sk, r);
		return r;
	}

	return 0;
}

/**
 * Start listening on all existing sockets (added via "listen" configuration
 * entries).
 */
static int
tfw_listen_sock_start_all(void)
{
	int r;
	TfwListenSock *ls;

	list_for_each_entry(ls, &tfw_listen_socks, list) {
		r = tfw_listen_sock_start(ls);
		if (r) {
			TFW_ERR_ADDR("can't start listening on", &ls->addr);
			return r;
		}
	}

	return 0;
}

static void
tfw_listen_sock_stop_all(void)
{
	TfwListenSock *ls;

	list_for_each_entry(ls, &tfw_listen_socks, list) {
		BUG_ON(!ls->sk);
		ss_release(ls->sk);
		ls->sk = NULL;
	}
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

static int
tfw_sock_clnt_cfg_handle_listen(TfwCfgSpec *cs, TfwCfgEntry *ce)
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
	return tfw_listen_sock_add(&addr, TFW_FSM_HTTP);

parse_err:
	TFW_ERR("Unable to parse 'listen' value: '%s'\n", in_str);
	return -EINVAL;
}

static void
tfw_sock_clnt_cfg_cleanup_listen(TfwCfgSpec *cs)
{
	tfw_listen_sock_del_all();
}

TfwCfgMod tfw_sock_clnt_cfg_mod  = {
	.name	= "sock_clnt",
	.start	= tfw_listen_sock_start_all,
	.stop	= tfw_listen_sock_stop_all,
	.specs	= (TfwCfgSpec[]){
		{
			"listen", "80",
			tfw_sock_clnt_cfg_handle_listen,
			.allow_repeat = true,
			.cleanup = tfw_sock_clnt_cfg_cleanup_listen
		},
		{}
	}
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int
tfw_sock_clnt_init(void)
{
	BUG_ON(tfw_cli_conn_cache);
	tfw_cli_conn_cache = kmem_cache_create("tfw_cli_conn_cache",
					       sizeof(TfwConnection),
					       0, 0, NULL);
	return !tfw_cli_conn_cache ? -ENOMEM : 0;
}

void
tfw_sock_clnt_exit(void)
{
	kmem_cache_destroy(tfw_cli_conn_cache);
}
