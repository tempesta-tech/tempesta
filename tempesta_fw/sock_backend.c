/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle internal (back-end) traffic.
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
/**
 * TODO
 * -- [connection pool, reverse proxy only] establish N connections with each backend
 *    for better parallelization on the server side.
 * -- limit number of persistent connections to be able to work as forward
 *    (transparent) proxy (probably we need to switch on/off functionality for
 *    connections pool)
 */
#include <linux/net.h>
#include <net/inet_sock.h>

#include "tempesta.h"
#include "connection.h"
#include "lib.h"
#include "log.h"
#include "server.h"

static unsigned int backend_socks_n = 0;
static struct socket **backend_socks;

/**
 * Connect to the back-end server.
  */
static int
tfw_backend_connect(struct socket **sock, void *addr)
{
	static struct {
		SsProto	_placeholder;
		int	type;
	} dummy_proto = {
		.type = TFW_FSM_HTTP,
	};

	TfwServer *srv;
	struct sock *sk;
	unsigned short family = *(unsigned short *)addr;
	unsigned short sza = family == AF_INET
			     ? sizeof(struct sockaddr_in)
			     : sizeof(struct sockaddr_in6);
	int r;

	r = sock_create_kern(family, SOCK_STREAM, IPPROTO_TCP, sock);
	if (r) {
		TFW_ERR("Can't create back-end connections socket (%d)\n", r);
		return r;
	}

	r = kernel_connect(*sock, (struct sockaddr *)addr, sza, 0);
	if (r) {
		char buf[MAX_ADDR_LEN];
		tfw_inet_ntop(addr, buf);
		TFW_ERR("Can't connect to back-end server %s (%d)\n", buf, r);
		goto err_sock_destroy;
	}
	sk = (*sock)->sk;

	/*
	 * TODO Set up socket callbacks.
	 * Do we need any?
	 */
	TFW_DBG("Created back-end connection %p\n", sk);

	/*
	 * TODO only one server connection is established now.
	 * Create N connections to each server for redundancy,
	 * so we shuldn't allocate a new server for each connection.
	 */
	srv = tfw_create_server(sk);
	if (!srv) {
		char buf[MAX_ADDR_LEN];
		tfw_inet_ntop(addr, buf);
		TFW_ERR("Can't create server descriptor for %s\n", buf);
		goto err_sock_destroy;
	}

	sk->sk_user_data = &dummy_proto;
	r = tfw_connection_new(sk, Conn_Srv, srv, tfw_destroy_server);
	if (r)
		goto err_conn_create;

	return 0;
err_conn_create:
	tfw_destroy_server(sk);
err_sock_destroy:
	sock_release(*sock);
	return r;
}


void
tfw_close_backend_sockets(void)
{
	down_read(&tfw_cfg.mtx);

	TFW_LOG("Close %u backend sockets\n", backend_socks_n);

	while (backend_socks_n)
		sock_release(backend_socks[--backend_socks_n]);
	kfree(backend_socks);

	up_read(&tfw_cfg.mtx);
}

/**
 * Connect to back-end server.
 */
int
tfw_open_backend_sockets(void)
{
	int r = -ENOMEM;
	TfwAddrCfg *be;

	down_read(&tfw_cfg.mtx);

	be = tfw_cfg.backends;

	TFW_LOG("Open %u backend sockets\n", be->count);

	backend_socks = kmalloc(sizeof(void *) * be->count, GFP_KERNEL);
	if (!backend_socks)
		goto out;

	while (backend_socks_n < be->count) {
		r = tfw_backend_connect(&backend_socks[backend_socks_n],
				       &be->addr[backend_socks_n]);
		if (r) {
			tfw_close_backend_sockets();
			goto out;
		}
		++backend_socks_n;
	}

	r = 0;
out:
	up_read(&tfw_cfg.mtx);
	return r;
}

/**
 * FIXME synchronize it with socket operations.
 */
int
tfw_reopen_backend_sockets(void)
{
	tfw_close_backend_sockets();
	return tfw_open_backend_sockets();
}
