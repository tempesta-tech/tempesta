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

#include "tempesta.h"
#include "connection.h"
#include "filter.h"
#include "http.h"
#include "log.h"

#include "sync_socket.h"

static unsigned int listen_socks_n = 0;
static SsProto *protos;

/**
 * Create a listening front-end socket.
 */
static int
__open_listen_socket(SsProto *proto, void *addr)
{
	struct socket *s;
	unsigned short family = *(unsigned short *)addr;
	unsigned short sza = family == AF_INET
			     ? sizeof(struct sockaddr_in)
			     : sizeof(struct sockaddr_in6);
	int r;

	r = sock_create_kern(family, SOCK_STREAM, IPPROTO_TCP, &s);
	if (r) {
		TFW_ERR("Can't create front-end listening socket (%d)\n", r);
		return r;
	}

	inet_sk(s->sk)->freebind = 1;
	s->sk->sk_reuse = 1;
	r = s->ops->bind(s, (struct sockaddr *)addr, sza);
	if (r) {
		TFW_ERR("Can't bind front-end listening socket (%d)\n", r);
		goto err;
	}

	ss_tcp_set_listen(s, proto);
	TFW_DBG("Created listening socket %p\n", s->sk);

	/* TODO adjust /proc/sys/net/core/somaxconn */
	r = s->ops->listen(s, 1024);
	if (r) {
		TFW_ERR("Can't listen on front-end socket (%d)\n", r);
		goto err;
	}

	return r;
err:
	sock_release(s);
	return r;
}

void
tfw_close_listen_sockets(void)
{
	down_read(&tfw_cfg.mtx);

	TFW_LOG("Close %u listening sockets\n", listen_socks_n);

	while (listen_socks_n)
		sock_release(protos[--listen_socks_n].listener);
	kfree(protos);

	up_read(&tfw_cfg.mtx);
}

int
tfw_open_listen_sockets(void)
{
	struct sockaddr_in6 *addr;
	int r = -ENOMEM;
	__be16 ports[DEF_MAX_PORTS];

	down_read(&tfw_cfg.mtx);

	TFW_LOG("Open %u listening sockets\n", tfw_cfg.listen->count);

	protos = kzalloc(sizeof(void *) * tfw_cfg.listen->count, GFP_KERNEL);
	if (!protos)
		goto out;

	for (listen_socks_n = 0; listen_socks_n < tfw_cfg.listen->count;
	     ++listen_socks_n)
	{
		SsProto *proto;

		if (listen_socks_n > DEF_MAX_PORTS) {
			TFW_ERR("Too many listening sockets\n");
			tfw_close_listen_sockets();
			goto out;
		}

		/*
		 * TODO If multiprotocol support is required, then here we must
		 * have information for which protocol we're establishing
		 * the new listener. So TfwAddrCfg must be extended with
		 * protocol information (e.g. HTTP enum value).
		 */
		proto = protos + listen_socks_n;
		proto->type = TFW_FSM_HTTP;
		addr = (struct sockaddr_in6 *)(tfw_cfg.listen->addr
					       + listen_socks_n);
		r = __open_listen_socket(proto, addr);
		if (r) {
			tfw_close_listen_sockets();
			goto out;
		}
		ports[listen_socks_n] = addr->sin6_port;
	}

	tfw_filter_set_inports(ports, listen_socks_n);

	r = 0;
out:
	up_read(&tfw_cfg.mtx);
	return r;
}

/**
 * FIXME synchronize it with socket operations.
 */
int
tfw_reopen_listen_sockets(void)
{
	tfw_close_listen_sockets();
	return tfw_open_listen_sockets();
}
