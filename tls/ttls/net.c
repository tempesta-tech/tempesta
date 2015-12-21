/*
 *  TCP/IP or UDP/IP networking functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_NET_C)

#include "net.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <net/sock.h>

/*
 * Initialize a context
 */
void
mbedtls_net_init(mbedtls_net_context *ctx)
{
	ctx->socket = NULL;
}
EXPORT_SYMBOL(mbedtls_net_init);

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int
mbedtls_net_connect(mbedtls_net_context *ctx,
		    const char *host, const char *port, int proto)
{
	printk(KERN_ERR "mbedtls_net_connect need implement for client\n");
	BUG();
	return 0;
}

/*
 * Create a listening socket on bind_ip:port
 */
int
mbedtls_net_bind(mbedtls_net_context *ctx,
		 const char *bind_ip, const char *port, int proto)
{
	int ret;
	struct socket *srv_socket;
	struct sockaddr_in sin;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &srv_socket);
	if(ret < 0)
		return MBEDTLS_ERR_NET_SOCKET_FAILED;

	srv_socket->sk->sk_reuse = 1;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(4433);

	ret = srv_socket->ops->bind(srv_socket, (struct sockaddr*)&sin,
				    sizeof(sin));
	if(ret < 0)
		return MBEDTLS_ERR_NET_BIND_FAILED;

	ret = srv_socket->ops->listen(srv_socket, 5);
	if(ret < 0)
		return MBEDTLS_ERR_NET_LISTEN_FAILED;

	ctx->socket = srv_socket;

	return 0;
}
EXPORT_SYMBOL(mbedtls_net_bind);

/*
 * Accept a connection from a remote client
 */
int
mbedtls_net_accept(mbedtls_net_context *bind_ctx,
		   mbedtls_net_context *client_ctx,
		   void *client_ip, size_t buf_size,
		   size_t *ip_len)
{
	int ret;
	struct socket *srv_socket = bind_ctx->socket;
	struct socket *cl_socket;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &cl_socket);
	if(ret < 0)
		return MBEDTLS_ERR_NET_ACCEPT_FAILED;

	ret = srv_socket->ops->accept(srv_socket, cl_socket, 0);
	if (ret < 0) {
		switch(-ret) {
		case EAGAIN:
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		return MBEDTLS_ERR_NET_ACCEPT_FAILED;
	}

	client_ctx->socket = cl_socket;

	return 0;
}
EXPORT_SYMBOL(mbedtls_net_accept);

/*
 * Read at most 'len' characters
 */
int
mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	struct socket *sock = ((mbedtls_net_context *)ctx)->socket;
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int ret;

	if(sock == NULL)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	if(sock->sk == NULL)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iter.type = ITER_IOVEC;
	msg.msg_iter.count = len;
	msg.msg_iter.iov = &iov;
	msg.msg_iter.nr_segs = 1;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret = sock_recvmsg(sock, &msg, len, MSG_DONTWAIT);
	set_fs(oldfs);

	if(ret < 0) {
		switch(-ret) {
		case EAGAIN:
			return MBEDTLS_ERR_SSL_WANT_READ;
		case EPIPE:
		case ECONNRESET:
			return MBEDTLS_ERR_NET_CONN_RESET;
		case EINTR:
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	return ret;
}
EXPORT_SYMBOL(mbedtls_net_recv);

/*
 * Write at most 'len' characters
 */
int
mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
	struct socket *sock = ((mbedtls_net_context *)ctx)->socket;
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	int ret;

	if(sock == NULL)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	iov.iov_base = (unsigned char *)buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iter.type = ITER_IOVEC;
	msg.msg_iter.count = len;
	msg.msg_iter.iov = &iov;
	msg.msg_iter.nr_segs = 1;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret = sock_sendmsg(sock, &msg);
	set_fs(oldfs);

	if(ret < 0) {
		switch(-ret) {
		case EAGAIN:
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		case EPIPE:
		case ECONNRESET:
			return MBEDTLS_ERR_NET_CONN_RESET;
		case EINTR:
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return ret;
}
EXPORT_SYMBOL(mbedtls_net_send);

/*
 * Gracefully close the connection
 */
void
mbedtls_net_free(mbedtls_net_context *ctx)
{
	if (ctx->socket == NULL)
		return;

	sock_release(ctx->socket);
	ctx->socket = NULL;
}
EXPORT_SYMBOL(mbedtls_net_free);

#endif /* MBEDTLS_NET_C */
