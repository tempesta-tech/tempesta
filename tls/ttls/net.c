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
#include "../../tempesta_fw/http.h"
#include "../../tempesta_fw/http_msg.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>

/*
 * Initialize a context
 */
void
mbedtls_net_init(mbedtls_net_context *ctx)
{
	ctx->sk = NULL;
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

static int
mbedtls_net_conn_new(struct sock *sk)
{
	TlsProto *proto = sk->sk_user_data;
	printk("new begin\n");

	ss_set_callbacks(sk);
	ss_sock_hold(sk);
	proto->cli_ctx->sk = sk;
	proto->cli_ctx->off = 0;
	ss_skb_queue_head_init(&proto->cli_ctx->skb_list);

	wake_up(&proto->wq);
	printk("new end\n");
	return 0;
}

static int
mbedtls_net_conn_drop(struct sock *sk)
{
	TlsProto *proto = sk->sk_user_data;
	printk("drop begin\n");

	proto->cli_ctx->sk = NULL;
	ss_sock_put(sk);

	printk("drop end\n");
	return 0;
}

static int
mbedtls_net_read(void *data, struct sk_buff *skb, unsigned int off)
{
	TlsProto *proto = data;
	printk("read begin\n");

	ss_skb_queue_tail(&proto->cli_ctx->skb_list, skb);

	printk("read end\n");
	return 0;
}

static SsHooks ssocket_hooks = {
	.connection_new		= mbedtls_net_conn_new,
	.connection_drop	= mbedtls_net_conn_drop,
	.connection_recv	= mbedtls_net_read,
};

/*
 * Create a listening socket on bind_ip:port
 */
int
mbedtls_net_bind(mbedtls_net_context *ctx, mbedtls_net_context *client_ctx,
		 const char *bind_ip, const char *port, int proto)
{
	int ret;
	struct sock *srv_sk;
	struct sockaddr_in sin;

	ret = ss_sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &srv_sk);
	if(ret < 0)
		return MBEDTLS_ERR_NET_SOCKET_FAILED;

	srv_sk->sk_reuse = 1;

	memset(&ctx->proto, 0, sizeof(ctx->proto));
	ss_proto_init((SsProto *)&ctx->proto, &ssocket_hooks, 0);
	init_waitqueue_head(&ctx->proto.wq);
	ctx->proto.cli_ctx = client_ctx;
	srv_sk->sk_user_data = &ctx->proto;
	ss_set_listen(srv_sk);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(4433);

	printk("bind %p %p\n", srv_sk, srv_sk->sk_user_data);
	ret = ss_bind(srv_sk, (struct sockaddr *)&sin, sizeof(sin));
	if (ret)
		return MBEDTLS_ERR_NET_BIND_FAILED;

	ret = ss_listen(srv_sk, 1000);
	if (ret)
		return MBEDTLS_ERR_NET_LISTEN_FAILED;

	ctx->sk = srv_sk;
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
	TlsProto *proto = &bind_ctx->proto;

	ret = wait_event_interruptible(proto->wq, proto->cli_ctx->sk != NULL);
	if(ret < 0) {
		return MBEDTLS_ERR_NET_ACCEPT_FAILED;
	}

	init_waitqueue_head(&proto->wq);

	return 0;
}
EXPORT_SYMBOL(mbedtls_net_accept);

static int
mbedtls_net_actor(void *ptr, unsigned char *buf, size_t buf_len)
{
	mbedtls_net_buf *data = ptr;
	size_t len = buf_len < data->len? buf_len: data->len;
	printk("actor %lu\n", buf_len);

	memcpy(data->buf, buf, len);

	data->buf += len;
	data->len -= len;

	return data->len != 0? -1: 0;
}

/*
 * Read at most 'len' characters
 */
int
mbedtls_net_recv(void *ptr, unsigned char *buf, size_t len)
{
	mbedtls_net_context *ctx = ptr;
	mbedtls_net_buf data;
	struct sk_buff *skb;
	printk("recv1 %lu\n", len);

	if (!ctx->sk)
		return MBEDTLS_ERR_NET_CONN_RESET;

	data.buf = buf;
	data.len = len;

	skb = ss_skb_peek(&ctx->skb_list);
	while (skb) {
		unsigned int off = ctx->off;
		ss_skb_process(skb, &off, mbedtls_net_actor, &data);

		if (data.len == 0) {
			ctx->off += len;
			return len;
		}

		ctx->off = 0;
		ss_skb_unlink(&ctx->skb_list, skb);
		skb = ss_skb_peek(&ctx->skb_list);
	}

	printk("recv2 %lu\n", len - data.len);
	if (data.len < len) {
		return len - data.len;
	}
	else {
		msleep(1000);
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
}
EXPORT_SYMBOL(mbedtls_net_recv);

/*
 * Write at most 'len' characters
 */
int
mbedtls_net_send(void *ptr, const unsigned char *buf, size_t len)
{
	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;
	mbedtls_net_context *ctx = ptr;
	printk("send %lu\n", len);

	if (!ctx->sk)
		return MBEDTLS_ERR_NET_CONN_RESET;

	msg.ptr = (unsigned char *)buf;
	msg.skb = NULL;
	msg.len = len;
	msg.flags = 0;

	req = tfw_http_msg_create(&it, Conn_Clnt, msg.len);
	tfw_http_msg_write(&it, req, &msg);
	ss_send(ctx->sk, &req->msg.skb_list, false);
	tfw_http_msg_free(req);

	return len;
}
EXPORT_SYMBOL(mbedtls_net_send);

/*
 * Gracefully close the connection
 */
void
mbedtls_net_free(mbedtls_net_context *ctx)
{
	if (ctx->sk == NULL)
		return;

	ss_release(ctx->sk);
	ctx->sk = NULL;
}
EXPORT_SYMBOL(mbedtls_net_free);

#endif /* MBEDTLS_NET_C */
