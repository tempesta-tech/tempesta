/**
 *		Synchronous Socket API.
 *
 * Server and client socket (connecton) definitions.
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
#ifndef __SS_SOCK_H__
#define __SS_SOCK_H__

#include <linux/skbuff.h>

/**
 * Responses from socket hook functions.
 */
enum {
	/* The packet must be dropped. */
	SS_DROP		= -2,

	/* The packet should be stashed (made by callback). */
	SS_POSTPONE	= -1,

	/* Current packet looks good and we can safely pass it. */
	SS_OK		= 0,
};

/* Protocols stack handlers. */
typedef struct ss_proto_t {
	struct socket	*listener;
	int		type;
} SsProto;

/* Table of socket connection callbacks. */
typedef struct {
	/* New connection accepted. */
	int (*connection_new)(struct sock *sk);

	/* Drop TCP connection associated with the socket. */
	int (*connection_drop)(struct sock *sk);

	/* Process data received on the socket. */
	int (*connection_recv)(struct sock *sk, unsigned char *data,
			       size_t len);

	/*
	 * Add the @skb to the current connection message.
	 * We need this low-level sk_buff opertation at connection (higher)
	 * level to provide zero-copy with socket buffers reusage.
	 *
	 * All the put skbs are owned by the protocol handlers.
	 * Sync sockets don't free the skbs.
	 */
	int (*put_skb_to_msg)(SsProto *proto, struct sk_buff *skb);

	/*
	 * Postpone the @skb into internal protocol queue.
	 */
	int (*postpone_skb)(SsProto *proto, struct sk_buff *skb);
} SsHooks;

int ss_hooks_register(SsHooks* hooks);
void ss_hooks_unregister(SsHooks* hooks);

void ss_tcp_set_listen(struct socket *sk, SsProto *handler);
void ss_send(struct sock *sk, struct sk_buff_head *skb_list, int len);
void ss_close(struct sock *sk);

#endif /* __SS_SOCK_H__ */
