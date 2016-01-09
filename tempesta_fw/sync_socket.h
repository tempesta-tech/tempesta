/**
 *		Synchronous Socket API.
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
#ifndef __SS_SOCK_H__
#define __SS_SOCK_H__

#include <net/sock.h>
#include <net/tcp.h>
#include <linux/skbuff.h>

#include "ss_skb.h"

/* Protocol descriptor. */
typedef struct ss_proto_t {
	const struct ss_hooks	*hooks;
	struct sock		*listener;
	int			type;
} SsProto;

/* Table of Synchronous Sockets connection callbacks. */
typedef struct ss_hooks {
	/* New connection accepted. */
	int (*connection_new)(struct sock *sk);

	/* Drop TCP connection associated with the socket. */
	int (*connection_drop)(struct sock *sk);

	/* Error on TCP connection associated with the socket. */
	int (*connection_error)(struct sock *sk);

	/* Process data received on the socket. */
	int (*connection_recv)(void *conn, struct sk_buff *skb,
			       unsigned int off);
} SsHooks;

static inline void
ss_sock_hold(struct sock *sk)
{
	sock_hold(sk);
}

static inline void
ss_sock_put(struct sock *sk)
{
	sock_put(sk);
}

static inline bool
ss_sock_live(struct sock *sk)
{
	return sk->sk_state == TCP_ESTABLISHED;
}

int ss_hooks_register(SsHooks* hooks);
void ss_hooks_unregister(SsHooks* hooks);

void ss_proto_init(SsProto *proto, const SsHooks *hooks, int type);
void ss_proto_inherit(const SsProto *parent, SsProto *child, int child_type);
void ss_set_callbacks(struct sock *sk);
void ss_set_listen(struct sock *sk);
void ss_send(struct sock *sk, SsSkbList *skb_list, bool pass_skb);
void ss_send_bh(struct sock *sk, SsSkbList *skb_list, bool pass_skb);
int ss_close(struct sock *sk);
int ss_close_bh(struct sock *sk);
int ss_sock_create(int family, int type, int protocol, struct sock **res);
void ss_release(struct sock *sk);
int ss_connect(struct sock *sk, struct sockaddr *addr, int addrlen, int flags);
int ss_bind(struct sock *sk, struct sockaddr *addr, int addrlen);
int ss_listen(struct sock *sk, int backlog);
int ss_getpeername(struct sock *sk, struct sockaddr *addr, int *addrlen);

#endif /* __SS_SOCK_H__ */
