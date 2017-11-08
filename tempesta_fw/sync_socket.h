/**
 *		Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
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

#include "addr.h"
#include "ss_skb.h"

/* Protocol descriptor. */
typedef struct ss_proto_t {
	const struct ss_hooks	*hooks;
	struct sock		*listener;
	int			type;
} SsProto;

/*
 * Flag bits definition for SsProto.type field.
 * NOTE: There are also flags definition for this
 * field in Connection layer (in connection.h)
 */
enum {
	/* Flag bits offset for SsProto field. */
	__Flag_Bits		= 0x10,

	/*
	 * Connection is in special state: it is alive and
	 * continue send responses to client, but no new
	 * requests longer accepted (flag is intended
	 * only for client connections).
	 */
	Conn_Suspected		= 0x1 << __Flag_Bits,
};

/* Table of Synchronous Sockets connection callbacks. */
typedef struct ss_hooks {
	/* New connection accepted. */
	int (*connection_new)(struct sock *sk);

	/*
	 * Drop TCP connection associated with the socket.
	 * The callback is called on intentional socket closing when the socket
	 * is already closed (i.e. there could not be ingress data on it) and we
	 * can safely do some clenup stuff. We need the callback sine socket
	 * closing always has chance to run asynchronously on other CPU and a
	 * caller doesn't know the it completes.
	 */
	void (*connection_drop)(struct sock *sk);

	/*
	 * Error on TCP connection (on Linux TCP socket layer) associated
	 * with the socket or at application (data processing) layer,
	 * i.e. unintentional connection closing.
	 */
	void (*connection_error)(struct sock *sk);

	/* Process data received on the socket. */
	int (*connection_recv)(void *conn, struct sk_buff *skb,
			       unsigned int off);
} SsHooks;

/**
 * Synchronous sockets per-CPU statistics.
 *
 * @rb_wq_sz	- number of items in ring-buffer work queue;
 * @backlog_sz	- size of backlog;
 */
typedef struct {
	unsigned int	rb_wq_sz;
	unsigned int	backlog_sz;
} SsStat;

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

enum {
	__SS_F_SYNC = 0,		/* Synchronous operation required. */
	__SS_F_KEEP_SKB,		/* Keep SKBs (use clones) on sending. */
	__SS_F_CONN_CLOSE,		/* Close (drop) the connection. */
};

#define SS_F_SYNC			(1 << __SS_F_SYNC)
#define SS_F_KEEP_SKB			(1 << __SS_F_KEEP_SKB)
#define SS_F_CONN_CLOSE			(1 << __SS_F_CONN_CLOSE)

#define ss_close(sk)			\
	__ss_close(sk, 0)
#define ss_close_sync(sk, drop)		\
	__ss_close(sk, SS_F_SYNC | (drop ? SS_F_CONN_CLOSE : 0))

int ss_hooks_register(SsHooks* hooks);
void ss_hooks_unregister(SsHooks* hooks);

void ss_proto_init(SsProto *proto, const SsHooks *hooks, int type);
void ss_proto_inherit(const SsProto *parent, SsProto *child, int child_type);
void ss_set_callbacks(struct sock *sk);
void ss_set_listen(struct sock *sk);
int ss_send(struct sock *sk, SsSkbList *skb_list, int flags);
int __ss_close(struct sock *sk, int flags);
int ss_sock_create(int family, int type, int protocol, struct sock **res);
void ss_release(struct sock *sk);
int ss_connect(struct sock *sk, struct sockaddr *addr, int addrlen, int flags);
int ss_bind(struct sock *sk, struct sockaddr *addr, int addrlen);
int ss_listen(struct sock *sk, int backlog);
void ss_getpeername(struct sock *sk, TfwAddr *addr);
void ss_wait_newconn(void);
void ss_synchronize(void);
void ss_start(void);
void ss_stop(void);
bool ss_active(void);
void ss_get_stat(SsStat *stat);

#define SS_CALL(f, ...)							\
	(sk->sk_user_data && ((SsProto *)(sk)->sk_user_data)->hooks->f	\
	? ((SsProto *)(sk)->sk_user_data)->hooks->f(__VA_ARGS__)	\
	: 0)

#define SS_CONN_TYPE(sk)							\
	(((SsProto *)(sk)->sk_user_data)->type)

#endif /* __SS_SOCK_H__ */
