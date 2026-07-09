/**
 *		Synchronous Socket API.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2026 Tempesta Technologies, Inc.
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
#include <linux/bug.h>

#include "addr.h"
#include "ss_skb.h"

/* Protocol descriptor. */
typedef struct ss_proto_t {
	const struct ss_hooks	*hooks;
	int			type;
} SsProto;

typedef enum {
	SS_SEND,
	SS_CLOSE,
} SsAction;

#define TFW_H_MAX 30

typedef struct {
	void *p;
	struct sock *sk;
	int op;
	int refcnt;
} t_history;

typedef struct {
	int begin;
	int mid1;
	int mid2;
	int end;
	int old_state1;
	int old_state2;
	int old_state3;
	int iteration_count;
	struct sock *sk;
	atomic_t cnt;
	t_history history[TFW_H_MAX];
} tfw_sk_history;

extern DEFINE_PER_CPU(tfw_sk_history, sk_history);

static inline void
tfw_sk_history_init(tfw_sk_history *h)
{
	int i;

	h->old_state3 = h->old_state2 = h->old_state1 = h->begin = h->end = h->mid1 = h->mid2 = h->iteration_count = 0;
	h->sk = NULL;
	atomic_set(&h->cnt, 0);
	for (i = 0; i < TFW_H_MAX; i++) {
		h->history[i].p = NULL;
		h->history[i].op = 0;
		h->history[i].refcnt = 0;
		h->history[i].sk = NULL;
	}
}

static inline void
tfw_sk_history_print_one(tfw_sk_history *h)
{
	int cnt = atomic_read(&h->cnt);
	int i;

	printk(KERN_ALERT "old_state %d %d %d begin %d mid1 %d mid2 %d end %d iter %d sk %px cnt %d\n",
                h->old_state1, h->old_state2, h->old_state3, h->begin, h->mid1, h->mid2, h->end, h->iteration_count, h->sk, cnt);
	if (h->sk)
		printk(KERN_ALERT "%d %d %d %d %d %d %d %d %d %d\n",
			sock_flag(h->sk, SOCK_TEMPESTA_1),
			sock_flag(h->sk, SOCK_TEMPESTA_2),
			sock_flag(h->sk, SOCK_TEMPESTA_3),
			sock_flag(h->sk, SOCK_TEMPESTA_4),
			sock_flag(h->sk, SOCK_TEMPESTA_5),
			sock_flag(h->sk, SOCK_TEMPESTA_6),
			sock_flag(h->sk, SOCK_TEMPESTA_7),
			sock_flag(h->sk, SOCK_TEMPESTA_8),
			sock_flag(h->sk, SOCK_TEMPESTA_9),
			sock_flag(h->sk, SOCK_TEMPESTA_10));
	
	
	for (i = 0; i < cnt; i++)
		printk(KERN_ALERT "%d: %ps op %d sk %px ref %d\n",
			i, h->history[i].p, h->history[i].op, h->history[i].sk,
			h->history[i].refcnt);
}

static inline void
tfw_sk_history_adjust(struct sock *sk, int op)
{
	tfw_sk_history *h = this_cpu_ptr(&sk_history);
	int cnt = atomic_fetch_add(1, &h->cnt);

	if (cnt < TFW_H_MAX) {
		h->history[cnt].op = op;
		h->history[cnt].sk = sk;
		h->history[cnt].refcnt = refcount_read(&sk->sk_refcnt);
	}
}

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
	Conn_Stop		= (0x1 << __Flag_Bits),
	/*
	 * Connection is in special state: we send FIN to
	 * the client and wait until ACK to our FIN is come.
	 * Socket is alive.
	 */
	Conn_Shutdown		= (0x2 << __Flag_Bits),
	/*
	 * Connection is in special state: it socket is DEAD
	 * and wait until ACK to our FIN is come.
	 */
	Conn_Closing		= (0x4 << __Flag_Bits),
};

typedef struct tfw_conn_t TfwConn;

/* Table of Synchronous Sockets connection callbacks. */
typedef struct ss_hooks {
	/* New connection accepted. */
	int (*connection_new)(struct sock *sk);

	/*
	 * Intentional socket closing when the socket is already closed (i.e.
	 * there could not be ingress data on it) and we can safely do some
	 * cleanup stuff or error on TCP connection (on Linux TCP socket layer)
	 * associated with the socket or at application (data processing)
	 * layer, i.e. unintentional connection closing.
	 * We need the callback since socket closing always has a chance to run
	 * asynchronously on another CPU and a caller doesn't know when it
	 * completes.
	 */
	void (*connection_drop)(struct sock *sk);

	/* Process data received on the socket. */
	int (*connection_recv)(TfwConn *conn, struct sk_buff *skb);

	/* Callback to make some job after processing received data. */
	int (*connection_recv_finish)(TfwConn *conn);

	/* Callback to make some job on connection shutdown. */
	void (*connection_on_shutdown)(TfwConn *conn);
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
ss_sock_hold(struct sock *sk, int op)
{
	if (ADJUST)
                ADJUST(sk, op);
	refcount_inc(&sk->sk_refcnt);
}

static inline void
ss_sock_put(struct sock *sk, int op)
{
	if (ADJUST)
                ADJUST(sk, op);

        if (refcount_dec_and_test_tfw(&sk->sk_refcnt, 155))
                sk_free(sk);
}

void tfw_sk_adjust_1(struct sock *sk, int op);

static inline bool
ss_sock_is_closed(struct sock *sk)
{
	return sk->sk_state == TCP_CLOSE;
}

static inline void
ss_proto_init(SsProto *proto, const SsHooks *hooks, int type)
{
	proto->hooks = hooks;
	proto->type = type;
}

/**
 * Add overhead to current TCP socket control data.
 */
static inline void
ss_add_overhead(struct sock *sk, unsigned int overhead)
{
	if (!overhead)
		return;
	sk_forced_mem_schedule(sk, overhead);
	sk->sk_wmem_queued += overhead;
	sk_mem_charge(sk, overhead);
}

/* Dummy user ID to differentiate server from client sockets. */
#define SS_SRV_USER			0x11223344

/* Synchronous operation required. */
#define SS_F_SYNC			0x01
/* Keep SKBs (use clones) on sending. */
#define SS_F_KEEP_SKB			0x02
/* Close (drop) the connection. */
#define SS_F_CONN_CLOSE			0x04
/* Call TLS encryption hook on the skb transmission. */
#define SS_F_ENCRYPT			0x08
/* Close with TCP RST (connection abort). */
#define __SS_F_RST			0x10
#define SS_F_ABORT			(__SS_F_RST | SS_F_SYNC)
#define __SS_F_FORCE			0x20
#define SS_F_ABORT_FORCE		(SS_F_ABORT | __SS_F_FORCE)
#define SS_F_CLOSE_FORCE		(SS_F_CONN_CLOSE | __SS_F_FORCE)

/* Conversion of skb type (flag) to/from TLS record type. */
#define SS_SKB_TYPE2F(t)		(((int)(t)) << 8)
#define SS_SKB_F2TYPE(f)		((f) >> 8)

/* Init functions. */
int tfw_sync_socket_init(void);
void tfw_sync_socket_exit(void);
int tfw_sock_clnt_init(void);
void tfw_sock_clnt_exit(void);
int tfw_sock_srv_init(void);
void tfw_sock_srv_exit(void);

void ss_set_callbacks(struct sock *sk);
void ss_set_listen(struct sock *sk);
int ss_send(struct sock *sk, struct sk_buff **skb_head, int flags);
int ss_close(struct sock *sk, int flags);
int ss_sock_create(int family, int type, int protocol, struct sock **res);
void ss_release(struct sock *sk);
int ss_connect(struct sock *sk, const TfwAddr *addr, int flags);
int ss_bind(struct sock *sk, const TfwAddr *addr);
int ss_listen(struct sock *sk, int backlog);
void ss_getpeername(struct sock *sk, TfwAddr *addr);
void ss_wait_newconn(void);
bool ss_synchronize(void);
void ss_start(void);
void ss_stop(void);
bool ss_active(void);
void ss_get_stat(SsStat *stat);
void ss_skb_tcp_entail(struct sock *sk, struct sk_buff *skb, unsigned int mark,
		       unsigned char tls_type);
int ss_skb_tcp_entail_list(struct sock *sk, struct sk_buff **skb_head,
			   unsigned int mss_now, unsigned long *snd_wnd);

/*
 * We should all linux kernel functions like `tcp_push` or
 * `tcp_push_pending_frames` using this macro, to prevent call
 * of `tcp_done` inside this functions in case of error.
 */
#define SS_IN_USE_PROTECT(lambda)					\
do {									\
	sock_set_flag(sk, SOCK_TEMPESTA_IN_USE);			\
	lambda;								\
	sock_reset_flag(sk, SOCK_TEMPESTA_IN_USE);			\
} while (0)


#define SS_CALL(f, ...)							\
	(sk->sk_user_data && ((SsProto *)(sk)->sk_user_data)->hooks->f	\
	? ((SsProto *)(sk)->sk_user_data)->hooks->f(__VA_ARGS__)	\
	: 0)

#define SS_CONN_TYPE(sk)	(((SsProto *)(sk)->sk_user_data)->type)

/*
 * This function is used to close sockets in TCP_CLOSE state.
 * Whe socket is created using `ss_inet_create` it is created
 * in TCP_CLOSE state. We can't close such socket using `ss_close`
 * because we check socket state in `ss_tx_action` before
 * calling `ss_do_close` to prevent multiple socket closing. But
 * we should close such sockets to prevent memory leak, because
 * socket destructor is not called for not DEAD sockets.
 */
void ss_close_not_connected_socket(struct sock *sk);

#endif /* __SS_SOCK_H__ */
