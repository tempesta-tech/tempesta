/**
 *		Tempesta FW
 *
 * Generic connection management.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#include "connection.h"
#include "gfsm.h"
#include "log.h"
#include "sync_socket.h"
#include "http.h"
#include "websocket.h"
#include "tcp.h"

TfwConnHooks *conn_hooks[TFW_CONN_MAX_PROTOS];

/*
 * Initialize the connection structure.
 * It's not on any list yet, so it's safe to do so without locks.
 */
void
tfw_connection_init(TfwConn *conn)
{
	memset(conn, 0, sizeof(*conn));
	INIT_LIST_HEAD(&conn->list);
}

void
tfw_connection_link_peer(TfwConn *conn, TfwPeer *peer)
{
	BUG_ON(conn->peer || !list_empty(&conn->list));
	conn->peer = peer;
	tfw_peer_add_conn(peer, &conn->list);
}

/**
 * Publish the "connection is established" event via TfwConnHooks.
 */
int
tfw_connection_new(TfwConn *conn)
{
	return TFW_CONN_HOOK_CALL(conn, conn_init);
}

/**
 * Call connection repairing via TfwConnHooks.
 */
void
tfw_connection_repair(TfwConn *conn)
{
	TFW_CONN_HOOK_CALL(conn, conn_repair);
}

int
tfw_connection_close(TfwConn *conn, bool sync)
{
	int r;

	/*
	 * When connection is closed from process context (when tempesta
	 * is shutdowning) there is a race between `ss_close` and socket
	 * and connection destruction in softirq. We should increment
	 * connection reference counter here to prevent conenction
	 * destruction in running in parallel softirq.
	 */
	tfw_connection_get(conn);
	r = TFW_CONN_HOOK_CALL(conn, conn_close, sync);
	tfw_connection_put(conn);

	return r;
}

void
tfw_connection_abort(TfwConn *conn)
{
	int r;

	/*
	 * Same as for tfw_connection_close() we should increment connection
	 * reference counter here.
	 */
	tfw_connection_get(conn);
	r = TFW_CONN_HOOK_CALL(conn, conn_abort);
	WARN_ON(r);
	tfw_connection_put(conn);
}

/**
 * Publish the "connection is dropped" event via TfwConnHooks.
 */
void
tfw_connection_drop(TfwConn *conn)
{
	/* Ask higher levels to free resources at connection close. */
	TFW_CONN_HOOK_CALL(conn, conn_drop);
}

/*
 * Publish the "connection is released" event via TfwConnHooks.
 */
void
tfw_connection_release(TfwConn *conn)
{
	/* Ask higher levels to free resources at connection release. */
	TFW_CONN_HOOK_CALL(conn, conn_release);
	BUG_ON((TFW_CONN_TYPE(conn) & Conn_Clnt)
	       && !list_empty(&((TfwCliConn *)conn)->seq_queue));
}

/*
 * Send @msg through connection @conn. Code architecture decisions
 * ensure that conn->sk remains valid for the life of @conn instance.
 * The socket itself may have been closed, but not deleted. ss_send()
 * makes sure that data is sent only on an active socket.
 *
 * Return value:
 *   0		- @msg had been sent successfully;
 *   -EBADF	- connection is broken;
 *   -EBUSY	- transmission work queue is full;
 *   -ENOMEM	- out-of-memory error occurred.
 */
int
tfw_connection_send(TfwConn *conn, TfwMsg *msg)
{
	/*
	 * NOTE: after `tfw_connection_send` returns, `msg` should not be used!
	 * See `tfw_tls_conn_send` for reference.
	 */
	return TFW_CONN_HOOK_CALL(conn, conn_send, msg);
}

int
tfw_connection_recv(TfwConn *conn, struct sk_buff *skb)
{
	int r = T_OK;
	struct sk_buff *next, *split;

	if (skb->prev)
		skb->prev->next = NULL;
	for (next = skb->next; skb;
	     skb = next, next = next ? next->next : NULL)
	{
		BUG_ON(r == T_DROP && TFW_CONN_TYPE(conn) & Conn_Srv);
		if (likely(r == T_OK || r == T_POSTPONE || r == T_DROP)) {
			split = skb->next = skb->prev = NULL;
			if (unlikely(TFW_CONN_PROTO(conn) == TFW_FSM_WS
				     || TFW_CONN_PROTO(conn) == TFW_FSM_WSS))
				r = tfw_ws_msg_process(conn, skb);
			else
				r = tfw_http_msg_process(conn, skb, &split);
			if (split) {
				/*
				 * In the case when the current skb contains
				 * multiple requests or responses, we split this
				 * skb along the boundary.
				 */
				split->next = next;
				next = split;
			}
		} else {
			__ss_kfree_skb(skb);
		}
	}

	/*
	 * T_BLOCK is error code for high level modules (like frang),
	 * here we should deal with error code, which accurately
	 * determine further closing behavior.
	 * When error occurs during response processing
	 * we should close connection with backend immediatly
	 * and try to reastablish it later, so we should not
	 * return T_DROP for server connections.
	 */
	BUG_ON(r == T_BLOCK ||
	       (r == T_DROP && TFW_CONN_TYPE(conn) & Conn_Srv));
	return r <= T_BAD || r == T_OK ? r : T_BAD;
}

void
tfw_connection_recv_finish(TfwConn *conn)
{
	TFW_CONN_HOOK_CALL(conn, conn_recv_finish);
}

void
tfw_connection_hooks_register(TfwConnHooks *hooks, int type)
{
	unsigned hid = TFW_CONN_TYPE2IDX(type);

	BUG_ON(hid >= TFW_CONN_MAX_PROTOS || conn_hooks[hid]);

	conn_hooks[hid] = hooks;
}

void
tfw_connection_hooks_unregister(int type)
{
	conn_hooks[TFW_CONN_TYPE2IDX(type)] = NULL;
}

/*
 * Do an opposite to what tfw_connection_link_to_sk() does. Tempesta
 * is unlinked from Sync Sockets layer, so that no data can be sent
 * anymore on a connection. The previously held socket is released.
 * Note that clearing of conn->sk is necessary. In case of failover
 * on a server connection an indicator is needed to remove a hold
 * on the socket. A zeroed conn->sk is that indicator.
 */
void
tfw_connection_unlink_to_sk(TfwConn *conn)
{
	struct sock *sk = conn->sk;

	if (tempesta_sock(sk)->class_prvt)
		tfw_classify_conn_close(sk);
	conn->sk = NULL;
	ss_sock_put(sk);
}

void
tfw_connection_on_send(TfwConn *conn, struct sk_buff **skb_head)
{
	ss_skb_queue_splice(&conn->write_queue, skb_head);
	sock_set_flag(conn->sk, SOCK_TEMPESTA_HAS_DATA);
}

static inline int
tfw_connection_shutdown(TfwConn *conn)
{
	struct sock *sk = conn->sk;

	SS_IN_USE_PROTECT({
		tcp_shutdown(sk, SEND_SHUTDOWN);
	});
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return -ENOMEM;
	return 0;
}

int
tfw_connection_push(TfwConn *conn, unsigned int mss_now)
{
	struct sock *sk = conn->sk;
	TfwH2Ctx *h2;
	unsigned long snd_wnd;
	int r;

	assert_spin_locked(&sk->sk_lock.slock);
	WARN_ON(SS_CONN_TYPE(sk) & Conn_Closing);

	/*
	 * Update snd_cwnd if nedeed, to correct caclulation
	 * of count of bytes to send.
	 */
	tcp_slow_start_after_idle_check(sk);

	/*
	 * First of all Tempesta FW entails skb from connection write queue
	 * (all http1 data, control frames, tls alerts and so on for http2),
	 * then if `snd_wnd` is not exceeded make frames for http2.
	 */
	r = ss_skb_tcp_entail_list(sk, &conn->write_queue,
				   mss_now, &snd_wnd);
	if (unlikely(r))
		return r;

	/*
	 * This function can be called both for HTTP1 and HTTP2 connections.
	 * Moreover this function can be called when HTTP2 connection is
	 * shutdowned before TLS hadshake was finished.
	 */
	h2 = TFW_CONN_PROTO(conn) == TFW_FSM_H2 ?
		tfw_h2_context_safe(conn) : NULL;
	if (!h2) {
		if (unlikely(!conn->write_queue)) {
			sock_reset_flag(sk, SOCK_TEMPESTA_HAS_DATA);
			if (unlikely(SS_CONN_TYPE(sk) & Conn_Shutdown))
				r = tfw_connection_shutdown(conn);
		}
		return r;
	}

	r = tfw_h2_make_frames(sk, h2, mss_now, snd_wnd);
	if (unlikely(r))
		return r;

	if (unlikely(!conn->write_queue)) {
		/*
		 * If connection is shutdowned and error responce was sent
		 * shutdown the whole connection.
		 */
		if (unlikely(SS_CONN_TYPE(sk) & Conn_Shutdown)
		    && (!h2->error
			|| tfw_h2_conn_or_stream_wnd_is_exceeded(h2,
								 h2->error)))
			r = tfw_connection_shutdown(conn);
		if (!tfw_h2_is_ready_to_send(h2))
			sock_reset_flag(sk, SOCK_TEMPESTA_HAS_DATA);
	}

	return r;
}
