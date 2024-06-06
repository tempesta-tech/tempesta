/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle client traffic.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#include <linux/sort.h>
#include <linux/bsearch.h>

#include "tempesta_fw.h"
#include "cfg.h"
#include "client.h"
#include "connection.h"
#include "http.h"
#include "http_limits.h"
#include "log.h"
#include "procfs.h"
#include "server.h"
#include "sync_socket.h"
#include "tls.h"

/*
 * ------------------------------------------------------------------------
 *	Client socket handling.
 * ------------------------------------------------------------------------
 */

static struct kmem_cache *tfw_h1_conn_cache;
static struct kmem_cache *tfw_https_conn_cache;
static struct kmem_cache *tfw_h2_conn_cache;
static int tfw_cli_cfg_ka_timeout = -1;

unsigned int tfw_cli_max_concurrent_streams;

static inline struct kmem_cache *
tfw_cli_cache(int type)
{
	switch (TFW_FSM_TYPE(type)) {
	case TFW_FSM_H2:
		return tfw_h2_conn_cache;
	case TFW_FSM_HTTPS:
	case TFW_FSM_WSS:
		return tfw_https_conn_cache;
	case TFW_FSM_HTTP:
	case TFW_FSM_WS:
		return tfw_h1_conn_cache;
	default:
		BUG();
	}
}

static void
tfw_sock_cli_keepalive_timer_cb(struct timer_list *t)
{
	TfwCliConn *cli_conn = from_timer(cli_conn, t, timer);

	T_DBG("Client timeout end\n");

	/*
	 * Close the socket (and the connection) asynchronously to avoid
	 * a deadlock on del_timer_sync(). In case of error try to close
	 * it one second later.
	 */
	if (tfw_connection_close((TfwConn *)cli_conn, false))
		mod_timer(&cli_conn->timer, jiffies + msecs_to_jiffies(1000));
}

static TfwCliConn *
tfw_cli_conn_alloc(int type)
{
	TfwCliConn *cli_conn;

	if (!(cli_conn = kmem_cache_alloc(tfw_cli_cache(type), GFP_ATOMIC)))
		return NULL;

	tfw_connection_init((TfwConn *)cli_conn);
	INIT_LIST_HEAD(&cli_conn->seq_queue);
	spin_lock_init(&cli_conn->seq_qlock);
	spin_lock_init(&cli_conn->ret_qlock);
	spin_lock_init(&cli_conn->timer_lock);
	bzero_fast(cli_conn->js_histoty, sizeof(cli_conn->js_histoty));
#ifdef CONFIG_LOCKDEP
	/*
	 * The lock is acquired at only one place where there is no conflict
	 * with the socket lock, so prevent LOCKDEP complaining the dependency.
	 * Use subclass > SINGLE_DEPTH_NESTING to avoid collisions with kernel
	 * and TempestaDB locking subclasses.
	 */
	lockdep_init_map(&cli_conn->ret_qlock.dep_map, "cli_conn->ret_qlock",
			 &__lockdep_no_validate__, 2);
#endif

	timer_setup(&cli_conn->timer, tfw_sock_cli_keepalive_timer_cb, 0);

	return cli_conn;
}
ALLOW_ERROR_INJECTION(tfw_cli_conn_alloc, NULL);

static void
tfw_cli_conn_free(TfwCliConn *cli_conn)
{
	BUG_ON(timer_pending(&cli_conn->timer));

	/*
	 * Free POSTPONED SKBs. This is necessary when h2 context has
	 * postponed frames and connection closing initiated.
	 */
	if (TFW_FSM_TYPE(TFW_FSM_TYPE(cli_conn->proto.type) == TFW_FSM_H2))
		ss_skb_queue_purge(&tfw_h2_context(cli_conn)->skb_head);

	/* Check that all nested resources are freed. */
	tfw_connection_validate_cleanup((TfwConn *)cli_conn);
	BUG_ON(!list_empty(&cli_conn->seq_queue));

	/*
	 * We need to check if it is a single version connection (HTTPS or H2)
	 * or negotiable HTTPS/H2 connection.
	 * In case of a single version connection, corresponding to
	 * this protocol cache was used.
	 * In case of a negotiable connection, H2 cache was used for
	 * both versions, and we need to free H2 cache.
	 */
	if (!(TFW_CONN_TYPE(cli_conn) & Conn_Negotiable))
		kmem_cache_free(tfw_cli_cache(TFW_CONN_TYPE(cli_conn)), cli_conn);
	else
		kmem_cache_free(tfw_cli_cache(TFW_FSM_H2), cli_conn);
}

void
tfw_cli_conn_release(TfwCliConn *cli_conn)
{
	if (likely(cli_conn->sk))
		tfw_connection_unlink_to_sk((TfwConn *)cli_conn);
	if (likely(cli_conn->peer))
		tfw_client_put((TfwClient *)cli_conn->peer);
	tfw_cli_conn_free(cli_conn);
	TFW_INC_STAT_BH(clnt.conn_disconnects);
}

int
tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg)
{
	int r;

	r = tfw_connection_send((TfwConn *)cli_conn, msg);
	/*
	 * The lock is needed because the timer deletion was moved from release() to
	 * drop(). While release() is called when there are no other users, there is
	 * no such luxury with drop() and the connection can still be used due to
	 * lingering threads.
	 */
	spin_lock(&cli_conn->timer_lock);
	if (timer_pending(&cli_conn->timer))
		mod_timer(&cli_conn->timer,
			  jiffies +
			  msecs_to_jiffies((long)tfw_cli_cfg_ka_timeout * 1000));
	spin_unlock(&cli_conn->timer_lock);

	if (r)
		/* Quite usual on system shutdown. */
		T_DBG("Cannot send data to client (%d)\n", r);

	return r;
}

/**
 * First `xmit` callback, which is used to add headers for HTTP2
 * HEADERS and DATA frames. Also used to add hpack dynamic table
 * size at the beginning of the first header block according to
 * RFC 7541. Implemented in separate function, because we use
 * `tso_fragment` with new limit to split skb before passing it
 * to the second `xmit` callback.
 */
static int
tfw_h2_sk_prepare_xmit(struct sock *sk, struct sk_buff *skb,
		       unsigned int mss_now, unsigned int *limit,
		       unsigned int *nskbs)
{
	TfwConn *conn = sk->sk_user_data;
	TfwH2Ctx *h2 = tfw_h2_context(conn);
	TfwHPackETbl *tbl = &h2->hpack.enc_tbl;
	unsigned short flags = skb_tfw_flags(skb);
	unsigned int skb_priv = skb_tfw_cb(skb);
	TfwStream *stream = tfw_h2_find_not_closed_stream(h2, skb_priv, false);
	unsigned int truesize = 0, tmp_truesize = 0;
	bool headers_was_done = false;
	int r = 0;

#define FRAME_HEADERS_SHOULD_BE_MADE(flags)				\
	(flags & SS_F_HTTT2_FRAME_HEADERS)

#define FRAME_DATA_SHOULD_BE_MADE(flags)				\
	(flags & SS_F_HTTT2_FRAME_DATA)

#define FRAME_HEADERS_OR_DATA_SHOULD_BE_MADE(flags)			\
	(FRAME_HEADERS_SHOULD_BE_MADE(flags)				\
	 || FRAME_DATA_SHOULD_BE_MADE(flags))

#define FRAME_ALREADY_PREPARED(flags)					\
	(flags & SS_F_HTTP2_FRAME_PREPARED)

#define CHECK_STREAM_IS_PRESENT(stream)					\
	if (!stream) {							\
		T_WARN("%s: stream with id (%u) already closed",	\
		       __func__, skb_priv);				\
		/*							\
		 * TODO #1196:						\
		 * Don't purge tcp queue and don't close connection,	\
		 * because we can still send data for other streams.	\
		 */							\
		r = -EPIPE;						\
		goto ret;						\
	}

#define TFW_H2_STREAM_SEND_PROCESS(h2, stream, type)			\
	r = tfw_h2_stream_send_process(h2, stream, type);		\
	if (unlikely(r != STREAM_FSM_RES_OK)) {				\
		T_WARN("Failed to process stream %d", (int)r);		\
		/*							\
		 * TODO #1196:						\
		 * drop all skbs for corresponding stream if		\
		 * r == STREAM_FSM_RES_TERM_STREAM.			\
		 */							\
		if (r == STREAM_FSM_RES_TERM_CONN) {			\
			r = -EPIPE;					\
			goto ret;					\
		}							\
	}

	BUG_ON(FRAME_ALREADY_PREPARED(flags));

	/*
	 * If some error occurs between `tcp_tfw_sk_prepare_xmit` and
	 * `tcp_tfw_sk_write_xmit`, skb which was already processed will
	 * be passed to this function again. We should not process this
	 * skb, just update limit according to already processed bytes.
	 */
	if (FRAME_HEADERS_OR_DATA_SHOULD_BE_MADE(flags)) {
		CHECK_STREAM_IS_PRESENT(stream);
		tfw_h2_stream_xmit_reinit(&stream->xmit);
		stream->xmit.nskbs = 1;
	} else {
		struct sk_buff *next = skb;
		unsigned short flags;

		/*
		 * Here we deal with skbs which do not contain HEADERS or
		 * DATA frames. They should be encrypted in separate tls
		 * record.
		 */
		*nskbs = 1;
		while (!tcp_skb_is_last(sk, next)) {
			next = skb_queue_next(&sk->sk_write_queue, next);
			flags = skb_tfw_flags(next);

			if (FRAME_HEADERS_OR_DATA_SHOULD_BE_MADE(flags))
				break;
			(*nskbs)++;
		}
	}

	if (flags & SS_F_HTTP2_ACK_FOR_HPACK_TBL_RESIZING) {
		tfw_hpack_set_rbuf_size(tbl, skb_priv);
		h2->rsettings.hdr_tbl_sz = tbl->window;
		skb_clear_tfw_flag(skb, SS_F_HTTP2_ACK_FOR_HPACK_TBL_RESIZING);
	}

	/*
	 * We should write new hpack dynamic table size at the
	 * beginning of the first header block.
	 */
	if (flags & SS_F_HTTP2_FRAME_START &&
	    !(flags & SS_F_HTTT2_HPACK_TBL_SZ_ENCODED)
	    && FRAME_HEADERS_SHOULD_BE_MADE(flags))
	{
		r = tfw_hpack_enc_tbl_write_sz(tbl, sk, skb, stream,
					       mss_now, &tmp_truesize);
		if (unlikely(r)) {
			T_WARN("%s: failed to encode new hpack dynamic "
			       "table size (%d)", __func__, r);
			goto ret;
		}

		flags |= (tmp_truesize ? SS_F_HTTT2_HPACK_TBL_SZ_ENCODED : 0);
		skb_set_tfw_flags(skb, flags);
	}

	truesize += tmp_truesize;
	tmp_truesize = 0;

	if (FRAME_HEADERS_SHOULD_BE_MADE(flags)) {
		if (*limit - stream->xmit.processed <= FRAME_HEADER_SIZE) {
			r = -ENOMEM;
			goto ret;
		}

		r = tfw_h2_make_headers_frames(sk, skb, h2, stream, mss_now,
					       *limit - stream->xmit.processed,
					       &tmp_truesize);
		if (unlikely(r)) {
			T_WARN("%s: failed to make headers frames (%d)",
			       __func__, r);
			goto ret;
		}

		truesize += tmp_truesize;
		tmp_truesize = 0;
		headers_was_done = true;

		/*
		 * We clear this flag to prevent it's copying
		 * during skb splitting.
		 */
		if (!stream->xmit.h_len) {
			skb_clear_tfw_flag(skb, SS_F_HTTT2_FRAME_HEADERS);
			TFW_H2_STREAM_SEND_PROCESS(h2, stream, HTTP2_HEADERS);
		}
	}

	if (FRAME_DATA_SHOULD_BE_MADE(flags)) {
		if (stream->rem_wnd <= 0 || h2->rem_wnd <= 0
		    || *limit - stream->xmit.processed <= FRAME_HEADER_SIZE) {
			if (headers_was_done)
				goto update_limit;
			r = -ENOMEM;
			goto ret;
		}

		r = tfw_h2_make_data_frames(sk, skb, h2, stream, mss_now,
					    *limit - stream->xmit.processed,
					    &tmp_truesize);
		if (unlikely(r)) {
			T_WARN("%s: failed to make data frames (%d)",
			       __func__, r);
			if (r == -ENOMEM && headers_was_done) {
				r = 0;
				goto update_limit;
			}
			goto ret;
		}

		truesize += tmp_truesize;
		tmp_truesize = 0;

		/*
		 * We clear this flag to prevent it's copying
		 * during skb splitting.
		 */
		if (!stream->xmit.b_len) {
			skb_clear_tfw_flag(skb, SS_F_HTTT2_FRAME_DATA);
			TFW_H2_STREAM_SEND_PROCESS(h2, stream, HTTP2_DATA);
		}
	}

update_limit:
	if (FRAME_HEADERS_OR_DATA_SHOULD_BE_MADE(flags)
	    && stream && stream->xmit.nskbs == 1)
		*limit = stream->xmit.processed;

	if (skb->len > *limit) {
		unsigned short saved_flags = skb_tfw_flags(skb);

		/*
		 * Hacky way to clear flags of skb that will be created after
		 * splitting such skb must be with cleared flags, but
		 * current skb must be with already set flags.
		 */
		skb->tfw_cb.flags &= (unsigned short)(~TEMPESTA_SKB_FLAG_CLEAR_MASK);
		r = tso_fragment(sk, skb, *limit, mss_now,
				 sk_gfp_mask(sk, GFP_ATOMIC));
		skb->tfw_cb.flags = saved_flags;
	}

ret:
	/* Reinit stream xmit context. */
	if (stream)
		*nskbs = !r ? stream->xmit.nskbs : 0;

	/*
	 * Since we add some data to skb, we should adjust the socket write
	 * memory both in case of success and in case of failure.
	 */
	if (unlikely(ss_add_overhead(sk, truesize))) {
		T_WARN("%s: failed to add overhead to current TCP "
		       "socket control data.", __func__);
		/*
		 * In case of previous error return it,
		 * otherwise return -ENOMEM.
		 */
		r = r ? r : -ENOMEM;
	}

	if (unlikely(r) && r != -ENOMEM) {
		if (stream)
			tfw_h2_stream_add_closed(h2, stream);
	}

	if (likely(!r))
		skb_set_tfw_flags(skb, SS_F_HTTP2_FRAME_PREPARED);

	return r;

#undef TFW_H2_STREAM_SEND_PROCESS
#undef CHECK_STREAM_IS_PRESENT
#undef FRAME_ALREADY_PREPARED
#undef FRAME_HEADERS_OR_DATA_SHOULD_BE_MADE
#undef FRAME_DATA_SHOULD_BE_MADE
#undef FRAME_HEADERS_SHOULD_BE_MADE
}

static int
tfw_sk_prepare_xmit(struct sock *sk, struct sk_buff *skb, unsigned int mss_now,
		    unsigned int *limit, unsigned int *nskbs)
{
	TfwConn *conn = sk->sk_user_data;
	bool h2_mode;
	int r = 0;

	assert_spin_locked(&sk->sk_lock.slock);
	/*
	 * This function is called under the socket lock, same as dropping a
	 * connection. Moreover this function is never called when socket
	 * state is TCP_CLOSE. When client closes the connection, we drop it
	 * from tcp_done() -> ss_conn_drop_guard_exit(), and socket state is
	 * set to TCP_CLOSE, so this function will never be called after it.
         */
	BUG_ON(!conn);

	*nskbs = UINT_MAX;
	h2_mode = TFW_CONN_PROTO(conn) == TFW_FSM_H2;
	if (h2_mode)
		r = tfw_h2_sk_prepare_xmit(sk, skb, mss_now, limit, nskbs);

	return r;
}

static int
tfw_sk_write_xmit(struct sock *sk, struct sk_buff *skb, unsigned int mss_now,
		  unsigned int limit, unsigned int nskbs)
{
	TfwConn *conn = sk->sk_user_data;
	TfwH2Ctx *h2;
	TfwHPackETbl *tbl;
	unsigned short flags;
	bool h2_mode;
	int r = 0;

	assert_spin_locked(&sk->sk_lock.slock);
	/* Same as for tfw_sk_prepare_xmit(). */
	BUG_ON(!conn);

	h2_mode = TFW_CONN_PROTO(conn) == TFW_FSM_H2;
	flags = skb_tfw_flags(skb);

	if (h2_mode) {
		h2 = tfw_h2_context(conn);
		tbl = &h2->hpack.enc_tbl;
	}

	r = tfw_tls_encrypt(sk, skb, mss_now, limit, nskbs);

	if (h2_mode && r != -ENOMEM && (flags & SS_F_HTTT2_HPACK_TBL_SZ_ENCODED))
		tfw_hpack_enc_tbl_write_sz_release(tbl, r);
	return r;
}

/**
 * This hook is called when a new client connection is established.
 */
static int
tfw_sock_clnt_new(struct sock *sk)
{
	int r = -ENOMEM;
	SsProto *proto;
	TfwClient *cli;
	TfwConn *conn;
	TfwAddr addr;

	T_DBG3("new client socket: sk=%p, state=%u\n", sk, sk->sk_state);
	TFW_INC_STAT_BH(clnt.conn_attempts);

	/*
	 * New sk->sk_user_data points to TfwListenSock{} of the parent
	 * listening socket. We set it to NULL to stop other functions
	 * from referencing TfwListenSock{} while a new TfwConn{} object
	 * is not yet allocated/initialized.
	 */
	proto = sk->sk_user_data;
	tfw_connection_unlink_from_sk(sk);

	ss_getpeername(sk, &addr);
	cli = tfw_client_obtain(addr, NULL, NULL, NULL);
	if (!cli) {
		T_ERR("can't obtain a client for the new socket\n");
		return -ENOENT;
	}

	conn = (TfwConn *)tfw_cli_conn_alloc(proto->type);
	if (!conn) {
		T_ERR("can't allocate a new client connection\n");
		goto err_client;
	}

	ss_proto_init(&conn->proto, proto->hooks, proto->type);
	BUG_ON(!(conn->proto.type & Conn_Clnt));

	conn->destructor = (void *)tfw_cli_conn_release;

	r = tfw_connection_new(conn);
	if (r) {
		T_ERR("cannot establish a new client connection\n");
		goto err_conn;
	}

#if defined(DEBUG) && (DEBUG == 3)
	sock_set_flag(sk, SOCK_DBG);
#endif

	/* Link Tempesta with the socket and the peer. */
	tfw_connection_revive(conn);
	tfw_connection_link_to_sk(conn, sk);
	tfw_connection_link_from_sk(conn, sk);
	tfw_connection_link_peer(conn, (TfwPeer *)cli);

	ss_set_callbacks(sk);
	if (TFW_CONN_TLS(conn)) {
		/*
		 * Probably, that's not beautiful to introduce an alternate
		 * upcall beside GFSM and SS, but that's efficient and I didn't
		 * find a simple and better solution.
		 */
		sk->sk_prepare_xmit = tfw_sk_prepare_xmit;
		sk->sk_write_xmit = tfw_sk_write_xmit;
	}

	/* Activate keepalive timer. */
	mod_timer(&conn->timer,
		  jiffies +
		  msecs_to_jiffies((long)tfw_cli_cfg_ka_timeout * 1000));

	T_DBG3("new client socket is accepted: sk=%p, conn=%p, cli=%p\n",
	       sk, conn, cli);
	TFW_INC_STAT_BH(clnt.conn_established);
	return 0;

err_conn:
	tfw_cli_conn_free((TfwCliConn *)conn);
err_client:
	tfw_client_put(cli);
	return r;
}

/*
 * The hook is executed when a client connection is closed by either
 * side of the connection or client connection is terminated due to
 * an error of any kind.
 */
static void
tfw_sock_clnt_drop(struct sock *sk)
{
	TfwConn *conn = sk->sk_user_data;

	T_DBG3("connection lost: close client socket: sk=%p, conn=%p, "
	       "client=%p\n", sk, conn, conn->peer);

	spin_lock(&((TfwCliConn *)conn)->timer_lock);
	del_timer_sync(&((TfwCliConn *)conn)->timer);
	spin_unlock(&((TfwCliConn *)conn)->timer_lock);

	/*
	 * A TLS connection was lost during handshake processing. Call FSM
	 * hooks to warn the Frang, since it accounts uncompleted TLS
	 * handshakes. Can't be done on frang_conn_close() since connection is
	 * unlinked from socket on that time and can be already destroyed.
	 */
	if (TFW_CONN_TLS(conn))
		tfw_tls_connection_lost(conn);

	/*
	 * Withdraw from socket activity. Connection is now closed,
	 * and Tempesta is not called anymore on events in the socket.
	 * Remove the connection from the list that is kept in @peer.
	 * Release resources allocated in Tempesta for the connection.
	 */
	tfw_connection_unlink_from_sk(sk);
	tfw_connection_unlink_from_peer(conn);
	tfw_connection_drop(conn);

	/*
	 * Connection @conn, as well as @sk and @peer that make
	 * the essence of it, remain accessible as long as there
	 * are references to @conn.
	 */
	tfw_connection_put(conn);
}

static const SsHooks tfw_sock_http_clnt_ss_hooks = {
	.connection_new		= tfw_sock_clnt_new,
	.connection_drop	= tfw_sock_clnt_drop,
	.connection_recv	= tfw_connection_recv,
};

static const SsHooks tfw_sock_tls_clnt_ss_hooks = {
	.connection_new		= tfw_sock_clnt_new,
	.connection_drop	= tfw_sock_clnt_drop,
	.connection_recv	= tfw_tls_connection_recv,
};

/*
 * We call the same TLS hooks before generic HTTP processing
 * for both the HTTP/1 and HTTP/2.
 */
static const SsProto tfw_sock_listen_protos[] = {
	{ &tfw_sock_http_clnt_ss_hooks,	TFW_FSM_HTTP},
	{ &tfw_sock_http_clnt_ss_hooks,	Conn_HttpClnt},

	{ &tfw_sock_tls_clnt_ss_hooks,	TFW_FSM_HTTPS},
	{ &tfw_sock_tls_clnt_ss_hooks,	Conn_HttpsClnt},

	{ &tfw_sock_tls_clnt_ss_hooks,	TFW_FSM_H2},
	{ &tfw_sock_tls_clnt_ss_hooks,	Conn_H2Clnt},

	{ &tfw_sock_tls_clnt_ss_hooks,	TFW_FSM_H2 | Conn_Negotiable},
	{ &tfw_sock_tls_clnt_ss_hooks,	Conn_H2Clnt | Conn_Negotiable},
};

static const SsProto *
tfw_sock_clnt_proto(int type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tfw_sock_listen_protos); ++i)
		if (tfw_sock_listen_protos[i].type == type)
			return &tfw_sock_listen_protos[i];
	BUG();
}

static int
__cli_conn_close_cb(TfwConn *conn)
{
	/*
	 * Use asynchronous closing to release peer connection list and
	 * client hash bucket locks as soon as possible and let softirq
	 * do all the jobs.
	 */
	return tfw_connection_close(conn, false);
}

static int
__cli_conn_abort_cb(TfwConn *conn)
{
	tfw_connection_abort(conn);
	return 0;
}

/**
 * Asynchronously close all client connections. Some connection close requests
 * may be lost due to workqueue overrun. So the function must be called
 * repeatedly until 0 is returned to guarantee that all connections are closed.
 */
static int
tfw_cli_conn_close_all(void *data)
{
	return tfw_peer_for_each_conn((TfwPeer *)data, __cli_conn_close_cb);
}

/**
 * Close all connections with a given client, called on security events. Unlike
 * @tfw_cli_conn_close_all(), this one must guarantee that all the close
 * requests will be done. Attackers can spam Tempesta with lot of requests and
 * connections, trying to cause a work queue overrun and delay security events
 * handlers. To detach attackers efficiently, we have to use synchronous close.
 */
int
tfw_cli_conn_abort_all(void *data)
{
	return tfw_peer_for_each_conn((TfwPeer *)data, __cli_conn_abort_cb);
}

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
 * @proto	- protocol descriptor for the listening socket;
 * @sk		- The underlying networking representation.
 * @list	- An entry in the tfw_listen_socks list.
 * @addr	- The IP address specified in the configuration.
 */
typedef struct {
	SsProto			proto;
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
static LIST_HEAD(tfw_listen_socks_reconf);
/* Count of entries in tfw_listen_socks list */
static size_t tfw_listen_socks_sz = 0;

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
	const SsHooks *shooks = tfw_sock_clnt_proto(type)->hooks;

	/* Is there such an address on the list already? */
	list_for_each_entry(ls, &tfw_listen_socks_reconf, list) {
		if (tfw_addr_eq(addr, &ls->addr)) {
			T_LOG_ADDR("Duplicate listener with", addr,
				   TFW_WITH_PORT);
			return -EINVAL;
		}
	}

	ls = kzalloc(sizeof(*ls), GFP_KERNEL);
	if (!ls)
		return -ENOMEM;

	ss_proto_init(&ls->proto, shooks, Conn_Clnt | type);
	list_add(&ls->list, &tfw_listen_socks_reconf);
	ls->addr = *addr;

	return 0;
}

static void
tfw_listen_sock_del_all(void)
{
	TfwListenSock *ls, *tmp;

	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks, list) {
		if (ls->sk)
			/*
			 * If error occurred during starting module,
			 * release sockets which were bound.
			 */
			ss_release(ls->sk);
		list_del(&ls->list);
		kfree(ls);
	}

	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks_reconf, list) {
		BUG_ON(ls->sk);
		list_del(&ls->list);
		kfree(ls);
	}

	tfw_listen_socks_sz = 0;
	INIT_LIST_HEAD(&tfw_listen_socks);
	INIT_LIST_HEAD(&tfw_listen_socks_reconf);
	tfw_classifier_cleanup_inport();
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

	T_LOG_ADDR("Open listen socket on", addr, TFW_WITH_PORT);

	r = ss_sock_create(tfw_addr_sa_family(addr), SOCK_STREAM, IPPROTO_TCP,
			   &sk);
	if (r) {
		T_ERR_NL("can't create listening socket (err: %d)\n", r);
		return r;
	}

	/*
	 * Link the new socket and TfwListenSock.
	 *
	 * We use static SsProto's for sk_user_data for listening sockets.
	 * This way initialization of passively open sockets doesn't depend
	 * on the listening socket, which might be closed during a new connection
	 * establishing.
	 *
	 * When a listening socket is closed, the children sockets might live for
	 * an unlimited time.
	 */
	ls->sk = sk;
	sk->sk_user_data = (SsProto *)tfw_sock_clnt_proto(ls->proto.type);

	ss_set_listen(sk);

	inet_sk(sk)->freebind = 1;
	sk->sk_reuse = 1;
	r = ss_bind(sk, addr);
	if (r) {
		T_ERR_ADDR("can't bind to", addr, TFW_WITH_PORT);
		goto err;
	}

	T_DBG("start listening on socket: sk=%p\n", sk);
	r = ss_listen(sk, TFW_LISTEN_SOCK_BACKLOG_LEN);
	if (r) {
		T_ERR_NL("can't listen on front-end socket sk=%p (%d)\n",
			 sk, r);
		goto err;
	}

	return 0;

err:
	ss_release(ls->sk);
	ls->sk = NULL;
	return r;
}

static int
tfw_sock_check_lst(TfwServer *srv)
{
	TfwListenSock *ls;

	T_DBG3("Checking server....\n");
	list_for_each_entry(ls, &tfw_listen_socks_reconf, list) {
		T_DBG3("Iterating listener\n");
		if (tfw_addr_ifmatch(&srv->addr, &ls->addr))
			return -EINVAL;
	}
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	configuration handling
 * ------------------------------------------------------------------------
 */

static int
tfw_cfgop_listen(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r, port, type = TFW_FSM_HTTP;
	TfwAddr addr;
	const char *in_str = NULL;

	if (tfw_cfg_check_val_n(ce, 1) || ce->attr_n > 1)
		goto parse_err;

	/*
	 * Try both:
	 * - a single port without IP address (e.g. "listen 8081");
	 * - a full IP address (e.g. "listen 127.0.0.1:8081").
	 */
	in_str = ce->vals[0];
	r = tfw_cfg_parse_int(in_str, &port);
	if (!r) {
		r = tfw_cfg_check_range(port, 0, 65535);
		if (r)
			goto parse_err;

		/* For single port, use 0.0.0.0:port (IPv4, but not IPv6). */
		addr = tfw_addr_new_v4(INADDR_ANY, htons(port));

	} else {
		r = tfw_addr_pton(&TFW_STR_FROM_CSTR(in_str), &addr);
		if (r)
			goto parse_err;
	}

	r = tfw_cfg_check_range(ce->attr_n, 0, 1);
	if (r)
		goto parse_err;

	/* Plain HTTP/1 is the default listening socket. */
	if (!ce->attr_n)
		goto done;

	in_str = tfw_cfg_get_attr(ce, "proto", NULL);
	if (!in_str)
		goto parse_err;

	if (!strcasecmp(in_str, "http"))
		goto done;

	type = tfw_tls_cfg_alpn_protos(in_str);
	if (type > 0)
		goto done;

parse_err:
	T_ERR_NL("Unable to parse 'listen' value: '%s'\n",
		 in_str ? in_str : "Invalid directive format");
	return -EINVAL;

done:
	if (type & TFW_FSM_HTTPS)
		tfw_tls_cfg_require();
	return tfw_listen_sock_add(&addr, type);
}

static int
tfw_cfgop_keepalive_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	TFW_CFG_CHECK_VAL_N(==, 1, cs, ce);

	if ((r = tfw_cfg_parse_int(ce->vals[0], &tfw_cli_cfg_ka_timeout))) {
		T_ERR_NL("Unable to parse 'keepalive_timeout' value: '%s'\n",
			 ce->vals[0] ? : "No value specified");
		return r;
	}

	if (tfw_cli_cfg_ka_timeout < 0) {
		T_ERR_NL("Unable to parse 'keepalive_timeout' value: '%s'\n",
			 "Value less the zero");
		return -EINVAL;
	}

	return 0;
}

static int
tfw_cfgop_max_concurrent_streams(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	if ((r = tfw_cfg_check_val_n(ce, 1)))
		return -EINVAL;

	if ((r = tfw_cfg_parse_uint(ce->vals[0], &tfw_cli_max_concurrent_streams))) {
		T_ERR_NL("Unable to parse 'max_concurrent_streams' value: '%s'\n",
			 ce->vals[0] ? : "No value specified");
		return -EINVAL;
	}

	return 0;
}

static void
tfw_cfgop_cleanup_sock_clnt(TfwCfgSpec *cs)
{
	tfw_listen_sock_del_all();
}

static int
tfw_sock_clnt_cfgend(void)
{
	int r;

	T_DBG("Checking backends and listeners\n");
	if ((r = tfw_sg_for_each_srv_reconfig(tfw_sock_check_lst))) {
		T_ERR_NL("One of the backends is Tempesta itself!"
			   " Please, fix the configuration.\n");
		return r;
	}

	return 0;
}

static int
tfw_listen_socks_array_cmp(const void *l, const void *r)
{
	TfwListenSock *a = *(TfwListenSock **)l;
	TfwListenSock *b = *(TfwListenSock **)r;
	int cmp;

	cmp = memcmp(&a->addr.sin6_addr, &b->addr.sin6_addr,
		     sizeof(a->addr.sin6_addr));
	if (cmp)
		return cmp;

	cmp = (int)a->addr.sin6_port - (int)b->addr.sin6_port;
	if (cmp)
		return cmp;

	return TFW_CONN_TYPE2IDX(a->proto.type) -
		TFW_CONN_TYPE2IDX(b->proto.type);
}

/**
 * Start listening on all existing sockets (added via "listen" configuration
 * entries).
 */
static int
tfw_sock_clnt_start(void)
{
	int r = 0;
	TfwListenSock *ls, *tmp;
	size_t i, listen_socks_sz = tfw_listen_socks_sz;
	TfwListenSock **ls_found, **listen_socks_array = NULL;
	bool *touched = NULL;

	touched = kzalloc(tfw_listen_socks_sz, GFP_KERNEL);
	if (!touched) {
		T_ERR("can't allocate memory\n");
		r = -ENOMEM;
		goto done;
	}

	listen_socks_array = kmalloc(tfw_listen_socks_sz *
				     sizeof(listen_socks_array[0]), GFP_KERNEL);
	if (!listen_socks_array) {
		T_ERR("can't allocate memory\n");
		r = -ENOMEM;
		goto done;
	}

	i = 0;
	list_for_each_entry(ls, &tfw_listen_socks, list)
		listen_socks_array[i++] = ls;
	BUG_ON(i != tfw_listen_socks_sz);

	sort(listen_socks_array, tfw_listen_socks_sz,
	     sizeof(listen_socks_array[0]), tfw_listen_socks_array_cmp, NULL);

	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks_reconf, list) {
		ls_found = bsearch(&ls, listen_socks_array, tfw_listen_socks_sz,
				   sizeof(listen_socks_array[0]),
				   tfw_listen_socks_array_cmp);
		if (ls_found) {
			touched[ls_found - &listen_socks_array[0]] = true;
			list_del(&ls->list);
			continue;
		}
	}

	for (i = 0; i < tfw_listen_socks_sz; ++i) {
		if (touched[i])
			continue;

		ls = listen_socks_array[i];
		tfw_classifier_remove_inport(tfw_addr_port(&ls->addr));
		listen_socks_sz--;

		list_del(&ls->list);
		if (ls->sk)
			ss_release(ls->sk);
		kfree(ls);
	}

	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks_reconf, list) {
		/*
		 * Paired with tfw_classify_conn_estab(): firstly add the port
		 * to the bitmap and then move it to the listen state to
		 * guarantee that the HTTP limits initialization code was called.
		 */
		tfw_classifier_add_inport(tfw_addr_port(&ls->addr));

		if ((r = tfw_listen_sock_start(ls))) {
			T_ERR_ADDR("can't start listening on", &ls->addr,
				   TFW_WITH_PORT);
			goto done;
		}
		list_del(&ls->list);
		list_add(&ls->list, &tfw_listen_socks);
		listen_socks_sz++;
	}

	tfw_listen_socks_sz = listen_socks_sz;

done:
	kfree(listen_socks_array);
	kfree(touched);

	/**
	 * The list contains the intersection of initial tfw_listen_socks_reconf
	 * and initial tfw_listen_socks
	 */
	list_for_each_entry_safe(ls, tmp, &tfw_listen_socks_reconf, list)
		kfree(ls);

	INIT_LIST_HEAD(&tfw_listen_socks_reconf);
	return r;
}

static void
tfw_sock_clnt_stop(void)
{
	TfwListenSock *ls;

	might_sleep();

	/*
	 * Stop listening sockets, but leave them in the list to bve freed by
	 * tfw_cfgop_cleanup_sock_clnt().
	 */
	list_for_each_entry(ls, &tfw_listen_socks, list) {
		if (!ls->sk)
			continue;
		ss_release(ls->sk);
		ls->sk = NULL;
	}
	ss_wait_newconn();

	/*
	 * Now all listening sockets are closed, so no new connections
	 * can appear. Close all established client connections.
	 * We're going to acquire client hash bucket and peer connection list
	 * locks, so disable softirq to avoid deadlock with the sockets closing
	 * in softirq context.
	 */
	local_bh_disable();
	while (tfw_client_for_each(tfw_cli_conn_close_all)) {
		/*
		 * SS transport is overloaded: let softirqs make progress and
		 * repeat again. Not a big deal that we'll probably close the
		 * same connections - SS can handle it and it's expected that
		 * softirqs close some of them while we wait.
		 */
		local_bh_enable();
		schedule();
		local_bh_disable();
	}
	local_bh_enable();
}

/**
 * Something wrong went on the network layer, e.g. many ACK segment drops and
 * some TLS sockets can not make progress on data transmission, so client
 * connection closing callbacks weren't called. This is unlikely, but probable,
 * situation. Do hard connections termination.
 */
void
tfw_cli_abort_all(void)
{
	local_bh_disable();
	while (tfw_client_for_each(tfw_cli_conn_abort_all))
		;
	local_bh_enable();
}

static TfwCfgSpec tfw_sock_clnt_specs[] = {
	{
		.name = "listen",
		.deflt = "80",
		.handler = tfw_cfgop_listen,
		.cleanup = tfw_cfgop_cleanup_sock_clnt,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "keepalive_timeout",
		.deflt = "75",
		.handler = tfw_cfgop_keepalive_timeout,
		.cleanup = tfw_cfgop_cleanup_sock_clnt,
		.allow_repeat = false,
	},
	{
		.name = "max_concurrent_streams",
		.deflt = "100",
		.handler = tfw_cfgop_max_concurrent_streams,
		.cleanup = tfw_cfgop_cleanup_sock_clnt,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{ 0 }
};

TfwMod tfw_sock_clnt_mod  = {
	.name		= "sock_clnt",
	.cfgend		= tfw_sock_clnt_cfgend,
	.start		= tfw_sock_clnt_start,
	.stop		= tfw_sock_clnt_stop,
	.specs		= tfw_sock_clnt_specs,
	.sock_user	= 1,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int
tfw_sock_clnt_init(void)
{
	/*
	 * Check that flags for SS layer and Connection
	 * layer are not overlapping.
	 */
	BUILD_BUG_ON(Conn_Stop & (Conn_Clnt | Conn_Srv
				  | TFW_FSM_HTTP | TFW_FSM_HTTPS));
	BUG_ON(tfw_h1_conn_cache);
	BUG_ON(tfw_https_conn_cache);
	BUG_ON(tfw_h2_conn_cache);

	tfw_h1_conn_cache = kmem_cache_create("tfw_h1_conn_cache",
					      sizeof(TfwCliConn), 0, 0, NULL);
	if (!tfw_h1_conn_cache)
		return -ENOMEM;

	tfw_https_conn_cache = kmem_cache_create("tfw_https_conn_cache",
						 sizeof(TfwTlsConn), 0, 0, NULL);
	if (!tfw_https_conn_cache) {
		kmem_cache_destroy(tfw_h1_conn_cache);
		return -ENOMEM;
	}

	tfw_h2_conn_cache = kmem_cache_create("tfw_h2_conn_cache",
					      sizeof(TfwH2Conn), 0, 0, NULL);
	if (!tfw_h2_conn_cache) {
		kmem_cache_destroy(tfw_https_conn_cache);
		kmem_cache_destroy(tfw_h1_conn_cache);
		return -ENOMEM;
	}

	tfw_mod_register(&tfw_sock_clnt_mod);

	return 0;
}

void
tfw_sock_clnt_exit(void)
{
	tfw_mod_unregister(&tfw_sock_clnt_mod);
	kmem_cache_destroy(tfw_h2_conn_cache);
	kmem_cache_destroy(tfw_https_conn_cache);
	kmem_cache_destroy(tfw_h1_conn_cache);
}
