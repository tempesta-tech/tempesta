/**
 *		Tempesta FW
 *
 * Definitions for generic connection management at OSI level 6 (presentation).
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#ifndef __TFW_CONNECTION_H__
#define __TFW_CONNECTION_H__

#include <net/sock.h>

#include "gfsm.h"
#include "msg.h"
#include "peer.h"

#include "sync_socket.h"
#include "tls.h"

enum {
	/* Protocol bits. */
	__Conn_Bits	= 0x8,

	/* Each connection has Client or Server bit. */
	Conn_Clnt	= 0x1 << __Conn_Bits,
	Conn_Srv	= 0x2 << __Conn_Bits,

	/* HTTP */
	Conn_HttpClnt	= Conn_Clnt | TFW_FSM_HTTP,
	Conn_HttpSrv	= Conn_Srv | TFW_FSM_HTTP,

	/* HTTPS */
	Conn_HttpsClnt	= Conn_Clnt | TFW_FSM_HTTPS,
	Conn_HttpsSrv	= Conn_Srv | TFW_FSM_HTTPS,
};

#define TFW_CONN_TYPE2IDX(t)	TFW_FSM_TYPE(t)

/**
 * Session/Presentation layer (in OSI terms) handling.
 *
 * An instance of TfwConn{} structure links each HTTP message to properties
 * of a connection the message has come on. Some messages may stay longer
 * in Tempesta after they're sent out to their destinations. Requests are
 * kept until a paired response comes. By the time the request's connection
 * is needed for sending the response, it may be destroyed already. Thus,
 * TfwConn{} instance is not destroyed along with the connection so that
 * it can be safely dereferenced. It's kept around until refcnt's value
 * permits freeing of the instance, so it may have longer lifetime than
 * the connection itself.
 *
 * @sk is an intrinsic property of TfwConn{}.
 * It has exactly the same lifetime as an instance of TfwConn{}.
 *
 * @peer is major property of TfwConn{}. An instance of @peer has longer
 * lifetime expectation than a connection. @peer is always valid while
 * it's referenced from an instance of TfwConn{}. That is supported by
 * a separate reference counter in @peer.
 *
 * These are the properties of a connection that are common to client
 * and server connections.
 *
 * @proto	- protocol handler. Base class, must be first;
 * @state	- connection processing state;
 * @list	- member in the list of connections with @peer;
 * @refcnt	- number of users of the connection structure instance;
 * @timer	- The keep-alive/retry timer for the connection;
 * @msg		- message that is currently being processed;
 * @peer	- TfwClient or TfwServer handler;
 * @sk		- an appropriate sock handler;
 * @destructor	- called when a connection is destroyed;
 * @forward	- called when a request is forwarded to server;
 */
#define TFW_CONN_COMMON					\
	SsProto			proto;			\
	TfwGState		state;			\
	struct list_head	list;			\
	atomic_t		refcnt;			\
	struct timer_list	timer;			\
	TfwMsg			*msg;			\
	TfwPeer 		*peer;			\
	struct sock		*sk;			\
	void			(*destructor)(void *);

typedef struct {
	TFW_CONN_COMMON;
} TfwConn;

#define TFW_CONN_TYPE(c)	((c)->proto.type)

/*
 * These are specific properties that are relevant to client connections.
 *
 * @seq_queue	- queue of client's messages in the order they came;
 * @seq_qlock	- lock for accessing @seq_queue;
 * @ret_qlock	- lock for serializing sets of responses;
 */
typedef struct {
	TFW_CONN_COMMON;
	struct list_head	seq_queue;
	spinlock_t		seq_qlock;
	spinlock_t		ret_qlock;
} TfwCliConn;

/*
 * These are specific properties that are relevant to server connections.
 * See the description of special features of this structure in sock_srv.c.
 *
 * @fwd_queue	- queue of messages to be sent to a back-end server;
 * @nip_queue	- queue of non-idempotent messages in server's @fwd_queue;
 * @fwd_qlock	- lock for accessing @fwd_queue and @nip_queue;
 * @flags	- atomic flags related to server connection's state;
 * @qsize	- current number of requests in server's @msg_queue;
 * @recns	- the number of reconnect attempts;
 * @msg_sent	- request that was sent last in a server connection;
 */
typedef struct {
	TFW_CONN_COMMON;
	struct list_head	fwd_queue;
	struct list_head	nip_queue;
	spinlock_t		fwd_qlock;
	unsigned long		flags;
	unsigned int		qsize;
	unsigned int		recns;
	TfwMsg			*msg_sent;
} TfwSrvConn;

#define TFW_CONN_DEATHCNT	(INT_MIN / 2)

/* Connection flags are defined by the bit number. */
enum {
	TFW_CONN_B_RESEND = 0,	/* Need to re-send requests. */
	TFW_CONN_B_QFORWD,	/* Need to forward requests in the queue. */
	TFW_CONN_B_HASNIP,	/* Has non-idempotent requests. */
	TFW_CONN_B_ISDEAD,	/* Is dead, unable to reconnect. */
};

#define TFW_CONN_F_RESEND	(1 << TFW_CONN_B_RESEND)
#define TFW_CONN_F_QFORWD	(1 << TFW_CONN_B_QFORWD)
#define TFW_CONN_F_HASNIP	(1 << TFW_CONN_B_HASNIP)
#define TFW_CONN_F_ISDEAD	(1 << TFW_CONN_B_ISDEAD)

/**
 * TLS hardened connection.
 */
typedef struct {
	TfwConn		conn;
	TfwTlsContext	tls;
} TfwTlsConn;

#define tfw_tls_context(p)	(TfwTlsContext *)(&((TfwTlsConn *)p)->tls)

/* Callbacks used by l5-l7 protocols to operate on connection level. */
typedef struct {
	/*
	 * Called before servicing a new connection (connection
	 * type, client or server, is checked in the callback).
	 * This is a good place to handle Access or GEO modules
	 * (block a client or bind its descriptor with GEO data).
	 */
	int (*conn_init)(TfwConn *conn);

	/*
	 * Called when a new connection is initialized and before
	 * the initialization is complete. Makes sense only for
	 * server connections. Used to re-send requests that were
	 * left in the connection queue.
	 */
	void (*conn_repair)(TfwConn *conn);

	/*
	 * Called when closing a connection (client or server,
	 * as in conn_init()). This is required for modules that
	 * maintain the number of established client connections.
	 */
	void (*conn_drop)(TfwConn *conn);

	/*
	 * Called when there are no more users of a connection
	 * and the connections's resources are finally released.
	 */
	void (*conn_release)(TfwConn *conn);

	/*
	 * Called by the connection layer when there is a message
	 * that needs to be send.
	 */
	int (*conn_send)(TfwConn *conn, TfwMsg *msg);
} TfwConnHooks;

#define TFW_CONN_MAX_PROTOS	TFW_GFSM_FSM_N

extern TfwConnHooks *conn_hooks[TFW_CONN_MAX_PROTOS];

/* These macros are for calling the defined proto hooks. */
#define tfw_conn_hook_call(proto, c, f, ...)	\
	conn_hooks[proto]->f ? conn_hooks[proto]->f(c, ## __VA_ARGS__) : 0
#define TFW_CONN_HOOK_CALL(c, f...)		\
	tfw_conn_hook_call(TFW_CONN_TYPE2IDX(TFW_CONN_TYPE(c)), c, f)

/*
 * Tell if a server connection connection is restricted. A restricted
 * server connection is not available to schedulers.
 *
 * The flag RESEND is set when a newly established server connection
 * has messages in the forwarding queue. That means that the connection
 * had been closed prematurely, and the messages in the queue need to
 * be re-sent to a back-end server. The new connection is not available
 * to schedulers (restricted) until all messages in the forwarding queue
 * are re-sent.
 */
static inline bool
tfw_srv_conn_restricted(TfwSrvConn *srv_conn)
{
	return test_bit(TFW_CONN_B_RESEND, &srv_conn->flags);
}

/*
 * Tell if a connection has non-idempotent requests.
 */
static inline bool
tfw_srv_conn_hasnip(TfwSrvConn *srv_conn)
{
	return test_bit(TFW_CONN_B_HASNIP, &srv_conn->flags);
}

static inline bool
tfw_connection_live(TfwConn *conn)
{
	return atomic_read(&conn->refcnt) > 0;
}
static inline bool
tfw_srv_conn_live(TfwSrvConn *srv_conn)
{
	return tfw_connection_live((TfwConn *)srv_conn);
}

static inline void
tfw_connection_get(TfwConn *conn)
{
	atomic_inc(&conn->refcnt);
}
static inline void
tfw_cli_conn_get(TfwCliConn *cli_conn)
{
	tfw_connection_get((TfwConn *)cli_conn);
}
static inline void
tfw_srv_conn_get(TfwSrvConn *srv_conn)
{
	tfw_connection_get((TfwConn *)srv_conn);
}

/**
 * Increment reference counter and return true if @conn is not in
 * failovering process, i.e. @refcnt wasn't less or equal to zero.
 */
static inline bool
__tfw_connection_get_if_live(TfwConn *conn)
{
	int old, rc = atomic_read(&conn->refcnt);

	while (likely(rc > 0)) {
		old = atomic_cmpxchg(&conn->refcnt, rc, rc + 1);
		if (likely(old == rc))
			return true;
		rc = old;
	}

	return false;
}
static inline bool
tfw_srv_conn_get_if_live(TfwSrvConn *srv_conn)
{
	return __tfw_connection_get_if_live((TfwConn *)srv_conn);
}

static inline void
tfw_connection_put(TfwConn *conn)
{
	int rc;

	if (unlikely(!conn))
		return;

	rc = atomic_dec_return(&conn->refcnt);
	if (likely(rc && rc != TFW_CONN_DEATHCNT))
		return;
	if (conn->destructor)
		conn->destructor(conn);
}
static inline void
tfw_cli_conn_put(TfwCliConn *cli_conn)
{
	tfw_connection_put((TfwConn *)cli_conn);
}
static inline void
tfw_srv_conn_put(TfwSrvConn *srv_conn)
{
	tfw_connection_put((TfwConn *)srv_conn);
}

static inline void
tfw_connection_put_to_death(TfwConn *conn)
{
	atomic_add(TFW_CONN_DEATHCNT, &conn->refcnt);
}

static inline void
tfw_connection_revive(TfwConn *conn)
{
	atomic_set(&conn->refcnt, 1);
}

/*
 * Link Sync Sockets layer with Tempesta. The socket @sk now carries
 * a reference to Tempesta's @conn instance. When a Tempesta's socket
 * callback is called by Sync Sockets on an event in the socket, then
 * the reference to @conn instance for the socket can be found quickly.
 */
static inline void
tfw_connection_link_from_sk(TfwConn *conn, struct sock *sk)
{
	BUG_ON(sk->sk_user_data);
	sk->sk_user_data = conn;
}

/*
 * Link Tempesta with Sync Sockets layer. @conn instance now carries
 * a reference to @sk. When there's need to send data on a connection,
 * then the socket for that connection can be found quickly. Also,
 * get a hold of the socket to avoid premature socket release.
 */
static inline void
tfw_connection_link_to_sk(TfwConn *conn, struct sock *sk)
{
	ss_sock_hold(sk);
	conn->sk = sk;
}

/*
 * Do an oposite to what tfw_connection_link_from_sk() does.
 * Sync Sockets layer is unlinked from Tempesta, so that Tempesta
 * callbacks are not called anymore on events in the socket.
 */
static inline void
tfw_connection_unlink_from_sk(struct sock *sk)
{
	BUG_ON(!sk->sk_user_data);
	sk->sk_user_data = NULL;
}

/*
 * Do an opposite to what tfw_connection_link_to_sk() does. Tempesta
 * is unlinked from Sync Sockets layer, so that no data can be sent
 * anymore on a connection. The previously held socket is released.
 * Note that clearing of conn->sk is necessary. In case of failover
 * on a server connection an indicator is needed to remove a hold
 * on the socket. A zeroed conn->sk is that indicator.
 */
static inline void
tfw_connection_unlink_to_sk(TfwConn *conn)
{
	struct sock *sk = conn->sk;

	conn->sk = NULL;
	ss_sock_put(sk);
}

static inline void
tfw_connection_unlink_from_peer(TfwConn *conn)
{
	BUG_ON(!conn->peer || list_empty(&conn->list));
	tfw_peer_del_conn(conn->peer, &conn->list);
}

static inline void
tfw_connection_unlink_msg(TfwConn *conn)
{
	conn->msg = NULL;
}

/**
 * Check that TfwConn{} resources are cleaned up properly.
 */
static inline void
tfw_connection_validate_cleanup(TfwConn *conn)
{
	int rc;

	BUG_ON(!conn);
	BUG_ON(!list_empty(&conn->list));
	BUG_ON(atomic_read(&conn->refcnt) & ~1);	/* FIXME */
	BUG_ON(conn->msg);

	rc = atomic_read(&conn->refcnt);
	BUG_ON(rc && rc != TFW_CONN_DEATHCNT);
}

void tfw_connection_hooks_register(TfwConnHooks *hooks, int type);
void tfw_connection_hooks_unregister(int type);
int tfw_connection_send(TfwConn *conn, TfwMsg *msg);

/* Generic helpers, used for both client and server connections. */
void tfw_connection_init(TfwConn *conn);
void tfw_connection_link_peer(TfwConn *conn, TfwPeer *peer);

int tfw_connection_new(TfwConn *conn);
void tfw_connection_repair(TfwConn *conn);
void tfw_connection_drop(TfwConn *conn);
void tfw_connection_release(TfwConn *conn);

int tfw_connection_recv(void *cdata, struct sk_buff *skb, unsigned int off);

#endif /* __TFW_CONNECTION_H__ */
