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
 * An instance of TfwConnection{} structure links each HTTP message
 * to the attributes of a connection the message has come on. Some
 * of those messages may stay longer in Tempesta after they're sent
 * out to their destinations. Requests are kept until a paired
 * response comes. By the time there's need to use the request's
 * connection to send the response on, it may already be destroyed.
 * With that in mind, TfwConnection{} instance is not destroyed
 * along with the connection so that is can be safely dereferenced.
 * It's kept around until refcnt permits freeing of the instance,
 * so it may have longer lifetime than the connection itself.
 *
 * @sk is an intrinsic property of TfwConnection{}.
 * It has exactly the same lifetime as an instance of TfwConnection{}.
 *
 * @peer is major property of TfwConnection{}. An instance of @peer
 * has longer lifetime expectation than a connection. @peer is always
 * valid while it's referenced from an instance of TfwConnection{}.
 * That is supported by a separate reference counter in @peer.
 *
 * @proto	- protocol handler. Base class, must be first;
 * @state	- connection processing state;
 * @list	- member in the list of connections with @peer;
 * @msg_queue	- queue of messages to be sent over the connection;
 * @msg_qlock	- lock for accessing @msg_queue;
 * @refcnt	- number of users of the connection structure instance;
 * @timer	- The keep-alive/retry timer for the connection;
 * @msg		- message that is currently being processed;
 * @peer	- TfwClient or TfwServer handler;
 * @sk		- an appropriate sock handler;
 */
typedef struct {
	SsProto			proto;
	TfwGState		state;
	struct list_head	list;
	struct list_head	msg_queue;
	spinlock_t		msg_qlock;
	atomic_t		refcnt;
	struct timer_list	timer;
	TfwMsg			*msg;
	TfwPeer 		*peer;
	struct sock		*sk;
	void			(*destructor)(void *);
} TfwConnection;

#define TFW_CONN_DEATHCNT	(INT_MIN / 2)

#define TFW_CONN_TYPE(c)	((c)->proto.type)

/**
 * TLS hardened connection.
 */
typedef struct {
	TfwConnection		conn;
	TfwTlsContext		tls;
} TfwTlsConnection;

#define tfw_tls_context(p)	(TfwTlsContext *)(&((TfwTlsConnection *)p)->tls)

/* Callbacks used by l5-l7 protocols to operate on connection level. */
typedef struct {
	/*
	 * Called before servicing a new connection (connection
	 * type, client or server, is checked in the callback).
	 * This is a good place to handle Access or GEO modules
	 * (block a client or bind its descriptor with GEO data).
	 */
	int (*conn_init)(TfwConnection *conn);

	/*
	 * Called when closing a connection (client or server,
	 * as in conn_init()). This is required for modules that
	 * maintain the number of established client connections.
	 */
	void (*conn_drop)(TfwConnection *conn);

	/*
	 * Called when there are no more users of a connection
	 * and the connections's resources are finally released.
	 */
	void (*conn_release)(TfwConnection *conn);

	/*
	 * Called by the connection layer when there is a message
	 * that needs to be send.
	 */
	int (*conn_send)(TfwConnection *conn, TfwMsg *msg);
} TfwConnHooks;

#define TFW_CONN_MAX_PROTOS	TFW_GFSM_FSM_N

extern TfwConnHooks *conn_hooks[TFW_CONN_MAX_PROTOS];

/* This macros are intended to use to call certain proto hooks. */
#define tfw_conn_hook_call(proto, c, f, ...)	\
	conn_hooks[proto]->f ? conn_hooks[proto]->f(c, ## __VA_ARGS__) : 0
#define TFW_CONN_HOOK_CALL(c, f...)		\
	tfw_conn_hook_call(TFW_CONN_TYPE2IDX(TFW_CONN_TYPE(c)), c, f)

static inline bool
tfw_connection_nfo(TfwConnection *conn)
{
	return atomic_read(&conn->refcnt) > 0;
}

static inline void
tfw_connection_get(TfwConnection *conn)
{
	atomic_inc(&conn->refcnt);
}

/**
 * Increment reference counter and return true if @conn isn't in failovering
 * process, i.e. @refcnt > 0.
 */
static inline bool
tfw_connection_get_if_nfo(TfwConnection *conn)
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

static inline void
tfw_connection_put(TfwConnection *conn)
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
tfw_connection_put_to_death(TfwConnection *conn)
{
	atomic_add(TFW_CONN_DEATHCNT, &conn->refcnt);
}

static inline void
tfw_connection_revive(TfwConnection *conn)
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
tfw_connection_link_from_sk(TfwConnection *conn, struct sock *sk)
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
tfw_connection_link_to_sk(TfwConnection *conn, struct sock *sk)
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
tfw_connection_unlink_to_sk(TfwConnection *conn)
{
	struct sock *sk = conn->sk;

	conn->sk = NULL;
	ss_sock_put(sk);
}

static inline void
tfw_connection_unlink_from_peer(TfwConnection *conn)
{
	BUG_ON(!conn->peer || list_empty(&conn->list));
	tfw_peer_del_conn(conn->peer, &conn->list);
}

static inline void
tfw_connection_unlink_msg(TfwConnection *conn)
{
	conn->msg = NULL;
}

/**
 * Check that TfwConnection resources are cleaned up properly.
 */
static inline void
tfw_connection_validate_cleanup(TfwConnection *conn)
{
	BUG_ON(!conn);
	BUG_ON(!list_empty(&conn->list));
	BUG_ON(!list_empty(&conn->msg_queue));
	BUG_ON(atomic_read(&conn->refcnt) & ~1);
	BUG_ON(conn->msg);
}

void tfw_connection_hooks_register(TfwConnHooks *hooks, int type);
void tfw_connection_hooks_unregister(int type);
int tfw_connection_send(TfwConnection *conn, TfwMsg *msg);

/* Generic helpers, used for both client and server connections. */
void tfw_connection_init(TfwConnection *conn);
void tfw_connection_link_peer(TfwConnection *conn, TfwPeer *peer);

int tfw_connection_new(TfwConnection *conn);
void tfw_connection_drop(TfwConnection *conn);
void tfw_connection_release(TfwConnection *conn);

int tfw_connection_recv(void *cdata, struct sk_buff *skb, unsigned int off);

#endif /* __TFW_CONNECTION_H__ */
