/**
 *		Tempesta FW
 *
 * Definitions for generic connection (at OSI level 4) management.
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
#ifndef __TFW_CONNECTION_H__
#define __TFW_CONNECTION_H__

#include <net/sock.h>

#include "gfsm.h"
#include "msg.h"
#include "peer.h"

#include "sync_socket.h"

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
 * @proto	- protocol handler. Base class, must be first;
 * @list	- member in the list of connections with @peer;
 * @msg_queue	- queue of messages to be sent over the connection;
 * @refcnt	- number of users of the connection structure;
 * @msg		- message that is currently being processed;
 * @peer	- TfwClient or TfwServer handler;
 * @sk		- an appropriate sock handler;
 * @splock	- lock for accessing @peer and @sk;
 */
typedef struct {
	SsProto			proto;
	struct list_head	list;
	struct list_head	msg_queue;
	atomic_t		refcnt;

	TfwMsg			*msg;
	TfwPeer 		*peer;
	struct sock		*sk;
	spinlock_t		splock;
} TfwConnection;

#define TFW_CONN_TYPE(c)	((c)->proto.type)

/* Callbacks used by l5-l7 protocols to operate on connection level. */
typedef struct {
	/*
	 * Before servicing a new connection (client or server - connection
	 * type should be checked in the callback).
	 * This is a good place to handle Access or GEO modules (block a client
	 * or bind its descriptor with Geo information).
	 */
	int (*conn_init)(TfwConnection *conn);

	/*
	 * Closing a connection (client or server as for conn_init()).
	 * This is necessary for modules who account number of established
	 * client connections.
	 */
	void (*conn_destruct)(TfwConnection *conn);

	/**
	 * High level protocols should be able to allocate messages with all
	 * required information.
	 */
	TfwMsg * (*conn_msg_alloc)(TfwConnection *conn);
} TfwConnHooks;

static inline void
tfw_connection_get(TfwConnection *conn)
{
	atomic_inc(&conn->refcnt);
}

static inline bool
tfw_connection_put(TfwConnection *conn)
{
	if (unlikely(!conn))
		return false;
	if (likely(atomic_read(&conn->refcnt) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&conn->refcnt)))
		return false;
	return true;
}

static inline void
tfw_connection_link_from_sk(TfwConnection *conn, struct sock *sk)
{
	BUG_ON(sk->sk_user_data);
	sk->sk_user_data = conn;
}

static inline void
tfw_connection_link_to_sk(TfwConnection *conn, struct sock *sk)
{
	BUG_ON(conn->sk);
	conn->sk = sk;
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

	spin_lock(&conn->splock);
	BUG_ON(conn->peer);
	BUG_ON(conn->sk);
	spin_unlock(&conn->splock);
}

void tfw_connection_hooks_register(TfwConnHooks *hooks, int type);
void tfw_connection_send(TfwConnection *conn, TfwMsg *msg);

/* Generic helpers, used for both client and server connections. */
void tfw_connection_init(TfwConnection *conn);
void tfw_connection_link_sk(TfwConnection *conn, struct sock *sk);
void tfw_connection_unlink_sk(TfwConnection *conn, struct sock *sk);
void tfw_connection_link_peer(TfwConnection *conn, TfwPeer *peer);
void tfw_connection_unlink_peer(TfwConnection *conn);

int tfw_connection_new(TfwConnection *conn);
void tfw_connection_destruct(TfwConnection *conn);

int tfw_connection_recv(void *cdata, struct sk_buff *skb, unsigned int off);

#endif /* __TFW_CONNECTION_H__ */
