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
 * @list	- list of connections with the @peer;
 * @msg_queue	- messages queue to be sent over the connection;
 * @msg		- currently processing (receiving) message;
 * @peer	- TfwClient or TfwServer handler;
 * @sock	- appropriate socket handler;
 * @sk_destruct	- original sk->sk_destruct. Destructors passed to
 * 		  tfw_connection_new() must call it manually;
 */
typedef struct {
	SsProto			proto;
	struct list_head	list;
	struct list_head	msg_queue;

	TfwMsg			*msg;
	TfwPeer 		*peer;
	struct sock		*sock;

	struct socket		*socket; /* XXX: temporary field */

	void (*sk_destruct)(struct sock *sk);
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

/* Connection downcalls. */
TfwConnection *tfw_connection_new(struct sock *sk, int type,
				  void (*destructor)(struct sock *s));
void tfw_connection_send(TfwConnection *conn, TfwMsg *msg);

void tfw_connection_hooks_register(TfwConnHooks *hooks, int type);

int tfw_connection_close(struct sock *);
int tfw_connection_recv(struct sock *, unsigned char *, size_t);
int tfw_connection_put_skb_to_msg(SsProto *, struct sk_buff *);
int tfw_connection_postpone_skb(SsProto *, struct sk_buff *);

#endif /* __TFW_CONNECTION_H__ */
