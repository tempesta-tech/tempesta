/**
 *		Tempesta FW
 *
 * Generic connection management.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITFWOUT
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

TfwConnHooks *conn_hooks[TFW_CONN_MAX_PROTOS];

/*
 * Initialize the connection structure.
 * It's not on any list yet, so it's safe to do so without locks.
 */
void
tfw_connection_init(TfwConnection *conn)
{
	memset(conn, 0, sizeof(*conn));

	INIT_LIST_HEAD(&conn->list);
	INIT_LIST_HEAD(&conn->msg_queue);
	spin_lock_init(&conn->msg_qlock);
}

void
tfw_connection_link_peer(TfwConnection *conn, TfwPeer *peer)
{
	BUG_ON(conn->peer || !list_empty(&conn->list));
	conn->peer = peer;
	tfw_peer_add_conn(peer, &conn->list);
}

/**
 * Publish the "connection is established" event via TfwConnHooks.
 */
int
tfw_connection_new(TfwConnection *conn)
{
	return TFW_CONN_HOOK_CALL(conn, conn_init);
}

/**
 * Call connection repairing via TfwConnHooks.
 */
void
tfw_connection_repair(TfwConnection *conn)
{
	TFW_CONN_HOOK_CALL(conn, conn_repair);
}

/**
 * Publish the "connection is dropped" event via TfwConnHooks.
 */
void
tfw_connection_drop(TfwConnection *conn)
{
	/* Ask higher levels to free resources at connection close. */
	TFW_CONN_HOOK_CALL(conn, conn_drop);
	BUG_ON(conn->msg);
}

/*
 * Publish the "connection is released" event via TfwConnHooks.
 */
void
tfw_connection_release(TfwConnection *conn)
{
	/* Ask higher levels to free resources at connection release. */
	TFW_CONN_HOOK_CALL(conn, conn_release);
	BUG_ON((TFW_CONN_TYPE(conn) & Conn_Clnt)
	       && !list_empty(&conn->msg_queue));
}

/*
 * Code architecture decisions ensure that conn->sk remains valid
 * for the life of @conn instance. The socket itself may have been
 * closed, but not deleted. ss_send() makes sure that data is sent
 * only on an active socket.
 */
int
tfw_connection_send(TfwConnection *conn, TfwMsg *msg)
{
	return TFW_CONN_HOOK_CALL(conn, conn_send, msg);
}

int
tfw_connection_recv(void *cdata, struct sk_buff *skb, unsigned int off)
{
	TfwConnection *conn = cdata;

	return tfw_gfsm_dispatch(&conn->state, conn, skb, off);
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
