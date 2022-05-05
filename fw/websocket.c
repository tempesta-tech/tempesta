/**
 *		Tempesta FW
 *
 * Websocket proxy protocol implementation for Tempesta FW.
 *
 * Copyright (C) 2022 Tempesta Technologies, Inc.
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
#undef DEBUG
#if DBG_WS > 0
#define DEBUG DBG_WS
#endif

#include "cfg.h"
#include "connection.h"
#include "websocket.h"
#include "server.h"
#include "sync_socket.h"
#include "tempesta_fw.h"

#define TFW_CONN_HTTP_TYPE(c)	\
	(TFW_FSM_TYPE(TFW_CONN_TYPE(c)) & (TFW_FSM_HTTP | TFW_FSM_HTTPS))

static struct kmem_cache *tfw_ws_conn_cache;

void
tfw_ws_srv_ss_hook_drop(struct sock *sk)
{
	TfwConn *conn = sk->sk_user_data;

	tfw_connection_drop(conn);
	tfw_connection_unlink_from_sk(sk);
}

/*
 * Hook `connection_new()` can never be called, because ws connection
 * can only be bootstraped from http connection.
 */
static const SsHooks tfw_ws_srv_ss_hooks = {
	.connection_new		= NULL,
	.connection_drop	= tfw_ws_srv_ss_hook_drop,
	.connection_recv	= tfw_connection_recv,
};

static void
tfw_ws_conn_release(void *conn)
{
	TfwConn *_conn = (TfwConn *)conn;

	T_DBG2("%s: conn=[%p]\n", __func__, conn);

	if (likely(_conn->sk))
		tfw_connection_unlink_to_sk(_conn);
	kmem_cache_free(tfw_ws_conn_cache, _conn);
}

TfwConn *
tfw_ws_conn_alloc(void)
{
	TfwConn *conn;

	if (!(conn = kmem_cache_alloc(tfw_ws_conn_cache, GFP_ATOMIC)))
		return NULL;

	T_DBG2("%s: conn=[%p]\n", __func__, conn);

	tfw_connection_init(conn);

	ss_proto_init(&conn->proto, &tfw_ws_srv_ss_hooks, Conn_WsSrv);

	return conn;
}

/*
 * We create plain (not server) connection, because we do not need special logic
 * for connection failovering for websocket connection. And there is no need
 * for adding connection to a list of server connections. On shutdown all client
 * connection will be closed along with server connections paired with it.
 */
TfwConn *
tfw_ws_srv_new_steal_sk(TfwSrvConn *srv_conn)
{
	TfwConn *conn = NULL;
	TfwServer *srv = (TfwServer *)srv_conn->peer;

	T_DBG2("%s: conn=[%p]\n", __func__, srv_conn);

	if (!(conn = tfw_ws_conn_alloc())) {
		T_WARN_ADDR("Can't create new connection for socket stealing",
			    &srv->addr, TFW_NO_PORT);
		goto err;
	}
	conn->peer = (TfwPeer *)srv;
	conn->sk = srv_conn->sk;
	conn->sk->sk_user_data = conn;

	conn->destructor = tfw_ws_conn_release;
	tfw_connection_revive(conn);

	/* Connection destructor does failover for server connections */
	srv_conn->sk = NULL;
	if (srv_conn->destructor)
		srv_conn->destructor(srv_conn);
err:
	clear_bit(TFW_CONN_B_UNSCHED, &srv_conn->flags);

	return conn;
}

/**
 * Global level websocket configuration.
 *
 * @client_ws_timeout	- timeout between two consecutive client sends before
 * 			  connection close;
 */
static struct tfw_cfg_ws_t {
	int client_ws_timeout;
} tfw_cfg_ws;

typedef struct tfw_cfg_ws_t TfwCfgWs;

/**
 * Rearm client connection timer for client timeout functionality,
 * `client_ws_timeout` is a corresponding config setting.
 * TODO #736: do not update time on each packet handling.
 */
void
tfw_ws_cli_mod_timer(TfwCliConn *conn)
{
	BUG_ON(!(TFW_CONN_TYPE(conn) & Conn_Clnt));

	spin_lock(&conn->timer_lock);
	if (timer_pending(&conn->timer))
		mod_timer(&conn->timer,
			jiffies + msecs_to_jiffies(
				(long)tfw_cfg_ws.client_ws_timeout
					* 1000));
	spin_unlock(&conn->timer_lock);
}

/**
 * Process data for websocket connection without any introspection and
 * analisis of the protocol. Just send it as is.
 */
int
tfw_ws_msg_process(TfwConn *conn, struct sk_buff *skb)
{
	int r;
	TfwMsg msg = { 0 };

	T_DBG2("%s: conn=[%p], skb=[%p]\n", __func__, conn, skb);

	ss_skb_queue_tail(&msg.skb_head, skb);

	if ((r = tfw_connection_send(conn->pair, &msg))) {
		T_DBG("%s: cannot send data to via websocket\n", __func__);
		tfw_connection_close(conn, true);
	}

	/* When receiving data from client we consider client timeout */
	if (TFW_CONN_TYPE(conn) & Conn_Clnt) {
		tfw_ws_cli_mod_timer((TfwCliConn *)conn);
	}

	return r;
}

/**
 * Websocket connection hooks.
 *
 * These hooks unified between wss and ws. For wss we call HTTPS state machine
 * and for plain ws we call HTTP conn_hook. No self recursion here just
 * downcall into lower layer through `tfw_conn_hook_call()`.
 *
 * TFW_CONN_HTTP_TYPE macro strips TFW_FSM_WEBSOCKET mark from connection type.
 */

static int
tfw_ws_conn_close(TfwConn *conn, bool sync)
{
	int r;

	T_DBG("%s: conn=[%p]\n", __func__, conn);

	r = tfw_conn_hook_call(TFW_CONN_HTTP_TYPE(conn), conn, conn_close, sync);

	return r;
}

static TfwConn *
tfw_ws_conn_unpair(TfwConn *conn)
{
	TfwConn *pair;

	if (!conn || !conn->pair)
		return NULL;

	pair = conn->pair;

	conn->pair = NULL;
	pair->pair = NULL;

	return pair;
}

static void
tfw_ws_conn_drop(TfwConn *conn)
{
	TfwConn *pair = tfw_ws_conn_unpair(conn);

	T_DBG("%s: conn=[%p]\n", __func__, conn);

	if (TFW_CONN_TYPE(conn) & Conn_Srv)
		tfw_connection_put(conn);
	else
		tfw_conn_hook_call(TFW_CONN_HTTP_TYPE(conn), conn, conn_drop);

	if (!pair)
		return;

	tfw_connection_close(pair, true);
}

/**
 * Send the @msg skbs as is.
 */
static int
tfw_ws_conn_send(TfwConn *conn, TfwMsg *msg)
{
	int r;

	T_DBG2("%s: conn=[%p], msg=[%p]\n", __func__, conn, msg);

	r = tfw_conn_hook_call(TFW_CONN_HTTP_TYPE(conn), conn, conn_send, msg);

	return r;
}

static TfwConnHooks ws_conn_hooks = {
	.conn_close	= tfw_ws_conn_close,
	.conn_drop	= tfw_ws_conn_drop,
	.conn_send	= tfw_ws_conn_send,
};

static TfwConnHooks wss_conn_hooks = {
	.conn_close	= tfw_ws_conn_close,
	.conn_drop	= tfw_ws_conn_drop,
	.conn_send	= tfw_ws_conn_send,
};

/*
 * ------------------------------------------------------------------------
 *	Websocket module configuration.
 * ------------------------------------------------------------------------
 */

static int
tfw_cfgop_ws_client_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int timeout;

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;
	if (tfw_cfg_parse_int(ce->vals[0], &timeout)) {
		T_ERR_NL("Unable to parse client ws timeout value: '%s'\n",
			 ce->vals[0]);
		return -EINVAL;
	}
	if (timeout < 0)
		return -EINVAL;

	tfw_cfg_ws.client_ws_timeout = timeout;

	return 0;
}

static int
tfw_ws_cfgstart(void)
{
	return 0;
}

static int
tfw_ws_cfgend(void)
{
	return 0;
}

static int
tfw_ws_start(void)
{
	return 0;
}

static TfwCfgSpec tfw_ws_specs[] = {
	{
		.name		= "client_ws_timeout",
		.deflt		= "3600",
		.handler	= tfw_cfgop_ws_client_timeout,
		.allow_none	= false,
		.allow_repeat	= false,
	},
	{ 0 }
};

TfwMod tfw_websocket_mod = {
	.name		= "websocket",
	.cfgend		= tfw_ws_cfgend,
	.cfgstart	= tfw_ws_cfgstart,
	.start		= tfw_ws_start,
	.specs		= tfw_ws_specs,
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int __init
tfw_websocket_init(void)
{
	tfw_ws_conn_cache = kmem_cache_create("tfw_ws_conn_cache",
					       sizeof(TfwConn), 0, 0, NULL);
	if (!tfw_ws_conn_cache)
		return -ENOMEM;

	tfw_connection_hooks_register(&ws_conn_hooks, TFW_FSM_WS);
	tfw_connection_hooks_register(&wss_conn_hooks, TFW_FSM_WSS);
	tfw_mod_register(&tfw_websocket_mod);

	return 0;
}

void
tfw_websocket_exit(void)
{
	tfw_mod_unregister(&tfw_websocket_mod);
	tfw_connection_hooks_unregister(TFW_FSM_WS);
	tfw_connection_hooks_unregister(TFW_FSM_WSS);

	kmem_cache_destroy(tfw_ws_conn_cache);
}
