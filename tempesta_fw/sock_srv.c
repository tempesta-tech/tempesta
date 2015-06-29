/**
 *		Tempesta FW
 *
 * Handling server connections.
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

/**
 * TODO
 * -- limit number of persistent connections to be able to work as forward
 *    (transparent) proxy (probably we need to switch on/off functionality for
 *    connections pool)
 * -- FIXME synchronize with sock operations.
 */
/*
 * TODO In case of forward proxy manage connections to servers
 * we can have too many servers, so we need to prune low-active
 * connections from the connection pool.
 */
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include <net/inet_sock.h>

#include "tempesta_fw.h"
#include "connection.h"
#include "addr.h"
#include "log.h"
#include "server.h"

/*
 * ------------------------------------------------------------------------
 *	Server connection establishment.
 * ------------------------------------------------------------------------
 *
 * This section of code is responsible for maintaining a server connection in
 * an established state, and doing so in an asynchronous (callback-based) way.
 *
 * The entry point is the tfw_sock_srv_connect_try() function.
 * It initiates a connect attempt and just exits without blocking.
 *
 * Later on, when connection state is changed, a callback is invoked:
 *  - tfw_sock_srv_connect_retry() - a connect attempt has failed.
 *  - tfw_sock_srv_connect_complete() - a connection is established.
 *  - tfw_sock_srv_connect_failover() - an established connection is closed.
 *
 * Both retry() and failover() call tfw_sock_srv_connect_try() again
 * to re-establish the connection, and thus tfw_sock_srv_connect_try() is
 * called repeatedly until the connection is finally established (or until
 * this "loop" of callbacks is stopped by tfw_sock_srv_disconnect()).
 */

/** The wakeup interval between failed connection attempts. */
#define TFW_SOCK_SRV_RETRY_TIMER_MIN	1000		/* 1 sec in msecs */
#define TFW_SOCK_SRV_RETRY_TIMER_MAX	(1000 * 300)	/* 5 min in msecs */

/**
 * TfwConnection extension for server sockets.
 *
 * @conn	- The base structure. Must be the first member.
 * @retry_timer	- The timer makes a delay between connection attempts.
 *
 * A server connection differs from a client connection.
 * For client sockets, a new TfwConnection object is created when a new client
 * socket is accepted (the connection is already established at that point).
 * For server sockets, we create a socket first, and then some time passes while
 * a connection is being established.
 *
 * Therefore, we need this separate structure with slightly different semantics:
 *  - When a server socket is created, we allocate a TfwSrvConnection object,
 *    but don't fully initialize it until a connection is actually established.
 *  - If a connection attempt is failed, we re-use the same TfwSrvConnection
 *    object with a new socket, and make another connection attempt.
 *
 * So basically a TfwSrvConnection object has a longer lifetime.
 */
typedef struct {
	TfwConnection		conn;
	struct timer_list	retry_timer;
	unsigned long		timeout;
	unsigned int		attempts;
} TfwSrvConnection;

/**
 * Initiate a new connect attempt without blocking
 * until the connection is established.
 */
static int
tfw_sock_srv_connect_try(TfwSrvConnection *srv_conn)
{
	int r;
	TfwAddr *addr;
	struct sock *sk;

	addr = &srv_conn->conn.peer->addr;

	r = ss_sock_create(addr->family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r) {
		TFW_ERR("can't create a server socket\n");
		return r;
	}

	sock_set_flag(sk, SOCK_DBG);
	tfw_connection_link_sk(&srv_conn->conn, sk);
	ss_set_callbacks(sk);

	r = ss_connect(sk, &addr->sa, tfw_addr_sa_len(addr), 0);
	if (r) {
		TFW_ERR("can't initiate a connect to server: error %d\n", r);
		tfw_connection_unlink_sk(&srv_conn->conn);
		ss_close(sk);
		return r;
	}

	return 0;
}

static inline void
__mod_retry_timer(TfwSrvConnection *srv_conn)
{
	/* A variant of exponential backoff delay algorithm. */
	if (srv_conn->timeout < TFW_SOCK_SRV_RETRY_TIMER_MAX) {
		srv_conn->timeout = min(TFW_SOCK_SRV_RETRY_TIMER_MAX,
					TFW_SOCK_SRV_RETRY_TIMER_MIN
					* (1 << srv_conn->attempts));
		srv_conn->attempts++;
	}
	mod_timer(&srv_conn->retry_timer,
		  jiffies + msecs_to_jiffies(srv_conn->timeout));
}

static inline void
__reset_retry_timer(TfwSrvConnection *srv_conn)
{
	srv_conn->timeout = 0;
	srv_conn->attempts = 0;
}

static void
tfw_sock_srv_connect_retry_timer_cb(unsigned long data)
{
	int r;
	TfwSrvConnection *srv_conn = (TfwSrvConnection *)data;

	r = tfw_sock_srv_connect_try(srv_conn);
	if (r) {
		/*
		 * Can't even initiate the connect?
		 * Just re-execute this function later.
		 */
		TFW_WARN("server connect retry failed\n");
		__mod_retry_timer(srv_conn);
	}
}

static inline void
__setup_retry_timer(TfwSrvConnection *srv_conn)
{
	__reset_retry_timer(srv_conn);
	setup_timer(&srv_conn->retry_timer, tfw_sock_srv_connect_retry_timer_cb,
		    (unsigned long)srv_conn);
}

/**
 * The hook is executed when a server connection is established.
 */
static int
tfw_sock_srv_connect_complete(struct sock *sk)
{
	int r;
	TfwSrvConnection *srv_conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)srv_conn->conn.peer;

	/* Notify higher-level levels. */
	r = tfw_connection_new(&srv_conn->conn);
	if (r) {
		TFW_ERR("conn_init() hook returned error\n");
		return r;
	}

	/* Notify the scheduler of new connection. */
	tfw_sg_update(srv->sg);

	__reset_retry_timer(srv_conn);

	TFW_DBG_ADDR("connected", &srv->addr);
	return 0;
}

/**
 * The hook is executed when a server connection is lost.
 * I.e. the connection was established before, but now it is closed.
 */
static int
tfw_sock_srv_connect_failover(struct sock *sk)
{
	int r;
	TfwSrvConnection *srv_conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)srv_conn->conn.peer;

	TFW_DBG_ADDR("connection lost", &srv->addr);

	/* Revert tfw_sock_srv_connect_complete(). */
	tfw_sg_update(srv->sg);
	tfw_connection_destruct(&srv_conn->conn);

	/* Revert tfw_sock_srv_connect_try(). */
	tfw_connection_unlink_sk(&srv_conn->conn);

	/*
	 * Initiate a new connect attempt.
	 * The TfwSrvConnection (and nested TfwConnection) is re-used here.
	 */
	r = tfw_sock_srv_connect_try(srv_conn);
	if (r) {
		TFW_WARN("failover connect failed\n");

		/* Just retry later. */
		__mod_retry_timer(srv_conn);
	}

	return 0;
}

/**
 * The hook is executed when there's unrecoverable error in a connection
 * (and not executed when an established connection is closed as usual).
 * An error may occur in any TCP state. All Tempesta resources associated
 * with the socket must be released in case they were allocated before.
 *
 * Basically it initiates a reconnect (calls tfw_sock_srv_try() again).
 * There should be a pause between connect attempts, so the reconnect
 * is done in a deferred context (in a timer callback).
 */
static int
tfw_sock_srv_connect_retry(struct sock *sk)
{
	TfwSrvConnection *srv_conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)srv_conn->conn.peer;

	TFW_DBG_ADDR("connection error", &srv->addr);

	/* Revert tfw_sock_srv_connect_complete(). */
	tfw_sg_update(srv->sg);
	tfw_connection_destruct(&srv_conn->conn);

	/* Revert tfw_sock_srv_connect_try(). */
	tfw_connection_unlink_sk(&srv_conn->conn);

	/*
	 * We need to create a new socket for each connect attempt.
	 * The old socket is released as soon as it is not used anymore.
	 * New socket is created after a delay in the timer callback.
	 */
	__mod_retry_timer(srv_conn);

	return 0;
}

static const SsHooks tfw_sock_srv_ss_hooks = {
	.connection_new		= tfw_sock_srv_connect_complete,
	.connection_drop	= tfw_sock_srv_connect_failover,
	.connection_error	= tfw_sock_srv_connect_retry,
	.connection_recv	= tfw_connection_recv,
	.put_skb_to_msg		= tfw_connection_put_skb_to_msg,
};

/**
 * Close a server connection, or stop connection attempts if the connection
 * is not established.
 */
static void
tfw_sock_srv_disconnect(TfwSrvConnection *srv_conn)
{
	TfwServer *srv = (TfwServer *)srv_conn->conn.peer;
	struct sock *sk = srv_conn->conn.sk;

	/* Prevent races with timer callbacks. */
	del_timer_sync(&srv_conn->retry_timer);

	/*
	 * Revert tfw_sock_srv_connect_try().
	 * It doesn't matter that the order in which we destroy
	 * the connection is different from what we did when created it.
	 * Doing it this way immediately disconnects Tempesta from all
	 * socket activity, so any possible concurrency is eliminated.
	 */
	if (sk) {
		ss_callback_write_lock(sk);
		tfw_connection_unlink_sk(&srv_conn->conn);
		ss_callback_write_unlock(sk);
		ss_close(sk);
	}
	/* Revert tfw_sock_srv_connect_complete(). */
	if (srv) {
		tfw_sg_update(srv->sg);
		tfw_connection_destruct(&srv_conn->conn);
	}
}

/*
 * ------------------------------------------------------------------------
 *	Global connect/disconnect routines.
 * ------------------------------------------------------------------------
 *
 * At this point, we support only the reverse proxy mode, so we connect to all
 * servers when the Tempesta FW is started, and close all connections when the
 * Tempesta FW is stopped. This section of code is responsible for that.
 *
 * This behavior may change in future for a forward proxy implementation.
 * Then we will have a lot of short-living connections. We should keep it in
 * mind to avoid possible bottlenecks. In particular, this is the reason why we
 * don't have a global list of all TfwSrvConnection objects and store
 * not-yet-established connections in the TfwServer->conn_list.
 */

static int
tfw_sock_srv_connect_srv(TfwServer *srv)
{
	TfwSrvConnection *srv_conn;

	list_for_each_entry(srv_conn, &srv->conn_list, conn.list) {
		if (tfw_sock_srv_connect_try(srv_conn))
			__mod_retry_timer(srv_conn);
	}

	return 0;
}

static int
tfw_sock_srv_disconnect_srv(TfwServer *srv)
{
	TfwSrvConnection *srv_conn;

	list_for_each_entry(srv_conn, &srv->conn_list, conn.list) {
		local_bh_disable();
		tfw_sock_srv_disconnect(srv_conn);
		local_bh_enable();
	}

	return 0;
}

static int
tfw_sock_srv_connect_all(void)
{
	return tfw_sg_for_each_srv(tfw_sock_srv_connect_srv);
}

static void
tfw_sock_srv_disconnect_all(void)
{
	int r = tfw_sg_for_each_srv(tfw_sock_srv_disconnect_srv);
	BUG_ON(r);
}

/*
 * ------------------------------------------------------------------------
 *	TfwServer creation/deletion helpers.
 * ------------------------------------------------------------------------
 *
 * This section of code is responsible for allocating TfwSrvConnection objects
 * and linking them with a TfwServer object.
 *
 * All server connections (TfwSrvConnection objects) are pre-allocated  when a
 * TfwServer is created. That happens when at the configuration parsing stage.
 *
 * Later on, when Tempesta FW is started, these TfwSrvConnection objects are
 * used to establish connections. These connection objects are re-used (but not
 * re-allocated) when connections are re-established.
 */

static struct kmem_cache *tfw_srv_conn_cache;

static TfwSrvConnection *
tfw_srv_conn_alloc(void)
{
	SsProto *proto;
	TfwSrvConnection *srv_conn;

	srv_conn = kmem_cache_alloc(tfw_srv_conn_cache, GFP_ATOMIC);
	if (!srv_conn)
		return NULL;

	tfw_connection_init(&srv_conn->conn);
	__setup_retry_timer(srv_conn);
	proto = &srv_conn->conn.proto;
	ss_proto_init(proto, &tfw_sock_srv_ss_hooks, Conn_HttpSrv);

	return srv_conn;
}

static void
tfw_srv_conn_free(TfwSrvConnection *srv_conn)
{
	tfw_connection_validate_cleanup(&srv_conn->conn);

	/* Check that all nested resources are already freed. */
	BUG_ON(timer_pending(&srv_conn->retry_timer));

	kmem_cache_free(tfw_srv_conn_cache, srv_conn);
}

static int
tfw_sock_srv_add_conns(TfwServer *srv, int conns_n)
{
	int i;
	TfwSrvConnection *srv_conn;

	for (i = 0; i < conns_n; ++i) {
		srv_conn = tfw_srv_conn_alloc();
		if (!srv_conn)
			return -ENOMEM;
		tfw_connection_link_peer(&srv_conn->conn, (TfwPeer *)srv);
	}

	return 0;
}

static int
tfw_sock_srv_delete_conns(TfwServer *srv)
{
	TfwSrvConnection *srv_conn, *tmp;

	list_for_each_entry_safe(srv_conn, tmp, &srv->conn_list, conn.list) {
		tfw_connection_unlink_peer(&srv_conn->conn);
		tfw_srv_conn_free(srv_conn);
	}

	return 0;
}

static void
tfw_sock_srv_delete_all_conns(void)
{
	int r = tfw_sg_for_each_srv(tfw_sock_srv_delete_conns);
	BUG_ON(r);
}

/*
 * ------------------------------------------------------------------------
 *	Configuration handling
 * ------------------------------------------------------------------------
 */

#define TFW_SRV_CFG_DEF_CONNS_N		"4"

/**
 * A "srv_group" which is currently being parsed.
 * All "server" entries are added to this group.
 */
static TfwSrvGroup *tfw_srv_cfg_curr_group;
static TfwScheduler *tfw_srv_cfg_dflt_sched;

/**
 * Handle "server" within an "srv_group", e.g.:
 *   srv_group foo {
 *       server 10.0.0.1;
 *       server 10.0.0.2;
 *       server 10.0.0.3 conns_n=1;
 *   }
 *
 * Every server is simply added to the tfw_srv_cfg_curr_group.
 */
static int
tfw_srv_cfg_handle_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwAddr addr;
	TfwServer *srv;
	int r, conns_n;
	const char *in_addr, *in_conns_n;

	BUG_ON(!tfw_srv_cfg_curr_group);

	r = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return -EINVAL;

	in_addr = ce->vals[0];
	in_conns_n = tfw_cfg_get_attr(ce, "conns_n", TFW_SRV_CFG_DEF_CONNS_N);

	r = tfw_addr_pton(in_addr, &addr);
	if (r)
		return r;
	r = tfw_cfg_parse_int(in_conns_n, &conns_n);
	if (r)
		return r;

	srv = tfw_create_server(&addr);
	if (!srv) {
		TFW_ERR("can't create a server socket\n");
		return -EPERM;
	}
	tfw_sg_add(tfw_srv_cfg_curr_group, srv);

	r = tfw_sock_srv_add_conns(srv, conns_n);
	if (r) {
		TFW_ERR("can't add connections to the server\n");
		return r;
	}

	return 0;
}

/**
 * Handle a top-level "server" entry that doesn't belong to any group.
 *
 * All such top-level entries are simply added to the "default" group.
 * So this configuration example:
 *    server 10.0.0.1;
 *    server 10.0.0.2;
 *    srv_group local {
 *        server 127.0.0.1:8000;
 *    }
 * is implicitly transformed to this:
 *    srv_group default {
 *        server 10.0.0.1;
 *        server 10.0.0.2;
 *    }
 *    srv_group local {
 *        server 127.0.0.1:8000;
 *    }
 */
static int
tfw_srv_cfg_handle_server_outside_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int ret;
	const char *dflt_sched_name;
	static const char __read_mostly s_default[] = "default";
	TfwSrvGroup *sg = tfw_sg_lookup(s_default);

	/* The group "default" is created implicitly. */
	if (sg == NULL) {
		if ((sg = tfw_sg_new(s_default, GFP_KERNEL)) == NULL) {
			TFW_ERR("Unable to add server group '%s'\n", s_default);
			return -EINVAL;
		}
		dflt_sched_name = tfw_srv_cfg_dflt_sched
				  ? tfw_srv_cfg_dflt_sched->name
				  : "round-robin";
		if ((ret = tfw_sg_set_sched(sg, dflt_sched_name)) != 0) {
			TFW_ERR("Unable to set scheduler '%s' "
				"for server group '%s'\n",
				dflt_sched_name, s_default);
			return ret;
		}
	}
	tfw_srv_cfg_curr_group = sg;

	return tfw_srv_cfg_handle_server(cs, ce);
}

/**
 * The callback is invoked on entering an "srv_group", e.g:
 *
 *   srv_group foo sched=hash {  <--- The position at the moment of call.
 *       server ...;
 *       server ...;
 *       ...
 *   }
 *
 * Basically it parses the group name and the "sched" attribute, creates a
 * new TfwSrvGroup object and sets the context for parsing nested "server"s.
 */
static int
tfw_srv_cfg_begin_srv_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	TfwSrvGroup *sg;
	const char *sg_name, *sched_name, *dflt_sched_name;

	r = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return r;
	sg_name = ce->vals[0];
	dflt_sched_name = tfw_srv_cfg_dflt_sched
			  ? tfw_srv_cfg_dflt_sched->name : "round-robin";
	sched_name = tfw_cfg_get_attr(ce, "sched", dflt_sched_name);

	TFW_DBG("begin srv_group: %s\n", sg_name);

	sg = tfw_sg_new(sg_name, GFP_KERNEL);
	if (!sg) {
		TFW_ERR("Unable to add server group '%s'\n", sg_name);
		return -EINVAL;
	}
	r = tfw_sg_set_sched(sg, sched_name);
	if (r) {
		TFW_ERR("Unable to set scheduler '%s' "
			"for server group '%s'\n", sched_name, sg_name);
		return r;
	}

	/* Set the current group. All nested "server"s are added to it. */
	tfw_srv_cfg_curr_group = sg;
	return 0;
}

/**
 * The callback is invoked upon exit from a "srv_group" when all nested
 * "server"s are parsed, e.g.:
 *
 *   srv_group foo sched=hash {
 *       server ...;
 *       server ...;
 *       ...
 *   }  <--- The position at the moment of call.
 */
static int
tfw_srv_cfg_finish_srv_group(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_srv_cfg_curr_group);
	BUG_ON(list_empty(&tfw_srv_cfg_curr_group->srv_list));
	TFW_DBG("finish srv_group: %s\n", tfw_srv_cfg_curr_group->name);
	tfw_srv_cfg_curr_group = NULL;
	return 0;
}

static int
tfw_srv_cfg_handle_sched_outside_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_cfg_check_val_n(ce, 1))
		return -EINVAL;
	tfw_srv_cfg_dflt_sched = tfw_sched_lookup(ce->vals[0]);
	if (tfw_srv_cfg_dflt_sched == NULL) {
		TFW_ERR("Unrecognized scheduler: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}
	return 0;
}

/**
 * Clean everything produced during parsing "server" and "srv_group" entries.
 */
static void
tfw_srv_cfg_clean_srv_groups(TfwCfgSpec *cs)
{
	tfw_sock_srv_delete_all_conns();
	tfw_sg_release_all();
	tfw_srv_cfg_curr_group = NULL;
}

static TfwCfgSpec tfw_sock_srv_cfg_srv_group_specs[] = {
	{
		"server", NULL,
		tfw_srv_cfg_handle_server,
		.allow_repeat = true,
		.cleanup = tfw_srv_cfg_clean_srv_groups
	},
	{ }
};

TfwCfgMod tfw_sock_srv_cfg_mod = {
	.name  = "sock_srv",
	.start = tfw_sock_srv_connect_all,
	.stop  = tfw_sock_srv_disconnect_all,
	.specs = (TfwCfgSpec[] ) {
		{
			"server",
			NULL,
			tfw_srv_cfg_handle_server_outside_group,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_srv_cfg_clean_srv_groups,
		},
		{
			"sched",
			NULL,
			tfw_srv_cfg_handle_sched_outside_group,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_srv_cfg_clean_srv_groups,
		},
		{
			"srv_group",
			NULL,
			tfw_cfg_handle_children,
			tfw_sock_srv_cfg_srv_group_specs,
			&(TfwCfgSpecChild ) {
				.begin_hook = tfw_srv_cfg_begin_srv_group,
				.finish_hook = tfw_srv_cfg_finish_srv_group
			},
			.allow_none = true,
			.allow_repeat = true,
		},
		{}
	}
};

/*
 * ------------------------------------------------------------------------
 *	init/exit
 * ------------------------------------------------------------------------
 */

int
tfw_sock_srv_init(void)
{
	BUG_ON(tfw_srv_conn_cache);
	tfw_srv_conn_cache = kmem_cache_create("tfw_srv_conn_cache",
					       sizeof(TfwSrvConnection),
					       0, 0, NULL);
	return !tfw_srv_conn_cache ? -ENOMEM : 0;
}

void
tfw_sock_srv_exit(void)
{
	kmem_cache_destroy(tfw_srv_conn_cache);
}
