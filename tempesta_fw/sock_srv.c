/**
 *		Tempesta FW
 *
 * Handling server connections.
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
#include <linux/net.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include <net/inet_sock.h>

#include "apm.h"
#include "tempesta_fw.h"
#include "connection.h"
#include "addr.h"
#include "log.h"
#include "server.h"
#include "procfs.h"

/*
 * ------------------------------------------------------------------------
 *	Server connection establishment.
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
 *
 * ------------------------------------------------------------------------
 */

/**
 * TfwConnection extension for server sockets.
 *
 * @conn	- The base structure. Must be the first member.
 *
 * A server connection differs from a client connection.
 * For client sockets, a new TfwConnection{} instance is created when
 * a new client socket is accepted (the connection is established at
 * that point). For server sockets, we create a socket first, and then
 * some time passes while a connection is being established.
 *
 * Therefore, this extension structure has slightly different semantics:
 * - First, a TfwSrvConnection{} instance is allocated and set up with
 *   data from configuration file.
 * - When a server socket is created, the TfwSrvConnection{} instance
 *   is partially initialized to allow a connect attempt to complete.
 * - When a connection is established, the TfwSrvConnection{} instance
 *   is fully initialized and set up.
 * - If a connect attempt has failed, or the connection has been reset
 *   or closed, the same TfwSrvConnection{} instance is reused with
 *   a new socket. Another attempt to establish a connection is made.
 *
 * So a TfwSrvConnection{} instance has a longer lifetime. In a sense,
 * a TfwSrvConnection{} instance is persistent. It lives from the time
 * it is created when Tempesta is started, and until the time it is
 * destroyed when Tempesta is stopped.
 *
 * @sk member of an instance is supposed to have the same lifetime as
 * the instance. But in this case the semantics is different. @sk member
 * of an instance is valid from the time a connection is established and
 * the instance is fully initialized, and until the time the instance is
 * reused for a new connection, and a new socket is created. Note that
 * @sk member is not cleared when it is no longer valid, and there is
 * a time frame until new connection is actually established. An old
 * non-valid @sk stays a member of an TfwSrvConnection{} instance during
 * that time frame. However, the condition for reuse of an instance is
 * that there're no more users of the instance, so no thread can make
 * use of an old socket @sk. Should something bad happen, then having
 * a stale pointer in conn->sk is no different than having a NULL pointer.
 *
 * The reference counter is still needed for TfwSrvConnection{} instances.
 * It tells when an instance can be reused for a new connect attempt.
 * A scenario that may occur is as follows:
 * 1. There's a client's request, so scheduler finds a server connection
 *    and returns it to the client's thread. The server connection has
 *    its refcnt incremented as there's a new user of it now.
 * 2. At that time the server sends RST on that connection in response
 *    to an earlier request. It starts the failover procedure that runs
 *    in parallel. Part of the procedure is a new attempt to connect to
 *    the server, which requires that TfwSrvConnection{} instance can be
 *    reused. So the attempt to reconnect has to wait. It is started as
 *    soon as the last client releases the server connection.
 */
typedef struct {
	TfwConnection		conn;
	unsigned long		timeout;
	unsigned int		attempts;
} TfwSrvConnection;

/**
 * Initiate a non-blocking connect attempt.
 * Returns immediately without waiting until a connection is established.
 */
static int
tfw_sock_srv_connect_try(TfwSrvConnection *srv_conn)
{
	int r;
	TfwAddr *addr;
	struct sock *sk;
	TfwConnection *conn = &srv_conn->conn;

	addr = &conn->peer->addr;

	r = ss_sock_create(addr->family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r) {
		TFW_ERR("Unable to create server socket\n");
		return r;
	}

	/*
	 * Setup connection handlers before ss_connect() call. We can get
	 * an established connection right when we're in the call in case
	 * of a local peer connection, so all handlers must be installed
	 * before the call.
	 */
#if defined(DEBUG) && (DEBUG >= 2)
	sock_set_flag(sk, SOCK_DBG);
#endif
	tfw_connection_link_from_sk(conn, sk);
	ss_set_callbacks(sk);

	/*
	 * There are two possible use patterns of this function:
	 *
	 * 1. tfw_sock_srv_connect_srv() called in system initialization
	 *    phase before initialization of client listening interfaces,
	 *    so there is no activity in the socket;
	 *
	 * 2. tfw_sock_srv_do_failover() upcalled from SS layer and with
	 *    inactive conn->sk, so nobody can send through the socket.
	 *    Also since the function is called by connection_error or
	 *    connection_drop hook from SoftIRQ, there can't be another
	 *    socket state change upcall from SS layer due to RSS.
	 *
	 * Thus we don't need syncronization for ss_connect().
	 */
	TFW_INC_STAT_BH(serv.conn_attempts);
	r = ss_connect(sk, &addr->sa, tfw_addr_sa_len(addr), 0);
	if (r) {
		TFW_ERR("Unable to initiate a connect to server: %d\n", r);
		ss_close_sync(sk, false);
		return r;
	}

	/*
	 * Set connection destructor such that connection failover can
	 * take place if the connection attempt fails.
	 */
	conn->destructor = (void *)tfw_srv_conn_release;

	return 0;
}

static inline void
tfw_sock_srv_connect_try_later(TfwSrvConnection *srv_conn)
{
	/*
	 * Timeout between connect attempts is increased with each unsuccessful
	 * attempt. Length of the timeout is decided with a variant of
	 * exponential backoff delay algorithm.
	 *
	 * It's essential that the new connection is established and failed
	 * connection is restored as fast as possible, so the min retry interval
	 * is set to 1. The next, second, step is good for loopback
	 * reconnection, e.g. if upstream is configured to reset connection
	 * periodically. Following steps are almost pure backoff starting from
	 * 100ms, good RTT for fast 10Gbps link. We do not increase timeout
	 * after 1 second as it have moderate overhead and still good in
	 * response time.
	 */
	static const unsigned long timeouts[] = { 1, 10, 100, 250, 500, 1000 };

	if (srv_conn->attempts < ARRAY_SIZE(timeouts)) {
		srv_conn->timeout = timeouts[srv_conn->attempts];
		TFW_DBG_ADDR("Cannot establish connection",
			     &srv_conn->conn.peer->addr);
	} else {
		srv_conn->timeout = timeouts[ARRAY_SIZE(timeouts) - 1];
		if (srv_conn->attempts == ARRAY_SIZE(timeouts)
		    || !(srv_conn->attempts % 60))
		{
			char addr_str[TFW_ADDR_STR_BUF_SIZE] = { 0 };
			tfw_addr_fmt_v6(&srv_conn->conn.peer->addr.v6.sin6_addr,
					0, addr_str);
			TFW_WARN("Cannot establish connection with %s in %u"
				 " tries, keep trying...\n",
				 addr_str, srv_conn->attempts);
		}
	}
	srv_conn->attempts++;

	mod_timer(&srv_conn->conn.timer,
		  jiffies + msecs_to_jiffies(srv_conn->timeout));
}

static void
tfw_sock_srv_connect_retry_timer_cb(unsigned long data)
{
	TfwSrvConnection *srv_conn = (TfwSrvConnection *)data;

	/* A new socket is created for each connect attempt. */
	if (tfw_sock_srv_connect_try(srv_conn))
		tfw_sock_srv_connect_try_later(srv_conn);
}

static inline void
__reset_retry_timer(TfwSrvConnection *srv_conn)
{
	srv_conn->timeout = 0;
	srv_conn->attempts = 0;
}

static inline void
__setup_retry_timer(TfwSrvConnection *srv_conn)
{
	__reset_retry_timer(srv_conn);
	setup_timer(&srv_conn->conn.timer,
		    tfw_sock_srv_connect_retry_timer_cb,
		    (unsigned long)srv_conn);
}

void
tfw_srv_conn_release(TfwConnection *conn)
{
	tfw_connection_release(conn);
	/*
	 * conn->sk may be zeroed if we get here after a failed
	 * connect attempt. In that case no connection has been
	 * established yet, and conn->sk has not been set.
	 */
	if (likely(conn->sk))
		tfw_connection_unlink_to_sk(conn);
	/*
	 * After a disconnect, new connect attempts are started
	 * in deferred context after a short pause (in a timer
	 * callback). Whatever the reason for a disconnect was,
	 * this is uniform for any of them.
	 */
	tfw_sock_srv_connect_try_later((TfwSrvConnection *)conn);
}

/**
 * The hook is executed when a server connection is established.
 */
static int
tfw_sock_srv_connect_complete(struct sock *sk)
{
	int r;
	TfwSrvConnection *srv_conn = sk->sk_user_data;
	TfwConnection *conn = &srv_conn->conn;
	TfwServer *srv = (TfwServer *)conn->peer;

	/* Link Tempesta with the socket. */
	tfw_connection_link_to_sk(conn, sk);

	/* Notify higher level layers. */
	r = tfw_connection_new(conn);
	if (r) {
		TFW_ERR("conn_init() hook returned error\n");
		return r;
	}

	/* Let schedulers use the connection hereafter. */
	tfw_connection_revive(conn);

	__reset_retry_timer(srv_conn);

	TFW_DBG_ADDR("connected", &srv->addr);
	TFW_INC_STAT_BH(serv.conn_established);

	return 0;
}

static int
tfw_sock_srv_do_failover(struct sock *sk, const char *msg)
{
	TfwConnection *conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)conn->peer;

	TFW_DBG_ADDR(msg, &srv->addr);

	/*
	 * Distiguish connections that go to failover state from those that
	 * are in that state already. In the latter case, take an extra
	 * connection reference to indicate that the connection is in the
	 * failover state.
	 */
	if (tfw_connection_nfo(conn)) {
		tfw_connection_put_to_death(conn);
		tfw_connection_drop(conn);
		TFW_INC_STAT_BH(serv.conn_disconnects);
	} else {
		tfw_connection_get(conn);
	}

	tfw_connection_unlink_from_sk(sk);
	tfw_connection_put(conn);

	return 0;
}

/**
 * The hook is executed when a server connection is lost.
 * I.e. the connection was established before, but now it is closed.
 *
 * FIXME #254: the hook must be called when Tempesta intentionaly closes
 * the connection during shutdown. SS layer must be adjusted correspondingly.
 * Failovering must not be called by the function.
 */
static int
tfw_sock_srv_connect_drop(struct sock *sk)
{
	return tfw_sock_srv_do_failover(sk, "connection lost");
}

/**
 * The hook is executed when there's unrecoverable error in a connection
 * (and not executed when an established connection is closed as usual).
 * An error may occur in any TCP state. All Tempesta resources associated
 * with the socket must be released in case they were allocated before.
 *
 * FIXME #254: the hook must be called when a connection error occured
 * and Tempesta must recover the connection.
 * SS layer must be adjusted correspondingly.
 */
static int
tfw_sock_srv_connect_error(struct sock *sk)
{
	return tfw_sock_srv_do_failover(sk, "connection error");
}

static const SsHooks tfw_sock_srv_ss_hooks = {
	.connection_new		= tfw_sock_srv_connect_complete,
	.connection_drop	= tfw_sock_srv_connect_drop,
	.connection_error	= tfw_sock_srv_connect_error,
	.connection_recv	= tfw_connection_recv,
};

/**
 * Close a server connection, or stop connection attempts if a connection
 * is not established. This is called only in user context at STOP time.
 *
 * This function should be called only when all traffic through Tempesta
 * has stopped. Otherwise concurrent closing of live connections may lead
 * to kernel crashes or deadlocks.
 *
 * FIXME This function is seriously outdated and needs a complete overhaul.
 */
static void
tfw_sock_srv_disconnect(TfwSrvConnection *srv_conn)
{
	TfwConnection *conn = &srv_conn->conn;
	struct sock *sk = conn->sk;

	/* Prevent races with timer callbacks. */
	del_timer_sync(&srv_conn->conn.timer);

	/*
	 * Withdraw from socket activity.
	 * Close and release the socket.
	 */
	if (sk) {
		/*
		 * FIXME this can cause BUG() in ss_tcp_process_data() on
		 * sk->sk_user_data == NULL.
		 */
		tfw_connection_unlink_from_sk(sk);
		tfw_connection_unlink_to_sk(conn);
		ss_close_sync(sk, true);
	}

	/*
	 * Release resources.
	 *
	 * FIXME #116, #254: New messages may keep coming,
	 * and that may lead to BUG() in tfw_connection_drop().
	 * See the problem description in #385.
	 *
	 * FIXME Actually the call is performed in tfw_sock_srv_do_failover()
	 * called by connection_drop callback from ss_close().
	 */
	tfw_connection_drop(conn);
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

	/*
	 * For each server connection, schedule an immediate connect
	 * attempt in SoftIRQ context. Otherwise, in case of an error
	 * in ss_connect() LOCKDEP detects that ss_close() is executed
	 * in parallel in both user and SoftIRQ contexts as the socket
	 * is locked, and spews lots of warnings. LOCKDEP doesn't know
	 * that parallel execution can't happen with the same socket.
	 */
	list_for_each_entry(srv_conn, &srv->conn_list, conn.list)
		tfw_sock_srv_connect_try_later(srv_conn);

	return 0;
}

/**
 * There should be no server socket users when the function is called.
 */
static int
tfw_sock_srv_disconnect_srv(TfwServer *srv)
{
	TfwSrvConnection *srv_conn;

	list_for_each_entry(srv_conn, &srv->conn_list, conn.list)
		tfw_sock_srv_disconnect(srv_conn);
	return 0;
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
	TfwSrvConnection *srv_conn;

	srv_conn = kmem_cache_alloc(tfw_srv_conn_cache, GFP_ATOMIC);
	if (!srv_conn)
		return NULL;

	tfw_connection_init(&srv_conn->conn);
	__setup_retry_timer(srv_conn);
	ss_proto_init(&srv_conn->conn.proto,
		      &tfw_sock_srv_ss_hooks, Conn_HttpSrv);

	return srv_conn;
}

static void
tfw_srv_conn_free(TfwSrvConnection *srv_conn)
{
	BUG_ON(timer_pending(&srv_conn->conn.timer));

	/* Check that all nested resources are freed. */
	tfw_connection_validate_cleanup(&srv_conn->conn);
	kmem_cache_free(tfw_srv_conn_cache, srv_conn);
}

static int
tfw_sock_srv_add_conns(TfwServer *srv, int conns_n)
{
	int i;
	TfwSrvConnection *srv_conn;

	for (i = 0; i < conns_n; ++i) {
		if (!(srv_conn = tfw_srv_conn_alloc()))
			return -ENOMEM;
		tfw_connection_link_peer(&srv_conn->conn, (TfwPeer *)srv);
		tfw_sg_add_conn(srv->sg, srv, &srv_conn->conn);
	}

	return 0;
}

static int
tfw_sock_srv_del_conns(TfwServer *srv)
{
	TfwSrvConnection *srv_conn, *tmp;

	list_for_each_entry_safe(srv_conn, tmp, &srv->conn_list, conn.list) {
		tfw_connection_unlink_from_peer(&srv_conn->conn);
		tfw_srv_conn_free(srv_conn);
	}
	return 0;
}

static void
tfw_sock_srv_delete_all_conns(void)
{
	tfw_sg_for_each_srv(tfw_sock_srv_del_conns);
}

/*
 * ------------------------------------------------------------------------
 *	Configuration handling
 * ------------------------------------------------------------------------
 */

#define TFW_CFG_SRV_CONNS_N_DEF		4
#define TFW_CFG_SRV_WEIGHT_MIN		1
#define TFW_CFG_SRV_WEIGHT_MAX		100
#define TFW_CFG_SRV_WEIGHT_DEF		50

static TfwServer *tfw_cfg_in_lst[TFW_SG_MAX_SRV];
static TfwServer *tfw_cfg_out_lst[TFW_SG_MAX_SRV];
static int tfw_cfg_in_lstsz, tfw_cfg_out_lstsz;
static TfwScheduler *tfw_cfg_in_sched, *tfw_cfg_out_sched;
static TfwSrvGroup *tfw_cfg_in_sg, *tfw_cfg_out_sg;
static unsigned int tfw_cfg_in_sg_flags = TFW_SG_F_SCHED_RATIO_STATIC;
static unsigned int tfw_cfg_out_sg_flags = TFW_SG_F_SCHED_RATIO_STATIC;

static int
tfw_cfg_handle_server(TfwCfgSpec *cs, TfwCfgEntry *ce,
		      TfwSrvGroup *sg, TfwServer **arg_srv)
{
	TfwAddr addr;
	TfwServer *srv;
	int i, conns_n = 0, weight = 0;
	bool has_conns_n = false, has_weight = false;
	const char *key, *val;

	if (ce->val_n != 1) {
		TFW_ERR("%s: %s: Invalid number of arguments: %d\n",
			sg->name, cs->name, (int)ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n > 2) {
		TFW_ERR("%s: %s: Invalid number of argument=value pairs: %d\n",
			sg->name, cs->name, (int)ce->attr_n);
		return -EINVAL;
	}

	if (tfw_addr_pton(&TFW_STR_FROM(ce->vals[0]), &addr)) {
		TFW_ERR("%s: %s: Invalid IP address: '%s'\n",
			sg->name, cs->name, ce->vals[0]);
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "conns_n")) {
			if (has_conns_n) {
				TFW_ERR("%s: %s: Duplicate argument: '%s=%s'\n",
					sg->name, cs->name, key, val);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &conns_n)) {
				TFW_ERR("%s: %s: Invalid value: '%s=%s'\n",
					sg->name, cs->name, key, val);
				return -EINVAL;
			}
			has_conns_n = true;
		} else if (!strcasecmp(key, "weight")) {
			if (has_weight) {
				TFW_ERR("%s: %s: Duplicate argument: '%s=%s'\n",
					sg->name, cs->name, key, val);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &weight)) {
				TFW_ERR("%s: %s: Invalid value: '%s=%s'\n",
					sg->name, cs->name, key, val);
				return -EINVAL;
			}
			has_weight = true;
		} else {
			TFW_ERR("%s: %s: unsupported argument: '%s=%s'\n",
				sg->name, cs->name, key, val);
			return -EINVAL;
		}
	}

	if (!has_conns_n) {
		conns_n = TFW_CFG_SRV_CONNS_N_DEF;
	} else if ((conns_n < 1) || (conns_n > TFW_SRV_MAX_CONN)) {
		TFW_ERR("%s: %s: Value out of range of [1..%d]: 'conns_n=%d'",
			sg->name, cs->name, TFW_SRV_MAX_CONN, conns_n);
		return -EINVAL;
	}
	/* Default weight is set only for static ratio scheduler. */
	if (has_weight && ((weight < 1) || (weight > 100))) {
		TFW_ERR("%s: %s: Value out of range of [%d..%d]: 'weight=%d'",
			sg->name, cs->name, TFW_CFG_SRV_WEIGHT_MIN,
			TFW_CFG_SRV_WEIGHT_MAX, weight);
		return -EINVAL;
	}

	if (!(srv = tfw_server_create(&addr))) {
		TFW_ERR("%s: %s: Error handling a server: '%s'\n",
			sg->name, cs->name, ce->vals[0]);
		return -EINVAL;
	}
	srv->weight = weight;
	tfw_sg_add(sg, srv);

	if (tfw_sock_srv_add_conns(srv, conns_n)) {
		TFW_ERR("%s: %s: Error adding connections to server: '%s'\n",
			sg->name, cs->name, ce->vals[0]);
		return -EINVAL;
	}

	*arg_srv = srv;

	return 0;
}

/**
 * Handle "server" within an "srv_group", e.g.:
 *   srv_group foo {
 *       server 10.0.0.1;
 *       server 10.0.0.2;
 *       server 10.0.0.3 conns_n=1;
 *   }
 *
 * Every server is simply added to the tfw_cfg_in_sg.
 */
static int
tfw_cfg_handle_in_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwServer *srv;

	if (tfw_cfg_in_lstsz >= TFW_SG_MAX_SRV)
		return -EINVAL;
	if (tfw_cfg_handle_server(cs, ce, tfw_cfg_in_sg, &srv))
		return -EINVAL;
	tfw_cfg_in_lst[tfw_cfg_in_lstsz++] = srv;

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
tfw_cfg_handle_out_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwServer *srv;

	if (tfw_cfg_out_lstsz >= TFW_SG_MAX_SRV)
		return -EINVAL;
	/*
	 * The group "default" is created implicitly, and only when
	 * a server outside of any group is found in the configuration.
	 */
	if (!tfw_cfg_out_sg) {
		static const char __read_mostly s_default[] = "default";

		if (!(tfw_cfg_out_sg = tfw_sg_new(s_default, GFP_KERNEL))) {
			TFW_ERR("Unable to add server group '%s'\n", s_default);
			return -EINVAL;
		}
	}

	if (tfw_cfg_handle_server(cs, ce, tfw_cfg_out_sg, &srv))
		return -EINVAL;
	tfw_cfg_out_lst[tfw_cfg_out_lstsz++] = srv;

	return 0;
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
tfw_cfg_begin_srv_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->val_n != 1) {
		TFW_ERR("%s: %s: Invalid number of arguments: %d\n",
			cs->name, ce->vals[0], (int)ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR("%s: %s: Arguments may not have the \'=\' sign\n",
			cs->name, ce->vals[0]);
		return -EINVAL;
	}

	if (!(tfw_cfg_in_sg = tfw_sg_new(ce->vals[0], GFP_KERNEL))) {
		TFW_ERR("Unable to add server group: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	TFW_DBG("begin srv_group: %s\n", sg->name);

	tfw_cfg_in_lstsz = 0;
	tfw_cfg_in_sched = tfw_cfg_out_sched;
	tfw_cfg_in_sg_flags = tfw_cfg_out_sg_flags;

	return 0;
}

static int
tfw_cfg_sg_ratio_adjust(TfwSrvGroup *sg, TfwServer **lst, unsigned int lstsz)
{
	int i;

	if (sg->flags & TFW_SG_F_SCHED_RATIO_STATIC) {
		for (i = 0; i < lstsz; ++i) {
			if (!lst[i]->weight)
				lst[i]->weight = TFW_CFG_SRV_WEIGHT_DEF;
		}
	}

	return 0;
}

static int
tfw_cfg_sg_ratio_verify(TfwSrvGroup *sg, TfwServer **lst, unsigned int lstsz)
{
	int i;

	if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC) {
		for (i = 0; i < lstsz; ++i)
			if (lst[i]->weight)
				break;
		if (i < lstsz) {
			TFW_ERR("srv_group: %s: static weight [%d] used "
				"with 'dynamic' scheduler option\n",
				sg->name, lst[i]->weight);
			return -EINVAL;
		}
	}

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
tfw_cfg_finish_srv_group(TfwCfgSpec *cs)
{
	TfwSrvGroup *sg = tfw_cfg_in_sg;

	BUG_ON(!sg);
	BUG_ON(list_empty(&sg->srv_list));
	BUG_ON(!tfw_cfg_in_sched);
	TFW_DBG("finish srv_group: %s\n", sg->name);

	sg->flags = tfw_cfg_in_sg_flags;

	if (!strcasecmp(tfw_cfg_in_sched->name, "round-robin")) {
		if (tfw_cfg_sg_ratio_verify(sg, tfw_cfg_in_lst,
					    tfw_cfg_in_lstsz))
			return -EINVAL;
		if (tfw_cfg_sg_ratio_adjust(sg, tfw_cfg_in_lst,
					    tfw_cfg_in_lstsz))
			return -EINVAL;
	}

	if (tfw_sg_set_sched(sg, tfw_cfg_in_sched->name)) {
		TFW_ERR("%s: %s: Unable to set scheduler: '%s'\n",
			cs->name, sg->name, tfw_cfg_in_sched->name);
		return -EINVAL;
	}

	return 0;
}

static int
tfw_cfg_handle_ratio(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned int *sg_flags)
{
	unsigned int idx, flags, value;

	if (ce->val_n < 2) {
		/* Default ratio scheduler type. */
		flags = TFW_SG_F_SCHED_RATIO_STATIC;
	} else if (!strcasecmp(ce->vals[1], "static")) {
		flags = TFW_SG_F_SCHED_RATIO_STATIC;
	} else if (!strcasecmp(ce->vals[1], "dynamic")) {
		flags = TFW_SG_F_SCHED_RATIO_DYNAMIC;
		if (ce->val_n < 3) {
			/* Default dynamic type. */
			flags |= TFW_PSTATS_IDX_AVG;
			goto done;
		}
		if (!strcasecmp(ce->vals[2], "minimum")) {
			idx = TFW_PSTATS_IDX_MIN;
		}else if (!strcasecmp(ce->vals[2], "maximum")) {
			idx = TFW_PSTATS_IDX_MAX;
		} else if (!strcasecmp(ce->vals[2], "average")) {
			idx = TFW_PSTATS_IDX_AVG;
		} else if (!strcasecmp(ce->vals[2], "percentile")) {
			if (ce->val_n < 4) {
				/* Default percentile. */
				flags |= TFW_PSTATS_IDX_P90;
				goto done;
			}
			if (tfw_cfg_parse_int(ce->vals[3], &value)) {
				TFW_ERR("%s %s %s %s: Invalid value: '%s'\n",
					cs->name, ce->vals[0], ce->vals[1],
					ce->vals[2], ce->vals[3]);
				return -EINVAL;
			}
			for (idx = 0; idx < ARRAY_SIZE(tfw_pstats_ith); ++idx) {
				if (!tfw_pstats_ith[idx])
					continue;
				if (tfw_pstats_ith[idx] == value)
					break;
			}
			if (idx == ARRAY_SIZE(tfw_pstats_ith)) {
				TFW_ERR("%s %s %s %s: Invalid value: '%s'\n",
					cs->name, ce->vals[0], ce->vals[1],
					ce->vals[2], ce->vals[3]);
				return -EINVAL;
			}
		} else {
			TFW_ERR("%s %s %s: unsupported argument: '%s'\n",
				cs->name, ce->vals[0],
				ce->vals[1], ce->vals[2]);
			return -EINVAL;
		}
		flags |= idx;
	} else {
		TFW_ERR("%s: %s: unsupported argument: '%s'\n",
			cs->name, ce->vals[0], ce->vals[1]);
		return -EINVAL;
	}

done:
	*sg_flags = flags;

	return 0;
}

static int
tfw_cfg_handle_sched(TfwCfgSpec *cs, TfwCfgEntry *ce,
		     TfwScheduler **arg_sched, unsigned int *sg_flags)
{
	TfwScheduler *sched;

	if (!ce->val_n) {
		TFW_ERR("%s: %s: Invalid number of arguments: %d\n",
			cs->name, ce->vals[0], (int)ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR("%s: %s: Arguments may not have the \'=\' sign\n",
			cs->name, ce->vals[0]);
		return -EINVAL;
	}

	if (!(sched = tfw_sched_lookup(ce->vals[0]))) {
		TFW_ERR("%s: Unrecognized scheduler: '%s'\n",
			cs->name, ce->vals[0]);
		return -EINVAL;
	}

	if (!strcasecmp(sched->name, "round-robin"))
		if (tfw_cfg_handle_ratio(cs, ce, sg_flags))
			return -EINVAL;

	*arg_sched = sched;

	return 0;
}

static int
tfw_cfg_handle_in_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfg_handle_sched(cs, ce, &tfw_cfg_in_sched,
					    &tfw_cfg_in_sg_flags);
}

static int
tfw_cfg_handle_out_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfg_handle_sched(cs, ce, &tfw_cfg_out_sched,
					    &tfw_cfg_out_sg_flags);
}

/**
 * Clean everything produced during parsing "server" and "srv_group" entries.
 */
static void
tfw_cfg_clean_srv_groups(TfwCfgSpec *cs)
{
	tfw_sock_srv_delete_all_conns();
	tfw_sg_release_all();

	tfw_cfg_in_sg_flags = tfw_cfg_out_sg_flags = 0;
	tfw_cfg_in_sg = tfw_cfg_out_sg = NULL;
	tfw_cfg_in_sched = tfw_cfg_out_sched = NULL;
	tfw_cfg_in_lstsz = tfw_cfg_out_lstsz = 0;
}

static int
tfw_sock_srv_start(void)
{
	int ret;
	TfwSrvGroup *sg = tfw_cfg_out_sg;

	if (sg) {
		BUG_ON(!tfw_cfg_out_sched);

		sg->flags = tfw_cfg_out_sg_flags;

		if (!strcasecmp(tfw_cfg_out_sched->name, "round-robin")) {
			if (tfw_cfg_sg_ratio_verify(sg, tfw_cfg_out_lst,
						    tfw_cfg_out_lstsz))
				return -EINVAL;
			if (tfw_cfg_sg_ratio_adjust(sg, tfw_cfg_out_lst,
						    tfw_cfg_out_lstsz))
				return -EINVAL;
		}

		if (tfw_sg_set_sched(sg, tfw_cfg_out_sched->name)) {
			TFW_ERR("%s: %s: Unable to set scheduler: '%s'\n",
				"srv_group", sg->name, tfw_cfg_out_sched->name);
			return -EINVAL;
		}
	}
	/*
	 * This must be executed only after the complete configuration
	 * has been processed as it depends on configuration directives
	 * that can be located anywhere in the configuration file.
	 */
	if ((ret = tfw_sg_for_each_srv(tfw_server_apm_create)) != 0)
		return ret;

	return tfw_sg_for_each_srv(tfw_sock_srv_connect_srv);
}

static void
tfw_sock_srv_stop(void)
{
	tfw_sg_for_each_srv(tfw_sock_srv_disconnect_srv);
}

static TfwCfgSpec tfw_srv_group_specs[] = {
	{
		"server", NULL,
		tfw_cfg_handle_in_server,
		.allow_none = false,
		.allow_repeat = true,
		.cleanup = tfw_cfg_clean_srv_groups
	},
	{
		"sched", "round-robin",
		tfw_cfg_handle_in_sched,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_cfg_clean_srv_groups,
	},
	{ 0 }
};

TfwCfgMod tfw_sock_srv_cfg_mod = {
	.name  = "sock_srv",
	.start = tfw_sock_srv_start,
	.stop  = tfw_sock_srv_stop,
	.specs = (TfwCfgSpec[] ) {
		{
			"server", NULL,
			tfw_cfg_handle_out_server,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_cfg_clean_srv_groups,
		},
		{
			"sched", "round-robin",
			tfw_cfg_handle_out_sched,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_cfg_clean_srv_groups,
		},
		{
			"srv_group", NULL,
			tfw_cfg_handle_children,
			tfw_srv_group_specs,
			&(TfwCfgSpecChild ) {
				.begin_hook = tfw_cfg_begin_srv_group,
				.finish_hook = tfw_cfg_finish_srv_group
			},
			.allow_none = true,
			.allow_repeat = true,
		},
		{ 0 }
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
	BUILD_BUG_ON(_TFW_PSTATS_IDX_COUNT > TFW_SG_F_PSTATS_IDX_MASK);
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
