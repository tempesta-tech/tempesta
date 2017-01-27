/**
 *		Tempesta FW
 *
 * Handling server connections.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
 * This is responsible for maintaining a server connection in established
 * state, and doing so in an asynchronous (callback-based) way.
 *
 * The entry point is the tfw_sock_srv_connect_try() function.
 * It initiates a connect attempt and just exits without blocking.
 *
 * Later on, when connection state is changed, a callback is invoked:
 *  - tfw_sock_srv_connect_retry()    - a connect attempt has failed.
 *  - tfw_sock_srv_connect_complete() - a connection is established.
 *  - tfw_sock_srv_connect_failover() - an established connection is closed.
 *
 * Both retry() and failover() call connect_try() again to re-establish the
 * connection. Thus connect_try() is called repeatedly until the connection
 * is finally established (or until this "loop" of callbacks is stopped by
 * tfw_sock_srv_disconnect()).
 * ------------------------------------------------------------------------
 */

/**
 * A server connection differs from a client connection.
 * For clients, a new TfwCliConnection{} instance is created when a new
 * client socket is accepted (the connection is established at that point).
 * For servers, a socket is created first, and then some time passes while
 * a connection is being established.
 *
 * TfwSrvConnection{} instance goes though the following periods of life:
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

/*
 * Timeout between connect attempts is increased with each unsuccessful
 * attempt. Length of the timeout for each attempt is chosen to follow
 * a variant of exponential backoff delay algorithm.
 *
 * It's essential that the new connection is established and the failed
 * connection is restored ASAP, so the min retry interval is set to 1.
 * The next step is good for a cyclic reconnect, e.g. if an upstream
 * ia configured to reset a connection periodically. The next steps are
 * almost a pure backoff algo starting from 100ms, which is a good RTT
 * for a fast 10Gbps link. The timeout is not increased after 1 second
 * as it has moderate overhead, and it's still good in response time.
 */
static const unsigned long tfw_srv_tmo_vals[] = { 1, 10, 100, 250, 500, 1000 };

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

	addr = &srv_conn->peer->addr;

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
	tfw_connection_link_from_sk((TfwConnection *)srv_conn, sk);
	ss_set_callbacks(sk);

	/*
	 * There are two possible use patterns of this function:
	 *
	 * 1. tfw_sock_srv_connect_srv() called in system initialization
	 *    phase before initialization of client listening interfaces,
	 *    so there is no activity in the socket;
	 *
	 * 2. tfw_sock_srv_do_failover() upcalled from SS layer and with
	 *    inactive @srv_conn->sk, so nobody can send through the socket.
	 *    Also since the function is called by connection_error or
	 *    connection_drop hook from SoftIRQ, there can't be another
	 *    socket state change upcall from SS layer due to RSS.
	 *
	 * Thus we don't need syncronization for ss_connect().
	 */
	TFW_INC_STAT_BH(serv.conn_attempts);
	r = ss_connect(sk, &addr->sa, tfw_addr_sa_len(addr), 0);
	if (r) {
		if (r != SS_SHUTDOWN)
			TFW_ERR("Unable to initiate a connect to server: %d\n",
				r);
		ss_close_sync(sk, false);
		/*
		 * We hadle shutdown by closing the socket, so we can return
		 * successful return code to upper layer.
		 */
		return r == SS_SHUTDOWN ? 0 : r;
	}

	/*
	 * Set connection destructor such that connection failover can
	 * take place if the connection attempt fails.
	 */
	srv_conn->destructor = (void *)tfw_srv_conn_release;

	return 0;
}

/*
 * @max_recns can be the maximum value for the data type to mean
 * the unlimited number of attempts, which is the value that should
 * never be reached. UINT_MAX seconds is more than 136 years. It's
 * safe to assume that it's not reached in a single run of Tempesta.
 *
 * The limit on the number of reconnect attempts is used to re-schedule
 * requests that would never be forwarded otherwise. Then, the attempts
 * to reconnect are continued in anticipation that the connection will
 * be re-established sooner or later. Otherwise the connection would
 * stay dead until Tempesta is restarted.
 */
static inline void
tfw_sock_srv_connect_try_later(TfwSrvConnection *srv_conn)
{
	TfwSrvGroup *sg = ((TfwServer *)srv_conn->peer)->sg;
	unsigned long timeout;

	/* Don't rearm reconnection timer if we're about to shutdown. */
	if (unlikely(!ss_active()))
		return;

	/*
	 * max_attempts can be the maximum value for the data type to mean
	 * the unlimited number of attempts, which is the value that should
	 * never be reached. UINT_MAX seconds is more than 136 years. It's
	 * safe to assume that it's not reached in a single run of Tempesta.
	 */
	if (unlikely((srv_conn->recns >= sg->max_recns)
		     && !test_bit(TFW_CONN_B_ISDEAD, &srv_conn->flags)))
	{
		TfwAddr *srv_addr = &srv_conn->peer->addr;
		char s_addr[TFW_ADDR_STR_BUF_SIZE] = { 0 };
		tfw_addr_ntop(srv_addr, s_addr, sizeof(s_addr));
		TFW_WARN("The limit of [%d] on reconnect attempts exceeded. "
			 "The server connection [%s] is down.\n",
			 sg->max_recns, s_addr);
		tfw_connection_repair((TfwConnection *)srv_conn);
		set_bit(TFW_CONN_B_ISDEAD, &srv_conn->flags);
	}
	if (srv_conn->recns < ARRAY_SIZE(tfw_srv_tmo_vals)) {
		timeout = tfw_srv_tmo_vals[srv_conn->recns];
		TFW_DBG_ADDR("Cannot establish connection",
			     &srv_conn->peer->addr);
	} else {
		timeout = tfw_srv_tmo_vals[ARRAY_SIZE(tfw_srv_tmo_vals) - 1];
		if (srv_conn->recns == ARRAY_SIZE(tfw_srv_tmo_vals)
		    || !(srv_conn->recns % 60))
		{
			char addr_str[TFW_ADDR_STR_BUF_SIZE] = { 0 };
			tfw_addr_fmt_v6(&srv_conn->peer->addr.v6.sin6_addr,
					0, addr_str);
			TFW_WARN("Cannot establish connection with %s in %u"
				 " tries, keep trying...\n",
				 addr_str, srv_conn->recns);
		}
	}
	srv_conn->recns++;

	mod_timer(&srv_conn->timer, jiffies + msecs_to_jiffies(timeout));
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
	srv_conn->recns = 0;
}

static inline void
__setup_retry_timer(TfwSrvConnection *srv_conn)
{
	__reset_retry_timer(srv_conn);
	setup_timer(&srv_conn->timer,
		    tfw_sock_srv_connect_retry_timer_cb,
		    (unsigned long)srv_conn);
}

void
tfw_srv_conn_release(TfwSrvConnection *srv_conn)
{
	tfw_connection_release((TfwConnection *)srv_conn);
	/*
	 * conn->sk may be zeroed if we get here after a failed
	 * connect attempt. In that case no connection has been
	 * established yet, and conn->sk has not been set.
	 */
	if (likely(srv_conn->sk))
		tfw_connection_unlink_to_sk((TfwConnection *)srv_conn);
	/*
	 * After a disconnect, new connect attempts are started
	 * in deferred context after a short pause (in a timer
	 * callback). Whatever the reason for a disconnect was,
	 * this is uniform for any of them.
	 */
	tfw_sock_srv_connect_try_later(srv_conn);
}

/**
 * The hook is executed when a server connection is established.
 */
static int
tfw_sock_srv_connect_complete(struct sock *sk)
{
	int r;
	TfwConnection *conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)conn->peer;

	/* Link Tempesta with the socket. */
	tfw_connection_link_to_sk(conn, sk);

	/* Notify higher level layers. */
	if ((r = tfw_connection_new(conn))) {
		TFW_ERR("conn_init() hook returned error\n");
		return r;
	}

	/* Let schedulers use the connection hereafter. */
	tfw_connection_revive(conn);

	/* Repair the connection if necessary. */
	if (unlikely(tfw_srv_conn_restricted((TfwSrvConnection *)conn)))
		tfw_connection_repair(conn);

	__reset_retry_timer((TfwSrvConnection *)conn);

	TFW_DBG_ADDR("connected", &srv->addr);
	TFW_INC_STAT_BH(serv.conn_established);

	return 0;
}

/**
 * The hook is executed when we intentionally close a server connection during
 * shutdown process. Now @sk is closed (but still alive) and we release all
 * associated resources before SS put()'s the socket.
 */
static void
tfw_sock_srv_connect_drop(struct sock *sk)
{
	TfwConnection *conn = sk->sk_user_data;

	TFW_INC_STAT_BH(serv.conn_disconnects);
	tfw_connection_drop(conn);
	tfw_connection_put(conn);
}

/**
 * The hook is executed when there's unrecoverable error in a connection
 * (and not executed when an established connection is closed as usual).
 * An error may occur in any TCP state including data processing on application
 * layer. All Tempesta resources associated with the socket must be released in
 * case they were allocated before. Server socket must be recovered.
 */
static void
tfw_sock_srv_connect_failover(struct sock *sk)
{
	TfwConnection *conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)conn->peer;

	TFW_DBG_ADDR("connection error", &srv->addr);

	/*
	 * Distiguish connections that go to failover state from those that
	 * are in that state already. In the latter case, take an extra
	 * connection reference to indicate that the connection is in the
	 * failover state.
	 */
	if (tfw_connection_live(conn)) {
		tfw_connection_put_to_death(conn);
		tfw_connection_drop(conn);
		TFW_INC_STAT_BH(serv.conn_disconnects);
	} else {
		tfw_connection_get(conn);
	}

	tfw_connection_unlink_from_sk(sk);
	tfw_connection_put(conn);
}

static const SsHooks tfw_sock_srv_ss_hooks = {
	.connection_new		= tfw_sock_srv_connect_complete,
	.connection_drop	= tfw_sock_srv_connect_drop,
	.connection_error	= tfw_sock_srv_connect_failover,
	.connection_recv	= tfw_connection_recv,
};

/**
 * Close a server connection, or stop connection attempts if a connection
 * is not established. This is called only in user context at STOP time.
 */
static int
tfw_sock_srv_disconnect(TfwConnection *conn)
{
	/* Prevent races with timer callbacks. */
	del_timer_sync(&conn->timer);

	/* Use synchronous closing to ensure that the job is enqueued. */
	return ss_close_sync(conn->sk, true);
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
	list_for_each_entry(srv_conn, &srv->conn_list, list)
		tfw_sock_srv_connect_try_later(srv_conn);

	return 0;
}

/**
 * There should be no server socket users when the function is called.
 */
static int
tfw_sock_srv_disconnect_srv(TfwServer *srv)
{
	TfwConnection *conn;

<<<<<<< 760ea44c0912d51bf97bb4ce7da4ed59151e545e
	return tfw_peer_for_each_conn(srv, conn, list, tfw_sock_srv_disconnect);
=======
	list_for_each_entry(srv_conn, &srv->conn_list, list)
		tfw_sock_srv_disconnect(srv_conn);
	return 0;
>>>>>>> Split TfwConnection{} into TfwCliConnection{} and TfwSrvConnection{}.
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

	if (!(srv_conn = kmem_cache_alloc(tfw_srv_conn_cache, GFP_ATOMIC)))
		return NULL;

	tfw_connection_init((TfwConnection *)srv_conn);
	INIT_LIST_HEAD(&srv_conn->fwd_queue);
	INIT_LIST_HEAD(&srv_conn->nip_queue);
	spin_lock_init(&srv_conn->fwd_qlock);

	__setup_retry_timer(srv_conn);
	ss_proto_init(&srv_conn->proto, &tfw_sock_srv_ss_hooks, Conn_HttpSrv);

	return srv_conn;
}

static void
tfw_srv_conn_free(TfwSrvConnection *srv_conn)
{
	BUG_ON(timer_pending(&srv_conn->timer));

	/* Check that all nested resources are freed. */
	tfw_connection_validate_cleanup((TfwConnection *)srv_conn);
	BUG_ON(!list_empty(&srv_conn->nip_queue));
	BUG_ON(ACCESS_ONCE(srv_conn->qsize));

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
		tfw_connection_link_peer((TfwConnection *)srv_conn,
					 (TfwPeer *)srv);
		tfw_sg_add_conn(srv->sg, srv, srv_conn);
	}

	return 0;
}

static int
tfw_sock_srv_del_conns(TfwServer *srv)
{
	TfwSrvConnection *srv_conn, *tmp;

	list_for_each_entry_safe(srv_conn, tmp, &srv->conn_list, list) {
		tfw_connection_unlink_from_peer((TfwConnection *)srv_conn);
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

/*
 * Default values for various configuration directives and options.
 */
#define TFW_CFG_SRV_CONNS_N_DEF		32	/* Default # of connections */
#define TFW_CFG_SRV_QUEUE_SIZE_DEF	1000	/* Max queue size */
#define TFW_CFG_SRV_FWD_TIMEOUT_DEF	60	/* Default request timeout */
#define TFW_CFG_SRV_FWD_RETRIES_DEF	5	/* Default number of tries */
#define TFW_CFG_SRV_RETRY_NIP_DEF	0	/* Do NOT resend NIP reqs */
#define TFW_CFG_SRV_RETRY_ATTEMPTS_DEF	10	/* Reconnect attempts. */

static TfwServer *tfw_cfg_in_slst[TFW_SG_MAX_SRV];
static TfwServer *tfw_cfg_out_slst[TFW_SG_MAX_SRV];
static int tfw_cfg_in_nconn[TFW_SG_MAX_SRV];
static int tfw_cfg_out_nconn[TFW_SG_MAX_SRV];
static int tfw_cfg_in_slstsz, tfw_cfg_out_slstsz;
static TfwScheduler *tfw_cfg_in_sched, *tfw_cfg_out_sched;
static TfwSrvGroup *tfw_cfg_in_sg, *tfw_cfg_out_sg;

static int tfw_cfg_in_queue_size = TFW_CFG_SRV_QUEUE_SIZE_DEF;
static int tfw_cfg_in_fwd_timeout = TFW_CFG_SRV_FWD_TIMEOUT_DEF;
static int tfw_cfg_in_fwd_retries = TFW_CFG_SRV_FWD_RETRIES_DEF;
static int tfw_cfg_in_retry_nip = TFW_CFG_SRV_RETRY_NIP_DEF;
static int tfw_cfg_in_retry_attempts = TFW_CFG_SRV_RETRY_ATTEMPTS_DEF;

static int tfw_cfg_out_queue_size = TFW_CFG_SRV_QUEUE_SIZE_DEF;
static int tfw_cfg_out_fwd_timeout = TFW_CFG_SRV_FWD_TIMEOUT_DEF;
static int tfw_cfg_out_fwd_retries = TFW_CFG_SRV_FWD_RETRIES_DEF;
static int tfw_cfg_out_retry_nip = TFW_CFG_SRV_RETRY_NIP_DEF;
static int tfw_cfg_out_retry_attempts = TFW_CFG_SRV_RETRY_ATTEMPTS_DEF;

static int
tfw_cfgop_intval(TfwCfgSpec *cs, TfwCfgEntry *ce, int *intval)
{
	int ret;

	if (ce->attr_n) {
		TFW_ERR("%s: Arguments may not have the \'=\' sign\n",
			cs->name);
		return -EINVAL;
	}
	if (ce->val_n != 1) {
		TFW_ERR("%s: Invalid number of arguments: %d\n",
			cs->name, (int)ce->val_n);
		return -EINVAL;
	}
	if ((ret = tfw_cfg_parse_int(ce->vals[0], intval)))
		return ret;

	return 0;
}

static int
tfw_cfgop_in_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_in_queue_size);
}

static int
tfw_cfgop_out_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_queue_size);
}

static int
tfw_cfgop_in_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_in_fwd_timeout);
}

static int
tfw_cfgop_out_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_fwd_timeout);
}

static int
tfw_cfgop_in_fwd_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_in_fwd_retries);
}

static int
tfw_cfgop_out_fwd_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_fwd_retries);
}

static inline int
tfw_cfgop_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce, int *retry_nip)
{
	if (ce->attr_n || ce->val_n) {
		TFW_ERR("%s: The option may not have arguments.\n", cs->name);
		return -EINVAL;
	}
	*retry_nip = 1;
	return 0;
}

static int
tfw_cfgop_in_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_retry_nip(cs, ce, &tfw_cfg_in_retry_nip);
}

static int
tfw_cfgop_out_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_retry_nip(cs, ce, &tfw_cfg_out_retry_nip);
}

static int
tfw_cfgop_in_conn_tries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_in_retry_attempts);
}

static int
tfw_cfgop_out_conn_tries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_retry_attempts);
}

static int
tfw_cfgop_set_conn_tries(TfwSrvGroup *sg, int recns)
{
	if (!recns) {
		sg->max_recns = UINT_MAX;
	} else if (recns < ARRAY_SIZE(tfw_srv_tmo_vals)) {
		sg->max_recns = ARRAY_SIZE(tfw_srv_tmo_vals);
	} else {
		sg->max_recns = recns;
	}

	return 0;
}

static int
tfw_cfgop_server(TfwCfgSpec *cs, TfwCfgEntry *ce,
		 TfwSrvGroup *sg, TfwServer **arg_srv, int *arg_conns_n)
{
	TfwAddr addr;
	TfwServer *srv;
	int i, conns_n = 0;
	bool has_conns_n = false;
	const char *key, *val, *saddr;

	if (ce->val_n != 1) {
		TFW_ERR("%s: %s %s: Invalid number of arguments: %zd\n",
			sg->name, cs->name, ce->val_n ? ce->vals[0] : "",
			ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n > 2) {
		TFW_ERR("%s: %s %s: Invalid number of key=value pairs: %zd\n",
			sg->name, cs->name, ce->vals[0], ce->attr_n);
		return -EINVAL;
	}

	saddr = ce->vals[0];

	if (tfw_addr_pton(&TFW_STR_FROM(saddr), &addr)) {
		TFW_ERR("%s: %s %s: Invalid IP address: '%s'\n",
			sg->name, cs->name, saddr, saddr);
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "conns_n")) {
			if (has_conns_n) {
				TFW_ERR("%s: %s %s: Duplicate arg: '%s=%s'\n",
					sg->name, cs->name, saddr, key, val);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &conns_n)) {
				TFW_ERR("%s: %s %s: Invalid value: '%s=%s'\n",
					sg->name, cs->name, saddr, key, val);
				return -EINVAL;
			}
			has_conns_n = true;
		} else {
			TFW_ERR("%s: %s %s: Unsupported argument: '%s=%s'\n",
				sg->name, cs->name, saddr, key, val);
			return -EINVAL;
		}
	}

	if (!has_conns_n) {
		conns_n = TFW_CFG_SRV_CONNS_N_DEF;
	} else if ((conns_n < 1) || (conns_n > TFW_SRV_MAX_CONN)) {
		TFW_ERR("%s: %s %s: Out of range of [1..%d]: 'conns_n=%d'\n",
			sg->name, cs->name, saddr, TFW_SRV_MAX_CONN, conns_n);
		return -EINVAL;
	}


	if (!(srv = tfw_server_create(&addr))) {
		TFW_ERR("%s: %s %s: Error handling the server\n",
			sg->name, cs->name, saddr);
		return -EINVAL;
	}
	tfw_sg_add(sg, srv);

	*arg_srv = srv;
	*arg_conns_n = conns_n;

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
 * Every server is simply added to the tfw_srv_cfg_curr_group.
 */
static int
tfw_cfgop_in_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int nconn;
	TfwServer *srv;

	if (tfw_cfg_in_slstsz >= TFW_SG_MAX_SRV)
		return -EINVAL;
	if (tfw_cfgop_server(cs, ce, tfw_cfg_in_sg, &srv, &nconn))
		return -EINVAL;
	tfw_cfg_in_nconn[tfw_cfg_in_slstsz] = nconn;
	tfw_cfg_in_slst[tfw_cfg_in_slstsz++] = srv;

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
tfw_cfgop_out_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int nconn;
	TfwServer *srv;

	if (tfw_cfg_out_slstsz >= TFW_SG_MAX_SRV)
		return -EINVAL;
	/*
	 * The group "default" is created implicitly, and only when
	 * a server outside of any group is found in the configuration.
	 */
	if (!tfw_cfg_out_sg) {
		static const char __read_mostly s_default[] = "default";

		if (!(tfw_cfg_out_sg = tfw_sg_new(s_default, GFP_KERNEL))) {
			TFW_ERR("Unable to add default server group\n");
			return -EINVAL;
		}
	}

	if (tfw_cfgop_server(cs, ce, tfw_cfg_out_sg, &srv, &nconn))
		return -EINVAL;
	tfw_cfg_out_nconn[tfw_cfg_out_slstsz] = nconn;
	tfw_cfg_out_slst[tfw_cfg_out_slstsz++] = srv;

	return 0;
}

/**
 * The callback is invoked on entering an "srv_group", e.g:
 *
 *   srv_group foo {  <--- The position at the moment of call.
 *       server ...;
 *       server ...;
 *       ...
 *   }
 *
 * Basically it parses the group name and the "sched" attribute, creates a
 * new TfwSrvGroup object and sets the context for parsing nested "server"s.
 */
static int
tfw_cfgop_begin_srv_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->val_n != 1) {
		TFW_ERR("%s %s: Invalid number of arguments: %zd\n",
			cs->name, ce->val_n ? ce->vals[0] : "", ce->val_n);
			return -EINVAL;
        }
	if (ce->attr_n) {
		TFW_ERR("%s %s: Arguments may not have the \'=\' sign\n",
			cs->name, ce->vals[0]);
		return -EINVAL;
	}

	if (!(tfw_cfg_in_sg = tfw_sg_new(ce->vals[0], GFP_KERNEL))) {
		TFW_ERR("%s %s: Unable to add group\n", cs->name, ce->vals[0]);
		return -EINVAL;
	}

	TFW_DBG("begin srv_group: %s\n", sg->name);

        tfw_cfg_in_slstsz = 0;
        tfw_cfg_in_sched = tfw_cfg_out_sched;
	tfw_cfg_in_retry_attempts = tfw_cfg_out_retry_attempts;
	tfw_cfg_in_queue_size = tfw_cfg_out_queue_size;
	tfw_cfg_in_fwd_timeout = tfw_cfg_out_fwd_timeout;
	tfw_cfg_in_fwd_retries = tfw_cfg_out_fwd_retries;
	tfw_cfg_in_retry_nip = tfw_cfg_out_retry_nip;

	return 0;
}

/**
 * The callback is invoked upon exit from a "srv_group" when all nested
 * "server"s are parsed, e.g.:
 *
 *   srv_group foo {
 *       server ...;
 *       server ...;
 *       ...
 *   }  <--- The position at the moment of call.
 */
static int
tfw_cfgop_finish_srv_group(TfwCfgSpec *cs)
{
	int i;
	TfwSrvGroup *sg = tfw_cfg_in_sg;

	BUG_ON(!sg);
	BUG_ON(list_empty(&sg->srv_list));
	BUG_ON(!tfw_cfg_in_sched);
	TFW_DBG("finish srv_group: %s\n", sg->name);

	tfw_cfgop_set_conn_tries(sg, tfw_cfg_in_retry_attempts);
	sg->max_qsize = tfw_cfg_in_queue_size ? : UINT_MAX;
	sg->max_jqage = tfw_cfg_in_fwd_timeout
		      ? msecs_to_jiffies(tfw_cfg_in_fwd_timeout * 1000)
		      : ULONG_MAX;
	sg->max_refwd = tfw_cfg_in_fwd_retries ? : UINT_MAX;
	sg->flags |= tfw_cfg_in_retry_nip ? TFW_SRV_RETRY_NIP : 0;

	if (tfw_sg_set_sched(sg, tfw_cfg_in_sched->name)) {
		TFW_ERR("%s %s: Unable to set scheduler: '%s'\n",
			cs->name, sg->name, tfw_cfg_in_sched->name);
		return -EINVAL;
	}
	/* Add connections only after a scheduler is set. */
	for (i = 0; i < tfw_cfg_in_slstsz; ++i) {
		TfwServer *srv = tfw_cfg_in_slst[i];
		if (tfw_sock_srv_add_conns(srv, tfw_cfg_in_nconn[i])) {
			char as[TFW_ADDR_STR_BUF_SIZE] = { 0 };
			tfw_addr_ntop(&srv->addr, as, sizeof(as));
			TFW_ERR("%s %s: server '%s': "
				"Error adding connections\n",
				cs->name, sg->name, as);
			return -EINVAL;
		}
	}

	return 0;
}

static int
tfw_cfgop_sched(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwScheduler **arg_sched)
{
	TfwScheduler *sched;

	if (!ce->val_n) {
		TFW_ERR("%s: Invalid number of arguments: %zd\n",
			cs->name, ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR("%s %s: Arguments may not have the \'=\' sign\n",
			cs->name, ce->vals[0]);
		return -EINVAL;
	}

	if (!(sched = tfw_sched_lookup(ce->vals[0]))) {
		TFW_ERR("%s %s: Unrecognized scheduler: '%s'\n",
			cs->name, ce->vals[0], ce->vals[0]);
		return -EINVAL;
	}

	*arg_sched = sched;

	return 0;
}

static int
tfw_cfgop_in_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_sched(cs, ce, &tfw_cfg_in_sched);
}

static int
tfw_cfgop_out_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_sched(cs, ce, &tfw_cfg_out_sched);
}

/**
 * Clean everything produced during parsing "server" and "srv_group" entries.
 */
static void
tfw_clean_srv_groups(TfwCfgSpec *cs)
{
	tfw_sock_srv_delete_all_conns();
	tfw_sg_release_all();

	tfw_cfg_in_sg = tfw_cfg_out_sg = NULL;
	tfw_cfg_in_sched = tfw_cfg_out_sched = NULL;
	tfw_cfg_in_slstsz = tfw_cfg_out_slstsz = 0;
}

static int
tfw_sock_srv_start(void)
{
	int i, ret;
	TfwSrvGroup *sg = tfw_cfg_out_sg;

	if (sg) {
		BUG_ON(!tfw_cfg_out_sched);

		tfw_cfgop_set_conn_tries(sg, tfw_cfg_out_retry_attempts);
		sg->max_qsize = tfw_cfg_out_queue_size ? : UINT_MAX;
		sg->max_jqage = tfw_cfg_out_fwd_timeout
			      ? msecs_to_jiffies(tfw_cfg_out_fwd_timeout * 1000)
			      : ULONG_MAX;
		sg->max_refwd = tfw_cfg_out_fwd_retries ? : UINT_MAX;
		sg->flags |= tfw_cfg_out_retry_nip ? TFW_SRV_RETRY_NIP : 0;

		if (tfw_sg_set_sched(sg, tfw_cfg_out_sched->name)) {
			TFW_ERR("srv_group %s: Unable to set scheduler: "
				"'%s'\n", sg->name, tfw_cfg_out_sched->name);
			return -EINVAL;
		}
		/* Add connections only after a scheduler is set. */
		for (i = 0; i < tfw_cfg_out_slstsz; ++i) {
			TfwServer *srv = tfw_cfg_out_slst[i];
			if (tfw_sock_srv_add_conns(srv, tfw_cfg_out_nconn[i])) {
				char as[TFW_ADDR_STR_BUF_SIZE] = { 0 };
				tfw_addr_ntop(&srv->addr, as, sizeof(as));
				TFW_ERR("srv_group %s: server '%s': "
					"Error adding connections\n",
					sg->name, as);
				return -EINVAL;
			}
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
		tfw_cfgop_in_server,
		.allow_repeat = true,
		.cleanup = tfw_clean_srv_groups
	},
	{
		"sched", "round-robin",
		tfw_cfgop_in_sched,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"server_queue_size", NULL,
		tfw_cfgop_in_queue_size,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"server_forward_timeout", NULL,
		tfw_cfgop_in_fwd_timeout,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"server_forward_retries", NULL,
		tfw_cfgop_in_fwd_retries,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"server_retry_non_idempotent", NULL,
		tfw_cfgop_in_retry_nip,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"connect_tries", NULL,
		tfw_cfgop_in_conn_tries,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
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
			tfw_cfgop_out_server,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"sched", "round-robin",
			tfw_cfgop_out_sched,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"server_queue_size", NULL,
			tfw_cfgop_out_queue_size,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"server_forward_timeout", NULL,
			tfw_cfgop_out_fwd_timeout,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"server_forward_retries", NULL,
			tfw_cfgop_out_fwd_retries,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"server_retry_non_idempotent", NULL,
			tfw_cfgop_out_retry_nip,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"connect_tries", NULL,
			tfw_cfgop_out_conn_tries,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"srv_group", NULL,
			tfw_cfg_handle_children,
			tfw_srv_group_specs,
			&(TfwCfgSpecChild ) {
				.begin_hook = tfw_cfgop_begin_srv_group,
				.finish_hook = tfw_cfgop_finish_srv_group
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
