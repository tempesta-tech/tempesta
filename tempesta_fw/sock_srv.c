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

#include "apm.h"
#include "tempesta_fw.h"
#include "connection.h"
#include "http_sess.h"
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
 *  - tfw_sock_srv_connect_complete() - a connection is established.
 *  - tfw_sock_srv_connect_failover() - an established connection is closed or
 *                                      a connect attempt has failed.
 *
 * After connection was closed the connection destructor is called to set up
 * timer to call connect_try() again and re-establish the
 * connection. Thus connect_try() is called repeatedly until the connection
 * is finally established (or until this "loop" of callbacks is stopped by
 * tfw_sock_srv_disconnect()).
 * ------------------------------------------------------------------------
 */

/**
 * A server connection differs from a client connection. For clients,
 * a new TfwCliConn{} instance is created when a new client socket is
 * accepted (the connection is established at that point). For servers,
 * a socket is created first, and then there's a period of time while
 * a connection is being established.
 *
 * TfwSrvConn{} instance goes though the following periods of life:
 * - First, a TfwSrvConn{} instance is allocated and set up with
 *   data from configuration file.
 * - When a server socket is created, the TfwSrvConn{} instance
 *   is partially initialized to allow a connect attempt to complete.
 * - When a connection is established, the TfwSrvConn{} instance
 *   is fully initialized and set up.
 * - If a connect attempt has failed, or the connection has been
 *   reset or closed, the same TfwSrvConn{} instance is reused with
 *   a new socket. Another attempt to establish a connection is made.
 *
 * So a TfwSrvConn{} instance has a longer lifetime. In a sense,
 * a TfwSrvConn{} instance is persistent. It lives from the time
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
 * non-valid @sk stays a member of an TfwSrvConn{} instance during
 * that time frame. However, the condition for reuse of an instance is
 * that there're no more users of the instance, so no thread can make
 * use of an old socket @sk. Should something bad happen, then having
 * a stale pointer in conn->sk is no different than having a NULL pointer.
 *
 * The reference counter is still needed for TfwSrvConn{} instances.
 * It tells when an instance can be reused for a new connect attempt.
 * A scenario that may occur is as follows:
 * 1. There's a client's request, so scheduler finds a server connection
 *    and returns it to the client's thread. The server connection has
 *    its refcnt incremented as there's a new user of it now.
 * 2. At that time the server sends RST on that connection in response
 *    to an earlier request. It starts the failover procedure that runs
 *    in parallel. Part of the procedure is a new attempt to connect to
 *    the server, which requires that TfwSrvConn{} instance can be
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
static void
tfw_sock_srv_connect_try(TfwSrvConn *srv_conn)
{
	int r;
	TfwAddr *addr;
	struct sock *sk;

	addr = &srv_conn->peer->addr;

	r = ss_sock_create(addr->family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r) {
		TFW_ERR("Unable to create server socket\n");
		return;
	}

	/*
	 * Save @sk in case the connect request is silently dropped by
	 * the other end (i.e. a firewall). It will be needed to close
	 * the socket. Initialize TfwSrvConn{}->refcnt to a special value.
	 * Setup connection handlers before ss_connect() call. We can get
	 * an established connection right when we're in the call in case
	 * of a local peer connection, so all handlers must be installed
	 * before the call.
	 */
#if defined(DEBUG) && (DEBUG >= 2)
	sock_set_flag(sk, SOCK_DBG);
#endif
	tfw_connection_link_from_sk((TfwConn *)srv_conn, sk);
	tfw_connection_link_to_sk((TfwConn *)srv_conn, sk);
	tfw_srv_conn_init_as_dead(srv_conn);
	ss_set_callbacks(sk);
	/*
	 * Set connection destructor such that connection failover can
	 * take place if the connection attempt fails.
	 */
	srv_conn->destructor = (void *)tfw_srv_conn_release;

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
		SS_CALL(connection_error, sk);
		/* Another try is handled in tfw_srv_conn_release() */
	}
}

/*
 * There are several stages in the reconnect process. All stages are
 * covered by tfw_connection_repair() function.
 *
 * 1. The attempts to reconnect are repeated at short intervals that are
 *    gradually increased. There's a great chance that the connection is
 *    restored during this stage. When that happens, all requests in the
 *    connection are re-sent to the server.
 * 2. The attempts to reconnect are continued at one second intervals.
 *    This covers a short server's downtime such as a service restart.
 *    During this time requests in the connection are checked to see if
 *    they should be evicted for a variety of reasons (timed out, etc.).
 *    Again, when the connection is restored, requests in the connection
 *    are re-sent to the server.
 * 3. When the number of attempts to reconnect exceeds the configured
 *    value, then the connection is marked as faulty. All requests in
 *    the connection are then re-scheduled to other servers/connections. 
 *    Attempts to reconnect are still continued at one second intervals.
 *    This would cover longer server's downtime due to a reboot or any
 *    other maintenance, Should the connection be restored at some time,
 *    everything will continue to work as usual.
 *
 * TODO: There's an interesting side effect in the described procedure.
 * Connections that are currently in failover may still accept incoming
 * requests if there are no active connections. When connections are
 * restored, all requests will be correctly forwarded/re-sent to their
 * respective servers. This may serve as a QoS feature that mitigates
 * some temporary short periods when servers are not available.
 */
static inline void
tfw_sock_srv_connect_try_later(TfwSrvConn *srv_conn)
{
	unsigned long timeout;

	/* Don't rearm the reconnection timer if we're about to shutdown. */
	if (unlikely(!ss_active()))
		return;

	if (srv_conn->recns < ARRAY_SIZE(tfw_srv_tmo_vals)) {
		if (srv_conn->recns)
			TFW_DBG_ADDR("Cannot establish connection",
				     &srv_conn->peer->addr);
		timeout = tfw_srv_tmo_vals[srv_conn->recns];
	} else {
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

		tfw_connection_repair((TfwConn *)srv_conn);
		timeout = tfw_srv_tmo_vals[ARRAY_SIZE(tfw_srv_tmo_vals) - 1];
	}
	srv_conn->recns++;

	mod_timer(&srv_conn->timer, jiffies + msecs_to_jiffies(timeout));
}

static void
tfw_sock_srv_connect_retry_timer_cb(unsigned long data)
{
	TfwSrvConn *srv_conn = (TfwSrvConn *)data;

	/* A new socket is created for each connect attempt. */
	tfw_sock_srv_connect_try(srv_conn);
}

static inline void
__reset_retry_timer(TfwSrvConn *srv_conn)
{
	srv_conn->recns = 0;
}

static inline void
__setup_retry_timer(TfwSrvConn *srv_conn)
{
	__reset_retry_timer(srv_conn);
	setup_timer(&srv_conn->timer,
		    tfw_sock_srv_connect_retry_timer_cb,
		    (unsigned long)srv_conn);
}

void
tfw_srv_conn_release(TfwSrvConn *srv_conn)
{
	tfw_connection_release((TfwConn *)srv_conn);
	/*
	 * conn->sk may be zeroed if we get here after a failed
	 * connect attempt. In that case no connection has been
	 * established yet, and conn->sk has not been set.
	 */
	if (likely(srv_conn->sk))
		tfw_connection_unlink_to_sk((TfwConn *)srv_conn);
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
	TfwConn *conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)conn->peer;

	BUG_ON(conn->sk != sk);

	/* Notify higher level layers. */
	if ((r = tfw_connection_new(conn))) {
		TFW_ERR("conn_init() hook returned error\n");
		return r;
	}

	/* Let schedulers use the connection hereafter. */
	tfw_connection_revive(conn);

	/* Repair the connection if necessary. */
	if (unlikely(tfw_srv_conn_restricted((TfwSrvConn *)conn)))
		tfw_connection_repair(conn);

	__reset_retry_timer((TfwSrvConn *)conn);

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
	TfwConn *conn = sk->sk_user_data;

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
	TfwConn *conn = sk->sk_user_data;
	TfwServer *srv = (TfwServer *)conn->peer;

	TFW_DBG_ADDR("connection error", &srv->addr);

	/*
	 * Distiguish connections that go to failover state
	 * from those that are in failover state already.
	 */
	if (tfw_connection_live(conn)) {
		TFW_INC_STAT_BH(serv.conn_disconnects);
		tfw_connection_put_to_death(conn);
		tfw_connection_drop(conn);
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
 *
 * There are two corner cases. In both cases calling ss_close_sync() won't
 * cause any effect as the connection is closed already. Instead, just free
 * the connection's resources directly.
 * 1. A connection has just been closed by the other side. A reconnect is
 *    prevented by stopping the timer. Yet the connection may have unfreed
 *    resources as closing was done as part of failover.
 * 2. A connection is being closed by the other side just as Tempesta is
 *    moved to STOP state. Both threads may call tfw_connection_release()
 *    at the same time. See the implementation of the underlying function
 *    tfw_srv_conn_release().
 */
static int
tfw_sock_srv_disconnect(TfwConn *conn)
{
	int ret = 0;
	struct sock *sk = conn->sk;

	/* Prevent races with timer callbacks. */
	del_timer_sync(&conn->timer);

	/*
	 * All resources attached to a connection is released  by calling
	 * connection destructor once the socket linked to a connection is
	 * closed. So no additional cleanup is needed if connection->refcnt
	 * is equals TFW_CONN_DEATHCNT.
	 */
	if (atomic_read(&conn->refcnt) != TFW_CONN_DEATHCNT)
		ret = ss_close_sync(sk, true);
	else
		tfw_connection_release(conn);

	return ret;
}

/*
 * ------------------------------------------------------------------------
 *	Global connect/disconnect routines.
 * ------------------------------------------------------------------------
 *
 * At this time, only reverse proxy mode is supported. All servers are
 * connected to when Tempesta is started, and all connections are closed
 * when Tempesta is stopped. The code in this section takes care of that.
 *
 * This behavior may change in future for a forward proxy implementation.
 * Then there will be lots of short-living connections. That should be kept
 * in mind to avoid possible bottlenecks. In particular, that is the reason
 * for not having a global list of all TfwSrvConn{} objects, and for storing
 * not-yet-established connections in the TfwServer->conn_list.
 */

static int
tfw_sock_srv_connect_srv(TfwServer *srv)
{
	TfwSrvConn *srv_conn;

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
 *
 * All resources attached a the server connection will be released once socket
 * linked to the server connection (e.g. http messages stored in connection's
 * forward queue and client connections referenced by that messages). So single
 * ss_synchronize() in tfw_cfg_stop() will guarantee that all server and client
 * connections was released.
 */
static int
tfw_sock_srv_disconnect_srv(TfwServer *srv)
{
	TfwConn *conn;

	return tfw_peer_for_each_conn(srv, conn, list,
				      tfw_sock_srv_disconnect);
}

/*
 * ------------------------------------------------------------------------
 *	TfwServer creation/deletion helpers.
 * ------------------------------------------------------------------------
 *
 * This section of code is responsible for allocating TfwSrvConn{} objects
 * and linking them with a TfwServer object.
 *
 * All server connections (TfwSrvConn{} objects) are pre-allocated when
 * TfwServer{} is created. That happens at the configuration parsing stage.
 *
 * Later on, when Tempesta FW is started, these TfwSrvConn{} objects are
 * used to establish connections. These connection objects are re-used
 * (but not re-allocated) when connections are re-established.
 */

static struct kmem_cache *tfw_srv_conn_cache;

static TfwSrvConn *
tfw_srv_conn_alloc(void)
{
	TfwSrvConn *srv_conn;

	if (!(srv_conn = kmem_cache_alloc(tfw_srv_conn_cache, GFP_ATOMIC)))
		return NULL;

	tfw_connection_init((TfwConn *)srv_conn);
	memset((char *)srv_conn + sizeof(TfwConn), 0,
	       sizeof(TfwSrvConn) - sizeof(TfwConn));
	INIT_LIST_HEAD(&srv_conn->fwd_queue);
	INIT_LIST_HEAD(&srv_conn->nip_queue);
	spin_lock_init(&srv_conn->fwd_qlock);

	__setup_retry_timer(srv_conn);
	ss_proto_init(&srv_conn->proto, &tfw_sock_srv_ss_hooks, Conn_HttpSrv);

	return srv_conn;
}

static void
tfw_srv_conn_free(TfwSrvConn *srv_conn)
{
	BUG_ON(timer_pending(&srv_conn->timer));

	/* Check that all nested resources are freed. */
	tfw_connection_validate_cleanup((TfwConn *)srv_conn);
	BUG_ON(!list_empty(&srv_conn->nip_queue));
	BUG_ON(ACCESS_ONCE(srv_conn->qsize));

	kmem_cache_free(tfw_srv_conn_cache, srv_conn);
}

static int
tfw_sock_srv_add_conns(TfwServer *srv)
{
	int i;
	TfwSrvConn *srv_conn;

	for (i = 0; i < srv->conn_n; ++i) {
		if (!(srv_conn = tfw_srv_conn_alloc()))
			return -ENOMEM;
		tfw_connection_link_peer((TfwConn *)srv_conn, (TfwPeer *)srv);
	}

	return 0;
}

static int
tfw_sock_srv_del_conns(TfwServer *srv)
{
	TfwSrvConn *srv_conn, *tmp;

	list_for_each_entry_safe(srv_conn, tmp, &srv->conn_list, list) {
		tfw_connection_unlink_from_peer((TfwConn *)srv_conn);
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
#define TFW_CFG_DFLT_VAL	"__dfltval__"	/* Use a default value. */

static struct list_head tfw_cfg_in_slst = LIST_HEAD_INIT(tfw_cfg_in_slst);
static struct list_head tfw_cfg_out_slst = LIST_HEAD_INIT(tfw_cfg_out_slst);
static struct list_head *tfw_cfg_slst;
static int tfw_cfg_slstsz, tfw_cfg_out_slstsz;
static TfwScheduler *tfw_cfg_sched, *tfw_cfg_out_sched;
static TfwSchrefPredict tfw_cfg_schref_predict, tfw_cfg_out_schref_predict;
static void *tfw_cfg_schref, *tfw_cfg_out_schref;
static TfwSrvGroup *tfw_cfg_sg, *tfw_cfg_out_sg;

static int tfw_cfg_queue_size, tfw_cfg_out_queue_size;
static int tfw_cfg_fwd_timeout, tfw_cfg_out_fwd_timeout;
static int tfw_cfg_fwd_retries, tfw_cfg_out_fwd_retries;
static int tfw_cfg_cns_retries, tfw_cfg_out_cns_retries;
static unsigned int tfw_cfg_retry_nip, tfw_cfg_out_retry_nip;
static unsigned int tfw_cfg_sticky_sess, tfw_cfg_out_sticky_sess;
static unsigned int tfw_cfg_sg_flags, tfw_cfg_out_sg_flags;

static int
tfw_cfgop_intval(TfwCfgSpec *cs, TfwCfgEntry *ce, int *intval)
{
	if (ce->val_n != 1) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
			return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}

	cs->dest = intval;
	return tfw_cfg_set_int(cs, ce);
}

static int
tfw_cfgop_in_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_queue_size);
}

static int
tfw_cfgop_out_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_queue_size);
}

static int
tfw_cfgop_in_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_fwd_timeout);
}

static int
tfw_cfgop_out_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_fwd_timeout);
}

static int
tfw_cfgop_in_fwd_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_fwd_retries);
}

static int
tfw_cfgop_out_fwd_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_fwd_retries);
}

static inline int
tfw_cfgop_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce, int *retry_nip)
{
	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}
	if (!ce->val_n) {
		*retry_nip = TFW_SRV_RETRY_NIP;
	} else if (!strcasecmp(ce->vals[0], TFW_CFG_DFLT_VAL))	{
		BUG_ON(ce->val_n != 1);
		*retry_nip = 0;
	} else {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}

	return 0;
}

static inline int
tfw_cfgop_sticky_sess(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned int *use_sticky)
{
	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}
	if (ce->val_n > 1) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (!ce->val_n) {
		*use_sticky = TFW_SRV_STICKY;
	} else if (!strcasecmp(ce->vals[0], "allow_failover")) {
		*use_sticky = TFW_SRV_STICKY | TFW_SRV_STICKY_FAILOVER;
	} else if (!strcasecmp(ce->vals[0], TFW_CFG_DFLT_VAL)) {
		*use_sticky = 0;
	} else  {
		TFW_ERR_NL("Unsupported argument: %s\n", ce->vals[0]);
		return  -EINVAL;
	}

	return 0;
}

static int
tfw_cfgop_in_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_retry_nip(cs, ce, &tfw_cfg_retry_nip);
}

static int
tfw_cfgop_out_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_retry_nip(cs, ce, &tfw_cfg_out_retry_nip);
}

static int
tfw_cfgop_in_sticky_sess(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_sticky_sess(cs, ce, &tfw_cfg_sticky_sess);
}

static int
tfw_cfgop_out_sticky_sess(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_sticky_sess(cs, ce, &tfw_cfg_out_sticky_sess);
}

static int
tfw_cfgop_in_conn_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_cns_retries);
}

static int
tfw_cfgop_out_conn_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_out_cns_retries);
}

/* Default and maximum values for "server" options. */
#define TFW_CFG_SRV_CONNS_N_DEF		32	/* Default # of connections */
#define TFW_CFG_SRV_WEIGHT_MIN		1	/* Min static weight value */
#define TFW_CFG_SRV_WEIGHT_MAX		100	/* Max static weight value */
#define TFW_CFG_SRV_WEIGHT_DEF		50	/* Dflt static weight value */

/**
 * Common code to handle 'server' directive.
 */
static int
tfw_cfgop_server(TfwCfgSpec *cs, TfwCfgEntry *ce, struct list_head *slst)
{
	TfwAddr addr;
	TfwServer *srv;
	int i, conns_n = 0, weight = 0;
	bool has_conns_n = false, has_weight = false;
	const char *key, *val;

	if (ce->val_n != 1) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n > 2) {
		TFW_ERR_NL("Invalid number of key=value pairs: %zu\n",
			   ce->attr_n);
		return -EINVAL;
	}

	if (tfw_addr_pton(&TFW_STR_FROM(ce->vals[0]), &addr)) {
		TFW_ERR_NL("Invalid IP address: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "conns_n")) {
			if (has_conns_n) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &conns_n)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_conns_n = true;
		} else if (!strcasecmp(key, "weight")) {
			if (has_weight) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &weight)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_weight = true;
		} else {
			TFW_ERR_NL("Unsupported argument: '%s'\n", key);
			return -EINVAL;
		}
	}

	if (!has_conns_n) {
		conns_n = TFW_CFG_SRV_CONNS_N_DEF;
	} else if ((conns_n < 1) || (conns_n > TFW_SRV_MAX_CONN_N)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'conns_n=%d'\n",
			   TFW_SRV_MAX_CONN_N, conns_n);
		return -EINVAL;
	}
	/* Default weight is set only for static ratio scheduler. */
	if (has_weight && ((weight < TFW_CFG_SRV_WEIGHT_MIN)
			   || (weight > TFW_CFG_SRV_WEIGHT_MAX)))
	{
		TFW_ERR_NL("Out of range of [%d..%d]: 'weight=%d'\n",
			   TFW_CFG_SRV_WEIGHT_MIN, TFW_CFG_SRV_WEIGHT_MAX,
			   weight);
		return -EINVAL;
	}

	if (!(srv = tfw_server_create(&addr))) {
		TFW_ERR_NL("Error handling the server: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}
	srv->weight = weight;
	srv->conn_n = conns_n;
	list_add_tail(&srv->list, slst);

	return 0;
}

/**
 * Handle "server" within an "srv_group", e.g.:
 *   srv_group foo {
 *       server 10.0.0.1;
 *       server 10.0.0.2;
 *       server 10.0.0.3 conns_n=1;
 *   }
 */
static int
tfw_cfgop_in_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_cfgop_server(cs, ce, tfw_cfg_slst))
		return -EINVAL;
	tfw_cfg_slstsz++;

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
	if (tfw_cfgop_server(cs, ce, &tfw_cfg_out_slst))
		return -EINVAL;
	tfw_cfg_out_slstsz++;

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
 * Basically it parses the group name, creates a new TfwSrvGroup{} object
 * and sets the context for parsing nested directives.
 */
static int
tfw_cfgop_begin_srv_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (ce->val_n != 1) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}

	if (!(tfw_cfg_sg = tfw_sg_new(ce->vals[0], GFP_KERNEL))) {
		TFW_ERR_NL("Unable to add group: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	TFW_DBG("begin srv_group: %s\n", tfw_cfg_sg->name);

	tfw_cfg_queue_size = tfw_cfg_out_queue_size;
	tfw_cfg_fwd_timeout = tfw_cfg_out_fwd_timeout;
	tfw_cfg_fwd_retries = tfw_cfg_out_fwd_retries;
	tfw_cfg_cns_retries = tfw_cfg_out_cns_retries;
	tfw_cfg_retry_nip = tfw_cfg_out_retry_nip;
	tfw_cfg_sticky_sess = tfw_cfg_out_sticky_sess;
	tfw_cfg_sg_flags = tfw_cfg_out_sg_flags;
	tfw_cfg_sched = tfw_cfg_out_sched;
	tfw_cfg_schref = tfw_cfg_out_schref;

	BUG_ON(!list_empty(&tfw_cfg_in_slst));
	tfw_cfg_slst = &tfw_cfg_in_slst;
	tfw_cfg_slstsz = 0;

	return 0;
}

/**
 * Set default static weights if not set. Used during configuration and in
 * unittests.
 */
static int
tfw_cfg_sg_ratio_adjust(struct list_head *slst)
{
	TfwServer *srv;

	list_for_each_entry(srv, slst, list)
		if (!srv->weight)
			srv->weight = TFW_CFG_SRV_WEIGHT_DEF;
	return 0;
}

static int
tfw_cfg_sg_ratio_verify(void)
{
	TfwServer *srv;
	int count = 0;

	if (tfw_cfg_sg->flags & (TFW_SG_F_SCHED_RATIO_DYNAMIC
				 || TFW_SG_F_SCHED_RATIO_PREDICT))
	{
		list_for_each_entry(srv, tfw_cfg_slst, list) {
			if (srv->weight)
				break;
			++count;
		}
		if (count < tfw_cfg_slstsz) {
			TFW_ERR_NL("srv_group %s: static weight [%d] used "
				   "with 'dynamic' scheduler option\n",
				   tfw_cfg_sg->name, srv->weight);
			return -EINVAL;
		}
	}

	return 0;
}

static int
tfw_cfgop_setup_srv_group(void)
{
	int ret;
	TfwServer *srv, *tmp;

	BUG_ON(!tfw_cfg_sg);
	BUG_ON(!tfw_cfg_sched);

	/* Limit maximum value to prevent race in tfw_srv_conn_queue_full(). */
	tfw_cfg_sg->max_qsize = tfw_cfg_queue_size ? : INT_MAX;
	tfw_cfg_sg->max_jqage = tfw_cfg_fwd_timeout
			      ? msecs_to_jiffies(tfw_cfg_fwd_timeout * 1000)
			      : ULONG_MAX;
	tfw_cfg_sg->max_refwd = tfw_cfg_fwd_retries;
	tfw_cfg_sg->max_recns = tfw_cfg_cns_retries
			      ? max_t(int, tfw_cfg_cns_retries,
				      ARRAY_SIZE(tfw_srv_tmo_vals))
			      : UINT_MAX;

	tfw_cfg_sg->flags = tfw_cfg_sg_flags;
	tfw_cfg_sg->flags |= tfw_cfg_retry_nip | tfw_cfg_sticky_sess;
	tfw_cfg_sg->sched_data = tfw_cfg_schref;

	/*
	 * Check 'ratio' scheduler configuration for incompatibilities.
	 * Set weight to default value for each server in the group
	 * if no weight is provided in the configuration. For dynamic
	 * or predictive ratios this sets initial equal weights to all
	 * servers.
	 */
	if (!strcasecmp(tfw_cfg_sched->name, "ratio")) {
		if (tfw_cfg_sg_ratio_verify())
			return -EINVAL;
		if (tfw_cfg_sg_ratio_adjust(tfw_cfg_slst))
			return -EINVAL;
	}
	/* Set up the server group with all servers that are in it. */
	list_for_each_entry_safe(srv, tmp, tfw_cfg_slst, list) {
		if ((ret = tfw_sock_srv_add_conns(srv)) != 0)
			return ret;
		list_del(&srv->list);
		tfw_sg_add(tfw_cfg_sg, srv);
	}
	/*
	 * Set up a scheduler and add the server group to the scheduler.
	 * Must be called only after the server group is set up with all
	 * servers (and all connections) that are in it.
	 */
	if (tfw_sg_set_sched(tfw_cfg_sg, tfw_cfg_sched->name)) {
		TFW_ERR_NL("Unable to add srv_group '%s' to scheduler '%s'\n",
			   tfw_cfg_sg->name, tfw_cfg_sched->name);
		return -EINVAL;
	}

	return 0;
}

/**
 * The callback is invoked upon exit from a "srv_group" when all nested
 * directives are parsed, e.g.:
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
	if (list_empty(tfw_cfg_slst))
		return -EINVAL;
	TFW_DBG("finish srv_group: %s\n", tfw_cfg_sg->name);

	return tfw_cfgop_setup_srv_group();
}

static int
tfw_cfg_handle_ratio_predyn_opts(TfwCfgEntry *ce, unsigned int *arg_flags)
{
	unsigned int idx, value, flags = *arg_flags;

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
			TFW_ERR_NL("Invalid value: '%s'\n", ce->vals[3]);
			return -EINVAL;
		}
		for (idx = 0; idx < ARRAY_SIZE(tfw_pstats_ith); ++idx) {
			if (!tfw_pstats_ith[idx])
				continue;
			if (tfw_pstats_ith[idx] == value)
				break;
		}
		if (idx == ARRAY_SIZE(tfw_pstats_ith)) {
			TFW_ERR_NL("Invalid value: '%s'\n", ce->vals[3]);
			return -EINVAL;
		}
	} else {
		TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[2]);
		return -EINVAL;
	}
	flags |= idx;

done:
	*arg_flags = flags;
	return 0;
}

/* Default and maximum values for "sched ratio predict" options. */
#define TFW_CFG_PAST_DEF	30	/* 30 secs of past APM vals */
#define TFW_CFG_PAST_MAX	120	/* 120 secs of past APM vals */
#define TFW_CFG_RATE_DEF	20	/* 20 times/sec */
#define TFW_CFG_RATE_MAX	20	/* 20 times/sec */

static int
tfw_cfg_handle_ratio_predict(TfwCfgEntry *ce,
			     void *arg_schref, unsigned int *arg_flags)
{
	int i, ret;
	const char *key, *val;
	bool has_past = false, has_rate = false, has_ahead = false;
	TfwSchrefPredict schref = { 0 };

	if ((ret = tfw_cfg_handle_ratio_predyn_opts(ce, arg_flags)))
		return ret;

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "past")) {
			if (has_past) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &schref.past)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_past = true;
		} else if (!strcasecmp(key, "rate")) {
			if (has_rate) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &schref.rate)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_rate = true;
		} else if (!strcasecmp(key, "ahead")) {
			if (has_ahead) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &schref.ahead)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_ahead = true;
		}
	}
	if (!has_past) {
		schref.past = TFW_CFG_PAST_DEF;
	} else if ((schref.past < 1) || (schref.past > TFW_CFG_PAST_MAX)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'past=%d'\n",
			   TFW_CFG_PAST_MAX, schref.past);
		return -EINVAL;
	}
	if (!has_rate) {
		schref.rate = TFW_CFG_RATE_DEF;
	} else if ((schref.rate < 1) || (schref.rate > TFW_CFG_RATE_MAX)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'rate=%d'\n",
			   TFW_CFG_RATE_MAX, schref.rate);
		return -EINVAL;
	}
	if (!has_ahead) {
		schref.ahead = schref.past > 1 ? schref.past / 2 : 1;
	} else if ((schref.ahead < 1) || (schref.ahead > schref.past / 2)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'ahead=%d'."
			   "Can't be greater than half of 'past=%d'.\n",
			   schref.past / 2, schref.ahead, schref.past);
		return -EINVAL;
	}

	*(TfwSchrefPredict *)arg_schref = schref;
	return 0;
}

static int
tfw_cfg_handle_ratio_dynamic(TfwCfgEntry *ce, unsigned int *arg_flags)
{
	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}

	return tfw_cfg_handle_ratio_predyn_opts(ce, arg_flags);
}

static int
tfw_cfg_handle_ratio(TfwCfgEntry *ce, void *schref, unsigned int *sg_flags)
{
	int ret;
	unsigned int flags;

	if (ce->val_n < 2) {
		/* Default ratio scheduler type. */
		flags = TFW_SG_F_SCHED_RATIO_STATIC;
	} else if (!strcasecmp(ce->vals[1], "static")) {
		flags = TFW_SG_F_SCHED_RATIO_STATIC;
	} else if (!strcasecmp(ce->vals[1], "dynamic")) {
		flags = TFW_SG_F_SCHED_RATIO_DYNAMIC;
		if ((ret = tfw_cfg_handle_ratio_dynamic(ce, &flags)))
			return ret;
	} else if (!strcasecmp(ce->vals[1], "predict")) {
		flags = TFW_SG_F_SCHED_RATIO_PREDICT;
		if ((ret = tfw_cfg_handle_ratio_predict(ce, schref, &flags)))
			return ret;
	} else {
		TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[1]);
		return -EINVAL;
	}

	*sg_flags = flags;
	return 0;
}

/*
 * Common code to handle 'sched' directive.
 */
static int
tfw_cfgop_sched(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwScheduler **arg_sched,
		void *schref, unsigned int *sg_flags)
{
	TfwScheduler *sched;

	if (!ce->val_n) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}

	if (!(sched = tfw_sched_lookup(ce->vals[0]))) {
		TFW_ERR_NL("Unrecognized scheduler: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	if (!strcasecmp(sched->name, "ratio"))
		if (tfw_cfg_handle_ratio(ce, schref, sg_flags))
			return -EINVAL;

	*arg_sched = sched;

	return 0;
}

static int
tfw_cfgop_in_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_schref = &tfw_cfg_schref_predict;

	return tfw_cfgop_sched(cs, ce, &tfw_cfg_sched,
				       tfw_cfg_schref,
				       &tfw_cfg_sg_flags);
}

static int
tfw_cfgop_out_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_out_schref = &tfw_cfg_out_schref_predict;

	return tfw_cfgop_sched(cs, ce, &tfw_cfg_out_sched,
				       tfw_cfg_out_schref,
				       &tfw_cfg_out_sg_flags);
}

/**
 * Clean everything produced during parsing "server" and "srv_group" entries.
 */
static void
tfw_clean_srv_groups(TfwCfgSpec *cs)
{
	TfwServer *srv, *tmp;

	list_for_each_entry_safe(srv, tmp, &tfw_cfg_in_slst, list) {
		list_del(&srv->list);
		tfw_sock_srv_del_conns(srv);
		tfw_server_destroy(srv);
	}
	list_for_each_entry_safe(srv, tmp, &tfw_cfg_out_slst, list) {
		list_del(&srv->list);
		tfw_sock_srv_del_conns(srv);
		tfw_server_destroy(srv);
	}

	tfw_cfg_sg = tfw_cfg_out_sg = NULL;
	tfw_cfg_sched = tfw_cfg_out_sched = NULL;
	tfw_cfg_schref = tfw_cfg_out_schref = NULL;
	tfw_cfg_slstsz = tfw_cfg_out_slstsz = 0;

	tfw_sock_srv_delete_all_conns();
	tfw_sg_release_all();
}

static int
tfw_sock_srv_start(void)
{
	int ret;

	/*
	 * The group "default" is created implicitly, and only when
	 * a server outside of any group is found in the configuration.
	 */
	if (tfw_cfg_out_slstsz) {
		tfw_cfg_out_sg = tfw_sg_new("default", GFP_KERNEL);
		if (!tfw_cfg_out_sg) {
			TFW_ERR_NL("Unable to add default server group\n");
			return -EINVAL;
		}

		tfw_cfg_cns_retries = tfw_cfg_out_cns_retries;
		tfw_cfg_queue_size  = tfw_cfg_out_queue_size;
		tfw_cfg_fwd_timeout = tfw_cfg_out_fwd_timeout;
		tfw_cfg_fwd_retries = tfw_cfg_out_fwd_retries;
		tfw_cfg_sticky_sess = tfw_cfg_out_sticky_sess;
		tfw_cfg_retry_nip = tfw_cfg_out_retry_nip;
		tfw_cfg_sg_flags = tfw_cfg_out_sg_flags;
		tfw_cfg_slst = &tfw_cfg_out_slst;
		tfw_cfg_slstsz = tfw_cfg_out_slstsz;
		tfw_cfg_sched = tfw_cfg_out_sched;
		tfw_cfg_schref = tfw_cfg_out_schref;
		tfw_cfg_sg = tfw_cfg_out_sg;

		if ((ret = tfw_cfgop_setup_srv_group()))
			return ret;
	}
	/*
	 * This must be executed only after the complete configuration
	 * has been processed as it depends on configuration directives
	 * that can be located anywhere in the configuration file.
	 */
	if ((ret = tfw_sg_for_each_srv(tfw_apm_add_srv)) != 0)
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
		"sched", "ratio static",
		tfw_cfgop_in_sched,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"server_queue_size", "1000",
		tfw_cfgop_in_queue_size,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
	},
	{
		"server_forward_timeout", "60",
		tfw_cfgop_in_fwd_timeout,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
	},
	{
		"server_forward_retries", "5",
		tfw_cfgop_in_fwd_retries,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
	},
	{
		"server_retry_nonidempotent", TFW_CFG_DFLT_VAL,
		tfw_cfgop_in_retry_nip,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
	},
	{
		"server_connect_retries", "10",
		tfw_cfgop_in_conn_retries,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup = tfw_clean_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
	},
	{
		"sticky_sessions", TFW_CFG_DFLT_VAL,
		tfw_cfgop_in_sticky_sess,
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
			"sched", "ratio static",
			tfw_cfgop_out_sched,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"server_queue_size", "1000",
			tfw_cfgop_out_queue_size,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
			.spec_ext = &(TfwCfgSpecInt) {
				.range = { 0, INT_MAX },
			},
		},
		{
			"server_forward_timeout", "60",
			tfw_cfgop_out_fwd_timeout,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
			.spec_ext = &(TfwCfgSpecInt) {
				.range = { 0, INT_MAX },
			},
		},
		{
			"server_forward_retries", "5",
			tfw_cfgop_out_fwd_retries,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
			.spec_ext = &(TfwCfgSpecInt) {
				.range = { 0, INT_MAX },
			},
		},
		{
			"server_retry_non_idempotent", TFW_CFG_DFLT_VAL,
			tfw_cfgop_out_retry_nip,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
		},
		{
			"server_connect_retries", "10",
			tfw_cfgop_out_conn_retries,
			.allow_none = true,
			.allow_repeat = false,
			.cleanup = tfw_clean_srv_groups,
			.spec_ext = &(TfwCfgSpecInt) {
				.range = { 0, INT_MAX },
			},
		},
		{
			"sticky_sessions", TFW_CFG_DFLT_VAL,
			tfw_cfgop_out_sticky_sess,
			.allow_none = true,
			.allow_repeat = false,
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
			.cleanup = tfw_clean_srv_groups,
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
	BUILD_BUG_ON(_TFW_PSTATS_IDX_COUNT > TFW_SG_M_PSTATS_IDX);
	BUG_ON(tfw_srv_conn_cache);
	tfw_srv_conn_cache = kmem_cache_create("tfw_srv_conn_cache",
					       sizeof(TfwSrvConn), 0, 0, NULL);
	return !tfw_srv_conn_cache ? -ENOMEM : 0;
}

void
tfw_sock_srv_exit(void)
{
	kmem_cache_destroy(tfw_srv_conn_cache);
}
