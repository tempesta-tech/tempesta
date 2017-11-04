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
	if (likely(!test_bit(TFW_CONN_B_DEL, &srv_conn->flags))) {
		tfw_sock_srv_connect_try_later(srv_conn);
	}
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
 * Close a server connection, or stop attempts to connect if a connection
 * is not established. This is called only in user context at STOP time.
 *
 * There are two different ways of closing a connection.
 * 1. A connection is closed by a backend. That is considered temporary.
 *    All pending requests in the connection's forwarding queue are resent
 *    to the backend if the connection is restored relatively quickly.
 *    Otherwise, pending requests are re-scheduled to other connections
 *    or servers. All of that is part of failover process.
 * 2. A connection is closed by Tempesta. That is considered permanent.
 *    The connection is not restored. Pending requests are deleted, and
 *    all resources are released. Right now this happens only at shutdown.
 *
 * Tempesta is in the process of being shut down when this function is
 * called. First, any attempts to reconnect are stopped. Then, closing
 * of the connection is initiated if it's not being closed yet. Still,
 * Closing of a connection may be initiated concurrently by a backend
 * or Tempesta. Only one request for a close is allowed to proceed, so
 * it may happen that request from a backend is serviced first. Either
 * way, all resources attached to a connection are released by calling
 * the connection destructor once the socket linked to a connection is
 * closed. The release function in the destructor recognizes the state
 * of shutdown and properly releases all resources. See the details of
 * the underlying function tfw_srv_conn_release().
 *
 * If a server connection is closed at the time this function runs, then
 * it had been closed by a backend before the shutdown, and the connection
 * is still in failover (not re-connected yet). The resources attached to
 * the connection had not been released, and it has to be done forcefully.
 */
static int
tfw_sock_srv_disconnect(TfwConn *conn)
{
	int ret = 0;
	struct sock *sk = conn->sk;
	TfwSrvConn *srv_conn = (TfwSrvConn *)conn;

	/* Stop any attempts to reconnect or reschedule. */
	del_timer_sync(&conn->timer);
	set_bit(TFW_CONN_B_DEL, &srv_conn->flags);

	/*
	 * Close the connection if it's not being closed yet. Resources
	 * attached to the connection are released. If the connection is
	 * closed already, then force the release of attached resources.
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

static TfwSrvConn *
tfw_sock_srv_new_conn(TfwServer *srv)
{
	TfwSrvConn *srv_conn;

	if (!(srv_conn = tfw_srv_conn_alloc()))
		return NULL;
	tfw_connection_link_peer((TfwConn *)srv_conn, (TfwPeer *)srv);

	return srv_conn;
}

static int
tfw_sock_srv_append_conns_n(TfwServer *srv, size_t conn_n)
{
	int i;
	TfwSrvConn *srv_conn;

	for (i = 0; i < conn_n; ++i) {
		if (!(srv_conn = tfw_sock_srv_new_conn(srv)))
			return -ENOMEM;
		tfw_sock_srv_connect_try_later(srv_conn);
	}

	return 0;
}

static int
tfw_sock_srv_add_conns(TfwServer *srv)
{
	int i;

	for (i = 0; i < srv->conn_n; ++i)
		if (!(tfw_sock_srv_new_conn(srv)))
			return -ENOMEM;

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
static struct kmem_cache *tfw_sg_cfg_cache;

#define TFW_CFG_DFLT_VAL	"__dfltval__"	/* Use a default value. */
#define TFW_CFG_IMPL_DFT_SG	"default"

/* Server list of the group has changed. */
#define TFW_CFG_MDF_SG_SRV	0x1
/* Server group scheduler has changed. */
#define TFW_CFG_MDF_SG_SCHED	0x2

/**
 * Describes how to change a server group to comply a new configuration.
 *
 * In-service configuration update (live reconfiguration) means that
 * HTTP processing is running during configuration update. No unnecessary
 * clients disconnects or backend server reconnects must happen. This means
 * that simple rcu-like swap of the current and the new configuration is
 * not possible. Instead current configuration must be updated step-by-step
 * to comply the new configuration.
 *
 * Update process is splitted in two stages:
 * - configuration parsing stage: tfw_sock_srv_cfgstart(), TfwCfgSpec handlers
 * and tfw_sock_srv_cfgend(). It's normal if an error happens during the
 * stage since the new configuration is provided by a user and may contain
 * errors.
 * - applying stage: tfw_sock_srv_start(). Errors are unrecoverable and mean
 * that only a part of changes was appied, so the resulting configuration is
 * invalid.
 *
 * On configuration parsing stage binary representation of a server group is
 * saved into @parsed_sg, while @orig_sg poins to the existing server group
 * with the same name if any. @orig_sg remain unchanged until applying stage.
 * @orig_sg if any or @parsed_sg otherwize is registered as server group
 * available after reconfig by tfw_sg_add_reconfig() call. This allow other
 * TempestaFW modules to save pointer to the desired group.
 *
 * On applying stage changes from @parsed_sg are distributed to @orig_sg if
 * @orig_sg is available, or @parsed_sg is promoted to active group by
 * starting it's connetions otherwize. After that list of server groups
 * available after reconfig replaces list of active groups by
 * tfw_sg_apply_reconfig() call.
 *
 * @orig_sg		- server group instance from the current configuration;
 * @parsed_sg		- server group representation based on a new
 *			  configuration;
 * @list		- member pointer in the sg_cfg_list list;
 * @reconf_flags	- TFW_CFG_MDF_SG_* flags;
 * @nip_flags		- non-idempotent req related flags;
 * @sticky_flags	- sticky sessions processing flags;
 * @sched_flags		- scheduler flags;
 * @sched_arg		- scheduler init argument.
 */
typedef struct {
	TfwSrvGroup		*orig_sg;
	TfwSrvGroup		*parsed_sg;
	struct list_head	list;
	unsigned int		reconf_flags;
	unsigned int		nip_flags;
	unsigned int		sticky_flags;
	unsigned int		sched_flags;
	void			*sched_arg;
} TfwCfgSrvGroup;

/* Currently parsed Server group. */
static TfwCfgSrvGroup *tfw_cfg_sg = NULL;
/* 'default' Server group. */
static TfwCfgSrvGroup *tfw_cfg_sg_def = NULL;

/* List of parsed server groups (TfwCfgSrvGroup). */
static LIST_HEAD(sg_cfg_list);

/* Servers removed from active configuration during reconfiguration. */
static LIST_HEAD(orphan_srvs);
/* Server groups removed from active configuration during reconfiguration. */
static LIST_HEAD(orphan_sgs);

static struct {
	bool max_qsize		: 1;
	bool max_refwd		: 1;
	bool max_jqage		: 1;
	bool max_recns		: 1;
	bool nip_flags		: 1;
	bool sticky_flags	: 1;
	bool sched		: 1;
} __attribute__((packed)) tfw_cfg_is_set;

/* Please keep the condition in these three macros in sync. */
#define TFW_CFGOP_HAS_DFLT(ce, v)					\
	(tfw_cfg_is_dflt_value(ce) && tfw_cfg_is_set.v)
#define TFW_CFGOP_INHERIT_OPT(ce, v)					\
({									\
	if (tfw_cfg_is_dflt_value(ce) && tfw_cfg_is_set.v) {		\
		tfw_cfg_sg->parsed_sg->v = tfw_cfg_sg_def->parsed_sg->v;\
		return 0;						\
	}								\
})
#define TFW_CFGOP_INHERIT_FLAGS(ce, v)					\
({									\
	if (tfw_cfg_is_dflt_value(ce) && tfw_cfg_is_set.v) {		\
		tfw_cfg_sg->v = tfw_cfg_sg_def->v;			\
		return 0;						\
	}								\
})

static void
tfw_cfgop_sg_copy_opts(TfwSrvGroup *to, TfwSrvGroup *from)
{
	BUG_ON(!to);
	BUG_ON(!from);

	to->max_qsize = from->max_qsize;
	to->max_refwd = from->max_refwd;
	to->max_jqage = from->max_jqage;
	to->max_recns = from->max_recns;
	to->flags     = from->flags;
}

static int
tfw_cfgop_sg_copy_sched_arg(void **to, void *from)
{
	if (!from) {
		*to = NULL;
		return 0;
	}

	/* Currently only one type of sched argument is used. */
	if (!(*to = kzalloc(sizeof(TfwSchrefPredict), GFP_KERNEL)))
		return -ENOMEM;
	memcpy(*to, from, sizeof(TfwSchrefPredict));

	return 0;
}

static TfwCfgSrvGroup *
tfw_cfgop_new_sg_cfg(const char *name)
{
	TfwCfgSrvGroup *sg_cfg = kmem_cache_alloc(tfw_sg_cfg_cache, GFP_KERNEL);
	if (!sg_cfg)
		return NULL;

	memset(sg_cfg, 0, sizeof(TfwCfgSrvGroup));
	sg_cfg->parsed_sg = tfw_sg_new(name, GFP_KERNEL);
	if (!sg_cfg->parsed_sg) {
		kmem_cache_free(tfw_sg_cfg_cache, sg_cfg);
		return NULL;
	}
	sg_cfg->orig_sg = tfw_sg_lookup(name);
	INIT_LIST_HEAD(&sg_cfg->list);

	list_add(&sg_cfg->list, &sg_cfg_list);

	return sg_cfg;
}

static int
tfw_cfgop_new_sg_cfg_default(void)
{
	BUG_ON(tfw_cfg_sg_def);

	if (!(tfw_cfg_sg_def = tfw_cfgop_new_sg_cfg(TFW_CFG_IMPL_DFT_SG)))
		return -ENOMEM;

	return 0;
}

static TfwCfgSrvGroup*
tfw_cfgop_lookup_sg_cfg(const char *name)
{
	TfwCfgSrvGroup *sg_cfg;

	list_for_each_entry(sg_cfg, &sg_cfg_list, list) {
		TfwSrvGroup *sg = sg_cfg->orig_sg ? : sg_cfg->parsed_sg;

		BUG_ON(!sg);
		if (!strcasecmp(sg->name, name))
			return sg_cfg;
	}
	return NULL;
}

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
tfw_cfgop_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned int *qsize)
{
	int r;

	if((r = tfw_cfgop_intval(cs, ce, qsize)))
		return r;
	/* Limit maximum value to prevent race in tfw_srv_conn_queue_full(). */
	*qsize = *qsize ? : INT_MAX;

	return 0;
}

static int
tfw_cfgop_in_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_CFGOP_INHERIT_OPT(ce, max_qsize);
	return tfw_cfgop_queue_size(cs, ce, &tfw_cfg_sg->parsed_sg->max_qsize);
}

static int
tfw_cfgop_out_queue_size(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.max_qsize = 1;
	return tfw_cfgop_queue_size(cs, ce,
				    &tfw_cfg_sg_def->parsed_sg->max_qsize);
}

static int
tfw_cfgop_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned long *to)
{
	int r;
	unsigned int time;

	if((r = tfw_cfgop_intval(cs, ce, &time)))
		return r;
	*to = time ? msecs_to_jiffies(time * 1000) : ULONG_MAX;

	return 0;
}

static int
tfw_cfgop_in_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_CFGOP_INHERIT_OPT(ce, max_jqage);
	return tfw_cfgop_fwd_timeout(cs, ce, &tfw_cfg_sg->parsed_sg->max_jqage);
}

static int
tfw_cfgop_out_fwd_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.max_jqage = 1;
	return tfw_cfgop_fwd_timeout(cs, ce,
				     &tfw_cfg_sg_def->parsed_sg->max_jqage);
}

static int
tfw_cfgop_in_fwd_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_CFGOP_INHERIT_OPT(ce, max_refwd);
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_sg->parsed_sg->max_refwd);
}

static int
tfw_cfgop_out_fwd_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.max_refwd = 1;
	return tfw_cfgop_intval(cs, ce, &tfw_cfg_sg_def->parsed_sg->max_refwd);
}

static inline int
tfw_cfgop_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned int *sg_flags)
{
	unsigned int retry_nip;

	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}
	if (tfw_cfg_is_dflt_value(ce)) {
		retry_nip = 0;
	} else if (!ce->val_n) {
		retry_nip = TFW_SRV_RETRY_NIP;
	} else {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	*sg_flags |= retry_nip;

	return 0;
}

static int
tfw_cfgop_in_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_CFGOP_INHERIT_FLAGS(ce, nip_flags);
	return tfw_cfgop_retry_nip(cs, ce, &tfw_cfg_sg->parsed_sg->flags);
}

static int
tfw_cfgop_out_retry_nip(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.nip_flags = 1;
	return tfw_cfgop_retry_nip(cs, ce, &tfw_cfg_sg_def->parsed_sg->flags);
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
	if (tfw_cfg_is_dflt_value(ce)) {
		*use_sticky = 0;
	} else if (!ce->val_n) {
		*use_sticky = TFW_SRV_STICKY;
	} else if (!strcasecmp(ce->vals[0], "allow_failover")) {
		*use_sticky = TFW_SRV_STICKY | TFW_SRV_STICKY_FAILOVER;
	} else  {
		TFW_ERR_NL("Unsupported argument: %s\n", ce->vals[0]);
		return  -EINVAL;
	}

	return 0;
}

static int
tfw_cfgop_in_sticky_sess(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_CFGOP_INHERIT_FLAGS(ce, sticky_flags);
	return tfw_cfgop_sticky_sess(cs, ce, &tfw_cfg_sg->sticky_flags);
}

static int
tfw_cfgop_out_sticky_sess(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.sticky_flags = 1;
	return tfw_cfgop_sticky_sess(cs, ce, &tfw_cfg_sg_def->parsed_sg->flags);
}

static int
tfw_cfgop_conn_retries(TfwCfgSpec *cs, TfwCfgEntry *ce, unsigned int *recns)
{
	int r;

	if((r = tfw_cfgop_intval(cs, ce, recns)))
		return r;
	*recns = *recns ? max_t(int, *recns, ARRAY_SIZE(tfw_srv_tmo_vals))
			: UINT_MAX;

	return 0;
}

static int
tfw_cfgop_in_conn_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TFW_CFGOP_INHERIT_OPT(ce, max_recns);
	return tfw_cfgop_conn_retries(cs, ce,
				      &tfw_cfg_sg->parsed_sg->max_recns);
}

static int
tfw_cfgop_out_conn_retries(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.max_recns = 1;
	return tfw_cfgop_conn_retries(cs, ce,
				      &tfw_cfg_sg_def->parsed_sg->max_recns);
}

static TfwServer *
__cfgop_server_lookup(struct list_head *srv_list, TfwAddr *addr)
{
	TfwServer *srv;

	list_for_each_entry(srv, srv_list, list)
		if (tfw_addr_eq(&srv->addr, addr))
			return srv;

	return NULL;
}

/**
 * Mark @sg_cfg as requiring scheduler update if the @srv wasn't present in
 * previous configuration or if it's options changed.
 */
static void
tfw_cfgop_server_orig_lookup(TfwCfgSrvGroup *sg_cfg, TfwServer *srv)
{
	TfwServer *orig_srv;

	if (!sg_cfg->orig_sg)
		return;

	orig_srv = __cfgop_server_lookup(&sg_cfg->orig_sg->srv_list,
					 &srv->addr);
	if (!orig_srv) {
		srv->flags |= TFW_CFG_F_ADD;
		goto done;
	}
	if (orig_srv->conn_n != srv->conn_n)
		goto changed;
	if (srv->weight && (srv->weight != orig_srv->weight))
		goto changed;

	/* Server is not changed and can be reused. */
	orig_srv->flags |= TFW_CFG_F_KEEP;
	srv->flags |= TFW_CFG_F_KEEP;

	return;
changed:
	orig_srv->flags |= TFW_CFG_F_MOD;
	srv->flags |= TFW_CFG_F_MOD;
done:
	sg_cfg->reconf_flags |= TFW_CFG_MDF_SG_SRV;
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
tfw_cfgop_server(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwCfgSrvGroup *sg_cfg)
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
	if (__cfgop_server_lookup(&sg_cfg->parsed_sg->srv_list, &addr)) {
		TFW_ERR_NL("Duplicated server '%s'\n", ce->vals[0]);
		return -EEXIST;
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
	tfw_sg_add_srv(sg_cfg->parsed_sg, srv);
	tfw_cfgop_server_orig_lookup(sg_cfg, srv);

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
	return tfw_cfgop_server(cs, ce, tfw_cfg_sg);
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
	return tfw_cfgop_server(cs, ce, tfw_cfg_sg_def);
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
	TfwCfgSrvGroup *sg_cfg;
	TfwSrvGroup *sg;

	if (ce->val_n != 1) {
		TFW_ERR_NL("Invalid number of arguments: %zu\n", ce->val_n);
		return -EINVAL;
	}
	if (ce->attr_n) {
		TFW_ERR_NL("Arguments may not have the \'=\' sign\n");
		return -EINVAL;
	}

	sg_cfg = tfw_cfgop_lookup_sg_cfg(ce->vals[0]);
	/*
	 * Default group exists in the list from the very begining of
	 * configuration parsing.
	*/
	if (!sg_cfg && strcasecmp(ce->vals[0], TFW_CFG_IMPL_DFT_SG)) {
		sg_cfg = tfw_cfgop_new_sg_cfg(ce->vals[0]);
	}
	if (!sg_cfg) {
		TFW_ERR_NL("Unable to create a group: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	/* Reuse original group if possible. */
	sg = sg_cfg->orig_sg ? : sg_cfg->parsed_sg;
	if (!tfw_sg_add_reconfig(sg)) {
		TFW_ERR_NL("Can't register already registered group '%s'\n",
			   ce->vals[0]);
		return -EINVAL;
	}

	tfw_cfg_sg = sg_cfg;
	TFW_DBG("begin srv_group: %s\n", tfw_cfg_sg->parsed_sg->name);

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
tfw_cfg_sg_ratio_verify(TfwSrvGroup *sg)
{
	TfwServer *srv;
	int count = 0;

	if (sg->flags & (TFW_SG_F_SCHED_RATIO_DYNAMIC
			 || TFW_SG_F_SCHED_RATIO_PREDICT))
	{
		list_for_each_entry(srv, &sg->srv_list, list) {
			if (srv->weight)
				break;
			++count;
		}
		if (count < sg->srv_n) {
			TFW_ERR_NL("srv_group %s: static weight [%d] used "
				   "with 'dynamic' scheduler option\n",
				   sg->name, srv->weight);
			return -EINVAL;
		}
	}

	return 0;
}

static bool
tfw_cfgop_sched_changed(TfwCfgSrvGroup *sg_cfg)
{
	if (!sg_cfg->orig_sg)
		return false;

	if (sg_cfg->orig_sg->sched != sg_cfg->parsed_sg->sched)
		return true;

	if (sg_cfg->sched_flags !=
	    (sg_cfg->orig_sg->flags & TFW_SG_M_SCHED_RATIO_TYPE))
		return true;

	/* TODO: check scheduler argument (not supported yet). */
	return false;
}

static int
tfw_cfgop_setup_srv_group(TfwCfgSrvGroup *sg_cfg)
{
	TfwSrvGroup *sg = sg_cfg->parsed_sg;

	/* Some servers was removed, so scheduler update is required */
	if (sg_cfg->orig_sg &&
	    (sg_cfg->orig_sg->srv_n != sg_cfg->parsed_sg->srv_n))
	{
		sg_cfg->reconf_flags |= TFW_CFG_MDF_SG_SRV;
	}

	sg->flags = sg_cfg->nip_flags | sg_cfg->sticky_flags |
			sg_cfg->sched_flags;
	/*
	 * Check 'ratio' scheduler configuration for incompatibilities.
	 * Set weight to default value for each server in the group
	 * if no weight is provided in the configuration. For dynamic
	 * or predictive ratios this sets initial equal weights to all
	 * servers.
	 */
	if (!strcasecmp(sg->sched->name, "ratio")) {
		if (tfw_cfg_sg_ratio_verify(sg))
			return -EINVAL;
		if (tfw_cfg_sg_ratio_adjust(&sg->srv_list))
			return -EINVAL;
	}

	if (tfw_cfgop_sched_changed(sg_cfg))
		sg_cfg->reconf_flags |= TFW_CFG_MDF_SG_SCHED;

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
	int r;

	if ((r = tfw_cfgop_setup_srv_group(tfw_cfg_sg)))
		return r;

	TFW_DBG("finish srv_group: %s\n", tfw_cfg_sg->parsed_sg->name);
	tfw_cfg_sg = tfw_cfg_sg_def;

	return 0;
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
			     void **scharg, unsigned int *arg_flags)
{
	int i, ret;
	const char *key, *val;
	bool has_past = false, has_rate = false, has_ahead = false;
	TfwSchrefPredict arg = { 0 };

	if ((ret = tfw_cfg_handle_ratio_predyn_opts(ce, arg_flags)))
		return ret;

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "past")) {
			if (has_past) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &arg.past)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_past = true;
		} else if (!strcasecmp(key, "rate")) {
			if (has_rate) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &arg.rate)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_rate = true;
		} else if (!strcasecmp(key, "ahead")) {
			if (has_ahead) {
				TFW_ERR_NL("Duplicate argument: '%s'\n", key);
				return -EINVAL;
			}
			if (tfw_cfg_parse_int(val, &arg.ahead)) {
				TFW_ERR_NL("Invalid value: '%s'\n", val);
				return -EINVAL;
			}
			has_ahead = true;
		}
	}
	if (!has_past) {
		arg.past = TFW_CFG_PAST_DEF;
	} else if ((arg.past < 1) || (arg.past > TFW_CFG_PAST_MAX)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'past=%d'\n",
			   TFW_CFG_PAST_MAX, arg.past);
		return -EINVAL;
	}
	if (!has_rate) {
		arg.rate = TFW_CFG_RATE_DEF;
	} else if ((arg.rate < 1) || (arg.rate > TFW_CFG_RATE_MAX)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'rate=%d'\n",
			   TFW_CFG_RATE_MAX, arg.rate);
		return -EINVAL;
	}
	if (!has_ahead) {
		arg.ahead = arg.past > 1 ? arg.past / 2 : 1;
	} else if ((arg.ahead < 1) || (arg.ahead > arg.past / 2)) {
		TFW_ERR_NL("Out of range of [1..%d]: 'ahead=%d'."
			   "Can't be greater than half of 'past=%d'.\n",
			   arg.past / 2, arg.ahead, arg.past);
		return -EINVAL;
	}

	return tfw_cfgop_sg_copy_sched_arg(scharg, &arg);
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
tfw_cfg_handle_ratio(TfwCfgEntry *ce, void *scharg, unsigned int *sched_flags)
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
		if ((ret = tfw_cfg_handle_ratio_predict(ce, scharg, &flags)))
			return ret;
	} else {
		TFW_ERR_NL("Unsupported argument: '%s'\n", ce->vals[1]);
		return -EINVAL;
	}

	*sched_flags = flags;
	return 0;
}

/*
 * Common code to handle 'sched' directive.
 */
static int
tfw_cfgop_sched(TfwCfgSpec *cs, TfwCfgEntry *ce, TfwScheduler **sched_val,
		void **scharg, unsigned int *sched_flags)
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
		if (tfw_cfg_handle_ratio(ce, scharg, sched_flags))
			return -EINVAL;

	*sched_val = sched;

	return 0;
}

static int
tfw_cfgop_in_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (TFW_CFGOP_HAS_DFLT(ce, sched)) {
		tfw_cfg_sg->parsed_sg->sched = tfw_cfg_sg_def->parsed_sg->sched;
		tfw_cfg_sg->sched_flags = tfw_cfg_sg_def->sched_flags;
		tfw_cfgop_sg_copy_sched_arg(&tfw_cfg_sg->sched_arg,
					    tfw_cfg_sg_def->sched_arg);
		return 0;
	}
	return tfw_cfgop_sched(cs, ce, &tfw_cfg_sg->parsed_sg->sched,
				       &tfw_cfg_sg->sched_arg,
				       &tfw_cfg_sg->sched_flags);
}

static int
tfw_cfgop_out_sched(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_cfg_is_set.sched = 1;
	return tfw_cfgop_sched(cs, ce, &tfw_cfg_sg_def->parsed_sg->sched,
				       &tfw_cfg_sg_def->sched_arg,
				       &tfw_cfg_sg_def->sched_flags);
}

static void
tfw_cfgop_cleanup_srv_cfg(TfwCfgSrvGroup *sg_cfg, bool reconf_failed)
{
	if (sg_cfg->orig_sg || reconf_failed) {
		__tfw_sg_for_each_srv(sg_cfg->parsed_sg,
				      tfw_sock_srv_del_conns);
		tfw_sg_release(sg_cfg->parsed_sg);
	}

	if (sg_cfg->sched_arg)
		kfree(sg_cfg->sched_arg);
	list_del_init(&sg_cfg->list);

	kmem_cache_free(tfw_sg_cfg_cache, sg_cfg);
}

static void
tfw_cfgop_cleanup_srv_cfgs(bool reconf_failed)
{
	TfwCfgSrvGroup *sg_cfg, *tmp;

	list_for_each_entry_safe(sg_cfg, tmp, &sg_cfg_list, list)
		tfw_cfgop_cleanup_srv_cfg(sg_cfg, reconf_failed);
	INIT_LIST_HEAD(&sg_cfg_list);

	tfw_cfg_sg = tfw_cfg_sg_def = NULL;
}

/**
 * Clean everything produced during parsing "server" and "srv_group" entries.
 *
 * Live reconfiguration may fail: on parsing stage
 */
static void
tfw_cfgop_cleanup_srv_groups(TfwCfgSpec *cs)
{
	TfwSrvGroup *sg, *sg_tmp;
	TfwServer *srv, *srv_tmp;

	/*
	 * Configuration failed before tfw_sock_srv_start():
	 * - must clear server.c:sg_list_reconfig
	 * - must delete all sg_cfg_list->parsed_sg
	 *
	 * Configuration failed during or after tfw_sock_srv_start:
	 * - must clear server.c:sg_list_reconfig if not cleared yet
	 * - must delete all sg_cfg_list->parsed_sg
	 * - must delete all active servers and groups (server.c:sg_list).
	 */
	tfw_sg_drop_reconfig();
	tfw_cfgop_cleanup_srv_cfgs(true);

	if (tfw_runstate_is_reconfig()) {
		/* tfw_sock_srv_start() was not called. */
		return;
	}

	/* Release active configuration. */
	tfw_sock_srv_delete_all_conns();
	tfw_sg_release_all();

	TFW_DBG2("clean orphaned servers\n");
	/* Release structures from previous reconfigs. */
	list_for_each_entry_safe(srv, srv_tmp, &orphan_srvs, list) {
		tfw_sock_srv_del_conns(srv);
		list_del_init(&srv->list);
		tfw_server_destroy(srv);
	}
	TFW_DBG2("clean orphaned groups\n");
	list_for_each_entry_safe(sg, sg_tmp, &orphan_sgs, list) {
		__tfw_sg_for_each_srv(sg, tfw_sock_srv_del_conns);
		list_del_init(&sg->list);
		tfw_sg_release(sg);
	}
	INIT_LIST_HEAD(&orphan_sgs);
}


static int
tfw_sock_srv_cfgstart(void)
{
	int r;

	INIT_LIST_HEAD(&sg_cfg_list);
	if ((r = tfw_cfgop_new_sg_cfg_default()))
		return r;

	tfw_cfg_sg = tfw_cfg_sg_def;

	return 0;
}

static int
tfw_sock_srv_cfgend(void)
{
	TfwSrvGroup *sg;
	int r;
	/*
	 * The group "default" is created implicitly, and only when
	 * a server outside of any group is found in the configuration.
	 */
	if (!tfw_cfg_sg_def->parsed_sg->srv_n) {
		tfw_cfgop_cleanup_srv_cfg(tfw_cfg_sg_def, true);
		tfw_cfg_sg_def = NULL;
		return 0;
	}

	if ((r = tfw_cfgop_setup_srv_group(tfw_cfg_sg_def)))
		return r;

	sg = tfw_cfg_sg_def->orig_sg ? : tfw_cfg_sg_def->parsed_sg;
	if (tfw_sg_add_reconfig(sg)) {
		TFW_ERR_NL("Unable to register implicit 'default' group\n");
		return -EINVAL;
	}

	return 0;
}

static int
tfw_cfgop_start_srv(TfwServer *srv)
{
	int r;

	TFW_DBG_ADDR("start server", &srv->addr);

	if ((r = tfw_sock_srv_add_conns(srv)))
		return r;
	if ((r = tfw_apm_add_srv(srv)))
		return r;
	if ((r = tfw_sock_srv_connect_srv(srv)))
		return r;

	return 0;
}

static int
tfw_cfgop_update_srv(TfwServer *orig_srv, TfwCfgSrvGroup *sg_cfg)
{
	TfwServer *srv;
	int r;

	if (!(srv = __cfgop_server_lookup(&sg_cfg->parsed_sg->srv_list,
					  &orig_srv->addr)))
		return -EINVAL;

	TFW_DBG_ADDR("Update server options", &srv->addr);

	orig_srv->weight = srv->weight;

	if (orig_srv->conn_n < srv->conn_n) {
		if ((r = tfw_sock_srv_append_conns_n(
			     srv, srv->conn_n - orig_srv->conn_n)))
			return r;

		orig_srv->conn_n = srv->conn_n;
	}
	else if (orig_srv->conn_n > srv->conn_n)
	{
		/*
		 * TODO: shrink connections: disconnect connection and remove
		 * it from server's conn_list
		 */
	}

	return 0;
}

static int
tfw_cfgop_update_sg_srv_list(TfwCfgSrvGroup *sg_cfg)
{
	TfwServer *srv, *tmp;
	TfwSrvGroup *sg = sg_cfg->orig_sg;
	int r = 0;

	TFW_DBG2("Update server list for group '%s'\n", sg_cfg->orig_sg->name);

	list_for_each_entry_safe(srv, tmp, &sg->srv_list, list) {
		/* Server was not found in new configuration. */
		if (!(srv->flags & TFW_CFG_M_ACTION)) {
			tfw_sg_del_srv(sg, srv);
			list_add(&srv->list, &orphan_srvs);
			if ((r = tfw_sock_srv_disconnect_srv(srv)))
				return r;
		}
		if (srv->flags & TFW_CFG_F_MOD)
			if ((r = tfw_cfgop_update_srv(srv, sg_cfg)))
				goto err;
		/* Server is unchanged: srv->flags & TFW_CFG_F_KEEP. */
		srv->flags &= ~TFW_CFG_M_ACTION;
	}

	/* Add new servers. */
	list_for_each_entry_safe(srv, tmp, &sg_cfg->parsed_sg->srv_list, list) {
		if (!(srv->flags & TFW_CFG_F_ADD))
			continue;

		tfw_sg_del_srv(sg_cfg->parsed_sg, srv);
		tfw_sg_add_srv(sg, srv);
		if ((r = tfw_cfgop_start_srv(srv)))
			goto err;
		srv->flags &= ~TFW_CFG_M_ACTION;
	}
err:
	return r;
}

/**
 * Set up a scheduler and add the server group to the scheduler.
 * Must be called only after the server group is set up with all
 * servers (and all connections) that are in it.
 */
static int
tfw_cfgop_sg_start_sched(TfwCfgSrvGroup *sg_cfg, TfwSrvGroup *sg)
{
	if (tfw_sg_start_sched(sg, sg_cfg->parsed_sg->sched,
			       sg_cfg->sched_arg)) {
		TFW_ERR_NL("Unable to add srv_group '%s' to scheduler '%s'\n",
			   sg->name, sg_cfg->parsed_sg->sched->name);
		return -EINVAL;
	}
	return 0;
}

static int
tfw_cfgop_update_sg_cfg(TfwCfgSrvGroup *sg_cfg)
{
	int r;

	TFW_DBG2("Update group '%s'\n", sg_cfg->orig_sg->name);

	tfw_cfgop_sg_copy_opts(sg_cfg->orig_sg, sg_cfg->parsed_sg);

	if (!(sg_cfg->reconf_flags &
	      (TFW_CFG_MDF_SG_SRV | TFW_CFG_MDF_SG_SCHED)))
		return 0;

	/*
	 * Schedulers walk over list of servers, so stop scheduler before
	 * updating server list.
	 */
	tfw_sg_stop_sched(sg_cfg->orig_sg);

	if (sg_cfg->reconf_flags & TFW_CFG_MDF_SG_SRV)
		if ((r = tfw_cfgop_update_sg_srv_list(sg_cfg)))
			return r;

	return tfw_cfgop_sg_start_sched(sg_cfg, sg_cfg->orig_sg);
}

static int
tfw_cfgop_start_sg_cfg(TfwCfgSrvGroup *sg_cfg)
{
	int r;
	TfwSrvGroup *sg = sg_cfg->parsed_sg;

	if (sg_cfg->orig_sg)
		return tfw_cfgop_update_sg_cfg(sg_cfg);

	TFW_DBG2("Setup new group '%s' to use after reconfiguration\n",
		 sg->name);
	if ((r = __tfw_sg_for_each_srv(sg, tfw_cfgop_start_srv)))
		return r;

	return tfw_cfgop_sg_start_sched(sg_cfg, sg);
}

static int
tfw_sock_srv_start(void)
{
	int r;
	TfwCfgSrvGroup *sg_cfg;
	TfwSrvGroup *sg, *tmp_sg;

	list_for_each_entry(sg_cfg, &sg_cfg_list, list)
		if ((r = tfw_cfgop_start_sg_cfg(sg_cfg)))
			return r;

	tfw_sg_apply_reconfig(&orphan_sgs);

	tfw_cfgop_cleanup_srv_cfgs(false);
	/*
	 * Disconnect unused server groups, orphaned servers are disconnected
	 * in tfw_cfgop_update_sg_srv_list()
	*/
	list_for_each_entry_safe(sg, tmp_sg, &orphan_sgs, list) {
		tfw_sg_stop_sched(sg);
		if ((r = __tfw_sg_for_each_srv(sg,
					       tfw_sock_srv_disconnect_srv)))
			return r;
	}

	return 0;
}

static void
tfw_sock_srv_stop(void)
{
	/* tfw_sock_srv_start() may failed just in the middle. */
	tfw_sg_for_each_srv_reconfig(tfw_sock_srv_disconnect_srv);
	tfw_sg_for_each_srv(tfw_sock_srv_disconnect_srv);
}

static TfwCfgSpec tfw_srv_group_specs[] = {
	{
		.name = "server",
		.deflt = NULL,
		.handler = tfw_cfgop_in_server,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "sched",
		.deflt = "ratio static",
		.handler = tfw_cfgop_in_sched,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_queue_size",
		.deflt = "1000",
		.handler = tfw_cfgop_in_queue_size,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_forward_timeout",
		.deflt = "60",
		.handler = tfw_cfgop_in_fwd_timeout,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_forward_retries",
		.deflt = "5",
		.handler = tfw_cfgop_in_fwd_retries,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_retry_nonidempotent",
		.deflt = TFW_CFG_DFLT_VAL,
		.handler = tfw_cfgop_in_retry_nip,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_connect_retries",
		.deflt = "10",
		.handler = tfw_cfgop_in_conn_retries,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "sticky_sessions",
		.deflt = TFW_CFG_DFLT_VAL,
		.handler = tfw_cfgop_in_sticky_sess,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfwCfgSpec tfw_sock_srv_specs[] = {
	{
		.name = "server",
		.deflt = NULL,
		.handler = tfw_cfgop_out_server,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{
		.name = "sched",
		.deflt = "ratio static",
		.handler = tfw_cfgop_out_sched,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_queue_size",
		.deflt = "1000",
		.handler = tfw_cfgop_out_queue_size,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_forward_timeout",
		.deflt = "60",
		.handler = tfw_cfgop_out_fwd_timeout,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_forward_retries",
		.deflt = "5",
		.handler = tfw_cfgop_out_fwd_retries,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_retry_non_idempotent",
		.deflt = TFW_CFG_DFLT_VAL,
		.handler = tfw_cfgop_out_retry_nip,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "server_connect_retries",
		.deflt = "10",
		.handler = tfw_cfgop_out_conn_retries,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.spec_ext = &(TfwCfgSpecInt) {
			.range = { 0, INT_MAX },
		},
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "sticky_sessions",
		.deflt = TFW_CFG_DFLT_VAL,
		.handler = tfw_cfgop_out_sticky_sess,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.allow_none = true,
		.allow_repeat = false,
		.allow_reconfig = true,
	},
	{
		.name = "srv_group",
		.deflt = NULL,
		.handler = tfw_cfg_handle_children,
		.cleanup = tfw_cfgop_cleanup_srv_groups,
		.dest = tfw_srv_group_specs,
		.spec_ext = &(TfwCfgSpecChild ) {
			.begin_hook = tfw_cfgop_begin_srv_group,
			.finish_hook = tfw_cfgop_finish_srv_group
		},
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

TfwMod tfw_sock_srv_mod = {
	.name		= "sock_srv",
	.cfgstart	= tfw_sock_srv_cfgstart,
	.cfgend		= tfw_sock_srv_cfgend,
	.start		= tfw_sock_srv_start,
	.stop		= tfw_sock_srv_stop,
	.specs		= tfw_sock_srv_specs,
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
	if (!tfw_srv_conn_cache)
		return -ENOMEM;

	tfw_sg_cfg_cache = kmem_cache_create("tfw_sg_cfg_cache",
					     sizeof(TfwCfgSrvGroup), 0, 0, NULL);
	if (!tfw_sg_cfg_cache)
		return -ENOMEM;

	tfw_mod_register(&tfw_sock_srv_mod);

	return 0;
}

void
tfw_sock_srv_exit(void)
{
	tfw_mod_unregister(&tfw_sock_srv_mod);
	kmem_cache_destroy(tfw_srv_conn_cache);
	kmem_cache_destroy(tfw_sg_cfg_cache);
}
