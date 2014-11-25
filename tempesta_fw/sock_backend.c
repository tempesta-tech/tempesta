/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle internal (back-end) traffic.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
 * -- [connection pool, reverse proxy only] establish N connections with each backend
 *    for better parallelization on the server side.
 * -- limit number of persistent connections to be able to work as forward
 *    (transparent) proxy (probably we need to switch on/off functionality for
 *    connections pool)
 * -- FIXME synchronize with socket operations.
 */
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include <net/inet_sock.h>

#include "tempesta.h"
#include "connection.h"
#include "addr.h"
#include "log.h"
#include "ptrset.h"
#include "sched.h"
#include "server.h"

typedef TFW_PTRSET_STRUCT(TfwServer, TFW_SCHED_MAX_SERVERS) TfwBeSrvSet;

TfwBeSrvSet backends;

/* The thread that connects to backend servers in background. */
static struct task_struct *tfw_bconnd_task = NULL;

#define TFW_BCONND_THREAD_NAME "tfw_bconnd"
#define TFW_BCONND_RETRY_INTERVAL 1000

/**
 * Number of parallel connections for each backend server.
 * TODO: make this this configurable via a config file.
 */
#define TFW_BACKEND_CONN_N 8

DECLARE_WAIT_QUEUE_HEAD(tfw_bconnd_wq);
static bool tfw_bconnd_should_reconnect;


static int
reconnect_in_background(struct sock *sk)
{
	tfw_bconnd_should_reconnect = true;
	wake_up(&tfw_bconnd_wq);

	return TFW_CONN_CLOSE_LEAVE;
}

static struct sock *
create_srv_connection(TfwServer *srv)
{
	static struct {
		SsProto	_placeholder;
		int	type;
	} dummy_proto = {
		.type = TFW_FSM_HTTP,
	};

	struct socket *sock;
	struct sock *sk;
	sa_family_t family;
	int r;

	family = srv->addr.sa.sa_family;

	r = sock_create_kern(family, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (r) {
		TFW_ERR("Can't create back-end connection socket\n");
		return NULL;
	}

	sk = sock->sk;
	sk->sk_user_data = &dummy_proto;
	ss_set_callbacks(sk);

	r = tfw_connection_new(sk, Conn_Srv, srv, reconnect_in_background);
	if (r) {
		TFW_ERR("Can't create TfwConnection\n");
		sock_release(sock);
		return NULL;
	}

	return sk;
}

static void
create_srv_connections(TfwServer *srv)
{
	struct sock *sk;
	int i, ret;

	for (i = 0; i < TFW_BACKEND_CONN_N; ++i) {
		sk = create_srv_connection(srv);
		BUG_ON(!sk);

		ret = tfw_ptrset_add(&srv->socks, sk);
		BUG_ON(ret);
	}
}

static void
create_backends_from_cfg(void)
{
	int i, addr_count;
	TfwAddrCfg *cfg;
	TfwServer *srv;

	down_read(&tfw_cfg.mtx);

	cfg = tfw_cfg.backends;
	addr_count = tfw_cfg.backends->count;

	for (i = 0; i < addr_count; ++i) {
		srv = tfw_server_alloc();
		BUG_ON(!srv);

		memcpy(&srv->addr, &cfg->addr[i], sizeof(srv->addr));
		create_srv_connections(srv);
	}

	up_read(&tfw_cfg.mtx);
}

static void
destroy_backends(void)
{
	TfwServer *srv;
	int srv_idx;
	tfw_ptrset_for_each(srv, srv_idx, &backends) {
		tfw_server_free(srv);
	}
	tfw_ptrset_purge(&backends);
}

static void
try_connect_all(TfwServer *srv)
{
	struct sock *sk;
	struct socket *sock;
	struct sockaddr *sa;
	int sa_len;
	int sk_idx;
	int r;
	socket_state state;

	tfw_ptrset_for_each(sk, sk_idx, &srv->socks) {
		sock = sk->sk_socket;
		state = sock->state;
		BUG_ON(state == SS_FREE);

		if (state == SS_UNCONNECTED) {
			sa = &srv->addr.sa;
			sa_len = tfw_addr_sa_len(&srv->addr);

			r = kernel_connect(sock, sa, sa_len, 0);
			if (r)
				TFW_WARN("Can't connect to back-end");
		}
	}
}

static bool
is_fully_connected(const TfwServer *srv)
{
	struct sock *sk;
	int sk_idx;

	tfw_ptrset_for_each(sk, sk_idx, &srv->socks) {
		if (sk->sk_socket->state != SS_CONNECTED)
			return false;
	}

	return true;
}

static bool
connect_all_backends(void)
{
	TfwServer *srv;
	int srv_idx;
	bool all_connected = true;

	tfw_ptrset_for_each(srv, srv_idx, &backends) {
		try_connect_all(srv);
		all_connected &= is_fully_connected(srv);
	}

	return all_connected;
}


/**
 * tfw_bconnd() - The main loop of the tfw_bconnd thread.
 *
 * The thread establishes connections to backends in the background.
 * Internally it maintains a list of connected/disconnected backends.
 * When there are not yet connected backends in the list, it wakes up
 * periodically and tries to connect to them.
 *
 * When all backends are connected (or there is no backends) the thread sleeps
 * waiting for a new configuration. When there is new configuration (the
 * tfw_sock_backend_refresh_cfg() is called), the thread wakes up and updates
 * the list of backends and begins connection attempts again.
 *
 * Note: If a backend connection is lost for some reason, the thread doesn't
 * restore it automatically until you call tfw_sock_backend_refresh_cfg().
 *
 */
static int
tfw_bconnd(void *data)
{
	bool all_connected = false;

	TFW_LOG("%s: starting\n", TFW_BCONND_THREAD_NAME);
	set_freezable();
	create_backends_from_cfg();
	
	do {
		long timeout = all_connected
			? MAX_SCHEDULE_TIMEOUT
			: TFW_BCONND_RETRY_INTERVAL;
		
		wait_event_freezable_timeout(tfw_bconnd_wq,
					      (kthread_should_stop() ||
					       tfw_bconnd_should_reconnect),
		                             timeout);

		if (tfw_bconnd_should_reconnect) {
			all_connected = false;
			tfw_bconnd_should_reconnect = false;
		}

		if (!all_connected) {
			all_connected = connect_all_backends();
		}
	} while (!kthread_should_stop());

	TFW_LOG("%s: stopping\n", TFW_BCONND_THREAD_NAME);
	destroy_backends();

	return 0;
}

/**
 * Initialize routines related to backend sockets.
 *
 * This function spawns the tfw_bconnd thread that connects to backends
 * in the background.
 */
int
tfw_sock_backend_init(void)
{
	int err;
	BUG_ON(tfw_bconnd_task);
	TFW_DBG("Starting thread: %s\n", TFW_BCONND_THREAD_NAME);

	tfw_bconnd_task = kthread_run(tfw_bconnd, NULL, TFW_BCONND_THREAD_NAME);

	if (!IS_ERR_OR_NULL(tfw_bconnd_task)) {
		return 0;
	}

	err = PTR_ERR(tfw_bconnd_task);
	tfw_bconnd_task = NULL;
	TFW_ERR("Can't create thread: %s (%d)", TFW_BCONND_THREAD_NAME, err);
	return err;
}

/**
 * Close connections to all backends and release all resources.
 * 
 * This function stops the tfw_bconnd thread that maintains the list of
 * opened sockets. Upon exit the thread should close all the sockets and
 * release allocated memory.
 */
void
tfw_sock_backend_shutdown(void)
{
	if (!tfw_bconnd_task)
		return;

	TFW_DBG("Stopping thread: %s\n", TFW_BCONND_THREAD_NAME);
	kthread_stop(tfw_bconnd_task);
	tfw_bconnd_task = NULL;
}
