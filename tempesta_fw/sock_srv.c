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
 * -- [connection pool, reverse proxy only] establish N connections with each server
 *    for better parallelization on the server side.
 * -- limit number of persistent connections to be able to work as forward
 *    (transparent) proxy (probably we need to switch on/off functionality for
 *    connections pool)
 * -- FIXME synchronize with socket operations.
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

/* The thread that connects to servers in background. */
static struct task_struct *tfw_sconnd_task = NULL;
DECLARE_WAIT_QUEUE_HEAD(tfw_sconnd_wq);

#define TFW_SCONND_THREAD_NAME		"tfw_sconnd"
#define TFW_SCONND_RETRY_INTERVAL	1000

// FIXME #87: this is temporal strut, abandon the stuff below.
typedef struct {
	struct list_head	list;
	struct socket		*sock;  /* NULL when not connected. */
} TfwServerSockEntry;

static LIST_HEAD(server_socks);

#define FOR_EACH_SOCK(entry) \
	list_for_each_entry(entry, &server_socks, list)

#define FOR_EACH_SOCK_SAFE(entry, tmp) \
	list_for_each_entry_safe(entry, tmp, &server_socks, list)

static struct sock *
tfw_server_connect(TfwAddr *addr)
{
	TfwServerSockEntry *se;
	struct sockaddr sa = addr->sa;
	sa_family_t family = addr->sa.sa_family;
	size_t sza = tfw_addr_sa_len(addr);
	int r;

	se = kzalloc(sizeof(*se), GFP_ATOMIC);
	if (!se) {
		TFW_ERR("Cannot allocate socket entry\n");
		return NULL;
	}
	INIT_LIST_HEAD(&se->list);

	r = sock_create_kern(family, SOCK_STREAM, IPPROTO_TCP, &se->sock);
	if (r) {
		TFW_ERR("Can't create back-end connections socket (%d)\n", r);
		goto err_se_free;
	}

	r = kernel_connect(se->sock, &sa, sza, 0);
	if (r)
		goto err_connect;

	ss_set_callbacks(se->sock->sk);

	list_add(&se->list, &server_socks);

	return se->sock->sk;

err_connect:
	sock_release(se->sock);
err_se_free:
	kfree(se);
	return NULL;
}

static int
tfw_server_conn_failover(TfwServer *srv)
{
	TfwConnection *conn;

	BUG_ON(list_empty(&srv->conn_list));

	conn = list_first_entry(&srv->conn_list, TfwConnection, list);

	/* FIXME #85 who sets @sock to NULL on connection failure? */
	if (likely(conn->sock))
		return 0;

	conn->sock = tfw_server_connect(&srv->addr);
	if (!conn->sock)
		return -EINVAL;

	return 0;
}

static void
release_server_socks(void)
{
	TfwServerSockEntry *entry;

	FOR_EACH_SOCK(entry) {
		if (entry->sock)
			sock_release(entry->sock);
	}
}

/**
 * tfw_sconnd() - The main loop of the tfw_sconnd thread.
 *
 * The thread establishes connections to servers in the background.
 * Internally it maintains a list of connected/disconnected servers.
 * When there are not yet connected servers in the list, it wakes up
 * periodically and tries to connect to them.
 *
 * Note: If a server connection is lost for some reason, the thread doesn't
 * restore it automatically.
 *
 * TODO (#83) replace kernel_connect() in tfw_server_connect() and call it
 * on TCP events, so the thread should be abandoned.
 * In fact, the approach with the thread is simply wron and inconsistent
 * with Syncronous Sockets technology, it won't work properly in context of
 * #76 (massive back-end servers farm).
 */
static int
tfw_sconnd(void *data)
{
	int r;
	LIST_HEAD(socks_list);

	set_freezable();
	
	do {
		wait_event_freezable_timeout(tfw_sconnd_wq,
					     kthread_should_stop(),
		                             MAX_SCHEDULE_TIMEOUT);

		r = tfw_sg_for_each_srv(tfw_server_conn_failover);
		if (r)
			TFW_WARN("Cannot failover server connection(s)\n");
	} while (!kthread_should_stop());

	TFW_LOG("%s: stopping\n", TFW_SCONND_THREAD_NAME);
	release_server_socks();

	return 0;
}

static int
start_sconnd(void)
{
	int ret = 0;

	BUG_ON(tfw_sconnd_task);
	TFW_DBG("Starting thread: %s\n", TFW_SCONND_THREAD_NAME);

	tfw_sconnd_task = kthread_run(tfw_sconnd, NULL, TFW_SCONND_THREAD_NAME);

	if (IS_ERR_OR_NULL(tfw_sconnd_task)) {
		TFW_ERR("Can't create thread: %s (%ld)",
			TFW_SCONND_THREAD_NAME, PTR_ERR(tfw_sconnd_task));
		ret = PTR_ERR(tfw_sconnd_task);
		tfw_sconnd_task = NULL;
	}

	return ret;
}

static void
stop_sconnd(void)
{
	BUG_ON(!tfw_sconnd_task);
	TFW_DBG("Stopping thread: %s\n", TFW_SCONND_THREAD_NAME);

	kthread_stop(tfw_sconnd_task);
	tfw_sconnd_task = NULL;
}

static int
add_server_entry(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	const char *raw_addr;
	TfwSrvGroup *sg;
	TfwServer *srv;
	TfwConnection *conn;
	struct sock *sk;
	TfwAddr addr;

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	raw_addr = ce->vals[0];
	if (tfw_addr_pton(raw_addr, &addr))
		return -EINVAL;

	sk = tfw_server_connect(&addr);
	if (!sk)
		return -ENOTCONN;

	/*
	 * Create a server group for each server now.
	 * FIXME #85 Allocate server groups in proper way.
	 */
	sg = tfw_sg_new(GFP_KERNEL);
	if (!sg)
		goto err_sg;

	conn = tfw_connection_new(sk, Conn_HttpSrv, NULL);
	if (!conn) {
		TFW_ERR("Cannot create new server connection\n");
		goto err_conn_create;
	}

	/*
	 * FIXME #85,#5
	 * Only one server connection is established now.
	 * Create N connections to each server for redundancy,
	 * so we shuldn't allocate a new server for each connection.
	 */
	srv = tfw_create_server(conn, &addr);
	if (!srv) {
		char buf[TFW_ADDR_STR_BUF_SIZE];
		tfw_addr_ntop(&addr, buf, sizeof(buf));
		TFW_ERR("Can't create server descriptor for %s\n", buf);
		goto err_srv;
	}

	tfw_sg_add(sg, srv);

	return 0;

err_srv:
	/*
	 * TODO check that tfw_connection_close() is called on
	 * socket destructor.
	 */
err_conn_create:
	tfw_sg_free(sg);
err_sg:
	ss_close(sk);
	/* FIXME #87: TfwServerSockEntry memory leak. */
	return -ENOMEM;
}

static void
release_server_entries(TfwCfgSpec *cs)
{
	/* FIXME #85: abandon the stuff. */
	TfwServerSockEntry *entry, *tmp;
	FOR_EACH_SOCK_SAFE(entry, tmp) {
		kfree(entry);
	}
	INIT_LIST_HEAD(&server_socks);

	tfw_sg_release_all();
}

// FIXME #85 rework the configuration to create server groups here
TfwCfgMod tfw_sock_server_cfg_mod = {
	.name = "sock_backend",
	.start = start_sconnd,
	.stop = stop_sconnd,
	.specs = (TfwCfgSpec[]) {
		{
			"backend", "127.0.0.1:8080",
			add_server_entry,
			.allow_repeat = true,
			.cleanup = release_server_entries
		},
		{}
	}
};
