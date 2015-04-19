/**
 *		Tempesta FW
 *
 * TCP/IP stack hooks and socket routines to handle server traffic.
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

#define TFW_SCONND_THREAD_NAME "tfw_sconnd"
#define TFW_SCONND_RETRY_INTERVAL 1000

typedef struct {
	struct list_head list;
	TfwAddr addr;
	struct sock *sk;  /* NULL when not connected. */
} TfwServerSockEntry;

/* The list of all known servers (either connected or disconnected). */
struct list_head server_socks = LIST_HEAD_INIT(server_socks);

#define FOR_EACH_SOCK(entry) \
	list_for_each_entry(entry, &server_socks, list)

#define FOR_EACH_SOCK_SAFE(entry, tmp) \
	list_for_each_entry_safe(entry, tmp, &server_socks, list)

SsHooks ss_server_hooks;

/*
 * To avoid sleeping in connect() call, a connect is split in two parts.
 * First, a socket is allocated, and a connect is initiated on the socket
 * in a non-blocking mode. Control is returned to the caller immediately.
 * However, that doesn't mean the connection has been established to the
 * remote server. The connect will be completed a bit later, after 3WHS.
 * That's when the second part of connect is triggered as the connection
 * is established successfully. At that time we know that we're connected
 * to the remote server. That is when we can start using the socket and
 * the connection in Tempesta.
 */
/*
 * Initiate a connect to back-end server.
 *
 * @sock  The output socket to be allocated and connected.
 *        The pointer is set to the allocated socket when connect
 *        is initiated successfully, and NULLed when that fails.
 *
 * Return: an error code, or zero on success.
 */
static int
tfw_server_connect(struct sock **server_sk, const TfwAddr *addr)
{
	static SsProto dummy_proto = { 0 };

	struct sock *sk;
	struct sockaddr sa = addr->sa;
	sa_family_t family = addr->sa.sa_family;
	size_t sza = tfw_addr_sa_len(addr);
	int r;

	/*
	 * XXX Just for the proof of concept.
	 * This works ONLY when there's just one backend server.
	 * We need one 'struct socket' holder per connection
	 * that lives for the whole duration of the connection.
	 */
	r = ss_sock_create(family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r != 0) {
		TFW_ERR("Unable to create sk socket (%d)\n", r);
		return r;
	}

	/*
	 * TODO: Specify an actual protocol instead of static HTTP.
	 * That would also require creating multiple dummy_proto{}.
	 */
	ss_set_proto(sk, &dummy_proto, TFW_FSM_HTTP, &ss_server_hooks);
	ss_set_callbacks(sk);
	TFW_DBG("Created server socket sk=%p\n", sk);

	r = ss_connect(sk, &sa, sza, 0);
	if (r) {
		TFW_DBG("Connect error on server socket sk=%p, r=%d\n", sk, r);
		ss_release(sk);
		return r;
	}

	*server_sk = sk;

	return 0;
}

/*
 * Complete a connect to back-end server
 *
 * This is the second part of the connect process. This function
 * is called asynchronously when the connection gets established.
 * The purpose is to set up whatever is necessary in Tempesta on
 * an established connection to a back-end server.
 */
static int
tfw_server_connect_complete(struct sock *sk)
{
	TfwServer *srv;
	TfwConnection *conn;

	conn = tfw_connection_new(sk, Conn_Srv, tfw_destroy_server);
	if (!conn) {
		TFW_ERR("Cannot create new server connection\n");
		goto err_conn_create;
	}

	/*
	 * TODO only one server connection is established now.
	 * Create N connections to each server for redundancy,
	 * so we shuldn't allocate a new server for each connection.
	 */
	srv = tfw_create_server(sk, conn);
	if (!srv) {
		TfwAddr addr;
		int len = sizeof(addr);
		char buf[TFW_ADDR_STR_BUF_SIZE];

		memset(&addr, 0, len);
		ss_getpeername(sk, &addr.sa, &len);
		tfw_addr_ntop(&addr, buf, sizeof(buf));
		TFW_ERR("Can't create server descriptor for %s\n", buf);
		goto err_sock_destroy;
	}
	TFW_DBG("Connected server socket sk=%p\n", sk);

	return 0;

err_sock_destroy:
	tfw_destroy_server(sk);
err_conn_create:
	ss_release(sk);
	return -1;
}

static int
tfw_server_connection_close(struct sock *sk)
{
	TfwConnection *conn = sk->sk_user_data;

	TFW_DBG("Close server socket %p, conn=%p\n", sk, conn);
	tfw_connection_close(sk);

	return 0;
}

/**
 * Connect not yet connected server sockets.
 *
 * Return: true if all sockets are connected, false otherwise.
 */
static bool
connect_server_socks(void)
{
	int ret;
	TfwServerSockEntry *entry;
	bool all_socks_connected = true;
	
	FOR_EACH_SOCK(entry) {
		if (!entry->sk) {
			ret = tfw_server_connect(&entry->sk, &entry->addr);

			if (!ret) {
				TFW_LOG_ADDR("Connected to server",
					     &entry->addr);
			} else {
				all_socks_connected = false;
				/* We should leave NULL if not connected. */
				BUG_ON(entry->sk);
			}
		}

	}

	return all_socks_connected;
}

static void
release_server_socks(void)
{
	TfwServerSockEntry *entry;

	FOR_EACH_SOCK(entry) {
		if (entry->sk)
			ss_release(entry->sk);
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
 */
static int
tfw_sconnd(void *data)
{

	LIST_HEAD(socks_list);
	bool all_socks_connected = false;

	set_freezable();
	
	do {
		long timeout = all_socks_connected
			       ? MAX_SCHEDULE_TIMEOUT
			       : TFW_SCONND_RETRY_INTERVAL;

		wait_event_freezable_timeout(tfw_sconnd_wq,
					     kthread_should_stop(),
		                             timeout);

		if (!all_socks_connected)
			all_socks_connected = connect_server_socks();
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
	int r;
	const char *raw_addr;
	TfwAddr parsed_addr;
	TfwServerSockEntry *be;

	r = tfw_cfg_check_single_val(ce);
	if (r)
		return -EINVAL;

	raw_addr = ce->vals[0];
	r = tfw_addr_pton(raw_addr, &parsed_addr);
	if (r)
		return -EINVAL;

	be = kzalloc(sizeof(*be), GFP_KERNEL);
	be->addr = parsed_addr;
	list_add_tail(&be->list, &server_socks);

	return 0;
}

static void
release_server_entries(TfwCfgSpec *cs)
{
	TfwServerSockEntry *entry, *tmp;

	FOR_EACH_SOCK_SAFE(entry, tmp) {
		kfree(entry);
	}

	INIT_LIST_HEAD(&server_socks);
}

SsHooks ss_server_hooks = {
	.connection_new		= tfw_server_connect_complete,
	.connection_drop	= tfw_server_connection_close,
	.connection_close	= tfw_server_connection_close,
	.connection_recv	= tfw_connection_recv,
	.put_skb_to_msg		= tfw_connection_put_skb_to_msg,
	.postpone_skb		= tfw_connection_postpone_skb,
};

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
