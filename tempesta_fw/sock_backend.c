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
#include "lib.h"
#include "log.h"
#include "server.h"


/* The thread that connects to backends in background. */
static struct task_struct *tfw_bconnd_task = NULL;

#define TFW_BCONND_THREAD_NAME "tfw_bconnd"
#define TFW_BCONND_RETRY_INTERVAL 1000

/*
 * This waitqueue is used to notify the thread that the configuration
 * has changed and therefore it should refresh the list of backends.
 */
DECLARE_WAIT_QUEUE_HEAD(tfw_bconnd_wq);
bool tfw_bconnd_should_refresh = false;

/* The list in which the thread maintains the sockets internally. */
typedef struct {
	struct list_head list;
	TfwAddr addr;
	struct socket *socket; /* The ptr is NULL when not connected. */
} TfwBackendSockDesc;


/**
 * Connect to the back-end server.
 *
 * @sock  The output socket to be allocated and connected.
 *        The pointer is set to allocated socket when connected successfully
 *        and NULLed when connection is failed.
 * @addr  A struct sockaddr that describes an address to connect to.
 *
 * Return: an error code, zero on success.
 */
static int
tfw_backend_connect(struct socket **sock, void *addr)
{
	static struct {
		SsProto	_placeholder;
		int	type;
	} dummy_proto = {
		.type = TFW_FSM_HTTP,
	};

	TfwServer *srv;
	struct sock *sk;
	unsigned short family = *(unsigned short *)addr;
	unsigned short sza = family == AF_INET
			     ? sizeof(struct sockaddr_in)
			     : sizeof(struct sockaddr_in6);
	int r;

	r = sock_create_kern(family, SOCK_STREAM, IPPROTO_TCP, sock);
	if (r) {
		TFW_ERR("Can't create back-end connections socket (%d)\n", r);
		return r;
	}

	r = kernel_connect(*sock, (struct sockaddr *)addr, sza, 0);
	if (r) {
		goto err_sock_destroy;
	}
	sk = (*sock)->sk;

	ss_set_callbacks(sk);

	/*
	 * TODO only one server connection is established now.
	 * Create N connections to each server for redundancy,
	 * so we shuldn't allocate a new server for each connection.
	 */
	srv = tfw_create_server(sk);
	if (!srv) {
		char buf[MAX_ADDR_LEN];
		tfw_inet_ntop(addr, buf);
		TFW_ERR("Can't create server descriptor for %s\n", buf);
		goto err_sock_destroy;
	}

	sk->sk_user_data = &dummy_proto;
	r = tfw_connection_new(sk, Conn_Srv, srv, tfw_destroy_server);
	if (r)
		goto err_conn_create;

	return 0;
err_conn_create:
	tfw_destroy_server(sk);
err_sock_destroy:
	sock_release(*sock);
	*sock = NULL;
	return r;
}

static bool
addr_is_in_list(TfwAddr *addr, struct list_head *list)
{
	TfwBackendSockDesc *be;
	list_for_each_entry(be, list, list) {
		if (tfw_addr_eq(addr, &be->addr))
			return true;
	}

	return false;
}

static bool
addr_is_in_cfg(TfwAddr *addr, TfwAddrCfg *cfg)
{
	int i;
	for (i = 0; i < cfg->count; ++i) {
		if (tfw_addr_eq(addr, &cfg->addr[i]))
			return true;
	}
	
	return false;
}

/**
 * Update given socks_list from global configuration.
 *
 * @sock_list  The list of TfwBackendSockDesc to be updated.
 * 
 * The function populates the socks_list by new backend addresses from tfw_cfg
 * with preserving already existing connections in the sock_list.
 * Old backends (those who not exist in the tfw_cfg) are removed from the list
 * and their sockets are released automatically.
 * For new backends the function doesn't allocate and connect sockets, you need
 * to iterate over the list and see which sockets are NULL and create them.
 */
static void
get_new_socks_from_cfg(struct list_head *socks_list)
{
	int i;
	size_t count;
	void *addr;
	TfwAddrCfg *cfg;
	TfwBackendSockDesc *be, *be_tmp;

	down_read(&tfw_cfg.mtx);

	cfg = tfw_cfg.backends;
	count = tfw_cfg.backends->count;

	/* Iterate over the old backends list and release those who not present
	 * in the new backends list. After this step the socks_list should
	 * contain an intersection between socks_list and tfw_cfg.backends. */
	list_for_each_entry_safe(be, be_tmp, socks_list, list) {
		addr = &be->addr;
		if (!addr_is_in_cfg(addr, cfg)) {
			TFW_DBG_ADDR("Removing old backend", addr);
			if (be->socket)
				sock_release(be->socket);
			list_del(&be->list);
			kfree(be);
		}
	}

	/* Iterate over the new configuration and add to the socks_list only
	 * new backends (thus preserving the already existing connections). */
	for (i = 0; i < count; ++i) {
		addr = &cfg->addr[i];
		if (!addr_is_in_list(addr, socks_list)) {
			TFW_DBG_ADDR("Adding new backend", addr);
			be = kzalloc(sizeof(*be), GFP_KERNEL);
			if (!be) {
				TFW_ERR("Can't allocate memory\n");
				goto out;
			}
			memcpy(&be->addr, addr, sizeof(be->addr));
			list_add(&be->list, socks_list);
		}
	}

out:
	up_read(&tfw_cfg.mtx);
}

/**
 * Release all sockets and free all elemenits in a list.
 */
static void
delete_all_sockets(struct list_head *socks_list)
{
	TfwBackendSockDesc *be, *be_tmp;
	list_for_each_entry_safe(be, be_tmp, socks_list, list) {
		if (be->socket)
			sock_release(be->socket);
		list_del(&be->list);
		kfree(be);
	}
}

/**
 * Release dead sockets from the given list.
 */
static void
release_closed_socks(struct list_head *socks_list)
{
	TfwBackendSockDesc *be;
	list_for_each_entry(be, socks_list, list) {
		if (be->socket && be->socket->sk->sk_shutdown) {
			sock_release(be->socket);
			be->socket = NULL;
		}
	}
}

/**
 * Connect not yet connected sockets in a given list.
 *
 * Return: true if all sockets are connected, false otherwise.
 */
static bool
connect_backend_socks(struct list_head *socks_list)
{
	int ret;
	TfwBackendSockDesc *be;
	bool all_socks_connected = true;
	
	list_for_each_entry(be, socks_list, list) {
		if (!be->socket) {
			ret = tfw_backend_connect(&be->socket, &be->addr);

			if (!ret) {
				TFW_LOG_ADDR("Connected to backend", &be->addr);
			} else {
				all_socks_connected = false;
				/* We should leave NULL if not connected. */
				BUG_ON(be->socket);
			}
		}

	}

	return all_socks_connected;
}

static inline bool
bconnd_should_wakeup(void)
{
	return (tfw_bconnd_should_refresh || kthread_should_stop());
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
	/* The socks_list contains the actual list of all known backends (either
	 * connected or disconnected). The list is updated according to the 
	 * current configuration when the thread receives a 'refresh' event. */
	LIST_HEAD(socks_list);
	bool all_socks_connected = false;

	set_freezable();
	
	do {
		long timeout = all_socks_connected
			? MAX_SCHEDULE_TIMEOUT
			: TFW_BCONND_RETRY_INTERVAL;
		
		wait_event_freezable_timeout(tfw_bconnd_wq,
		                             bconnd_should_wakeup(),
		                             timeout);

		if (tfw_bconnd_should_refresh) {
			get_new_socks_from_cfg(&socks_list);
			release_closed_socks(&socks_list);
			all_socks_connected = false;
			tfw_bconnd_should_refresh = false;
		}

		if (!all_socks_connected) {
			all_socks_connected = connect_backend_socks(&socks_list);
		}
	} while (!kthread_should_stop());

	TFW_LOG("%s: stopping\n", TFW_BCONND_THREAD_NAME);
	delete_all_sockets(&socks_list);

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
	int ret = 0;
	
	BUG_ON(tfw_bconnd_task);
	TFW_DBG("Starting thread: %s\n", TFW_BCONND_THREAD_NAME);

	tfw_bconnd_task = kthread_run(tfw_bconnd, NULL, TFW_BCONND_THREAD_NAME);

	if (IS_ERR_OR_NULL(tfw_bconnd_task)) {
		TFW_ERR("Can't create thread: %s (%ld)", 
			TFW_BCONND_THREAD_NAME, PTR_ERR(tfw_bconnd_task));
		ret = PTR_ERR(tfw_bconnd_task);
		tfw_bconnd_task = NULL;
	} else {
		tfw_sock_backend_refresh_cfg();
	}

	return ret;
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

/**
 * Refresh backends configuration.
 *
 * This function should be called when you change the backend configuration
 * (the addresses list in tfw_cfg). It wakes up the tfw_bconnd thread that
 * fetches the new configuration and connects to new backends.
 */
void
tfw_sock_backend_refresh_cfg(void)
{
	tfw_bconnd_should_refresh = true;
	wake_up(&tfw_bconnd_wq);
}
