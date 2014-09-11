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
 * -- FIXME synchronize it with socket operations.
 */
#include <linux/net.h>
#include <linux/kthread.h>
#include <net/inet_sock.h>

#include "tempesta.h"
#include "connection.h"
#include "lib.h"
#include "log.h"
#include "server.h"


typedef struct TfwBackendSockDesc {
	union TfwAddr addr;
	struct socket *socket;  /* the ptr is NULL when not connected */
} TfwBackendSockDesc;


/* the global list of all known backends (either connected or disconnected) */
static TfwBackendSockDesc *backend_socks = NULL;
static unsigned int backend_socks_n = 0;
DEFINE_MUTEX(backend_socks_mtx);


/* the thread that reopens connections to dead backends in background */
static struct task_struct *backend_reconnnect_thread = NULL;
const char *backend_reconnect_thread_name = "tempesta_breconnd";
const unsigned int backend_reconnect_interval_msec = 1000;
bool backend_reconnnect_thread_should_exit = false;


/* forward declarations of local functions */
static void start_backend_reconnect_thread(void);
static void stop_backend_reconnect_thread(void);
static int backend_reconnect_thread_main_loop(void *data);
static void open_new_backend_sockets(void);
static void reopen_dead_backend_sockets(void);
static void close_all_backend_sockets(void);
static bool all_backend_sockets_are_closed(void);
static void copy_new_backend_addresses_from_cfg(void);
static void free_backends_mem(void);
static int tfw_backend_connect(struct socket **sock, void *addr);


void
tfw_apply_new_backends_cfg(void)
{
	stop_backend_reconnect_thread();
	close_all_backend_sockets();
	copy_new_backend_addresses_from_cfg();
	open_new_backend_sockets();
	start_backend_reconnect_thread();
}


void
tfw_close_backend_sockets_and_free_memory(void)
{
	stop_backend_reconnect_thread();
	close_all_backend_sockets();
	free_backends_mem();
}



static void
start_backend_reconnect_thread(void)
{
	struct task_struct *t;
	
	BUG_ON(backend_reconnnect_thread);
	TFW_LOG("Starting thread: %s\n", backend_reconnect_thread_name);
	
	t = kthread_run(
		backend_reconnect_thread_main_loop,
		NULL,
		backend_reconnect_thread_name
	);
	
	if (IS_ERR_OR_NULL(t)) {
		TFW_LOG("Can't create thread: %s (%ld)",
			backend_reconnect_thread_name,
			PTR_ERR(t));
	} else {
		backend_reconnnect_thread = t;
	}
}


static void
stop_backend_reconnect_thread(void)
{
	if (backend_reconnnect_thread) {
		TFW_LOG("Stopping thread: %s\n", backend_reconnect_thread_name);
		kthread_stop(backend_reconnnect_thread);
		backend_reconnnect_thread = NULL;
	}
}


static int
backend_reconnect_thread_main_loop(void *data)
{
	while (true) {
		msleep_interruptible(backend_reconnect_interval_msec);
		reopen_dead_backend_sockets();
		
		if (kthread_should_stop()) {
			return 0;
		}
	}
}


static void
open_new_backend_sockets(void)
{
	size_t i;	
	mutex_lock(&backend_socks_mtx);
	
	for (i = 0; i < backend_socks_n; ++i) {
		TfwBackendSockDesc *backend = &backend_socks[i];

		if (!backend->socket) {
			int ret = 0;
			
			char addr_str[MAX_ADDR_LEN] = { 0 };
			tfw_inet_ntop(&backend->addr, addr_str);
			TFW_LOG("Connecting to backend: %s\n", addr_str);

			ret = tfw_backend_connect(&backend->socket, &backend->addr);
			if (!ret) {
				TFW_LOG("Connected to backend: %s\n", addr_str);
			} else {
				TFW_LOG("Can't connect to: %s (%d)\n", addr_str, ret);
			}

			/* we should leave NULL ptr when connection is failed */
			BUG_ON(ret && backend->socket);
		}
	}
	
	mutex_unlock(&backend_socks_mtx);
}


static void
reopen_dead_backend_sockets(void)
{
	size_t i;	
	mutex_lock(&backend_socks_mtx);
	
	for (i = 0; i < backend_socks_n; ++i) {
		TfwBackendSockDesc *backend = &backend_socks[i];
		
		/* TODO: reconnect already existing sockets */
		
		if (!backend->socket) {
			int ret = 0;

			ret = tfw_backend_connect(&backend->socket, &backend->addr);
			if (!ret) {
				char addr_str[MAX_ADDR_LEN] = { 0 };
				tfw_inet_ntop(&backend->addr, addr_str);
				TFW_LOG("Connected to backend: %s\n", addr_str);
			} else {
				BUG_ON(backend->socket);
			}
		}
	}
	
	mutex_unlock(&backend_socks_mtx);
}


void
close_all_backend_sockets(void)
{
	size_t i;
	mutex_lock(&backend_socks_mtx);
	
	for (i = 0; i < backend_socks_n; ++i) {
		TfwBackendSockDesc *backend = &backend_socks[i];
		struct socket *tmp_socket = backend->socket;
					
		if (tmp_socket) {
			char addr_str[MAX_ADDR_LEN] = { 0 };
			tfw_inet_ntop(&backend->addr, addr_str);
			TFW_LOG("Closing backend connection: %s\n", addr_str);
			
			backend->socket = NULL;
			sock_release(tmp_socket);
		}
	}
	
	mutex_unlock(&backend_socks_mtx);
}


static bool
all_backend_sockets_are_closed(void)
{
	size_t i;
	bool ret = true;
	
	mutex_lock(&backend_socks_mtx);
	
	for (i = 0; i < backend_socks_n; ++i) {
		if (backend_socks[i].socket) {
			ret = false;
		}
	}
	
	mutex_unlock(&backend_socks_mtx);
	
	return ret;
}


void
copy_new_backend_addresses_from_cfg(void)
{
	int i;
	size_t addr_count;
	TfwAddrCfg *backend_addrs;
	TfwBackendSockDesc *allocated_backends;
	
	BUG_ON(!all_backend_sockets_are_closed());

	/* allocate memory for new backends table and copy configuration to there*/
	
	down_read(&tfw_cfg.mtx);

	backend_addrs = tfw_cfg.backends;
	addr_count = backend_addrs->count;
	
	allocated_backends = kcalloc(1, sizeof(*allocated_backends) * addr_count, GFP_KERNEL);
	if (!allocated_backends) {
		up_read(&tfw_cfg.mtx);
		TFW_ERR("Can't allocate memory\n");
		return;
	}
	
	for (i = 0; i < addr_count; ++i) {
		TfwBackendSockDesc *backend = &allocated_backends[i];
		void *addr = &backend_addrs->addr[i];
		memcpy(&backend->addr, addr, sizeof(backend->addr));
	}
	
	up_read(&tfw_cfg.mtx);
	
	
	mutex_lock(&backend_socks_mtx);
	if (backend_socks) {
		kfree(backend_socks);
	}
	backend_socks = allocated_backends;
	backend_socks_n = addr_count;
	mutex_unlock(&backend_socks_mtx);
}


static void
free_backends_mem()
{
	mutex_lock(&backend_socks_mtx);
	
	if (backend_socks) {
		kfree(backend_socks);
		backend_socks = NULL;
		backend_socks_n = 0;
	}
	
	mutex_unlock(&backend_socks_mtx);
}



/**
 * Connect to the back-end server.
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

	/*
	 * TODO Set up socket callbacks.
	 * Do we need any?
	 */

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
