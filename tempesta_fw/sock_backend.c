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
#include <net/inet_sock.h>

#include "tempesta.h"
#include "connection.h"
#include "lib.h"
#include "log.h"
#include "server.h"


typedef struct {
	TfwAddr addr;
	struct socket *socket; /* The ptr is NULL when not connected. */
} TfwBackendSockDesc;


/* The global list of all known backends (either connected or disconnected). */
static TfwBackendSockDesc *backend_socks = NULL;
static unsigned int backend_socks_n = 0;
DEFINE_MUTEX(backend_socks_mtx);

/* the helper macro for iteration over the backend list */
#define FOR_EACH_IN_BACKEND_SOCKS(i, curr) \
	for ( \
		(i) = 0,  (curr) = backend_socks;  \
		(i) < backend_socks_n;  \
		++(i),  ++(curr)  \
	)


/* The thread that reopens dead backend connections in background. */
static struct task_struct *breconnd_task = NULL;
#define TFW_BRECONND_NAME "tfw_breconnd"
#define TFW_BRECONND_INTERVAL 1000


/* Forward declarations for local functions. */
static void start_breconnd_thread(void);
static void stop_breconnd_thread(void);
static int breconnd_main_loop(void *data);
static void open_new_backend_sockets(void);
static void reopen_dead_backend_sockets(void);
static void close_all_backend_sockets(void);
static bool all_backend_sockets_are_closed(void);
static void copy_new_backend_addresses_from_cfg(void);
static void free_backends_mem(void);
static int tfw_backend_connect(struct socket **sock, void *addr);


/*
 * Apply the new backends configuration.
 *
 * This function should be called when you change the backend configuration
 * (the addresses list in tfw_cfg). It closes all active connections to backends
 * and then opens new ones within the new configuration.
 * Also it restarts the thread that re-connects to the backends in background.
 */
void
tfw_apply_new_backends_cfg(void)
{
	stop_breconnd_thread();
	close_all_backend_sockets();
	copy_new_backend_addresses_from_cfg();

	if (backend_socks_n > 0) {
		open_new_backend_sockets();
		start_breconnd_thread();
	}
}


/*
 * The clean-up routine: it closes all backend connections, terminates
 * background threads and releases allocated memory.
 */
void
tfw_release_backend_sockets(void)
{
	stop_breconnd_thread();
	close_all_backend_sockets();
	free_backends_mem();
}



static void
start_breconnd_thread(void)
{
	struct task_struct *t;

	BUG_ON(breconnd_task);
	TFW_DBG("Starting thread: %s\n", TFW_BRECONND_NAME);

	t = kthread_run(
		breconnd_main_loop,
		NULL,
		TFW_BRECONND_NAME
	);

	if (IS_ERR_OR_NULL(t)) {
		TFW_ERR("Can't create thread: %s (%ld)",
			TFW_BRECONND_NAME,
			PTR_ERR(t));
	} else {
		breconnd_task = t;
	}
}


static void
stop_breconnd_thread(void)
{
	/* FIXME:
	 * The function will block while the thread sleeps because the
	 * kthread_stop() waits until the thread exits.
	 * We need to somehow notify the thread that it should exit and then
	 * interrupt its sleep (perhaps by sending a signal).
	 */
	if (breconnd_task) {
		TFW_DBG("Stopping thread: %s\n", TFW_BRECONND_NAME);
		kthread_stop(breconnd_task);
		breconnd_task = NULL;
	}
}


static int
breconnd_main_loop(void *data)
{
	while (true) {
		msleep_interruptible(TFW_BRECONND_INTERVAL);
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
	TfwBackendSockDesc *be;

	mutex_lock(&backend_socks_mtx);

	FOR_EACH_IN_BACKEND_SOCKS(i, be) {
		if (!be->socket) {
			int ret = tfw_backend_connect(&be->socket, &be->addr);

			if (ret) {
				TFW_WARN_ADDR("Can't connect to backend", &be->addr);
			} else {
				TFW_LOG_ADDR("Connected to backend", &be->addr);
			}

			/* it should leave NULL ptr when connection is failed */
			BUG_ON(ret && be->socket);
		}
	}

	mutex_unlock(&backend_socks_mtx);
}


static void
reopen_dead_backend_sockets(void)
{
	size_t i;
	TfwBackendSockDesc *be;

	mutex_lock(&backend_socks_mtx);

	FOR_EACH_IN_BACKEND_SOCKS(i, be) {
		if (be->socket && be->socket->sk->sk_shutdown) {
			TFW_LOG_ADDR("Disconnected from backend", &be->addr);
			sock_release(be->socket);
			be->socket = NULL;
		}

		if (!be->socket) {
			int ret = tfw_backend_connect(&be->socket, &be->addr);

			if (!ret) {
				TFW_LOG_ADDR("Connected to backend", &be->addr);
			} else {
				BUG_ON(be->socket);
			}
		}
	}

	mutex_unlock(&backend_socks_mtx);
}


void
close_all_backend_sockets(void)
{
	size_t i;
	TfwBackendSockDesc *be;

	mutex_lock(&backend_socks_mtx);

	FOR_EACH_IN_BACKEND_SOCKS(i, be) {
		if (be->socket) {
			struct socket *tmp_socket = be->socket;
			be->socket = NULL;
			sock_release(tmp_socket);

			TFW_LOG_ADDR("Closing backend connection", &be->addr);
		}
	}

	mutex_unlock(&backend_socks_mtx);
}


static bool
all_backend_sockets_are_closed(void)
{
	bool ret = true;
	size_t i;
	TfwBackendSockDesc *be;

	mutex_lock(&backend_socks_mtx);

	FOR_EACH_IN_BACKEND_SOCKS(i, be) {
		if (be->socket) {
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
	size_t new_be_count;
	TfwBackendSockDesc *new_backends;
	TfwAddrCfg *cfg;

	BUG_ON(!all_backend_sockets_are_closed());

	down_read(&tfw_cfg.mtx);

	cfg = tfw_cfg.backends;
	new_be_count = tfw_cfg.backends->count;

	/* Allocate memory for the new backends list. */
	new_backends = kzalloc(sizeof(*new_backends) * new_be_count, GFP_KERNEL);
	if (!new_backends) {
		up_read(&tfw_cfg.mtx);
		TFW_ERR("Can't allocate memory\n");
		return;
	}

	/* Pull addresses from tfw_cfg to the allocated memory. */
	for (i = 0; i < new_be_count; ++i) {
		TfwBackendSockDesc *be = &new_backends[i];
		void *addr = &cfg->addr[i];
		memcpy(&be->addr, addr, sizeof(be->addr));
	}

	up_read(&tfw_cfg.mtx);


	/* Replace old backends list with the freshly allocated one. */
	mutex_lock(&backend_socks_mtx);
	kfree(backend_socks);
	backend_socks = new_backends;
	backend_socks_n = new_be_count;
	mutex_unlock(&backend_socks_mtx);
}


static void
free_backends_mem()
{
	mutex_lock(&backend_socks_mtx);

	kfree(backend_socks);
	backend_socks = NULL;
	backend_socks_n = 0;

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
