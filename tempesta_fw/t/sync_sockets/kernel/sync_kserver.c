/**
 * Multiplexing kernel server using synchronous sockets for performance testing
 * of Synchronous Socket API.
 *
 * It works fully in softirq context as opposed to kserver working mostly in
 * kworker threads.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/inet_sock.h>

#include "sync_socket.h"

#define MAX_CONN	(1000 * 1000)
#define PORT		5000
#define READ_SZ		(MSG_SZ * sizeof(int))

/* Application logic class inherited from SsProto. */
typedef struct {
	SsProto		proto;
} MyProto;

static MyProto my_proto;

/* Statistics */
static long last_ts = 0;
static unsigned int pps_curr = 0, pps_max = 0;

static int g_counter;

static atomic_t conn_i = ATOMIC_INIT(0);
static struct sock *conn[MAX_CONN] = { NULL };

MODULE_LICENSE("GPL");

static void
stat_update(int events)
{
	/* Only one softirq context, so no synchronization is needed. */
	if (last_ts == jiffies / HZ) {
		pps_curr += events;
	} else {
		// recharge
		if (pps_curr > pps_max)
			pps_max = pps_curr;
		pps_curr = events;
		last_ts = jiffies / HZ;
	}
}

void
stat_print(void)
{
	printk(KERN_ERR "Best rps: %lu\n",
	       (pps_curr > pps_max ? pps_curr : pps_max) / READ_SZ);
}

/*
 * Just do some useless work.
 */
static int
kserver_read(struct sock *sk, unsigned char *data, size_t len)
{
	int i;
	for (i = 0; i < len / 4; ++i)
		g_counter += data[i];

	stat_update(len);

	return 0;
}

static int
kserver_connection_new(struct sock *sk)
{
	int ci;

	BUG_ON(!sk->sk_user_data);

	/* TODO Typically we should allocate a new connection here. */

	/* Write the socket to free it as module exit. */
	ci = atomic_inc_return(&conn_i);
	if (ci < MAX_CONN) {
		conn[ci] = sk;
	} else {
		printk(KERN_ERR "Too many connections!\n");
	}

	stat_update(READ_SZ);

	return 0;
}

static int
kserver_connection_drop(struct sock *sk)
{
	stat_update(READ_SZ);

	return 0;
}

static SsHooks ssocket_hooks = {
	.connection_new		= kserver_connection_new,
	.connection_drop	= kserver_connection_drop,
	.connection_recv	= kserver_read,
};

int __init
kserver_init(void)
{
	int r;
	struct sock *lsk;
	struct sockaddr_in saddr;

	r = ss_sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &lsk);
	if (r) {
		printk(KERN_ERR "Can't listening socket\n");
		goto err_create;
	}

	inet_sk(lsk)->freebind = 1;
	lsk->sk_reuse = 1;

	/* Set TCP handlers. */
	ss_proto_init((SsProto *)&my_proto, &ssocket_hooks, 0);
	lsk->sk_user_data = (SsProto *)&my_proto;
	ss_set_listen(lsk);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);

	r = ss_bind(lsk, (struct sockaddr *)&saddr, sizeof(saddr));
	if (r) {
		printk(KERN_ERR "Can't bind listening socket\n");
		goto err_call;
	}

	r = ss_listen(lsk, 1000);
	if (r) {
		printk(KERN_ERR "Can't listen on socket\n");
		goto err_call;
	}

	return 0;
err_call:
	ss_release(lsk);
err_create:
	return r;
}

void __exit
kserver_exit(void)
{
	int ci;

	ss_release(my_proto.proto.listener);

	for (ci = 0; ci < atomic_read(&conn_i); ++ci)
		if (conn[ci])
			ss_close_sync(conn[ci], true);

	/*
	 * FIXME at this point the module can crash if there is some active
	 * softirq processing the sockets which are calling ssocket_hooks
	 * callbacks.
	 */

	stat_print();
}

module_init(kserver_init);
module_exit(kserver_exit);
