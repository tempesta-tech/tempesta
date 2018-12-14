/**
 * Multiplexing kernel server for performance testing of Synchronous Socket API.
 *
 * The code is mostly inspired by Oracle RDS (linux/net/rds).
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/in.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/uaccess.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

#define MAX_CONN	(1000 * 1000)
#define PORT		5000
#define READ_SZ		(MSG_SZ * sizeof(int))

typedef struct {
	struct work_struct	work;
	struct socket		*sk;
} SocketWork;

static void kserver_accept_worker(struct work_struct *);
static void kserver_read_worker(struct work_struct *);

static struct socket *listen_sock;
static struct workqueue_struct *kserver_wq;
static struct kmem_cache *sw_cache;

/* Statistics */
static long last_ts = 0;
static unsigned int pps_curr = 0, pps_max = 0;
static DEFINE_SPINLOCK(stat_lock);

static int stop = 0;
static atomic_t works = ATOMIC_INIT(0); /* number of works in progress */
static int msg_buf[MSG_SZ];
static int g_counter;

static atomic_t conn_i = ATOMIC_INIT(0);
static struct socket *conn[MAX_CONN] = { NULL };

MODULE_LICENSE("GPL");

static void
stat_update(int events)
{
	spin_lock(&stat_lock);
	if (last_ts == jiffies / HZ) {
		pps_curr += events;
	} else {
		// recharge
		if (pps_curr > pps_max)
			pps_max = pps_curr;
		pps_curr = events;
		last_ts = jiffies / HZ;
	}
	spin_unlock(&stat_lock);
}

void
stat_print(void)
{
	printk(KERN_ERR "Best rps: %lu\n",
	       (pps_curr > pps_max ? pps_curr : pps_max) / READ_SZ);
}

static void
kserver_do_socket_read(struct socket *sock)
{
	int r, count = 0;
	do {
	        struct msghdr msg = {
			.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL
		};
		struct kvec iov = { msg_buf, READ_SZ };

		r = kernel_recvmsg(sock, &msg, &iov, 1, READ_SZ,
				   msg.msg_flags);
		if (r >= 0) {
			// Just do some useless work.
			int i;
			for (i = 0; i < r / 4; ++i)
				g_counter += msg_buf[i];
			count += r;
		} else if (r != -EAGAIN)
			printk(KERN_ERR "error (%d) on socket %p\n", r, sock);
	} while (r > 0);

	stat_update(count);
}

static void
kserver_read_worker(struct work_struct *work)
{
	SocketWork *sw = (SocketWork *)work;

	BUG_ON(!sw->sk);

	kserver_do_socket_read(sw->sk);

	kmem_cache_free(sw_cache, sw);
	atomic_dec(&works);
}

static void
kserver_read_data_ready(struct sock *sk)
{
	SocketWork *sw;

	atomic_inc(&works);
	if (stop) {
		atomic_dec(&works);
		goto out;
	}

	sw = kmem_cache_alloc(sw_cache, GFP_ATOMIC);
	if (!sw) {
		printk(KERN_ERR "Can't allocate read work\n");
		atomic_dec(&works);
		goto out;
	}
	INIT_WORK(&sw->work, kserver_read_worker);
	sw->sk = sk->sk_socket;

	BUG_ON(!sk->sk_socket->ops);

	read_lock(&sk->sk_callback_lock);

	queue_work(kserver_wq, &sw->work);

	read_unlock(&sk->sk_callback_lock);

out:
	return;
}

static void
kserver_state_change(struct sock *sk)
{
	read_lock(&sk->sk_callback_lock);

	switch (sk->sk_state) {
	case TCP_CLOSE:
		stat_update(READ_SZ);
	default:
		break;
	}

	read_unlock(&sk->sk_callback_lock);
}

static int
kserver_accept(struct socket *sock)
{
	struct socket *new_sock = NULL;
	int ci, r = 1;

	if (stop)
		goto out;

	r = sock_create_lite(sock->sk->sk_family, sock->sk->sk_type,
			     sock->sk->sk_protocol, &new_sock);
	if (r)
		goto out;

	new_sock->type = sock->type;
	new_sock->ops = sock->ops;
	r = sock->ops->accept(sock, new_sock, O_NONBLOCK);
	if (r < 0)
		goto err;

	write_lock_bh(&new_sock->sk->sk_callback_lock);
	new_sock->sk->sk_state_change = kserver_state_change;
	write_unlock_bh(&new_sock->sk->sk_callback_lock);

	/* Write the socket to free it as module exit. */
	ci = atomic_inc_return(&conn_i);
	if (ci < MAX_CONN) {
		conn[ci] = new_sock;
	} else {
		printk(KERN_ERR "Too many connections!\n");
	}

	/* Check whether the socket has some data to read. */
	kserver_do_socket_read(new_sock);

	return 0;
err:
	if (new_sock)
		sock_release(new_sock);
out:
	return r;
}

static void
kserver_accept_worker(struct work_struct *work)
{
	SocketWork *sw = (SocketWork *)work;

	BUG_ON(sw->sk != listen_sock);

	while (!kserver_accept(sw->sk)) {
		stat_update(READ_SZ);
		cond_resched();
	}

	kmem_cache_free(sw_cache, sw);
	atomic_dec(&works);
}

static void
kserver_listen_data_ready(struct sock *sk)
{
	SocketWork *sw;

	atomic_inc(&works);

	sw = kmem_cache_alloc(sw_cache, GFP_ATOMIC);
	if (!sw) {
		printk(KERN_ERR "Can't allocate accept work\n");
		atomic_dec(&works);
		return;
	}
	INIT_WORK(&sw->work, kserver_accept_worker);
	sw->sk = listen_sock;

	read_lock(&sk->sk_callback_lock);

	if (sk->sk_state == TCP_LISTEN) {
		queue_work(kserver_wq, &sw->work);
	} else {
		kmem_cache_free(sw_cache, sw);
		atomic_dec(&works);
	}

	read_unlock(&sk->sk_callback_lock);
}

static void
kserver_data_ready(struct sock *sk, int bytes __attribute__((unused)))
{
	if (!sk->sk_socket)
		/*
		 * Just established, not fully initialized, socket.
		 * Now we can't read from it, but we'll drain its receive
		 * queue just when it's fully initialized in kserver_accept().
		 */
		return;

	if (sk->sk_socket == listen_sock)
		kserver_listen_data_ready(sk);
	else
		/*
		 * We process child socket data in parent callback
		 * to avoid absence of proper callback on data arriving
		 * due to registration of callback after accepting the socket.
		 */
		kserver_read_data_ready(sk);
}

int __init
kserver_init(void)
{
	int r = -ENOMEM;
	struct sockaddr_in saddr;

	sw_cache = kmem_cache_create("kserver_work_cache", sizeof(SocketWork),
				     0, 0, NULL);
	if (!sw_cache) {
		printk(KERN_ERR "Can't create read work cache\n");
		return r;
	}

	kserver_wq = create_singlethread_workqueue("kserverd");
	if (!kserver_wq) {
		printk(KERN_ERR "Can't create workqueue\n");
		goto err;
	}

	r = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_sock);
	if (r) {
		printk(KERN_ERR "Can't listening socket\n");
		goto err_sock;
	}

	inet_sk(listen_sock->sk)->freebind = 1;
	listen_sock->sk->sk_reuse = 1;

	write_lock_bh(&listen_sock->sk->sk_callback_lock);
	listen_sock->sk->sk_data_ready = kserver_data_ready;
	write_unlock_bh(&listen_sock->sk->sk_callback_lock);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(PORT);

	r = listen_sock->ops->bind(listen_sock, (struct sockaddr *)&saddr,
				   sizeof(saddr));
	if (r) {
		printk(KERN_ERR "Can't bind listening socket\n");
		goto err_call;
	}

	r = listen_sock->ops->listen(listen_sock, 1000);
	if (r) {
		printk(KERN_ERR "Can't listen on socket\n");
		goto err_call;
	}

	return 0;
err_call:
	sock_release(listen_sock);
err_sock:
	destroy_workqueue(kserver_wq);
err:
	kmem_cache_destroy(sw_cache);
	return r;
}

void __exit
kserver_exit(void)
{
	int ci;

	stop = 1;

	sock_release(listen_sock);
	for (ci = 0; ci < atomic_read(&conn_i); ++ci)
		if (conn[ci])
			sock_release(conn[ci]);

	while (atomic_read(&works))
		schedule();

	stat_print();

	destroy_workqueue(kserver_wq);
	kmem_cache_destroy(sw_cache);
}

module_init(kserver_init);
module_exit(kserver_exit);
