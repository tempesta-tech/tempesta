/*
 * A client for testing Synchronous Sockets connect() that does not sleep.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include <net/inet_sock.h>

#include "addr.h"
#include "log.h"
#include "sync_socket.h"

/*
 * Start KCLIENT_NTHREADS threads. Each thread initiates KCLIENT_NCONNECTS
 * connects to a remote server, and finishes. Errors in this process are
 * marked with a KCLIENT_CONNECT_ERROR flag, which may be used for extra
 * reporting. Successful connect attempts are counted.
 *
 * Another thread is started that waits on these connect attempts to finish.
 *
 * As each connect attempt finishes after 3WHS, an SS hook is invoked that
 * marks the connection as established. 
 *
 * The waiting thread waits on all successful connects attempts to complete.
 * After that, it closes all open connections.
 *
 * In the end, when the module is unloaded, a stat report is printed.
 */
#ifdef SS_BANNER
#undef SS_BANNER
#endif
#define SS_BANNER	"[kclient] "

#define KCLIENT_NTHREADS		(16)
#define KCLIENT_NCONNECTS		(64)
#define KCLIENT_WAIT_INTVL		(2)		/* in seconds */
#define KCLIENT_WAIT_MAX		(1 * 60)	/* in seconds */

/* Flags for kclient_desc_t.flags */
#define KCLIENT_CONNECT_STARTED		(0x0001)
#define KCLIENT_CONNECT_ESTABLISHED	(0x0002)
#define KCLIENT_CONNECT_CLOSED		(0x0004)
#define KCLIENT_CONNECT_ERROR		(0x0100)

typedef struct kclient_desc {
	SsProto		proto;
	struct sock	*sk;
	uint32_t	flags;
} kclient_desc_t;

/*
 * There's a descriptor for each connection that keeps the connection's
 * state and status. All descriptors are kept in a static two-dimensional
 * array. SsProto.type field is used here to store the index into that
 * array that can be passed around between callbacks.
 */
static kclient_desc_t kclient_desc[KCLIENT_NTHREADS][KCLIENT_NCONNECTS];
static struct task_struct *kclient_connect_task[KCLIENT_NTHREADS];
DECLARE_WAIT_QUEUE_HEAD(kclient_connect_wq);
static atomic_t kclient_nthreads;

static struct task_struct *kclient_finish_task;
DECLARE_WAIT_QUEUE_HEAD(kclient_finish_wq);

static atomic_t kclient_connect_nattempt;	/* Successful attempts */
static atomic_t kclient_connect_ncomplete;	/* Connections established */
static atomic_t kclient_connect_nclose;		/* Connections closed */
static atomic_t kclient_connect_nerror;		/* Number of errors */

static char *server = "127.0.0.1:5000";
static TfwAddr kclient_server_address;
static SsHooks kclient_hooks;

module_param(server, charp, 0);
MODULE_PARM_DESC(server, "Server host address and optional port nunber");
MODULE_LICENSE("GPL");

static int
kclient_connect(int descidx)
{
	int ret;
	struct sock *sk;
	kclient_desc_t *desc = *(kclient_desc + descidx / KCLIENT_NCONNECTS)
					      + descidx % KCLIENT_NCONNECTS;

	ret = ss_sock_create(kclient_server_address.sa.sa_family,
			     SOCK_STREAM, IPPROTO_TCP, &sk);
	if (ret) {
		SS_DBG("Unable to create kernel socket (%d)\n", ret);
		desc->flags |= KCLIENT_CONNECT_ERROR;
		atomic_inc(&kclient_connect_nerror);
		return ret;
	}
	ss_proto_init(&desc->proto, &kclient_hooks, descidx);
	sk->sk_user_data = &desc->proto;
	ss_set_callbacks(sk);
	ret = ss_connect(sk, &kclient_server_address.sa,
			 tfw_addr_sa_len(&kclient_server_address), 0);
	if (ret) {
		SS_DBG("Connect error on server socket sk %p (%d)\n", sk, ret);
		ss_release(sk);
		desc->flags |= KCLIENT_CONNECT_ERROR;
		atomic_inc(&kclient_connect_nerror);
		return ret;
        }
	desc->sk = sk;
	desc->flags |= KCLIENT_CONNECT_STARTED;
	atomic_inc(&kclient_connect_nattempt);
	return 0;
}

static int
kclient_connect_complete(struct sock *sk)
{
	int descidx;
	kclient_desc_t *desc;
	SsProto *proto = sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(kclient_desc + descidx / KCLIENT_NCONNECTS)
			      + descidx % KCLIENT_NCONNECTS;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &kclient_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->flags |= KCLIENT_CONNECT_ESTABLISHED;
	atomic_inc(&kclient_connect_ncomplete);
	wake_up(&kclient_finish_wq);
	return 0;
}

static int
kclient_connection_close(struct sock *sk)
{
	int descidx;
	kclient_desc_t *desc;
	SsProto *proto = sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(kclient_desc + descidx / KCLIENT_NCONNECTS)
			      + descidx % KCLIENT_NCONNECTS;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &kclient_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= KCLIENT_CONNECT_CLOSED;
	atomic_inc(&kclient_connect_nclose);
	wake_up(&kclient_finish_wq);
	return 0;
}

static int
kclient_connection_error(struct sock *sk)
{
	int descidx;
	kclient_desc_t *desc;
	SsProto *proto = sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(kclient_desc + descidx / KCLIENT_NCONNECTS)
			      + descidx % KCLIENT_NCONNECTS;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &kclient_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= KCLIENT_CONNECT_ERROR;
	atomic_inc(&kclient_connect_nerror);
	wake_up(&kclient_finish_wq);
	return 0;
}

static SsHooks kclient_hooks = {
	.connection_new		= kclient_connect_complete,
	.connection_drop	= kclient_connection_close,
	.connection_error	= kclient_connection_error,
};

static void
kclient_report(void)
{
	SS_ERR("Initiated %d connects\n",
		KCLIENT_NTHREADS * KCLIENT_NCONNECTS);
	SS_ERR("Of those %d connects initiated successfully\n",
		atomic_read(&kclient_connect_nattempt));
	SS_ERR("Of those %d connections were established successfully\n",
		atomic_read(&kclient_connect_ncomplete));
	SS_ERR("and %d connections completed with error\n",
		atomic_read(&kclient_connect_nerror));
}

static void
kclient_release_sockets(void)
{
	int i, k;

	for (i = 0; i < KCLIENT_NTHREADS; i++) {
		for (k = 0; k < KCLIENT_NCONNECTS; k++) {
			if (kclient_desc[i][k].sk) {
				ss_release(kclient_desc[i][k].sk);
				kclient_desc[i][k].sk = NULL;
			}
		}
	}
}

static int
kclient_thread_finish(void *data)
{
	int nattempt = atomic_read(&kclient_connect_nattempt);
	uint64_t time_max = (uint64_t)get_seconds() + KCLIENT_WAIT_MAX;

	set_freezable();
	do {
		long timeout = KCLIENT_WAIT_INTVL;
		int nerror = atomic_read(&kclient_connect_nerror);
		int ncomplete = atomic_read(&kclient_connect_ncomplete);

		if (ncomplete + nerror == nattempt) {
			break;
		}
		wait_event_freezable_timeout(kclient_finish_wq,
					     kthread_should_stop(),
					     timeout);
		if ((uint64_t)get_seconds() > time_max) {
			SS_ERR("%s exceeded maximum wait time of %d seconds\n",
				"kclient_thread_finish", KCLIENT_WAIT_MAX);
			break;
		}
	} while (!kthread_should_stop());

	kclient_release_sockets();
	kclient_finish_task = NULL;
	return 0;
}

static int
kclient_thread_connect(void *data)
{
	int i, nconnects = 0;
	int threadn = (int)(long)data;
	int descidx = threadn * KCLIENT_NCONNECTS;

	SS_DBG("connect_thread_%02d started\n", threadn);
	for (i = 0; i < KCLIENT_NCONNECTS; i++) {
		if (kclient_connect(descidx + i) == 0) {
			nconnects++;
		}
	}
	kclient_connect_task[threadn] = NULL;
	atomic_dec(&kclient_nthreads);
	wake_up(&kclient_connect_wq);
	SS_DBG("Thread %d has initiated %d connects out of %d\n",
	       threadn, nconnects, KCLIENT_NCONNECTS);
	return 0;
}

static void
kclient_stop_threads(void)
{
	int i;

	for (i = 0; i < KCLIENT_NTHREADS; i++) {
		if (kclient_connect_task[i]) {
			kthread_stop(kclient_connect_task[i]);
			kclient_connect_task[i] = NULL;
		}
	}
	if (kclient_finish_task) {
		kthread_stop(kclient_finish_task);
		kclient_finish_task = NULL;
	}
	kclient_release_sockets();
}

static int __init
kclient_init(void)
{
	int i, ret = 0;
	struct task_struct *task;

	if (tfw_addr_pton(server, &kclient_server_address)) {
		SS_ERR("Unable to parse server's address: %s", server);
		return -EINVAL;
	}
	SS_ERR("Started kclient module, server's address is %s\n", server);

	task = kthread_create(kclient_thread_finish, 0,
			      "kclient_thread_finish");
	if (IS_ERR_OR_NULL(task)) {
		ret = PTR_ERR(task);
		SS_ERR("Unable to create thread: %s (%d)\n",
		       "kclient_finish_task", ret);
		return ret;
	}
	kclient_finish_task = task;

	for (i = 0; i < KCLIENT_NTHREADS; i++) {
		task = kthread_create(kclient_thread_connect, (void *)(long)i,
				      "kclient_thread_connect_%02d", i);
		if (IS_ERR_OR_NULL(task)) {
			ret = PTR_ERR(task);
			SS_ERR("Unable to create a thread: %s%02d (%d)\n",
				"kclient_thread_connect", i, ret);
			break;
		}
		kclient_connect_task[i] = task;
	}
	if (ret) {
		kclient_stop_threads();
	} else {
		atomic_set(&kclient_nthreads, KCLIENT_NTHREADS);
		for (i = 0; i < KCLIENT_NTHREADS; i++) {
			wake_up_process(kclient_connect_task[i]);
		}
		SS_ERR("Started %d threads to initiate %d connects each\n",
			KCLIENT_NTHREADS, KCLIENT_NCONNECTS);
		wait_event_interruptible(kclient_connect_wq,
					 atomic_read(&kclient_nthreads) == 0);
		wake_up_process(kclient_finish_task);
	}
	return ret;
}

static void
kclient_exit(void)
{
	kclient_stop_threads();
	kclient_report();
}

module_init(kclient_init);
module_exit(kclient_exit);
