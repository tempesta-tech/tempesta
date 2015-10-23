/*
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
#include "connection.h"
#include "http_msg.h"
#include "sync_socket.h"
#include "tfw_fuzzer.h"

#ifdef SS_BANNER
#undef SS_BANNER
#endif
#define SS_BANNER	"[tfw_bomber] "

static int tfw_threads = 4;
static int tfw_connects = 16;
static int tfw_iterations = 10;
module_param(tfw_threads, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(tfw_connects, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(tfw_iterations, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

#define TFW_BOMBER_WAIT_INTVL		(2)		/* in seconds */
#define TFW_BOMBER_WAIT_MAX		(1 * 60)	/* in seconds */

/* Flags for tfw_bomber_desc_t.flags */
#define TFW_BOMBER_CONNECT_STARTED		(0x0001)
#define TFW_BOMBER_CONNECT_ESTABLISHED		(0x0002)
#define TFW_BOMBER_CONNECT_CLOSED		(0x0004)
#define TFW_BOMBER_CONNECT_ERROR		(0x0100)

#ifndef DEBUG
#define DEBUG
#endif

typedef struct tfw_bomber_desc {
	SsProto		proto;
	struct sock	*sk;
	uint32_t	flags;
} tfw_bomber_desc_t;

/*
 * There's a descriptor for each connection that keeps the connection's
 * state and status. All descriptors are kept in a static two-dimensional
 * array. SsProto.type field is used here to store the index into that
 * array that can be passed around between callbacks.
 */
static tfw_bomber_desc_t **tfw_bomber_desc;
static struct task_struct **tfw_bomber_connect_task;
static wait_queue_head_t *tfw_bomber_connect_wq;
static atomic_t *tfw_bomber_nthread;

static struct task_struct **tfw_bomber_finish_task;
static wait_queue_head_t *tfw_bomber_finish_wq;

/* Successful attempts */
static atomic_t *tfw_bomber_connect_nattempt;
/* Connections established */
static atomic_t *tfw_bomber_connect_ncomplete;
/* Number of errors */
static atomic_t *tfw_bomber_connect_nerror;
static atomic_t *tfw_bomber_iterations;

static char *server = "127.0.0.1:80";
static TfwAddr tfw_bomber_server_address;
static SsHooks tfw_bomber_hooks;

static int tfw_bomber_thread_finish(void *data);

module_param(server, charp, 0);
MODULE_PARM_DESC(server, "Server host address and optional port nunber");
MODULE_LICENSE("GPL");

static int
tfw_bomber_connect(int descidx)
{
	int ret;
	struct sock *sk;
	tfw_bomber_desc_t *desc = *(tfw_bomber_desc + descidx / tfw_connects)
		+ descidx % tfw_connects;

	ret = ss_sock_create(tfw_bomber_server_address.sa.sa_family,
			SOCK_STREAM, IPPROTO_TCP, &sk);
	if (ret) {
		SS_DBG("Unable to create kernel socket (%d)\n", ret);
		desc->flags |= TFW_BOMBER_CONNECT_ERROR;
		atomic_inc(&tfw_bomber_connect_nerror[descidx / tfw_connects]);
		return ret;
	}
	ss_proto_init(&desc->proto, &tfw_bomber_hooks, descidx);
	sk->sk_user_data = &desc->proto;
	ss_set_callbacks(sk);
	local_bh_disable();
	ret = ss_connect(sk, &tfw_bomber_server_address.sa,
			tfw_addr_sa_len(&tfw_bomber_server_address), 0);
	if (ret) {
		SS_DBG("Connect error on server socket sk %p (%d)\n", sk, ret);
		sk->sk_user_data = NULL;
		ss_close(sk);
		local_bh_enable();
		desc->flags |= TFW_BOMBER_CONNECT_ERROR;
		atomic_inc(&tfw_bomber_connect_nerror[descidx / tfw_connects]);
		return ret;
	}

	local_bh_enable();
	desc->sk = sk;
	desc->flags |= TFW_BOMBER_CONNECT_STARTED;
	atomic_inc(&tfw_bomber_connect_nattempt[descidx / tfw_connects]);

	return 0;
}

static void
msg_send(tfw_bomber_desc_t *desc)
{
	struct sock *sk = desc->sk;
	char *str;
	int len, ret;

	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;

	BUG_ON(!sk);

	len = 1 * 1024 * 1024;
	str = vmalloc(len);
	if(!str) {
		printk("%s:could not allocate str\n", __func__);
		return;
	}
	ret = fuzz_gen(str, str + len, 0, 1, FUZZ_REQ);
	if (ret == FUZZ_END)
		printk("%s:FUZZ_END\n", __func__);
	msg.ptr = str;
	msg.skb = NULL;
	msg.len = strlen(str) - 1;
	msg.flags = 0;

	req = tfw_http_msg_create(&it, Conn_Clnt, msg.len);
	tfw_http_msg_write(&it, req, &msg);
	printk("%s:sk:%p, sk->sk_socket %p, msg:%p\n",
			__func__, sk, sk->sk_socket, &msg);
	local_bh_disable();
	printk("%s:softirq disabled\n", __func__);
	ss_send(sk, &req->msg.skb_list, false);
	printk("%s:sent\n", __func__);
	local_bh_enable();
	printk("%s:softirq enabled\n", __func__);

	vfree(str);
}

static int
tfw_bomber_connect_complete(struct sock *sk)
{
	int descidx, ret = 0;
	tfw_bomber_desc_t *desc;
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(tfw_bomber_desc + descidx / tfw_connects)
		+ descidx % tfw_connects;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bomber_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	printk("%s:connect complete, thread:%d\n",
			__func__, descidx / tfw_connects);
	desc->flags |= TFW_BOMBER_CONNECT_ESTABLISHED;
	atomic_inc(&tfw_bomber_connect_ncomplete[descidx / tfw_connects]);
	wake_up(&tfw_bomber_finish_wq[descidx / tfw_connects]);

	return ret;
}

static int
tfw_bomber_connection_close(struct sock *sk)
{
	int descidx;
	tfw_bomber_desc_t *desc;
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(tfw_bomber_desc + descidx / tfw_connects)
		+ descidx % tfw_connects;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bomber_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	printk("%s:close sk: %p, threadn %d\n", __func__, desc->sk, descidx / tfw_connects);
	desc->sk = NULL;
	desc->flags |= TFW_BOMBER_CONNECT_CLOSED;
	wake_up(&tfw_bomber_finish_wq[descidx / tfw_connects]);
	return 0;
}

static int
tfw_bomber_connection_error(struct sock *sk)
{
	int descidx;
	tfw_bomber_desc_t *desc;
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(tfw_bomber_desc + descidx / tfw_connects)
		+ descidx % tfw_connects;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bomber_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	printk("%s:error sk: %p, threadn %d\n", __func__, desc->sk, descidx / tfw_connects);
	desc->sk = NULL;
	desc->flags |= TFW_BOMBER_CONNECT_ERROR;
	atomic_inc(&tfw_bomber_connect_nerror[descidx / tfw_connects]);
	wake_up(&tfw_bomber_finish_wq[descidx / tfw_connects]);
	return 0;
}

static SsHooks tfw_bomber_hooks = {
	.connection_new		= tfw_bomber_connect_complete,
	.connection_drop	= tfw_bomber_connection_close,
	.connection_error	= tfw_bomber_connection_error,
};

static void
tfw_bomber_send_msgs(int threadn)
{
	int i;

	printk("%s:threadn:%d\n", __func__, threadn);
	for (i = 0; i < tfw_connects; i++)
		if (tfw_bomber_desc[threadn][i].sk)
			msg_send(&tfw_bomber_desc[threadn][i]);
}

static void
tfw_bomber_release_sockets(int threadn)
{
	int i;

	printk("%s:threadn:%d\n", __func__, threadn);
	for (i = 0; i < tfw_connects; i++) {
		if (tfw_bomber_desc[threadn][i].sk) {
			local_bh_disable();
			tfw_bomber_desc[threadn][i].sk->sk_user_data = NULL;
			ss_close(tfw_bomber_desc[threadn][i].sk);
			local_bh_enable();
			tfw_bomber_desc[threadn][i].sk = NULL;
		}
	}
}

static int
tfw_bomber_thread_connect(void *data)
{
	int i, nconnects = 0;
	int threadn = (int)(long)data;
	int descidx = threadn * tfw_connects;

	SS_DBG("connect_thread_%02d started\n", threadn);
	for (i = 0; i < tfw_connects; i++) {
		if (tfw_bomber_connect(descidx + i) == 0) {
			nconnects++;
		}
	}
	tfw_bomber_connect_task[threadn] = NULL;
	atomic_dec(&tfw_bomber_nthread[threadn]);
	wake_up(&tfw_bomber_connect_wq[threadn]);
	SS_DBG("Thread %d has initiated %d connects out of %d\n",
			threadn, nconnects, tfw_connects);
	return 0;
}

static void
tfw_bomber_stop_threads(void)
{
	int i;

	SS_DBG("%s: stop all threads\n", __func__);
	for (i = 0; i < tfw_threads; i++) {
		if (tfw_bomber_connect_task[i]) {
			kthread_stop(tfw_bomber_connect_task[i]);
			tfw_bomber_connect_task[i] = NULL;
		}
		if (tfw_bomber_finish_task[i]) {
			kthread_stop(tfw_bomber_finish_task[i]);
			tfw_bomber_finish_task[i] = NULL;
		}
		tfw_bomber_release_sockets(i);
	}
}

static int
tfw_bomber_recreate_thread(int threadn)
{
	int ret = 0;
	struct task_struct *task;

	task = kthread_create(tfw_bomber_thread_finish,
			(void *)(long)threadn,
			"tfw_bomber_thread_finish_%02d", threadn);
	if (IS_ERR_OR_NULL(task)) {
		ret = PTR_ERR(task);
		SS_ERR("Unable to create thread: %s%02d (%d)\n",
				"tfw_bomber_finish_task", threadn, ret);
		tfw_bomber_stop_threads();
		return ret;
	}
	tfw_bomber_finish_task[threadn] = task;

	task = kthread_create(tfw_bomber_thread_connect,
			(void *)(long)threadn,
			"tfw_bomber_thread_connect_%02d", threadn);
	if (IS_ERR_OR_NULL(task)) {
		ret = PTR_ERR(task);
		SS_ERR("Unable to create a thread: %s%02d (%d)\n",
				"tfw_bomber_thread_connect", threadn, ret);
		tfw_bomber_stop_threads();
		return ret;
	}
	tfw_bomber_connect_task[threadn] = task;

	atomic_set(&tfw_bomber_connect_nattempt[threadn], 0);
	atomic_set(&tfw_bomber_connect_ncomplete[threadn], 0);
	atomic_set(&tfw_bomber_connect_nerror[threadn], 0);
	atomic_set(&tfw_bomber_nthread[threadn], 1);

	wake_up_process(tfw_bomber_connect_task[threadn]);
	wait_event_interruptible(tfw_bomber_connect_wq[threadn],
			atomic_read(&tfw_bomber_nthread[threadn]) == 0);

	wake_up_process(tfw_bomber_finish_task[threadn]);

	return 0;
}

static int
tfw_bomber_thread_finish(void *data)
{
	int threadn = (int)(long)data;
	int nattempt = atomic_read(&tfw_bomber_connect_nattempt[threadn]);
	uint64_t time_max = (uint64_t)get_seconds() + TFW_BOMBER_WAIT_MAX;
	int niterations;
	int ret = 0;
	long timeout = TFW_BOMBER_WAIT_INTVL;
	int nerror, ncomplete;

	printk("%s,nattempt:%d,thread:%d\n", __func__, nattempt, threadn);
	set_freezable();
	do {
		nerror = atomic_read(&tfw_bomber_connect_nerror[threadn]);
		ncomplete = atomic_read(&tfw_bomber_connect_ncomplete[threadn]);

		printk("%s,ncomplete:%d,nerror:%d,threadn:%d\n",
				__func__, ncomplete, nerror, threadn);
		if (ncomplete + nerror == nattempt) {
			break;
		}
		wait_event_freezable_timeout(tfw_bomber_finish_wq[threadn],
				kthread_should_stop(),
				timeout);
		if ((uint64_t)get_seconds() > time_max) {
			SS_ERR("%s exceeded maximum wait time of %d seconds\n",
					"tfw_bomber_thread_finish", TFW_BOMBER_WAIT_MAX);
			break;
		}
	} while (!kthread_should_stop() && ncomplete + nerror < nattempt);

	tfw_bomber_send_msgs(threadn);
	tfw_bomber_release_sockets(threadn);
	tfw_bomber_finish_task[threadn] = NULL;

	niterations = atomic_dec_return(&tfw_bomber_iterations[threadn]);
	printk("%s:niterations:%d,threadn:%d\n", __func__, niterations, threadn);

	if (niterations)
		ret = tfw_bomber_recreate_thread(threadn);

	return ret;
}

static int
tfw_bomber_create_tasks(void)
{
	int i, ret = 0;
	struct task_struct *task;

	for (i = 0; i < tfw_threads; i++) {
		task = kthread_create(tfw_bomber_thread_finish, (void *)(long)i,
				"tfw_bomber_thread_finish_%02d", i);
		if (IS_ERR_OR_NULL(task)) {
			ret = PTR_ERR(task);
			SS_ERR("Unable to create thread: %s%02d (%d)\n",
					"tfw_bomber_finish_task", i, ret);
			break;
		}
		tfw_bomber_finish_task[i] = task;

		task = kthread_create(tfw_bomber_thread_connect, (void *)(long)i,
				"tfw_bomber_thread_connect_%02d", i);
		if (IS_ERR_OR_NULL(task)) {
			ret = PTR_ERR(task);
			SS_ERR("Unable to create a thread: %s%02d (%d)\n",
					"tfw_bomber_thread_connect", i, ret);
			break;
		}
		tfw_bomber_connect_task[i] = task;

		atomic_set(&tfw_bomber_connect_nattempt[i], 0);
		atomic_set(&tfw_bomber_connect_ncomplete[i], 0);
		atomic_set(&tfw_bomber_connect_nerror[i], 0);
		atomic_set(&tfw_bomber_iterations[i], tfw_iterations);
	}

	return ret;
}

static int __init
tfw_bomber_init(void)
{
	int i, j, ret = 0;

	if (tfw_addr_pton(server, &tfw_bomber_server_address)) {
		SS_ERR("Unable to parse server's address: %s", server);
		return -EINVAL;
	}
	SS_ERR("Started kclient module, server's address is %s\n", server);

	tfw_bomber_desc = kmalloc(tfw_threads *
			sizeof(tfw_bomber_desc_t *), GFP_KERNEL);
	if (!tfw_bomber_desc)
		return -ENOMEM;

	for (i = 0; i < tfw_threads; i++) {
		tfw_bomber_desc[i] = kzalloc(tfw_connects *
				sizeof(tfw_bomber_desc_t), GFP_KERNEL);
		if (!tfw_bomber_desc[i]) {
			for (j = 0; j < i; j++)
				kfree(tfw_bomber_desc[i]);
			ret = -ENOMEM;
			goto err_bomber_desc;
		}
	}

	tfw_bomber_connect_task = kmalloc(tfw_threads *
			sizeof(struct task_struct *), GFP_KERNEL);
	if (!tfw_bomber_connect_task) {
		ret = -ENOMEM;
		goto err_connect_task;
	}
	tfw_bomber_connect_wq = kmalloc(tfw_threads *
			sizeof(wait_queue_head_t), GFP_KERNEL);
	if (!tfw_bomber_connect_wq) {
		ret = -ENOMEM;
		goto err_connect_wq;
	}
	tfw_bomber_nthread = kmalloc(tfw_threads *
			sizeof(atomic_t), GFP_KERNEL);
	if (!tfw_bomber_nthread) {
		ret = -ENOMEM;
		goto err_bomber_nthread;
	}

	tfw_bomber_finish_task = kmalloc(tfw_threads *
			sizeof(struct task_struct *), GFP_KERNEL);
	if (!tfw_bomber_finish_task) {
		ret = -ENOMEM;
		goto err_finish_task;
	}
	tfw_bomber_finish_wq = kmalloc(tfw_threads *
			sizeof(wait_queue_head_t), GFP_KERNEL);
	if (!tfw_bomber_finish_wq) {
		ret = -ENOMEM;
		goto err_finish_wq;
	}

	tfw_bomber_connect_nattempt = kmalloc(tfw_threads *
			sizeof(atomic_t), GFP_KERNEL);
	if (!tfw_bomber_connect_nattempt) {
		ret = -ENOMEM;
		goto err_connect_nattempt;
	}
	tfw_bomber_connect_ncomplete = kmalloc(tfw_threads *
			sizeof(atomic_t), GFP_KERNEL);
	if (!tfw_bomber_connect_ncomplete) {
		ret = -ENOMEM;
		goto err_connect_ncomplete;
	}
	tfw_bomber_connect_nerror = kmalloc(tfw_threads *
			sizeof(atomic_t), GFP_KERNEL);
	if (!tfw_bomber_connect_nerror) {
		ret = -ENOMEM;
		goto err_connect_error;
	}
	tfw_bomber_iterations = kmalloc(tfw_threads *
			sizeof(atomic_t), GFP_KERNEL);
	if (!tfw_bomber_iterations) {
		ret = -ENOMEM;
		goto err_iterations;
	}

	for (i = 0; i < tfw_threads; i++) {
		init_waitqueue_head(&tfw_bomber_connect_wq[i]);
		init_waitqueue_head(&tfw_bomber_finish_wq[i]);
	}

	fuzz_reset();

	ret = tfw_bomber_create_tasks();

	if (ret) {
		goto err_create_tasks;
	} else {
		for (i = 0; i < tfw_threads; i++) {
			atomic_set(&tfw_bomber_nthread[i], 1);
			wake_up_process(tfw_bomber_connect_task[i]);
			// TODO: remove wait_event. Just connect
			// and start tfw_bomber_finish_task.
			wait_event_interruptible(tfw_bomber_connect_wq[i],
					atomic_read(&tfw_bomber_nthread[i]) == 0);
		}
		SS_ERR("Started %d threads to initiate %d connects each\n",
				tfw_threads, tfw_connects);

		for (i = 0; i < tfw_threads; i++)
			wake_up_process(tfw_bomber_finish_task[i]);
	}

	return ret;

err_create_tasks:
	tfw_bomber_stop_threads();
	kfree(tfw_bomber_iterations);
err_iterations:
	kfree(tfw_bomber_connect_nerror);
err_connect_error:
	kfree(tfw_bomber_connect_ncomplete);
err_connect_ncomplete:
	kfree(tfw_bomber_connect_nattempt);
err_connect_nattempt:
	kfree(tfw_bomber_finish_wq);
err_finish_wq:
	kfree(tfw_bomber_finish_task);
err_finish_task:
	kfree(tfw_bomber_nthread);
err_bomber_nthread:
	kfree(tfw_bomber_connect_wq);
err_connect_wq:
	kfree(tfw_bomber_connect_task);
err_connect_task:
	for (i = 0; i < tfw_threads; i++)
		kfree(tfw_bomber_desc[i]);
err_bomber_desc:
	kfree(tfw_bomber_desc);

	return ret;
}

static void
tfw_bomber_exit(void)
{
	int i;

	tfw_bomber_stop_threads();

	for (i = 0; i < tfw_threads; i++)
		kfree(tfw_bomber_desc[i]);
	kfree(tfw_bomber_desc);
	kfree(tfw_bomber_connect_task);
	kfree(tfw_bomber_connect_wq);
	kfree(tfw_bomber_nthread);
	kfree(tfw_bomber_finish_task);
	kfree(tfw_bomber_finish_wq);
	kfree(tfw_bomber_connect_nattempt);
	kfree(tfw_bomber_connect_ncomplete);
	kfree(tfw_bomber_connect_nerror);
	kfree(tfw_bomber_iterations);
}

module_init(tfw_bomber_init);
module_exit(tfw_bomber_exit);
