/**
 *		Tempesta FW
 *
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
#include "tfw_fuzzer.h"

#ifdef SS_BANNER
#undef SS_BANNER
#endif
#define SS_BANNER	"[tfw_bomber] "

static int tfw_threads = 4;
static int tfw_connects = 16;
static int tfw_messages = 4;
static char *tfw_server = "127.0.0.1:80";

module_param(tfw_threads, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(tfw_connects, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(tfw_messages, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(tfw_server, charp, 0);

MODULE_PARM_DESC(tfw_server, "Server host address and optional port nunber");
MODULE_LICENSE("GPL");

#define TFW_BOMBER_WAIT_INTVL		(2)		/* in seconds */
#define TFW_BOMBER_WAIT_MAX		(1 * 60)	/* in seconds */

/* Flags for tfw_bomber_desc_t.flags */
#define TFW_BOMBER_CONNECT_STARTED	(0x0001)
#define TFW_BOMBER_CONNECT_ESTABLISHED	(0x0002)
#define TFW_BOMBER_CONNECT_CLOSED	(0x0004)
#define TFW_BOMBER_CONNECT_ERROR	(0x0100)

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
static struct task_struct *tfw_bomber_finish_task;

DECLARE_WAIT_QUEUE_HEAD(tfw_bomber_connect_wq);
DECLARE_WAIT_QUEUE_HEAD(tfw_bomber_finish_wq);

static atomic_t tfw_bomber_nthread;
static atomic_t tfw_bomber_connect_nattempt;  /* Successful attempts */
static atomic_t tfw_bomber_connect_ncomplete; /* Connections established */
static atomic_t tfw_bomber_connect_nerror;    /* Number of errors */
static atomic_t tfw_bomber_request_nsend;     /* Number of requests */

static TfwAddr tfw_bomber_server_address;
static SsHooks tfw_bomber_hooks;

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
		atomic_inc(&tfw_bomber_connect_nerror);
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
		atomic_inc(&tfw_bomber_connect_nerror);
		return ret;
	}

	local_bh_enable();
	desc->sk = sk;
	desc->flags |= TFW_BOMBER_CONNECT_STARTED;
	atomic_inc(&tfw_bomber_connect_nattempt);

	return 0;
}

static void
msg_send(tfw_bomber_desc_t *desc)
{
	struct sock *sk;
	char *str;
	int len, ret;
	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;

	sk = desc->sk;
	BUG_ON(!sk);

	atomic_inc(&tfw_bomber_request_nsend);

	len = 1 * 1024 * 1024;
	str = vmalloc(len);
	if(!str) {
		SS_ERR("Could not allocate memory for request\n");
		return;
	}
	ret = fuzz_gen(str, str + len, 0, 1, FUZZ_REQ);
	if (ret == FUZZ_END)
		fuzz_reset();

	msg.ptr = str;
	msg.skb = NULL;
	msg.len = strlen(str);
	msg.flags = 0;

	req = tfw_http_msg_create(&it, Conn_Clnt, msg.len);
	tfw_http_msg_write(&it, req, &msg);
	local_bh_disable();
	ss_send(sk, &req->msg.skb_list, false);
	local_bh_enable();

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

	desc->flags |= TFW_BOMBER_CONNECT_ESTABLISHED;
	atomic_inc(&tfw_bomber_connect_ncomplete);
	wake_up(&tfw_bomber_finish_wq);

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

	desc->sk = NULL;
	desc->flags |= TFW_BOMBER_CONNECT_CLOSED;
	wake_up(&tfw_bomber_finish_wq);
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

	desc->sk = NULL;
	desc->flags |= TFW_BOMBER_CONNECT_ERROR;
	atomic_inc(&tfw_bomber_connect_nerror);
	wake_up(&tfw_bomber_finish_wq);
	return 0;
}

static SsHooks tfw_bomber_hooks = {
	.connection_new		= tfw_bomber_connect_complete,
	.connection_drop	= tfw_bomber_connection_close,
	.connection_error	= tfw_bomber_connection_error,
};

static void
tfw_bomber_send_msgs(void)
{
	int i, k, m;

	for (i = 0; i < tfw_threads; i++) {
		for (k = 0; k < tfw_connects; k++) {
			for (m = 0; m < tfw_messages; m++) {
				if (tfw_bomber_desc[i][k].sk) {
					msg_send(&tfw_bomber_desc[i][k]);
				}
			}
		}
	}
}

static void
bomber_report(void)
{
	printk("Initiated %d connects\n",
		tfw_connects * tfw_threads);
	printk("Of those %d connects initiated successfully\n",
		atomic_read(&tfw_bomber_connect_nattempt));
	printk("Of those %d connections were established successfully\n",
		atomic_read(&tfw_bomber_connect_ncomplete));
	printk("and %d connections completed with error\n",
		atomic_read(&tfw_bomber_connect_nerror));
	printk("and %d request sent\n",
		atomic_read(&tfw_bomber_request_nsend));
}

static void
tfw_bomber_release_sockets(void)
{
	int i, k;

	for (i = 0; i < tfw_threads; i++) {
		for (k = 0; k < tfw_connects; k++) {
			if (tfw_bomber_desc[i][k].sk) {
				local_bh_disable();
				tfw_bomber_desc[i][k].sk->sk_user_data = NULL;
				ss_close(tfw_bomber_desc[i][k].sk);
				local_bh_enable();
				tfw_bomber_desc[i][k].sk = NULL;
			}
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
	atomic_dec(&tfw_bomber_nthread);
	wake_up(&tfw_bomber_connect_wq);
	SS_DBG("Thread %d has initiated %d connects out of %d\n",
	       threadn, nconnects, tfw_connects);
	return 0;
}

static void
tfw_bomber_stop_threads(void)
{
	int i;

	for (i = 0; i < tfw_threads; i++) {
		if (tfw_bomber_connect_task[i]) {
			kthread_stop(tfw_bomber_connect_task[i]);
			tfw_bomber_connect_task[i] = NULL;
		}
	}

	if (tfw_bomber_finish_task) {
		kthread_stop(tfw_bomber_finish_task);
		tfw_bomber_finish_task = NULL;
	}
	tfw_bomber_release_sockets();
}

static int
tfw_bomber_thread_finish(void *data)
{
	int nattempt = atomic_read(&tfw_bomber_connect_nattempt);
	uint64_t time_max = (uint64_t)get_seconds() + TFW_BOMBER_WAIT_MAX;
	int ret = 0;
	int nerror, ncomplete;
	struct timeval tvs, tve;
	int delta;

	do_gettimeofday(&tvs);

	set_freezable();
	do {
		nerror = atomic_read(&tfw_bomber_connect_nerror);
		ncomplete = atomic_read(&tfw_bomber_connect_ncomplete);

		if (ncomplete + nerror == nattempt) {
			break;
		}
		wait_event_freezable_timeout(tfw_bomber_finish_wq,
				kthread_should_stop(),
				TFW_BOMBER_WAIT_INTVL);
		if ((uint64_t)get_seconds() > time_max) {
			SS_ERR("%s exceeded maximum wait time of %d seconds\n",
			       "tfw_bomber_thread_finish", TFW_BOMBER_WAIT_MAX);
			break;
		}
	} while (!kthread_should_stop() && ncomplete + nerror < nattempt);

	tfw_bomber_send_msgs();
	tfw_bomber_release_sockets();
	tfw_bomber_finish_task = NULL;

	do_gettimeofday(&tve);

	bomber_report();

	delta = (tve.tv_sec - tvs.tv_sec) * 1e6 + (tve.tv_usec - tvs.tv_usec);
	printk("Total time: %d usec\n",delta);

	return ret;
}

static int
tfw_bomber_create_tasks(void)
{
	int i, ret = 0;
	struct task_struct *task;

	task = kthread_create(tfw_bomber_thread_finish, 0,
			      "tfw_bomber_thread_finish");
	if (IS_ERR_OR_NULL(task)) {
		ret = PTR_ERR(task);
		SS_ERR("Unable to create thread: %s (%d)\n",
		       "tfw_bomber_finish_task", ret);
		return ret;
	}
	tfw_bomber_finish_task = task;

	for (i = 0; i < tfw_threads; i++) {
		task = kthread_create(tfw_bomber_thread_connect, (void *)(long)i,
				      "tfw_bomber_thread_connect_%02d", i);
		if (IS_ERR_OR_NULL(task)) {
			ret = PTR_ERR(task);
			SS_ERR("Unable to create a thread: %s%02d (%d)\n",
			       "tfw_bomber_thread_connect", i, ret);
			break;
		}
		tfw_bomber_connect_task[i] = task;

		atomic_set(&tfw_bomber_connect_nattempt, 0);
		atomic_set(&tfw_bomber_connect_ncomplete, 0);
		atomic_set(&tfw_bomber_connect_nerror, 0);
		atomic_set(&tfw_bomber_request_nsend, 0);
	}

	return ret;
}

static int __init
tfw_bomber_init(void)
{
	int i, j, ret = 0;

	if (tfw_addr_pton(tfw_server, &tfw_bomber_server_address)) {
		SS_ERR("Unable to parse server's address: %s", tfw_server);
		return -EINVAL;
	}
	SS_DBG("Started bomber module, server's address is %s\n", tfw_server);

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

	ret = tfw_bomber_create_tasks();

	if (ret) {
		goto err_create_tasks;
	} else {
		atomic_set(&tfw_bomber_nthread, tfw_threads);
		for (i = 0; i < tfw_threads; i++) {
			wake_up_process(tfw_bomber_connect_task[i]);
		}
		SS_DBG("Started %d threads to initiate %d connects each\n",
			tfw_threads, tfw_connects);
		wait_event_interruptible(tfw_bomber_connect_wq,
					 atomic_read(&tfw_bomber_nthread) == 0);
		wake_up_process(tfw_bomber_finish_task);
	}

	return ret;

err_create_tasks:
	tfw_bomber_stop_threads();
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

	fuzz_reset();
}

module_init(tfw_bomber_init);
module_exit(tfw_bomber_exit);
