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

#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <net/inet_sock.h>

#include "addr.h"
#include "connection.h"
#include "http_msg.h"
#include "log.h"
#include "sync_socket.h"
#include "tfw_fuzzer.h"

static int nthreads = 2;
static int niter = 2;
static int nconnects = 2;
static int nmessages = 2;
static char *server = "127.0.0.1:80";

module_param(nthreads, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(niter, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(nconnects, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(nmessages, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param(server, charp, 0);

MODULE_PARM_DESC(nthreads,
		 "Number of threads (set this to the number of CPU cores)");
MODULE_PARM_DESC(niter, "Number of thread iterations");
MODULE_PARM_DESC(nconnects, "Number of connections");
MODULE_PARM_DESC(nmessages, "Number of messages by connection");
MODULE_PARM_DESC(server, "Server host address and optional port nunber");

MODULE_LICENSE("GPL");

#ifdef TFW_BANNER
#undef TFW_BANNER
#endif
#define TFW_BANNER			"[tfw_bomber] "

#define TFW_BMB_WAIT_INTVL		(2)		/* in seconds */
#define TFW_BMB_WAIT_MAX		(1 * 60)	/* in seconds */

#define TFW_BMB_CONNECT_STARTED		(0x0001)
#define TFW_BMB_CONNECT_ESTABLISHED	(0x0002)
#define TFW_BMB_CONNECT_CLOSED		(0x0004)
#define TFW_BMB_CONNECT_ERROR		(0x0100)

#define BUF_SIZE 20 * 1024 * 1024

/*
 * There's a descriptor for each connection that keeps the connection's
 * state and status. SsProto.type field is used here to store the index into
 * that array that can be passed around between callbacks.
 */
typedef struct tfw_bmb_desc {
	SsProto		proto;
	struct sock	*sk;
	uint32_t	flags;
} tfw_bmb_desc_t;

DECLARE_WAIT_QUEUE_HEAD(tfw_bmb_task_wq);
DECLARE_WAIT_QUEUE_HEAD(tfw_bmb_conn_wq);

static tfw_bmb_desc_t **tfw_bmb_desc;
static struct task_struct **tfw_bmb_tasks;
static atomic_t tfw_bmb_nthread;
static atomic_t *tfw_bmb_conn_nattempt;		/* Successful attempts */
static atomic_t *tfw_bmb_conn_ncomplete;	/* Connections established */
static atomic_t *tfw_bmb_conn_nerror;		/* Number of errors */
static atomic_t tfw_bmb_request_nsend;		/* Number of requests */
static TfwAddr tfw_bmb_server_address;
static SsHooks tfw_bmb_hooks;
static struct timeval tvs, tve;
static char **bufs;

static int
tfw_bmb_conn_complete(struct sock *sk)
{
	int descidx;
	tfw_bmb_desc_t *desc;
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(tfw_bmb_desc + descidx / nconnects)
			      + descidx % nconnects;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->flags |= TFW_BMB_CONNECT_ESTABLISHED;
	atomic_inc(&tfw_bmb_conn_ncomplete[descidx / nconnects]);
	wake_up(&tfw_bmb_conn_wq);
	return 0;
}

static int
tfw_bmb_conn_close(struct sock *sk)
{
	int descidx;
	tfw_bmb_desc_t *desc;
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(tfw_bmb_desc + descidx / nconnects)
			      + descidx % nconnects;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= TFW_BMB_CONNECT_CLOSED;
	wake_up(&tfw_bmb_conn_wq);
	return 0;
}

static int
tfw_bmb_conn_error(struct sock *sk)
{
	int descidx;
	tfw_bmb_desc_t *desc;
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);

	descidx = proto->type;
	desc = *(tfw_bmb_desc + descidx / nconnects)
			      + descidx % nconnects;
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= TFW_BMB_CONNECT_ERROR;
	atomic_inc(&tfw_bmb_conn_nerror[descidx / nconnects]);
	wake_up(&tfw_bmb_conn_wq);
	return 0;
}

static SsHooks tfw_bmb_hooks = {
	.connection_new		= tfw_bmb_conn_complete,
	.connection_drop	= tfw_bmb_conn_close,
	.connection_error	= tfw_bmb_conn_error,
};

static int
tfw_bmb_connect(int descidx)
{
	int ret;
	struct sock *sk;
	tfw_bmb_desc_t *desc = *(tfw_bmb_desc + descidx / nconnects)
					      + descidx % nconnects;

	ret = ss_sock_create(tfw_bmb_server_address.sa.sa_family,
			     SOCK_STREAM, IPPROTO_TCP, &sk);
	if (ret) {
		TFW_ERR("Unable to create kernel socket (%d)\n", ret);
		desc->flags |= TFW_BMB_CONNECT_ERROR;
		return ret;
	}
	ss_proto_init(&desc->proto, &tfw_bmb_hooks, descidx);
	sk->sk_user_data = &desc->proto;
	ss_set_callbacks(sk);
	ret = ss_connect(sk, &tfw_bmb_server_address.sa,
			 tfw_addr_sa_len(&tfw_bmb_server_address), 0);
	if (ret) {
		TFW_ERR("Connect error on server socket sk %p (%d)\n", sk, ret);
		ss_release(sk);
		desc->flags |= TFW_BMB_CONNECT_ERROR;
		return ret;
        }
	desc->sk = sk;
	desc->flags |= TFW_BMB_CONNECT_STARTED;
	atomic_inc(&tfw_bmb_conn_nattempt[descidx / nconnects]);
	return 0;
}

static void
tfw_bmb_release_sockets(int threadn)
{
	int i;

	for (i = 0; i < nconnects; i++) {
		if (tfw_bmb_desc[threadn][i].sk) {
			ss_release(tfw_bmb_desc[threadn][i].sk);
			tfw_bmb_desc[threadn][i].sk = NULL;
		}
	}
}

static void
tfw_bmb_msg_send(int threadn, int connn)
{
	tfw_bmb_desc_t *desc = &tfw_bmb_desc[threadn][connn];
	char *s = bufs[threadn];
	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;
	int c = 0, r;

	BUG_ON(!desc->sk);

	do {
		c++;
		r = fuzz_gen(s, s + BUF_SIZE, 0, 1, FUZZ_REQ);
		if (r == FUZZ_END) {
			fuzz_reset();
		}
	} while ((r == FUZZ_END || r == FUZZ_INVALID) && c < 3);

	msg.ptr = s;
	msg.skb = NULL;
	msg.len = strlen(s);
	msg.flags = 0;

	req = tfw_http_msg_create(&it, Conn_Clnt, msg.len);
	tfw_http_msg_write(&it, req, &msg);
	local_bh_disable();
	ss_send(desc->sk, &req->msg.skb_list, false);
	local_bh_enable();
	tfw_http_msg_free(req);

	atomic_inc(&tfw_bmb_request_nsend);
}

static int
tfw_bmb_worker(void *data)
{
	int threadn = (int)(long)data;
	uint64_t time_max;
	int nattempt, k, i, j;

	for (k = 0; k < niter; k++)
	{
		for (i = 0; i < nconnects; i++) {
			tfw_bmb_connect(threadn * nconnects + i);
		}

		set_freezable();
		time_max = (uint64_t)get_seconds() + TFW_BMB_WAIT_MAX;
		nattempt = atomic_read(&tfw_bmb_conn_nattempt[threadn]);
		do {
			int nerror, ncompl;

			nerror = atomic_read(&tfw_bmb_conn_nerror[threadn]);
			ncompl = atomic_read(&tfw_bmb_conn_ncomplete[threadn]);
			if (ncompl + nerror == nattempt) {
				break;
			}
			wait_event_freezable_timeout(tfw_bmb_conn_wq,
						     kthread_should_stop(),
						     TFW_BMB_WAIT_INTVL);
			if ((uint64_t)get_seconds() > time_max) {
				TFW_ERR("%s exceeded maximum wait time of \
					%d sec\n",
					"worker", TFW_BMB_WAIT_MAX);
				break;
			}
		} while (!kthread_should_stop());

		for (i = 0; i < nconnects; i++) {
			for (j = 0; j < nmessages; j++) {
				if (tfw_bmb_desc[threadn][i].sk) {
					tfw_bmb_msg_send(threadn, i);
				}
			}
		}

		tfw_bmb_release_sockets(threadn);
	}

	tfw_bmb_tasks[threadn] = NULL;
	atomic_dec(&tfw_bmb_nthread);
	wake_up(&tfw_bmb_task_wq);

	do_gettimeofday(&tve);
	return 0;
}

static void
tfw_bmb_stop_threads(void)
{
	int i;

	for (i = 0; i < nthreads; i++) {
		if (tfw_bmb_tasks[i]) {
			kthread_stop(tfw_bmb_tasks[i]);
			tfw_bmb_tasks[i] = NULL;
		}
	}
}

static void
tfw_bmb_report(void)
{
	int i, nattempt, ncomplete, nerror;

	nattempt = ncomplete = nerror = 0;
	for (i = 0; i < nthreads; i++)
	{
		nattempt += atomic_read(&tfw_bmb_conn_nattempt[i]);
		ncomplete += atomic_read(&tfw_bmb_conn_ncomplete[i]);
		nerror += atomic_read(&tfw_bmb_conn_nerror[i]);
	}

	printk("Initiated %d connects\n", nconnects * niter * nthreads);
	printk("Of those %d connects initiated successfully\n",
		nattempt);
	printk("Of those %d connections were established successfully\n",
		ncomplete);
	printk("and %d connections completed with error\n",
		nerror);
	printk("and %d requests sent\n",
		atomic_read(&tfw_bmb_request_nsend));
	printk("Total time: %ld usec\n", (tve.tv_sec - tvs.tv_sec) * 1000000 +
					 (tve.tv_usec - tvs.tv_usec));
}

static int __init
tfw_bmb_init(void)
{
	int i, j, ret = 0;

	fuzz_set_only_valid_gen(true);

	if (tfw_addr_pton(&TFW_STR_FROM(server), &tfw_bmb_server_address)) {
		TFW_ERR("Unable to parse server's address: %s", server);
		return -EINVAL;
	}
	TFW_DBG("Started bomber module, server's address is %s\n", server);

	tfw_bmb_desc = kmalloc(nthreads * sizeof(tfw_bmb_desc_t *), GFP_KERNEL);
	if (!tfw_bmb_desc) {
		return -ENOMEM;
	}

	for (i = 0; i < nthreads; i++) {
		tfw_bmb_desc[i] = kzalloc(nconnects * sizeof(tfw_bmb_desc_t),
					  GFP_KERNEL);
		if (!tfw_bmb_desc[i]) {
			for (j = 0; j < i; j++)
				kfree(tfw_bmb_desc[i]);
			ret = -ENOMEM;
			goto err_malloc_desc;
		}
	}

	tfw_bmb_tasks = kzalloc(nthreads * sizeof(struct task_struct *),
				GFP_KERNEL);
	if (!tfw_bmb_tasks) {
		ret = -ENOMEM;
		goto err_malloc_tasks;
	}

	tfw_bmb_conn_nattempt = kmalloc(nthreads * sizeof(atomic_t *),
					GFP_KERNEL);
	if (!tfw_bmb_conn_nattempt) {
		ret = -ENOMEM;
		goto err_malloc_nattempt;
	}

	tfw_bmb_conn_ncomplete = kmalloc(nthreads * sizeof(atomic_t *),
					 GFP_KERNEL);
	if (!tfw_bmb_conn_ncomplete) {
		ret = -ENOMEM;
		goto err_malloc_ncomplete;
	}

	tfw_bmb_conn_nerror = kmalloc(nthreads * sizeof(atomic_t *),
				      GFP_KERNEL);
	if (!tfw_bmb_conn_nerror) {
		ret = -ENOMEM;
		goto err_malloc_nerror;
	}

	bufs = kmalloc(nthreads * sizeof(char *), GFP_KERNEL);
	if (!bufs) {
		ret = -ENOMEM;
		goto err_malloc_bufs;
	}

	for (i = 0; i < nthreads; i++) {
		bufs[i] = vmalloc(BUF_SIZE * sizeof(char));
		if (!bufs[i]) {
			for (j = 0; j < i; j++)
				vfree(bufs[i]);
			ret = -ENOMEM;
			goto err_malloc_buf;
		}
	}

	for (i = 0; i < nthreads; i++) {
		atomic_set(&tfw_bmb_conn_nattempt[i], 0);
		atomic_set(&tfw_bmb_conn_ncomplete[i], 0);
		atomic_set(&tfw_bmb_conn_nerror[i], 0);
	}
	atomic_set(&tfw_bmb_request_nsend, 0);

	for (i = 0; i < nthreads; i++) {
		struct task_struct *task;

		task = kthread_create(tfw_bmb_worker, (void *)(long)i, "worker");
		if (IS_ERR_OR_NULL(task)) {
			ret = PTR_ERR(task);
			TFW_ERR("Unable to create thread: (%d)\n", ret);
			goto err_create_tasks;
		}
		tfw_bmb_tasks[i] = task;
	}

	do_gettimeofday(&tvs);
	atomic_set(&tfw_bmb_nthread, nthreads);
	for (i = 0; i < nthreads; i++) {
		wake_up_process(tfw_bmb_tasks[i]);
	}

	wait_event_interruptible(tfw_bmb_task_wq,
				 atomic_read(&tfw_bmb_nthread) == 0);

	tfw_bmb_report();
	fuzz_reset();

err_create_tasks:
	tfw_bmb_stop_threads();

err_malloc_buf:
	kfree(bufs);

err_malloc_bufs:
	kfree(tfw_bmb_conn_nerror);

err_malloc_nerror:
	kfree(tfw_bmb_conn_ncomplete);

err_malloc_ncomplete:
	kfree(tfw_bmb_conn_nattempt);

err_malloc_nattempt:
	kfree(tfw_bmb_tasks);

err_malloc_tasks:
	for (i = 0; i < nthreads; i++)
		kfree(tfw_bmb_desc[i]);

err_malloc_desc:
	kfree(tfw_bmb_desc);

	return 0;
}

static void
tfw_bmb_exit(void)
{
}

module_init(tfw_bmb_init);
module_exit(tfw_bmb_exit);
