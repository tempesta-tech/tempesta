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

static int nthreads	= 2;
static int niters	= 2;
static int nconnects	= 2;
static int nmessages	= 2;
static char *server	= "127.0.0.1:80";

module_param_named(t, nthreads,  int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(i, niters,    int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(c, nconnects, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(m, nmessages, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(s, server, charp, 0);

MODULE_PARM_DESC(t, "Number of threads (set this to the number of CPU cores)");
MODULE_PARM_DESC(i, "Number of thread iterations");
MODULE_PARM_DESC(c, "Number of connections");
MODULE_PARM_DESC(m, "Number of messages per connection");
MODULE_PARM_DESC(s, "Server host address and optional port nunber");

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

#define BUF_SIZE			(20 * 1024 * 1024)

/*
 * There's a descriptor for each connection that keeps the connection's
 * state and status. SsProto.type field is used here to store the index into
 * that array that can be passed around between callbacks.
 */
typedef struct task_struct tfw_bmb_task_t;
typedef struct tfw_bmb_desc {
	SsProto		proto;
	struct sock	*sk;
	uint32_t	flags;
} tfw_bmb_desc_t;

DECLARE_WAIT_QUEUE_HEAD(tfw_bmb_task_wq);
static wait_queue_head_t *tfw_bmb_conn_wq;

static tfw_bmb_task_t	**tfw_bmb_tasks;
static tfw_bmb_desc_t	**tfw_bmb_desc;
static int		**tfw_bmb_rdconn;
static atomic_t		tfw_bmb_nthread;
static atomic_t		*tfw_bmb_conn_nattempt;  /* Successful attempts */
static atomic_t		*tfw_bmb_conn_ncomplete; /* Connections established */
static atomic_t		*tfw_bmb_conn_nerror;    /* Number of errors */
static atomic_t		*tfw_bmb_rdconn_end;
static atomic_t		tfw_bmb_request_nsend;   /* Number of requests */
static TfwAddr		tfw_bmb_server_address;
static SsHooks		tfw_bmb_hooks;
static struct timeval	tvs, tve;
static char		**bufs;
static void		*alloc_ptr;

static int
tfw_bmb_conn_complete(struct sock *sk)
{
	int descidx, threadn, connn, end;
	tfw_bmb_desc_t *desc;
	SsProto *proto;

	proto = (SsProto *)sk->sk_user_data;
	BUG_ON(proto == NULL);

	descidx = proto->type;
	threadn = descidx / nconnects;
	connn = descidx % nconnects;

	desc = &tfw_bmb_desc[threadn][connn];
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->flags |= TFW_BMB_CONNECT_ESTABLISHED;

	end = atomic_read(&tfw_bmb_rdconn_end[threadn]);
	tfw_bmb_rdconn[threadn][end + 1] = connn;
	atomic_inc(&tfw_bmb_rdconn_end[threadn]);

	atomic_inc(&tfw_bmb_conn_ncomplete[threadn]);
	wake_up(&tfw_bmb_conn_wq[threadn]);
	return 0;
}

static int
tfw_bmb_conn_close(struct sock *sk)
{
	int descidx, threadn, connn;
	tfw_bmb_desc_t *desc;
	SsProto *proto;

	proto = (SsProto *)sk->sk_user_data;
	BUG_ON(proto == NULL);

	descidx = proto->type;
	threadn = descidx / nconnects;
	connn = descidx % nconnects;

	desc = &tfw_bmb_desc[threadn][connn];
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= TFW_BMB_CONNECT_CLOSED;
	wake_up(&tfw_bmb_conn_wq[threadn]);
	return 0;
}

static int
tfw_bmb_conn_error(struct sock *sk)
{
	int descidx, threadn, connn;
	tfw_bmb_desc_t *desc;
	SsProto *proto;

	proto = (SsProto *)sk->sk_user_data;
	BUG_ON(proto == NULL);

	descidx = proto->type;
	threadn = descidx / nconnects;
	connn = descidx % nconnects;

	desc = &tfw_bmb_desc[threadn][connn];
	BUG_ON(desc->proto.type != descidx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &tfw_bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= TFW_BMB_CONNECT_ERROR;
	atomic_inc(&tfw_bmb_conn_nerror[threadn]);
	wake_up(&tfw_bmb_conn_wq[threadn]);
	return 0;
}

static SsHooks tfw_bmb_hooks = {
	.connection_new		= tfw_bmb_conn_complete,
	.connection_drop	= tfw_bmb_conn_close,
	.connection_error	= tfw_bmb_conn_error,
};

static int
tfw_bmb_connect(int threadn, int connn)
{
	int ret;
	struct sock *sk;
	tfw_bmb_desc_t *desc = &tfw_bmb_desc[threadn][connn];

	ret = ss_sock_create(tfw_bmb_server_address.sa.sa_family,
			     SOCK_STREAM, IPPROTO_TCP, &sk);
	if (ret) {
		TFW_ERR("Unable to create kernel socket (%d)\n", ret);
		desc->flags |= TFW_BMB_CONNECT_ERROR;
		return ret;
	}
	ss_proto_init(&desc->proto, &tfw_bmb_hooks, threadn * nconnects + connn);
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
	atomic_inc(&tfw_bmb_conn_nattempt[threadn]);
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
	tfw_bmb_desc_t *desc;
	int c, r;
	char *s;
	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;

	desc = &tfw_bmb_desc[threadn][connn];
	BUG_ON(!desc->sk);

	c = 0;
	s = bufs[threadn];
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
	int nattempt, ncompl, nerror, nsend, end, k, i, c;

	for (k = 0; k < niters; k++)
	{
		for (i = 0; i < nconnects; i++) {
			tfw_bmb_connect(threadn, i);
		}

		set_freezable();
		time_max = (uint64_t)get_seconds() + TFW_BMB_WAIT_MAX;
		nattempt = atomic_read(&tfw_bmb_conn_nattempt[threadn]);
		do {
			ncompl = atomic_read(&tfw_bmb_conn_ncomplete[threadn]);
			if (ncompl > 0) {
				break;
			}

			nerror = atomic_read(&tfw_bmb_conn_nerror[threadn]);
			if (nerror == nattempt) {
				goto release_sockets;
			}

			wait_event_freezable_timeout(tfw_bmb_conn_wq[threadn],
						     kthread_should_stop(),
						     TFW_BMB_WAIT_INTVL * HZ);
			if ((uint64_t)get_seconds() > time_max) {
				TFW_ERR("%s exceeded maximum wait time of \
					%d sec\n",
					"worker", TFW_BMB_WAIT_MAX);
				goto release_sockets;
			}
		} while (!kthread_should_stop());

		nsend = 0;
		while (nsend < nconnects * nmessages) {
			end = atomic_read(&tfw_bmb_rdconn_end[threadn]);
			for (i = 0; i < end; i++){
				c = tfw_bmb_rdconn[threadn][i];
				if (tfw_bmb_desc[threadn][c].sk) {
					tfw_bmb_msg_send(threadn, c);
				}
				nsend++;
			}
		}

release_sockets:
		tfw_bmb_release_sockets(threadn);
	}

	do_gettimeofday(&tve);

	tfw_bmb_tasks[threadn] = NULL;
	atomic_dec(&tfw_bmb_nthread);
	wake_up(&tfw_bmb_task_wq);

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

	printk("Initiated %d connects\n", nconnects * niters * nthreads);
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

static int
tfw_bmb_alloc(void)
{
	int i;
	void *p;

	alloc_ptr = p = vzalloc(nthreads * sizeof(struct task_struct *) +
				nthreads * sizeof(tfw_bmb_desc_t *) +
				nthreads * sizeof(int *) +
				nthreads * sizeof(char *) +
				nthreads * sizeof(wait_queue_head_t) +
				nthreads * nconnects * sizeof(tfw_bmb_desc_t) +
				nthreads * nconnects * sizeof(int) +
				nthreads * BUF_SIZE * sizeof(char) +
				nthreads * 4 * sizeof(atomic_t));
	if (!alloc_ptr) {
		return -ENOMEM;
	}

	tfw_bmb_tasks = p;
	p += nthreads * sizeof(struct task_struct *);

	tfw_bmb_desc = p;
	p += nthreads * sizeof(tfw_bmb_desc_t *);

	tfw_bmb_rdconn = p;
	p += nthreads * sizeof(int *);

	bufs = p;
	p += nthreads * sizeof(char *);

	tfw_bmb_conn_wq = p;
	p += nthreads * sizeof(wait_queue_head_t);

	for (i = 0; i < nthreads; i++) {
		tfw_bmb_desc[i] = p;
		p += nconnects * sizeof(tfw_bmb_desc_t);

		tfw_bmb_rdconn[i] = p;;
		p += nconnects * sizeof(int);

		bufs[i] = p;
		p += BUF_SIZE * sizeof(char);
	}

	tfw_bmb_conn_nattempt  = p + 0 * nthreads * sizeof(atomic_t);
	tfw_bmb_conn_ncomplete = p + 1 * nthreads * sizeof(atomic_t);
	tfw_bmb_conn_nerror    = p + 2 * nthreads * sizeof(atomic_t);
	tfw_bmb_rdconn_end     = p + 3 * nthreads * sizeof(atomic_t);
	p += nthreads * 4 * sizeof(atomic_t);

	return 0;
}

static void
tfw_bmb_free(void)
{
	vfree(alloc_ptr);
}

static int __init
tfw_bmb_init(void)
{
	int i;

	fuzz_set_only_valid_gen(true);

	if (tfw_addr_pton(&TFW_STR_FROM(server), &tfw_bmb_server_address)) {
		TFW_ERR("Unable to parse server's address: %s", server);
		return -EINVAL;
	}
	TFW_DBG("Started bomber module, server's address is %s\n", server);

	if (tfw_bmb_alloc()) {
		return -ENOMEM;
	}

	atomic_set(&tfw_bmb_request_nsend, 0);
	for (i = 0; i < nthreads; i++) {
		struct task_struct *task;

		atomic_set(&tfw_bmb_conn_nattempt[i], 0);
		atomic_set(&tfw_bmb_conn_ncomplete[i], 0);
		atomic_set(&tfw_bmb_conn_nerror[i], 0);
		atomic_set(&tfw_bmb_rdconn_end[i], -1);

		init_waitqueue_head(&tfw_bmb_conn_wq[i]);

		task = kthread_create(tfw_bmb_worker, (void *)(long)i, "worker");
		if (IS_ERR_OR_NULL(task)) {
			TFW_ERR("Unable to create thread\n");
			tfw_bmb_free();
			return -EINVAL;
		}
		tfw_bmb_tasks[i] = task;
	}

	atomic_set(&tfw_bmb_nthread, nthreads);
	do_gettimeofday(&tvs);
	for (i = 0; i < nthreads; i++) {
		wake_up_process(tfw_bmb_tasks[i]);
	}

	wait_event_interruptible(tfw_bmb_task_wq,
				 atomic_read(&tfw_bmb_nthread) == 0);

	tfw_bmb_report();
	tfw_bmb_stop_threads();
	tfw_bmb_free();
	fuzz_reset();

	return 0;
}

static void
tfw_bmb_exit(void)
{
}

module_init(tfw_bmb_init);
module_exit(tfw_bmb_exit);
