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
#define TFW_BANNER		"[tfw_bomber] "

#define WAIT_MAX		(1 * 60)	/* in seconds */

#define CONNECT_STARTED 	(0x0001)
#define CONNECT_ESTABLISHED	(0x0002)
#define CONNECT_CLOSED		(0x0004)
#define CONNECT_ERROR		(0x0100)

#define BUF_SIZE		(20 * 1024 * 1024)

/*
 * There's a descriptor for each connection that keeps the connection's
 * state and status. SsProto.type field is used here to store the index into
 * that array that can be passed around between callbacks.
 */
typedef struct bmb_desc {
	SsProto		proto;
	struct sock	*sk;
	uint32_t	flags;
} TfwConDesc;

DECLARE_WAIT_QUEUE_HEAD(bmb_task_wq);
static wait_queue_head_t *bmb_conn_wq;

static struct task_struct **bmb_tasks;
static atomic_t bmb_nthread;

static TfwConDesc **bmb_desc;
static int **bmb_rdconn;

static atomic_t bmb_conn_nattempt_all;
static atomic_t bmb_conn_ncomplete_all;
static atomic_t bmb_conn_nerror_all;
static atomic_t bmb_conn_drop;
static atomic_t bmb_request_nsend_all;

static int *bmb_conn_nattempt;
static atomic_t *bmb_conn_ncomplete;
static atomic_t *bmb_conn_nerror;
static atomic_t *bmb_rdconn_end;

static TfwAddr bmb_server_address;
static SsHooks bmb_hooks;
static struct timeval bmb_tvs, bmb_tve;
static char **bmb_bufs;
static void *bmb_alloc_ptr;
static TfwFuzzContext *bmb_contexts;

static int
tfw_bmb_conn_complete(struct sock *sk)
{
	int idx, threadn, connn, end;
	TfwConDesc *desc;
	SsProto *proto;

	proto = (SsProto *)sk->sk_user_data;
	BUG_ON(proto == NULL);

	idx = proto->type;
	threadn = idx / nconnects;
	connn = idx % nconnects;

	desc = &bmb_desc[threadn][connn];
	BUG_ON(desc->proto.type != idx);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->flags |= CONNECT_ESTABLISHED;

	end = atomic_read(&bmb_rdconn_end[threadn]);
	bmb_rdconn[threadn][end] = connn;
	atomic_inc(&bmb_rdconn_end[threadn]);

	atomic_inc(&bmb_conn_ncomplete[threadn]);

	wake_up(&bmb_conn_wq[threadn]);

	return 0;
}

static int
__update_conn(struct sock *sk, int flags)
{
	int threadn, connn;
	TfwConDesc *desc;
	SsProto *proto;

	proto = (SsProto *)sk->sk_user_data;
	BUG_ON(proto == NULL);

	threadn = proto->type / nconnects;
	connn = proto->type % nconnects;

	desc = &bmb_desc[threadn][connn];
	BUG_ON(desc->proto.type != proto->type);
	BUG_ON(desc->proto.listener != NULL);
	BUG_ON(desc->proto.hooks != &bmb_hooks);
	BUG_ON(desc->sk && (desc->sk != sk));

	desc->sk = NULL;
	desc->flags |= flags;

	wake_up(&bmb_conn_wq[threadn]);

	return 0;
}

static int
tfw_bmb_conn_close(struct sock *sk)
{
	return __update_conn(sk, CONNECT_CLOSED);
}

static int
tfw_bmb_conn_error(struct sock *sk)
{
	SsProto *proto = (SsProto *)sk->sk_user_data;

	BUG_ON(proto == NULL);
	atomic_inc(&bmb_conn_nerror[proto->type / nconnects]);

	return __update_conn(sk, CONNECT_ERROR);
}

static SsHooks bmb_hooks = {
	.connection_new		= tfw_bmb_conn_complete,
	.connection_drop	= tfw_bmb_conn_close,
	.connection_error	= tfw_bmb_conn_error,
};

static int
tfw_bmb_connect(int threadn, int connn)
{
	int ret;
	struct sock *sk;
	TfwConDesc *desc;

	desc = &bmb_desc[threadn][connn];

	ret = ss_sock_create(bmb_server_address.sa.sa_family, SOCK_STREAM,
			     IPPROTO_TCP, &sk);
	if (ret) {
		TFW_ERR("Unable to create kernel socket (%d)\n", ret);
		desc->flags |= CONNECT_ERROR;
		return ret;
	}

	ss_proto_init(&desc->proto, &bmb_hooks, threadn * nconnects + connn);
	sk->sk_user_data = &desc->proto;
	ss_set_callbacks(sk);

	ret = ss_connect(sk, &bmb_server_address.sa,
			 tfw_addr_sa_len(&bmb_server_address), 0);
	if (ret) {
		TFW_ERR("Connect error on server socket sk %p (%d)\n", sk, ret);
		ss_release(sk);
		desc->flags |= CONNECT_ERROR;
		return ret;
        }

	desc->sk = sk;
	desc->flags |= CONNECT_STARTED;
	bmb_conn_nattempt[threadn]++;
	return 0;
}

static void
tfw_bmb_release_sockets(int threadn)
{
	int i;

	for (i = 0; i < nconnects; i++) {
		if (bmb_desc[threadn][i].sk) {
			ss_release(bmb_desc[threadn][i].sk);
			bmb_desc[threadn][i].sk = NULL;
		}
	}
}

static void
tfw_bmb_msg_send(int threadn, int connn)
{
	TfwConDesc *desc;
	int c, r;
	char *s;
	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;

	desc = &bmb_desc[threadn][connn];
	BUG_ON(!desc->sk);

	c = 0;
	s = bmb_bufs[threadn];
	do {
		c++;
		r = fuzz_gen(&bmb_contexts[threadn], s, s + BUF_SIZE, 0, 1,
			     FUZZ_REQ);
		if (r == FUZZ_END) {
			fuzz_init(&bmb_contexts[threadn], true);
		}
	} while ((r == FUZZ_END || r == FUZZ_INVALID) && c < 3);

	msg.ptr = s;
	msg.skb = NULL;
	msg.len = strlen(s);
	msg.flags = 0;

	req = tfw_http_msg_create(&it, Conn_Clnt, msg.len);
	if (!req) {
		TFW_WARN("Cannot create HTTP request.\n");
		return;
	}
	tfw_http_msg_write(&it, req, &msg);
	local_bh_disable();
	ss_send(desc->sk, &req->msg.skb_list, false);
	local_bh_enable();
	tfw_http_msg_free(req);

	atomic_inc(&bmb_request_nsend_all);
}

static int
tfw_bmb_worker(void *data)
{
	int thr_n = (int)(long)data;
	int nattempt, nsend, k, i;
	uint64_t time_max;

	fuzz_init(&bmb_contexts[thr_n], true);

	for (k = 0; k < niters; k++) {
		bmb_conn_nattempt[thr_n] = 0;
		atomic_set(&bmb_conn_ncomplete[thr_n], 0);
		atomic_set(&bmb_conn_nerror[thr_n], 0);
		atomic_set(&bmb_rdconn_end[thr_n], 0);
		init_waitqueue_head(&bmb_conn_wq[thr_n]);

		for (i = 0; i < nconnects; i++)
			tfw_bmb_connect(thr_n, i);

		set_freezable();
		time_max = (uint64_t)get_seconds() + WAIT_MAX;
		nattempt = bmb_conn_nattempt[thr_n];
		do {
#define COND()	(atomic_read(&bmb_conn_ncomplete[thr_n]) > 0		\
		 || atomic_read(&bmb_conn_nerror[thr_n]) == nattempt)

			wait_event_freezable_timeout(bmb_conn_wq[thr_n],
						     COND(), HZ);
#undef COND
			if (atomic_read(&bmb_conn_ncomplete[thr_n]) > 0)
				break;
			if (atomic_read(&bmb_conn_nerror[thr_n]) == nattempt) 
				goto release_sockets;
			if ((uint64_t)get_seconds() > time_max) {
				TFW_ERR("%s exceeded maximum wait time of \
					%d sec\n", "worker", WAIT_MAX);
				goto release_sockets;
			}
		} while (!kthread_should_stop());

		for (nsend = 0; nsend < nconnects * nmessages; ) {
			int end = atomic_read(&bmb_rdconn_end[thr_n]);
			for (i = 0; i < end; i++){
				int c = bmb_rdconn[thr_n][i];
				if (bmb_desc[thr_n][c].sk)
					tfw_bmb_msg_send(thr_n, c);
				else
					/* Connection is dropped. */
					atomic_inc(&bmb_conn_drop);
				nsend++;
			}
		}

release_sockets:
		atomic_add(nattempt, &bmb_conn_nattempt_all);
		atomic_add(atomic_read(&bmb_conn_ncomplete[thr_n]),
			   &bmb_conn_ncomplete_all);
		atomic_add(atomic_read(&bmb_conn_nerror[thr_n]),
			   &bmb_conn_nerror_all);

		tfw_bmb_release_sockets(thr_n);
	}

	do_gettimeofday(&bmb_tve);

	bmb_tasks[thr_n] = NULL;
	atomic_dec(&bmb_nthread);
	wake_up(&bmb_task_wq);

	return 0;
}

static void
tfw_bmb_stop_threads(void)
{
	int i;

	for (i = 0; i < nthreads; i++) {
		if (bmb_tasks[i]) {
			kthread_stop(bmb_tasks[i]);
			bmb_tasks[i] = NULL;
		}
	}
}

static void
tfw_bmb_report(void)
{
	TFW_LOG("BOMBER SUMMARY:");
	TFW_LOG("  total connections: %d\n", nconnects * niters * nthreads);
	TFW_LOG("  attempred connections: %d\n",
		atomic_read(&bmb_conn_nattempt_all));
	TFW_LOG("  completed connections: %d\n",
		atomic_read(&bmb_conn_ncomplete_all));
	TFW_LOG("  error connections: %d\n",
		atomic_read(&bmb_conn_nerror_all));
	TFW_LOG("  dropped connections: %d\n", atomic_read(&bmb_conn_drop));
	TFW_LOG("  total requests: %d\n",
		atomic_read(&bmb_request_nsend_all));
	TFW_LOG("  total time: %ldusec\n",
		(bmb_tve.tv_sec - bmb_tvs.tv_sec) * 1000000
		+ bmb_tve.tv_usec - bmb_tvs.tv_usec);
}

static int
tfw_bmb_alloc(void)
{
	int i;
	void *p;

	bmb_alloc_ptr = p = vzalloc(nthreads * sizeof(struct task_struct *) +
				    nthreads * sizeof(TfwConDesc *) +
				    nthreads * sizeof(int *) +
				    nthreads * sizeof(char *) +
				    nthreads * sizeof(wait_queue_head_t) +
				    nthreads * sizeof(int) +
				    nthreads * sizeof(TfwFuzzContext) +
				    nthreads * nconnects * sizeof(TfwConDesc) +
				    nthreads * nconnects * sizeof(int) +
				    nthreads * BUF_SIZE * sizeof(char) +
				    nthreads * 3 * sizeof(atomic_t));
	if (!bmb_alloc_ptr) {
		return -ENOMEM;
	}

	bmb_tasks = p;
	p += nthreads * sizeof(struct task_struct *);

	bmb_desc = p;
	p += nthreads * sizeof(TfwConDesc *);

	bmb_rdconn = p;
	p += nthreads * sizeof(int *);

	bmb_bufs = p;
	p += nthreads * sizeof(char *);

	bmb_conn_wq = p;
	p += nthreads * sizeof(wait_queue_head_t);

	bmb_conn_nattempt = p;
	p += nthreads * sizeof(int);

	bmb_contexts = p;
	p += nthreads * sizeof(TfwFuzzContext);

	for (i = 0; i < nthreads; i++) {
		bmb_desc[i] = p;
		p += nconnects * sizeof(TfwConDesc);

		bmb_rdconn[i] = p;
		p += nconnects * sizeof(int);

		bmb_bufs[i] = p;
		p += BUF_SIZE * sizeof(char);
	}

	bmb_conn_ncomplete = p + 0 * nthreads * sizeof(atomic_t);
	bmb_conn_nerror = p + 1 * nthreads * sizeof(atomic_t);
	bmb_rdconn_end = p + 2 * nthreads * sizeof(atomic_t);
	p += nthreads * 3 * sizeof(atomic_t);

	return 0;
}

static void
tfw_bmb_free(void)
{
	vfree(bmb_alloc_ptr);
}

static int __init
tfw_bmb_init(void)
{
	long i;
	int r;
	struct task_struct *task;

	r = 0;

	if (tfw_addr_pton(&TFW_STR_FROM(server), &bmb_server_address)) {
		TFW_ERR("Unable to parse server's address: %s", server);
		return -EINVAL;
	}
	TFW_DBG("Started bomber module, server's address is %s\n", server);

	if (tfw_bmb_alloc()) {
		return -ENOMEM;
	}

	atomic_set(&bmb_conn_nattempt_all, 0);
	atomic_set(&bmb_conn_ncomplete_all, 0);
	atomic_set(&bmb_conn_nerror_all, 0);
	atomic_set(&bmb_conn_drop, 0);
	atomic_set(&bmb_request_nsend_all, 0);
	for (i = 0; i < nthreads; i++) {
		task = kthread_create(tfw_bmb_worker, (void *)i, "worker");
		if (IS_ERR_OR_NULL(task)) {
			TFW_ERR("Unable to create worker\n");
			r = -EINVAL;
			goto stop_threads;
		}
		bmb_tasks[i] = task;
	}

	do_gettimeofday(&bmb_tvs);
	atomic_set(&bmb_nthread, nthreads);
	for (i = 0; i < nthreads; i++) {
		wake_up_process(bmb_tasks[i]);
	}

	wait_event_interruptible(bmb_task_wq, atomic_read(&bmb_nthread) == 0);
	tfw_bmb_report();

stop_threads:
	tfw_bmb_stop_threads();
	tfw_bmb_free();

	return r;
}

static void
tfw_bmb_exit(void)
{
}

module_init(tfw_bmb_init);
module_exit(tfw_bmb_exit);
