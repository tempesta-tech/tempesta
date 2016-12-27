/**
 *		Tempesta FW
 *
 * Tempesta Bomber: a tool for HTTP servers stress testing.
 *
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <net/inet_sock.h>

#include "addr.h"
#include "connection.h"
#include "http_msg.h"
#include "log.h"
#include "sync_socket.h"
#include "fuzzer.h"

static int nthreads	= 2;
static int niters	= 2;
static int nconns	= 2;
static int nmessages	= 2;
static int verbose	= 0;
static char *server	= "127.0.0.1:80";

module_param_named(t, nthreads,  int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(i, niters,    int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(c, nconns,    int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(m, nmessages, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(v, verbose,   int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
module_param_named(s, server, charp, 0);

MODULE_PARM_DESC(t, "Number of threads (set this to the number of CPU cores)");
MODULE_PARM_DESC(i, "Number of thread iterations");
MODULE_PARM_DESC(c, "Number of connections");
MODULE_PARM_DESC(m, "Number of messages per connection");
MODULE_PARM_DESC(v, "Verbosity level");
MODULE_PARM_DESC(s, "Server host address and optional port nunber");

MODULE_AUTHOR("Tempesta Technologies, Inc");
MODULE_DESCRIPTION("Tempesta Boomber");
MODULE_VERSION("0.2.3");
MODULE_LICENSE("GPL");

#ifdef TFW_BANNER
#undef TFW_BANNER
#endif
#define TFW_BANNER		"[tfw_bomber] "

#define BUF_SIZE		(20 * 1024 * 1024)
#define DEAD_TRIES		HZ

enum {
	TFW_BMB_SK_INACTIVE,
	TFW_BMB_SK_ACTIVE
};

struct tfw_bmb_task_t;

/*
 * Connection descripton.
 */
typedef struct {
	SsProto			proto;
	struct sock 		*sk;
	struct tfw_bmb_task_t	*task;
} TfwBmbConn;

/*
 * Bomber task descriptor.
 *
 * @conn		- connection descriptions
 * @conn_compl		- number of complate connections
 * @conn_error		- number of error connections
 * @conn_wq		- wait queue on all connections establishing
 * @ctx			- context for fuzzer
 * @buf			- request buffer for fuzzer
 */
typedef struct tfw_bmb_task_t {
	struct task_struct	*task_struct;
	TfwBmbConn		*conn;
	atomic_t		conn_compl;
	atomic_t		conn_error;
	wait_queue_head_t	conn_wq;
	TfwFuzzContext		ctx;
	char 			buf[BUF_SIZE];
} TfwBmbTask;

DECLARE_WAIT_QUEUE_HEAD(bmb_task_wq);

static atomic_t bmb_threads 		= ATOMIC_INIT(0);
static atomic_t bmb_conn_attempt	= ATOMIC_INIT(0);
static atomic_t bmb_conn_compl		= ATOMIC_INIT(0);
static atomic_t bmb_conn_error		= ATOMIC_INIT(0);
static atomic_t bmb_conn_drop		= ATOMIC_INIT(0);
static atomic_t bmb_request_send	= ATOMIC_INIT(0);

static TfwAddr bmb_server_address;
static SsHooks bmb_hooks;
static TfwBmbTask *bmb_tasks;

static inline void
__check_conn(TfwBmbConn *conn)
{
	BUG_ON(conn->proto.listener);
	BUG_ON(conn->proto.hooks != &bmb_hooks);
	BUG_ON(!conn->sk);
	BUG_ON(!conn->task);
}

static int
tfw_bmb_conn_compl(struct sock *sk)
{
	TfwBmbConn *conn = sk->sk_user_data;

	BUG_ON(!conn);
	conn->proto.type = TFW_BMB_SK_ACTIVE;
	__check_conn(conn);

	atomic_inc(&conn->task->conn_compl);
	wake_up(&conn->task->conn_wq);

	return 0;
}

static int
tfw_bmb_conn_drop(struct sock *sk)
{
	TfwBmbConn *conn = sk->sk_user_data;

	BUG_ON(!conn);
	__check_conn(conn);

	atomic_inc(&bmb_conn_drop);
	atomic_inc(&conn->task->conn_error);

	tfw_connection_unlink_from_sk(sk);
	conn->proto.type = TFW_BMB_SK_INACTIVE;

	wake_up(&conn->task->conn_wq);

	return 0;
}

static int
tfw_bmb_print_msg(void *msg_data, unsigned char *data, size_t len)
{
	printk(KERN_INFO "%.*s\n", (int)len, data);
	return 0;
}

static int
tfw_bmb_conn_recv(void *cdata, struct sk_buff *skb, unsigned int off)
{
	if (verbose) {
		unsigned int data_off = 0;

		TFW_LOG("Server response:\n------------------------------\n");
		ss_skb_process(skb, &data_off, tfw_bmb_print_msg, NULL);
		printk(KERN_INFO "\n------------------------------\n");
	}

	__kfree_skb(skb);
	return TFW_PASS;
}

static SsHooks bmb_hooks = {
	.connection_new		= tfw_bmb_conn_compl,
	.connection_drop	= tfw_bmb_conn_drop,
	.connection_error	= tfw_bmb_conn_drop,
	.connection_recv	= tfw_bmb_conn_recv,
};

static int
tfw_bmb_connect(TfwBmbTask *task, TfwBmbConn *conn)
{
	int ret;
	struct sock *sk;

	ret = ss_sock_create(bmb_server_address.sa.sa_family, SOCK_STREAM,
			     IPPROTO_TCP, &sk);
	if (ret) {
		TFW_ERR("Unable to create kernel socket (%d)\n", ret);
		return ret;
	}

	ss_proto_init(&conn->proto, &bmb_hooks, TFW_BMB_SK_INACTIVE);
	sk->sk_user_data = &conn->proto;
	ss_set_callbacks(sk);
	conn->sk = sk;
	conn->task = task;

	ret = ss_connect(sk, &bmb_server_address.sa,
			 tfw_addr_sa_len(&bmb_server_address), 0);
	if (ret) {
		TFW_ERR("Connect error on server socket sk %p (%d)\n", sk, ret);
		ss_close_sync(sk, false);
		conn->sk = NULL;
		return ret;
        }

	return 0;
}

static void
tfw_bmb_release_sockets(TfwBmbTask *task)
{
	int i;

	for (i = 0; i < nconns; i++) {
		if (task->conn[i].proto.type == TFW_BMB_SK_INACTIVE)
			/* The socket is dead or softirq is killing it. */
			continue;
		if (ss_close_sync(task->conn[i].sk, true))
			TFW_WARN("Cannot close %dth socket\n", i);
	}
}

static void
tfw_bmb_msg_send(TfwBmbTask *task, int cn)
{
	int fz_tries = 0, r;
	TfwStr msg;
	TfwHttpMsg req;
	TfwMsgIter it;

	do {
		if (++fz_tries > 10) {
			TFW_ERR("Too many fuzzer tries to generate request\n");
			return;
		}

		r = fuzz_gen(&task->ctx, task->buf, &task->buf[BUF_SIZE], 0, 1,
			     FUZZ_REQ);
		if (r < 0) {
			TFW_ERR("Cannot generate HTTP request, r=%d\n", r);
			return;
		}
		if (r == FUZZ_END)
			fuzz_init(&task->ctx, true);
	} while (r != FUZZ_VALID);

	msg.ptr = task->buf;
	msg.skb = NULL;
	msg.len = strlen(msg.ptr);
	msg.flags = 0;
	BUG_ON(msg.len > BUF_SIZE);

	if (!tfw_http_msg_create(&req, &it, Conn_Clnt, msg.len)) {
		TFW_WARN("Cannot create HTTP request.\n");
		return;
	}

	if (verbose)
		TFW_LOG("Send request:\n"
			"------------------------------\n"
			"%s\n"
			"------------------------------\n",
			task->buf);

	tfw_http_msg_write(&it, &req, &msg);
	ss_send(task->conn[cn].sk, &req.msg.skb_list, true);

	atomic_inc(&bmb_request_send);
}

static void
do_send_work(TfwBmbTask *task, int to_send)
{
	int c, sent = 0, dead_try = 0;

	while (1) {
		int prev_sent = sent;
		for (c = 0; c < nconns; ++c) {
			if (task->conn[c].proto.type == TFW_BMB_SK_INACTIVE)
				continue;
			tfw_bmb_msg_send(task, c);
			if (++sent == to_send)
				return;
			dead_try = 0;
		}
		if (prev_sent == sent) {
			if (++dead_try == DEAD_TRIES) {
				TFW_WARN("Dead sockets, sent %d\n", sent);
				return;
			} else {
				schedule();
			}
		}
	}
}

static int
tfw_bmb_worker(void *data)
{
	int attempt, i, c;
	unsigned long time_max;
	TfwBmbTask *task = data;

	fuzz_init(&task->ctx, true);

	for (i = 0; i < niters; i++) {
		attempt = 0;
		atomic_set(&task->conn_compl, 0);
		atomic_set(&task->conn_error, 0);
		init_waitqueue_head(&task->conn_wq);

		for (c = 0; c < nconns; c++)
			if (!tfw_bmb_connect(task, task->conn + c))
				++attempt;

		set_freezable();
		time_max = jiffies + 60 * HZ;
		do {
#define COND()	(atomic_read(&task->conn_compl) > 0 || \
		 atomic_read(&task->conn_error) == attempt)
			wait_event_freezable_timeout(task->conn_wq, COND(), HZ);
#undef COND
			if (atomic_read(&task->conn_compl) > 0)
				break;
			if (atomic_read(&task->conn_error) == attempt)
				goto release_sockets;
			if (jiffies > time_max) {
				TFW_ERR("worker exceeded maximum wait time\n");
				goto release_sockets;
			}
		} while (!kthread_should_stop());

		do_send_work(task, nconns * nmessages);

release_sockets:
		atomic_add(attempt, &bmb_conn_attempt);
		atomic_add(atomic_read(&task->conn_compl), &bmb_conn_compl);
		atomic_add(atomic_read(&task->conn_error), &bmb_conn_error);

		tfw_bmb_release_sockets(task);
		/* Wait till softirq closes all connections. */
		for (c = 0; c < nconns; c++) {
			int tries = 0;
			while (task->conn[c].proto.type == TFW_BMB_SK_ACTIVE) {
				schedule();
				if (++tries == DEAD_TRIES) {
					local_bh_disable();
					ss_close_sync(task->conn[c].sk, false);
					local_bh_enable();
					break;
				}
			}
		}

		/*
		 * FIXME at this point work_queue still can contain many works.
		 * The wait loop above can be passed by connection error at
		 * the middle of the work queue processing, i.e. softirq
		 * still didn't process our ss_close() work. Thus freed sockets
		 * crash is possible when we're done.
		 */
	}

	task->task_struct = NULL;
	atomic_dec(&bmb_threads);
	wake_up(&bmb_task_wq);

	return 0;
}

static void
tfw_bmb_stop_threads(void)
{
	int i;

	for (i = 0; i < nthreads; i++) {
		if (bmb_tasks[i].task_struct) {
			/* FIXME possible race with the thread completion. */
			kthread_stop(bmb_tasks[i].task_struct);
			bmb_tasks[i].task_struct = NULL;
			atomic_dec(&bmb_threads);
		}
	}
}

/*
 * TODO add server performance measurement.
 */
static void
tfw_bmb_report(unsigned long ts_start)
{
	/* Always print full message regardless debug level. */
#define R(...)	pr_info(TFW_BANNER __VA_ARGS__)
	R("BOMBER SUMMARY:");
	R("  total connections: %d\n", nconns * niters * nthreads);
	R("  attempted connections: %d\n", atomic_read(&bmb_conn_attempt));
	R("  completed connections: %d\n", atomic_read(&bmb_conn_compl));
	R("  error connections: %d\n", atomic_read(&bmb_conn_error));
	R("  dropped connections: %d\n", atomic_read(&bmb_conn_drop));
	R("  total requests: %d\n", atomic_read(&bmb_request_send));
	R("  total time: %ldms\n", jiffies - ts_start);
#undef R
}

static int
tfw_bmb_alloc(void)
{
	int i;
	char *p;

	p = vzalloc(nthreads * (sizeof(TfwBmbTask)
				+ nconns * sizeof(TfwBmbConn)));
	if (!p)
		return -ENOMEM;

	bmb_tasks = (TfwBmbTask *)p;
	p += nthreads * sizeof(TfwBmbTask);
	for (i = 0; i < nthreads; i++) {
		bmb_tasks[i].conn = (TfwBmbConn *)p;
		p += nconns * sizeof(TfwBmbConn);
	}

	return 0;
}

static void
tfw_bmb_free(void)
{
	if (bmb_tasks) {
		vfree(bmb_tasks);
		bmb_tasks = NULL;
	}
}

static int __init
tfw_bmb_init(void)
{
	long i;
	volatile unsigned long ts_start;
	struct task_struct *task;
	int r = 0;

	if (tfw_addr_pton(&TFW_STR_FROM(server), &bmb_server_address)) {
		TFW_ERR("Unable to parse server's address: %s", server);
		return -EINVAL;
	}
	TFW_LOG("Started bomber module, server's address is %s\n", server);

	if (tfw_bmb_alloc())
		return -ENOMEM;

	ts_start = jiffies;

	for (i = 0; i < nthreads; i++) {
		task = kthread_create(tfw_bmb_worker, bmb_tasks + i, "bomber");
		if (IS_ERR_OR_NULL(task)) {
			TFW_ERR("Unable to create worker\n");
			r = -EINVAL;
			tfw_bmb_stop_threads();
			goto out;
		}
		bmb_tasks[i].task_struct = task;
		atomic_inc(&bmb_threads);
	}
	for (i = 0; i < nthreads; i++)
		wake_up_process(bmb_tasks[i].task_struct);

	wait_event_interruptible(bmb_task_wq, !atomic_read(&bmb_threads));

	tfw_bmb_report(ts_start);
out:
	tfw_bmb_free();

	return r;
}

static void
tfw_bmb_exit(void)
{
	if (!bmb_tasks)
		return; /* already stopped and freed */

	tfw_bmb_stop_threads();
	tfw_bmb_free();
}

module_init(tfw_bmb_init);
module_exit(tfw_bmb_exit);
