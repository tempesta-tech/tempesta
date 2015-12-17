/**
 *		Tempesta FW
 *
 * Tempesta Bomber: a tool for HTTP servers stress testing.
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
MODULE_VERSION("0.2.0");
MODULE_LICENSE("GPL");

#ifdef TFW_BANNER
#undef TFW_BANNER
#endif
#define TFW_BANNER		"[tfw_bomber] "

#define CONNECT_STARTED 	0x0001
#define CONNECT_ESTABLISHED	0x0002
#define CONNECT_CLOSED		0x0004
#define CONNECT_ERROR		0x0100

#define BUF_SIZE		(20 * 1024 * 1024)

/*
 * There's a descriptor for each connection that keeps the connection's
 * state and status. SsProto.type field is used here to store the index into
 * that array that can be passed around between callbacks.
 */
struct bmb_conn {
	SsProto		proto;
	struct sock	*sk;
	uint32_t	flags;
};

struct bmb_task {
	struct task_struct	*task_struct;

	struct bmb_conn		*conn;
	int			*conn_rd;
	atomic_t		conn_rd_tail;
	wait_queue_head_t	conn_wq;
	int			conn_attempt;
	atomic_t		conn_compl;
	atomic_t		conn_error;

	TfwFuzzContext		ctx;
	char 			*buf;
};

DECLARE_WAIT_QUEUE_HEAD(bmb_task_wq);

static atomic_t bmb_threads 		= ATOMIC_INIT(0);
static atomic_t bmb_conn_attempt	= ATOMIC_INIT(0);
static atomic_t bmb_conn_compl		= ATOMIC_INIT(0);
static atomic_t bmb_conn_error		= ATOMIC_INIT(0);
static atomic_t bmb_conn_drop		= ATOMIC_INIT(0);
static atomic_t bmb_request_send	= ATOMIC_INIT(0);

static TfwAddr bmb_server_address;
static SsHooks bmb_hooks;
static void *bmb_alloc_ptr;
static struct bmb_task *bmb_task;

static int
tfw_bmb_conn_compl(struct sock *sk)
{
	SsProto *proto = (SsProto *)rcu_dereference_sk_user_data(sk);
	struct bmb_task *task;
	struct bmb_conn *conn;
	int tail;

	BUG_ON(!proto);

	task = &bmb_task[proto->type / nconns];
	conn = &task->conn[proto->type % nconns];

	BUG_ON(conn->proto.type != proto->type);
	BUG_ON(conn->proto.listener != NULL);
	BUG_ON(conn->proto.hooks != &bmb_hooks);
	BUG_ON(conn->sk && (conn->sk != sk));

	conn->flags |= CONNECT_ESTABLISHED;

	tail = atomic_read(&task->conn_rd_tail);
	task->conn_rd[tail] = proto->type % nconns;
	atomic_inc(&task->conn_rd_tail);

	atomic_inc(&task->conn_compl);

	wake_up(&task->conn_wq);

	return 0;
}

static int
__update_conn(struct sock *sk, int flags)
{
	SsProto *proto = (SsProto *)rcu_dereference_sk_user_data(sk);
	struct bmb_task *task;
	struct bmb_conn *conn;

	BUG_ON(proto == NULL);

	task = &bmb_task[proto->type / nconns];
	conn = &task->conn[proto->type % nconns];

	BUG_ON(conn->proto.type != proto->type);
	BUG_ON(conn->proto.listener != NULL);
	BUG_ON(conn->proto.hooks != &bmb_hooks);
	BUG_ON(conn->sk && (conn->sk != sk));

	conn->sk = NULL;
	conn->flags |= flags;

	wake_up(&task->conn_wq);

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
	SsProto *proto = (SsProto *)rcu_dereference_sk_user_data(sk);

	BUG_ON(proto == NULL);
	atomic_inc(&bmb_task[proto->type / nconns].conn_error);

	return __update_conn(sk, CONNECT_ERROR);
}

static int
tfw_bmb_print_msg(void *msg_data, unsigned char *data, size_t len)
{
	printk(KERN_INFO "%.*s", (int)len, data);
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
	.connection_drop	= tfw_bmb_conn_close,
	.connection_error	= tfw_bmb_conn_error,
	.connection_recv	= tfw_bmb_conn_recv,
};

static int
tfw_bmb_connect(int tn, int cn)
{
	int ret;
	struct sock *sk;
	struct bmb_conn *conn;

	conn = &bmb_task[tn].conn[cn];

	ret = ss_sock_create(bmb_server_address.sa.sa_family, SOCK_STREAM,
			     IPPROTO_TCP, &sk);
	if (ret) {
		TFW_ERR("Unable to create kernel socket (%d)\n", ret);
		conn->flags |= CONNECT_ERROR;
		return ret;
	}

	ss_proto_init(&conn->proto, &bmb_hooks, tn * nconns + cn);
	rcu_assign_sk_user_data(sk, &conn->proto);
	ss_set_callbacks(sk);

	ret = ss_connect(sk, &bmb_server_address.sa,
			 tfw_addr_sa_len(&bmb_server_address), 0);
	if (ret) {
		TFW_ERR("Connect error on server socket sk %p (%d)\n", sk, ret);
		tfw_connection_unlink_from_sk(sk);
		ss_close(sk);
		conn->flags |= CONNECT_ERROR;
		return ret;
        }

	conn->sk = sk;
	conn->flags |= CONNECT_STARTED;
	bmb_task[tn].conn_attempt++;
	return 0;
}

static void
tfw_bmb_release_sockets(int tn)
{
	int i;

	TFW_DBG("Release connections.\n");

	for (i = 0; i < nconns; i++) {
		if (bmb_task[tn].conn[i].sk) {
			tfw_connection_unlink_from_sk(bmb_task[tn].conn[i].sk);
			ss_close(bmb_task[tn].conn[i].sk);
			bmb_task[tn].conn[i].sk = NULL;
		}
	}
}

static void
tfw_bmb_msg_send(int tn, int cn)
{
	struct bmb_task *task = &bmb_task[tn];
	int fz_tries = 0, r;
	TfwStr msg;
	TfwHttpMsg *req;
	TfwMsgIter it;

	BUG_ON(!task->conn[cn].sk);

	do {
		if (++fz_tries > 10) {
			TFW_ERR("Too many fuzzer tries to generate request\n");
			return;
		}

		r = fuzz_gen(&task->ctx, task->buf, task->buf + BUF_SIZE, 0, 1,
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

	req = tfw_http_msg_create(&it, Conn_Clnt, msg.len);
	if (!req) {
		TFW_WARN("Cannot create HTTP request.\n");
		return;
	}

	if (verbose)
		TFW_LOG("Send request:\n"
			"------------------------------\n"
			"%s\n"
			"------------------------------\n",
			task->buf);

	tfw_http_msg_write(&it, req, &msg);
	local_bh_disable();
	ss_send(task->conn[cn].sk, &req->msg.skb_list, true);
	local_bh_enable();
	tfw_http_msg_free(req);

	atomic_inc(&bmb_request_send);
}

static int
tfw_bmb_worker(void *data)
{
	int tn = (int)(long)data;
	struct bmb_task *task = &bmb_task[tn];
	int attempt, send, k, i;
	unsigned long time_max;

	fuzz_init(&task->ctx, true);

	for (k = 0; k < niters; k++) {
		task->conn_attempt = 0;
		atomic_set(&task->conn_compl, 0);
		atomic_set(&task->conn_error, 0);
		atomic_set(&task->conn_rd_tail, 0);
		init_waitqueue_head(&task->conn_wq);

		for (i = 0; i < nconns; i++)
			tfw_bmb_connect(tn, i);

		set_freezable();
		time_max = jiffies + 60 * HZ;
		attempt = task->conn_attempt;
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

		for (send = 0; send < nconns * nmessages; ) {
			int tail = atomic_read(&task->conn_rd_tail);
			for (i = 0; i < tail; i++){
				int c = task->conn_rd[i];
				if (task->conn[c].sk)
					tfw_bmb_msg_send(tn, c);
				else
					/* Connection is dropped. */
					atomic_inc(&bmb_conn_drop);
				send++;
			}
		}

release_sockets:
		atomic_add(attempt, &bmb_conn_attempt);
		atomic_add(atomic_read(&task->conn_compl), &bmb_conn_compl);
		atomic_add(atomic_read(&task->conn_error), &bmb_conn_error);

		/*
		 * FIXME workaround for ss_close() and ss_tcp_process_data()
		 * receiving server reply.
		 */
		udelay(1000);

		tfw_bmb_release_sockets(tn);
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
		if (bmb_task[i].task_struct) {
			kthread_stop(bmb_task[i].task_struct);
			bmb_task[i].task_struct = NULL;
		}
	}
}

static void
tfw_bmb_report(unsigned long ts_start)
{
	TFW_LOG("BOMBER SUMMARY:");
	TFW_LOG("  total connections: %d\n", nconns * niters * nthreads);
	TFW_LOG("  attempted connections: %d\n", atomic_read(&bmb_conn_attempt));
	TFW_LOG("  completed connections: %d\n", atomic_read(&bmb_conn_compl));
	TFW_LOG("  error connections: %d\n", atomic_read(&bmb_conn_error));
	TFW_LOG("  dropped connections: %d\n", atomic_read(&bmb_conn_drop));
	TFW_LOG("  total requests: %d\n", atomic_read(&bmb_request_send));
	TFW_LOG("  total time: %ldms\n", jiffies - ts_start);
}

static int
tfw_bmb_alloc(void)
{
	int i;
	void *p;

	bmb_alloc_ptr = p = vzalloc(nthreads * sizeof(struct bmb_task) +
				   nthreads * nconns * sizeof(struct bmb_conn) +
				   nthreads * nconns * sizeof(int) +
				   nthreads * BUF_SIZE * sizeof(char));
	if (!bmb_alloc_ptr)
		return -ENOMEM;

	bmb_task = p;
	p += nthreads * sizeof(struct bmb_task);

	for (i = 0; i < nthreads; i++) {
		bmb_task[i].conn = p;
		p += nconns * sizeof(struct bmb_conn);

		bmb_task[i].conn_rd = p;
		p += nconns * sizeof(int);

		bmb_task[i].buf = p;
		p += BUF_SIZE * sizeof(char);
	}

	return 0;
}

static void
tfw_bmb_free(void)
{
	if (bmb_alloc_ptr) {
		vfree(bmb_alloc_ptr);
		bmb_alloc_ptr = NULL;
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
		task = kthread_create(tfw_bmb_worker, (void *)i, "worker");
		if (IS_ERR_OR_NULL(task)) {
			TFW_ERR("Unable to create worker\n");
			r = -EINVAL;
			goto stop_threads;
		}
		bmb_task[i].task_struct = task;
	}

	atomic_set(&bmb_threads, nthreads);
	for (i = 0; i < nthreads; i++)
		wake_up_process(bmb_task[i].task_struct);

	wait_event_interruptible(bmb_task_wq, !atomic_read(&bmb_threads));

	tfw_bmb_report(ts_start);

stop_threads:
	tfw_bmb_stop_threads();
	tfw_bmb_free();

	return r;
}

static void
tfw_bmb_exit(void)
{
	if (!bmb_alloc_ptr)
		return; /* already stopped and freed */

	tfw_bmb_stop_threads();
	tfw_bmb_free();
}

module_init(tfw_bmb_init);
module_exit(tfw_bmb_exit);
