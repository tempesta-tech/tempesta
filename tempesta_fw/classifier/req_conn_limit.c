/**
 *		Tempesta FW
 *
 * Simple classification module which performs following limitings per a client:
 *	1. HTTP requests rate;
 *	2. number of concurrent connections;
 *	3. new connections rate.
 * All the limits works for specified temporal bursts.
 *
 * The module exports appropriate configuration options in
 * /proc/net/tempesta/req_conn_limit directory. Options with names *_rate
 * define requests/connections rate per second. *_burst are temporal burst
 * for 1/RCL_FREQ of second.
 *
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
#include <linux/ctype.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/ipv6.h>

#include "../tempesta_fw.h"
#include "../classifier.h"
#include "../client.h"
#include "../connection.h"
#include "../gfsm.h"
#include "../http.h"
#include "../log.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta rate limiting classifier");
MODULE_VERSION("0.1.1");
MODULE_LICENSE("GPL");

/* We account users with RCL_FREQ frequency per second. */
#define RCL_FREQ	8
/* Garbage collection timeout (seconds). */
#define GC_TO		1800
#define RCL_HASH_BITS	17

typedef struct {
	unsigned long	ts;
	unsigned int	conn_new;
	unsigned int	req;
} RclRates;

typedef struct rcl_account_t {
	struct hlist_node	hentry;
	struct in6_addr		addr; /* client address */
	unsigned long		last_ts; /* last access time */
	unsigned int		conn_curr; /* current connections number */
	RclRates		history[RCL_FREQ];
} RclAccount;

typedef struct {
	struct hlist_head	list;
	spinlock_t		lock;
} RclHashBucket;

RclHashBucket rcl_hash[1 << RCL_HASH_BITS] = {
	[0 ... ((1 << RCL_HASH_BITS) - 1)] = {
		HLIST_HEAD_INIT,
		__SPIN_LOCK_UNLOCKED(lock)
	}
};

static struct kmem_cache *rcl_mem_cache;

/* Limits (zero means unlimited). */
static unsigned int rcl_req_rate = 0;
static unsigned int rcl_req_burst = 0;
static unsigned int rcl_conn_rate = 0;
static unsigned int rcl_conn_burst = 0;
static unsigned int rcl_conn_max = 0;

/* Limits for HTTP request contents: uri, headers, body, etc. */
static unsigned int rcl_http_uri_len = 0;
static unsigned int rcl_http_field_len = 0;
static unsigned int rcl_http_body_len = 0;

static void
rcl_get_ipv6addr(struct sock *sk, struct in6_addr *addr)
{
	struct inet_sock *isk = (struct inet_sock *)sk;

#if IS_ENABLED(CONFIG_IPV6)
	if (isk->pinet6)
		memcpy(addr, &isk->pinet6->saddr, sizeof(*addr));
	else
#endif
	ipv6_addr_set_v4mapped(isk->inet_saddr, addr);
}

static int
rcl_account_do(struct sock *sk, int (*func)(RclAccount *ra, struct sock *sk))
{
	struct in6_addr addr;
	struct hlist_node *tmp;
	RclAccount *ra;
	RclHashBucket *hb;
	unsigned int key, r;

	rcl_get_ipv6addr(sk, &addr);
	key = addr.s6_addr32[0] ^ addr.s6_addr32[1] ^ addr.s6_addr32[2]
		^ addr.s6_addr32[3];

	hb = &rcl_hash[hash_min(key, RCL_HASH_BITS)];

	spin_lock(&hb->lock);

	hlist_for_each_entry_safe(ra, tmp, &hb->list, hentry) {
		if (ipv6_addr_equal(&addr, &ra->addr))
			break;
		/* Collect garbage. */
		if (ra->last_ts + GC_TO < jiffies / HZ)
			hash_del(&ra->hentry);
	}
	if (!ra) {
		spin_unlock(&hb->lock);

		/*
		 * Add new client account.
		 * Other CPUs should not add the same account while we
		 * allocating the account w/o lock.
		 */
		ra = kmem_cache_alloc(rcl_mem_cache, GFP_ATOMIC | __GFP_ZERO);
		if (!ra) {
			TFW_WARN("rcl: can't alloc account record\n");
			return TFW_BLOCK;
		}

		memcpy(&ra->addr, &addr, sizeof(addr));

		spin_lock(&hb->lock);
		hlist_add_head(&ra->hentry, &hb->list);
	}

	ra->last_ts = jiffies;

	r = func(ra, sk);

	spin_unlock(&hb->lock);

	return r;
}

static int
rcl_conn_limit(RclAccount *ra, struct sock *unused)
{
	unsigned long ts = jiffies * RCL_FREQ / HZ;
	unsigned int csum = 0;
	int i = ts % RCL_FREQ;

	if (ra->history[i].ts != ts) {
		ra->history[i].ts = ts;
		ra->history[i].conn_new = 0;
		ra->history[i].req = 0;
	}

	/*
	 * Increment connection counters ever if we return TFW_BLOCK.
	 * Synchronous sockets will call connection_drop callback,
	 * so our rcl_conn_close() is also called and we decrement
	 * conn_curr there, but leave conn_new as is - we account failed
	 * connection tries as well as successfully establised connections.
	 */
	ra->history[i].conn_new++;
	ra->conn_curr++;

	if (rcl_conn_max && ra->conn_curr > rcl_conn_max)
		return TFW_BLOCK;
	if (rcl_req_burst && ra->history[i].req > rcl_req_burst)
		return TFW_BLOCK;

	/* Collect new connections sum. */
	for (i = 0; i < RCL_FREQ; i++)
		if (ra->history[i].ts + RCL_FREQ >= ts)
			csum += ra->history[i].conn_new;
	if (rcl_conn_rate && csum > rcl_conn_rate)
		return TFW_BLOCK;

	return TFW_PASS;
}

static int
rcl_conn_new(struct sock *sk)
{
	return rcl_account_do(sk, rcl_conn_limit);
}

static int
__rcl_conn_close(RclAccount *ra, struct sock *unused)
{
	BUG_ON(!ra->conn_curr);

	ra->conn_curr--;

	return TFW_PASS;
}

/**
 * Just update current connection count for the user.
 */
static int
rcl_conn_close(struct sock *sk)
{
	return rcl_account_do(sk, __rcl_conn_close);
}

static int
rcl_req_limit(RclAccount *ra, struct sock *sk)
{
	unsigned long ts = jiffies * RCL_FREQ / HZ;
	unsigned int rsum = 0;
	int i = ts % RCL_FREQ;

	if (ra->history[i].ts != ts) {
		ra->history[i].ts = ts;
		ra->history[i].conn_new = 0;
		ra->history[i].req = 0;
	}
	ra->history[i].req++;

	if (rcl_req_burst && ra->history[i].req > rcl_req_burst)
		goto block;

	/* Collect current request sum. */
	for (i = 0; i < RCL_FREQ; i++)
		if (ra->history[i].ts + RCL_FREQ >= ts)
			rsum += ra->history[i].req;
	if (rcl_req_rate && rsum > rcl_req_rate)
		goto block;

	return TFW_PASS;

block:
	/*
	 * TODO reset connection istead of wasting resources on
	 * gentle closing. See ss_do_close() in sync_socket.
	 */
	TFW_DBG("%s: close connection\n", __FUNCTION__);
	ss_close(sk);
	return TFW_BLOCK;
}

static int
rcl_http_uri_len_limit(const TfwHttpReq *req)
{
	/* FIXME: tfw_str_len() iterates over chunks to calculate the length.
	 * This is too slow. The value must be stored in a TfwStr field. */
	if (rcl_http_uri_len && tfw_str_len(&req->uri) > rcl_http_uri_len) {
		TFW_DBG("rcl: http_uri_len limit is reached\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
rcl_http_field_len_limit(const TfwHttpReq *req)
{
	const TfwStr *field, *end;

	if (!rcl_http_field_len)
		return TFW_PASS;

	TFW_HTTP_FOR_EACH_HDR_FIELD(field, end, req) {
		if (tfw_str_len(field) > rcl_http_field_len) {
			TFW_DBG("rcl: http_field_len limit is reached\n");
			return TFW_BLOCK;
		}
	}

	return TFW_PASS;
}

static int
rcl_http_body_len_limit(const TfwHttpReq *req)
{
	if (rcl_http_body_len && tfw_str_len(&req->body) > rcl_http_body_len) {
		TFW_DBG("rcl: http_body_len limit is reached\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
rcl_http_len_limit(const TfwHttpReq *req)
{
	int r;

	r = rcl_http_uri_len_limit(req);
	if (r)
		return r;
	r = rcl_http_field_len_limit(req);
	if (r)
		return r;
	r = rcl_http_body_len_limit(req);
	if (r)
		return r;

	return 0;
}

static int
rcl_http_req_handler(void *obj, unsigned char *data, size_t len)
{
	int r;
	TfwConnection *c = (TfwConnection *)obj;
	TfwHttpReq *req = container_of(c->msg, TfwHttpReq, msg);

	r = rcl_account_do(c->sess->cli->sock, rcl_req_limit);
	if (r)
		return r;
	r = rcl_http_len_limit(req);
	if (r)
		return r;

	return 0;
}

static int
rcl_http_chunk_handler(void *obj, unsigned char *data, size_t len)
{
	TfwConnection *c = (TfwConnection *)obj;
	TfwHttpReq *req = container_of(c->msg, TfwHttpReq, msg);

	return rcl_http_len_limit(req);
}

static TfwClassifier rcl_class_ops = {
	.classify_conn_estab	= rcl_conn_new,
	.classify_conn_close	= rcl_conn_close,
};

static int
rcl_sysctl_int(ctl_table *ctl, int write, void __user *buffer, size_t *lenp,
	       loff_t *ppos)
{
	unsigned int *param = ctl->extra1;

	if (write) {
		unsigned int tmp_v = 0;
		char *p, *tmp_buf;

		tmp_buf = kzalloc(ctl->maxlen + 1, GFP_KERNEL);
		if (!tmp_buf)
			return -ENOMEM;
		if (copy_from_user(tmp_buf, buffer, ctl->maxlen)) {
			kfree(tmp_buf);
			return -EFAULT;
		}

		for (p = tmp_buf; *p; ++p) {
			if (!isdigit(*p)) {
				kfree(tmp_buf);
				return -EINVAL;
			}
			tmp_v = tmp_v * 10 + *p - '0';
		}
		*param = tmp_v;

		kfree(tmp_buf);
	}

	return proc_dostring(ctl, write, buffer, lenp, ppos);
}

#define RCL_INT_LEN	10

char rcl_req_rate_str[RCL_INT_LEN];
char rcl_req_burst_str[RCL_INT_LEN];
char rcl_conn_rate_str[RCL_INT_LEN];
char rcl_conn_burst_str[RCL_INT_LEN];
char rcl_conn_max_str[RCL_INT_LEN];
char rcl_http_uri_len_str[RCL_INT_LEN];
char rcl_http_field_len_str[RCL_INT_LEN];
char rcl_http_body_len_str[RCL_INT_LEN];

static ctl_table rcl_ctl_table[] = {
	{
		.procname	= "request_rate",
		.data		= rcl_req_rate_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_req_rate,
	},
	{
		.procname	= "request_burst",
		.data		= rcl_req_burst_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_req_burst,
	},
	{
		.procname	= "new_connection_rate",
		.data		= rcl_conn_rate_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_conn_rate,
	},
	{
		.procname	= "new_connection_burst",
		.data		= rcl_conn_burst_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_conn_burst,
	},
	{
		.procname	= "concurrent_connections",
		.data		= rcl_conn_max_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_conn_max,
	},
	{
		.procname 	= "http_uri_len",
		.data		= rcl_http_uri_len_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_http_uri_len,
	},
	{
		.procname 	= "http_field_len",
		.data		= rcl_http_field_len_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_http_field_len,
	},
	{
		.procname 	= "http_body_len",
		.data		= rcl_http_body_len_str,
		.maxlen		= 10,
		.mode		= 0644,
		.proc_handler	= rcl_sysctl_int,
		.extra1		= &rcl_http_body_len,
	},
	{}
};
static struct ctl_path __tfw_path[] = {
	{ .procname = "net/tempesta/req_conn_limit", },
	{}
};

static int __init
rcl_init(void)
{
	int r;
	struct ctl_table_header *rcl_ctl;

	rcl_mem_cache = KMEM_CACHE(rcl_account_t, 0);
	if (!rcl_mem_cache) {
		TFW_ERR("rcl: can't create cache\n");
		return -EINVAL;
	}

	rcl_ctl = register_net_sysctl(&init_net, "net/tempesta/req_conn_limit",
				      rcl_ctl_table);
	if (!rcl_ctl) {
		TFW_ERR("rcl: can't register sysctl table\n");
		r = -1;
		goto err_sysctl;
	}

	r = tfw_classifier_register(&rcl_class_ops);
	if (r) {
		TFW_ERR("rcl: can't register classifier\n");
		goto err_class;
	}

	/**
	 * FIXME:
	 *  Here we add two primitive hooks by registering two FSMs.
	 *  There is a bunch of problems here:
	 *  - We can't unregister hooks. Therefore, we can't unload this module
	 *    and can't recover if the second tfw_gfsm_register_hook() fails.
	 *  - We have to add every hook to the global enum of FSMs.
	 *  - We register two FSMs, but actually don't implement anything close
	 *    to FSM and don't need the FSM switching logic.
	 *
	 * The suggested solution is to extend the GFSM with the support of
	 * "lightweight hooks" that behave like plain functions rather than FSM.
	 * That should solve all these problems listed above:
	 *  - Such hook may be unregistered any time it is not executed.
	 *  - The hook doesn't need an ID, so no need to maintain a global list
	 *    of all known hooks in the GFSM code.
	 *  - No need to create a dummy FSM just to call the hook.
	 *    This is easy to comprehend, and perhaps faster since the GFSM
	 *    doesn't need to switch FSMs.
	 */
	r = tfw_gfsm_register_fsm(TFW_FSM_RCL_REQ, rcl_http_req_handler);
	if (r) {
		TFW_ERR("rcl: can't register fsm: req\n");
		goto err_fsm_req;
	}
	r = tfw_gfsm_register_fsm(TFW_FSM_RCL_CHUNK, rcl_http_chunk_handler);
	if (r) {
		TFW_ERR("rcl: can't register fsm: chunk\n");
		goto err_fsm_chunk;
	}

	r = tfw_gfsm_register_hook(TFW_FSM_HTTP, TFW_GFSM_HOOK_PRIORITY_ANY,
				   TFW_HTTP_FSM_REQ_MSG, 0,
				   TFW_FSM_RCL_REQ);
	if (r) {
		TFW_ERR("rcl: can't register gfsm hook: req\n");
		goto err_hook_req;
	}
	r = tfw_gfsm_register_hook(TFW_FSM_HTTP, TFW_GFSM_HOOK_PRIORITY_ANY,
				   TFW_HTTP_FSM_REQ_CHUNK, 0,
				   TFW_FSM_RCL_CHUNK);
	if (r) {
		TFW_ERR("rcl: can't register gfsm hook: chunk\n");
		TFW_ERR("rcl: can't recover\n");
		BUG();
	}

	TFW_WARN("rcl mudule can't be unloaded, "
		 "so all allocated resources won't freed\n");

	return 0;
err_hook_req:
	tfw_gfsm_unregister_fsm(TFW_FSM_RCL_CHUNK);
err_fsm_chunk:
	tfw_gfsm_unregister_fsm(TFW_FSM_RCL_REQ);
err_fsm_req:
	tfw_classifier_unregister();
err_class:
	unregister_sysctl_table(rcl_ctl);
err_sysctl:
	kmem_cache_destroy(rcl_mem_cache);
	return r;
}

module_init(rcl_init);
