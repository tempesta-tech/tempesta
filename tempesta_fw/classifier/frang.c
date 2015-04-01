/**
 *		Tempesta FW
 *
 * Simple classification module which performs following limitings:
 *
 * Temporal limitings per a client:
 *	1. HTTP requests rate;
 *	2. number of concurrent connections;
 *	3. new connections rate.
 * All the limits works for specified temporal bursts.
 *
 * Static limits for contents of a HTTP request:
 * 	1. maximum length of URI/header/body.
 * 	2. checks for presence of certain required header fields
 * 	3. HTTP method and Content-Type restrictions (check that the value is
 * 	   in a set of allowed values defined by the user).
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
MODULE_DESCRIPTION("Tempesta static limiting classifier");
MODULE_VERSION("0.1.1");
MODULE_LICENSE("GPL");

/* We account users with FRANG_FREQ frequency per second. */
#define FRANG_FREQ	8
/* Garbage collection timeout (seconds). */
#define GC_TO		1800
#define FRANG_HASH_BITS	17

typedef struct {
	unsigned long	ts;
	unsigned int	conn_new;
	unsigned int	req;
} FrangRates;

typedef struct frang_account_t {
	struct hlist_node	hentry;
	struct in6_addr		addr; /* client address */
	unsigned long		last_ts; /* last access time */
	unsigned int		conn_curr; /* current connections number */
	FrangRates		history[FRANG_FREQ];
} FrangAcc;

typedef struct {
	struct hlist_head	list;
	spinlock_t		lock;
} FrangHashBucket;

FrangHashBucket frang_hash[1 << FRANG_HASH_BITS] = {
	[0 ... ((1 << FRANG_HASH_BITS) - 1)] = {
		HLIST_HEAD_INIT,
		__SPIN_LOCK_UNLOCKED(lock)
	}
};

static struct kmem_cache *frang_mem_cache;

typedef struct {
	char   *str;
	size_t len;	/* The pre-computed strlen(@str). */
} FrangCtVal;

typedef struct {
	/* Limits (zero means unlimited). */
	unsigned int 	req_rate;
	unsigned int 	req_burst;
	unsigned int 	conn_rate;
	unsigned int 	conn_burst;
	unsigned int 	conn_max;

	/* Limits for HTTP request contents: uri, headers, body, etc. */
	unsigned int 	http_uri_len;
	unsigned int 	http_field_len;
	unsigned int 	http_body_len;
	bool 		http_ct_is_required;
	bool 		http_host_is_required;
	/* The bitmask of allowed HTTP Method values. */
	unsigned long 	http_methods_mask;
	/* The list of allowed Content-Type values. */
	FrangCtVal	*http_ct_vals;
} FrangCfg;

static FrangCfg frang_cfg __read_mostly;

static void
frang_get_ipv6addr(struct sock *sk, struct in6_addr *addr)
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
frang_account_do(struct sock *sk, int (*func)(FrangAcc *ra, struct sock *sk))
{
	struct in6_addr addr;
	struct hlist_node *tmp;
	FrangAcc *ra;
	FrangHashBucket *hb;
	unsigned int key, r;

	frang_get_ipv6addr(sk, &addr);
	key = addr.s6_addr32[0] ^ addr.s6_addr32[1] ^ addr.s6_addr32[2]
		^ addr.s6_addr32[3];

	hb = &frang_hash[hash_min(key, FRANG_HASH_BITS)];

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
		ra = kmem_cache_alloc(frang_mem_cache, GFP_ATOMIC | __GFP_ZERO);
		if (!ra) {
			TFW_WARN("frang: can't alloc account record\n");
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
frang_conn_limit(FrangAcc *ra, struct sock *unused)
{
	unsigned long ts = jiffies * FRANG_FREQ / HZ;
	unsigned int csum = 0;
	int i = ts % FRANG_FREQ;

	if (ra->history[i].ts != ts) {
		ra->history[i].ts = ts;
		ra->history[i].conn_new = 0;
		ra->history[i].req = 0;
	}

	/*
	 * Increment connection counters ever if we return TFW_BLOCK.
	 * Synchronous sockets will call connection_drop callback,
	 * so our frang_conn_close() is also called and we decrement
	 * conn_curr there, but leave conn_new as is - we account failed
	 * connection tries as well as successfully establised connections.
	 */
	ra->history[i].conn_new++;
	ra->conn_curr++;

	if (frang_cfg.conn_max && ra->conn_curr > frang_cfg.conn_max)
		return TFW_BLOCK;
	if (frang_cfg.req_burst && ra->history[i].req > frang_cfg.req_burst)
		return TFW_BLOCK;

	/* Collect new connections sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			csum += ra->history[i].conn_new;
	if (frang_cfg.conn_rate && csum > frang_cfg.conn_rate)
		return TFW_BLOCK;

	return TFW_PASS;
}

static int
frang_conn_new(struct sock *sk)
{
	return frang_account_do(sk, frang_conn_limit);
}

static int
__frang_conn_close(FrangAcc *ra, struct sock *unused)
{
	BUG_ON(!ra->conn_curr);

	ra->conn_curr--;

	return TFW_PASS;
}

/**
 * Just update current connection count for the user.
 */
static int
frang_conn_close(struct sock *sk)
{
	return frang_account_do(sk, __frang_conn_close);
}

static int
frang_req_limit(FrangAcc *ra, struct sock *sk)
{
	unsigned long ts = jiffies * FRANG_FREQ / HZ;
	unsigned int rsum = 0;
	int i = ts % FRANG_FREQ;

	if (ra->history[i].ts != ts) {
		ra->history[i].ts = ts;
		ra->history[i].conn_new = 0;
		ra->history[i].req = 0;
	}
	ra->history[i].req++;

	if (frang_cfg.req_burst && ra->history[i].req > frang_cfg.req_burst)
		goto block;

	/* Collect current request sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			rsum += ra->history[i].req;
	if (frang_cfg.req_rate && rsum > frang_cfg.req_rate)
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
frang_http_uri_len_limit(const TfwHttpReq *req)
{
	/* FIXME: tfw_str_len() iterates over chunks to calculate the length.
	 * This is too slow. The value must be stored in a TfwStr field. */
	if (frang_cfg.http_uri_len &&
	    tfw_str_len(&req->uri_path) > frang_cfg.http_uri_len) {
		TFW_DBG("frang: http_uri_len limit is reached\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_http_field_len_limit(const TfwHttpReq *req)
{
	const TfwStr *field, *end;

	if (!frang_cfg.http_field_len)
		return TFW_PASS;

	TFW_HTTP_FOR_EACH_HDR_FIELD(field, end, req) {
		if (tfw_str_len(field) > frang_cfg.http_field_len) {
			TFW_DBG("frang: http_field_len limit is reached\n");
			return TFW_BLOCK;
		}
	}

	return TFW_PASS;
}

static int
frang_http_body_len_limit(const TfwHttpReq *req)
{
	if (frang_cfg.http_body_len &&
	    tfw_str_len(&req->body) > frang_cfg.http_body_len) {
		TFW_DBG("frang: http_body_len limit is reached\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_http_methods_check(const TfwHttpReq *req)
{
	unsigned long m = (1 << req->method);

	if (frang_cfg.http_methods_mask && (frang_cfg.http_methods_mask & m))
		return TFW_PASS;

	TFW_DBG("frang: forbidden method: %d (%#lx)\n", req->method, m);
	return TFW_BLOCK;
}

static int
frang_http_ct_check(const TfwHttpReq *req)
{
#define _CT "Content-Type"
#define _CTLEN (sizeof(_CT) - 1)
	TfwStr *ct, *end;
	FrangCtVal *curr;

	if (!frang_cfg.http_ct_is_required || !frang_cfg.http_ct_vals ||
	    req->method != TFW_HTTP_METH_POST)
		return TFW_PASS;

	/* Find the Content-Type header.
	 *
	 * XXX: Should we make the header "special"?
	 * It would speed up this function, but bloat the HTTP parser code,
	 * and pollute the headers table.
	 */
	TFW_HTTP_FOR_EACH_RAW_HDR_FIELD(ct, end, req) {
		if (tfw_str_eq_cstr(ct, _CT, _CTLEN, TFW_STR_EQ_PREFIX_CASEI))
			break;

	}
	if (ct == end) {
		TFW_DBG("frang: Content-Type is missing\n");
		return TFW_BLOCK;
	}

	/* Check that the Content-Type is in the list of allowed values.
	 *
	 * TODO: possible improvement: binary search.
	 * Generally the binary search is more efficient, but linear search is
	 * usually faster for small sets of values. Perhaps we should switch
	 * between two if the performance is that critical here, but benchmarks
	 * should be done to measure the impact.
	 *
	 * TODO: don't store field name in the TfwStr. Store only the header
	 * value, and thus get rid of the nasty tfw_str_eq_kv().
	 */
	for (curr = frang_cfg.http_ct_vals; curr->str; ++curr) {
		if (tfw_str_eq_kv(ct, _CT, _CTLEN, ':', curr->str, curr->len,
				  TFW_STR_EQ_PREFIX_CASEI))
			break;
	}

	if (!curr->str) {
		TFW_DBG("frang: forbidden Content-Type value\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
#undef _CT
#undef _CTLEN
}

static int
frang_http_host_check(const TfwHttpReq *req)
{
	TfwStr *field;

	if (!frang_cfg.http_host_is_required || req->method != TFW_HTTP_METH_POST)
		return TFW_PASS;

	field = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST].field;
	if (!field->ptr) {
		TFW_DBG("frang: the Host header is missing\n");
		return TFW_BLOCK;
	}

	/* FIXME: here should be a check that the Host value is not an IP
	 * address. Need a fast routine that supports compound TfwStr.
	 * Perhaps should implement a tiny FSM or postpone the task until we
	 * have a good regex library. */
	return TFW_PASS;
}

static int
frang_http_req_handler(void *obj, unsigned char *data, size_t len)
{
	int r;
	TfwConnection *c = (TfwConnection *)obj;
	TfwClient *clnt = (TfwClient *)c->peer;
	TfwHttpReq *req = container_of(c->msg, TfwHttpReq, msg);

	r = frang_account_do(clnt->sock, frang_req_limit);
	if (r)
		return r;

	r = frang_http_methods_check(req);
	if (r)
		return r;
	r = frang_http_uri_len_limit(req);
	if (r)
		return r;
	r = frang_http_field_len_limit(req);
	if (r)
		return r;
	r = frang_http_body_len_limit(req);
	if (r)
		return r;
	r = frang_http_ct_check(req);
	if (r)
		return r;
	r = frang_http_host_check(req);
	if (r)
		return r;

	return 0;
}

static TfwClassifier frang_class_ops = {
	.classify_conn_estab	= frang_conn_new,
	.classify_conn_close	= frang_conn_close,
};

static const TfwCfgEnum frang_http_methods_enum[] = {
	{ "get", TFW_HTTP_METH_GET },
	{ "post", TFW_HTTP_METH_POST },
	{ "head", TFW_HTTP_METH_HEAD },
	{}
};

static int
frang_set_methods_mask(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int i, r, method_id;
	const char *method_str;
	unsigned long methods_mask = 0;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, method_str) {
		r = tfw_cfg_map_enum(frang_http_methods_enum, method_str,
				     &method_id);
		if (r) {
			TFW_ERR("frang: invalid method: '%s'\n", method_str);
			return -EINVAL;
		}

		TFW_DBG("frang: parsed method: %s => %d\n",
			method_str, method_id);
		methods_mask |= (1 << method_id);
	}

	TFW_DBG("parsed methods_mask: %#lx\n", methods_mask);
	frang_cfg.http_methods_mask = methods_mask;
	return 0;
}

static void
frang_clear_methods_mask(TfwCfgSpec *cs)
{
	frang_cfg.http_methods_mask = 0;
}

static int
frang_set_ct_vals(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	void *mem;
	const char *in_str;
	char *strs, *strs_pos;
	FrangCtVal *vals, *vals_pos;
	size_t i, strs_size, vals_n, vals_size;

	/* Allocate a single chunk of memory which is suitable to hold the
	 * variable-sized list of variable-sized strings.
	 *
	 * Basically that will look like:
	 *  [[FrangCtVal, FrangCtVal, FrangCtVal, NULL]str1\0\str2\0\str3\0]
	 *           +         +         +             ^      ^      ^
	 *           |         |         |             |      |      |
	 *           +---------------------------------+      |      |
	 *                     |         |                    |      |
	 *                     +------------------------------+      |
	 *                               |                           |
	 *                               +---------------------------+
	 */
	vals_n = ce->val_n;
	vals_size = sizeof(FrangCtVal) * (vals_n + 1);
	strs_size = 0;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		strs_size += strlen(in_str) + 1;
	}
	mem = kzalloc(vals_size + strs_size, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;
	vals = mem;
	strs = mem + vals_size;

	/* Copy tokens to the new vals/strs list. */
	/* TODO: validate tokens, they should look like: "text/plain". */
	vals_pos = vals;
	strs_pos = strs;
	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, in_str) {
		size_t len = strlen(in_str) + 1;

		memcpy(strs_pos, in_str, len);
		vals_pos->str = strs_pos;
		vals_pos->len = (len - 1);

		TFW_DBG("parsed Content-Type value: '%s'\n", in_str);

		vals_pos++;
		strs_pos += len;
	}
	BUG_ON(vals_pos != (vals + vals_n));
	BUG_ON(strs_pos != (strs + strs_size));

	frang_cfg.http_ct_vals = vals;
	return 0;
}

static void
frang_free_ct_vals(TfwCfgSpec *cs)
{
	kfree(frang_cfg.http_ct_vals);
	frang_cfg.http_ct_vals = NULL;
}

static TfwCfgSpec frang_cfg_section_specs[] = {
	{
		"request_rate", "0",
		tfw_cfg_set_int,
		&frang_cfg.req_rate,
	},
	{
		"request_burst", "0",
		tfw_cfg_set_int,
		&frang_cfg.req_burst,
	},
	{
		"new_connection_rate", "0",
		tfw_cfg_set_int,
		&frang_cfg.conn_rate,
	},
	{
		"new_connection_burst", "0",
		tfw_cfg_set_int,
		&frang_cfg.conn_burst,
	},
	{
		"concurrent_connections", "0",
		tfw_cfg_set_int,
		&frang_cfg.conn_max,
	},
	{
		"http_uri_len", "0",
		tfw_cfg_set_int,
		&frang_cfg.http_uri_len,
	},
	{
		"http_field_len", "0",
		tfw_cfg_set_int,
		&frang_cfg.http_field_len,
	},
	{
		"http_body_len", "0",
		tfw_cfg_set_int,
		&frang_cfg.http_body_len,
	},
	{
		"http_host_is_required", "false",
		tfw_cfg_set_bool,
		&frang_cfg.http_host_is_required,
	},
	{
		"http_ct_is_required", "false",
		tfw_cfg_set_bool,
		&frang_cfg.http_ct_is_required,
	},
	{
		"http_methods", NULL,
		frang_set_methods_mask,
		.cleanup = frang_clear_methods_mask,
	},
	{
		"http_ct_vals", NULL,
		frang_set_ct_vals,
		.cleanup = frang_free_ct_vals
	},
	{}
};

static TfwCfgSpec frang_cfg_toplevel_specs[] = {
	{
		"frang_limits", NULL,
		tfw_cfg_handle_children,
		&frang_cfg_section_specs
	},
	{}
};

static TfwCfgMod frang_cfg_mod = {
	.name = "frang",
	.specs = frang_cfg_toplevel_specs
};

static int __init
frang_init(void)
{
	int r;

	frang_mem_cache = KMEM_CACHE(frang_account_t, 0);
	if (!frang_mem_cache) {
		TFW_ERR("frang: can't create cache\n");
		return -EINVAL;
	}

	r = tfw_cfg_mod_register(&frang_cfg_mod);
	if (r) {
		TFW_ERR("frang: can't register as a configuration module\n");
		goto err_cfg;
	}

	r = tfw_classifier_register(&frang_class_ops);
	if (r) {
		TFW_ERR("frang: can't register classifier\n");
		goto err_class;
	}

	/* FIXME: this is not a FSM here, but rather a set of static checks
	 * that are executed when a HTTP request is fully parsed.
	 * These checks should be executed during the parsing process in order
	 * to drop suspicious requests as early as possible. */
	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG, frang_http_req_handler);
	if (r) {
		TFW_ERR("frang: can't register fsm: req\n");
		goto err_fsm;
	}

	r = tfw_gfsm_register_hook(TFW_FSM_HTTP, TFW_GFSM_HOOK_PRIORITY_ANY,
				   TFW_HTTP_FSM_REQ_MSG, TFW_FSM_FRANG, 0);
	if (r) {
		TFW_ERR("frang: can't register gfsm hook: req\n");
		goto err_hook;
	}

	TFW_WARN("frang mudule can't be unloaded, "
		 "so all allocated resources won't freed\n");

	return 0;
err_hook:
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG);
err_fsm:
	tfw_classifier_unregister();
err_class:
	tfw_cfg_mod_unregister(&frang_cfg_mod);
err_cfg:
	kmem_cache_destroy(frang_mem_cache);
	return r;
}

module_init(frang_init);
