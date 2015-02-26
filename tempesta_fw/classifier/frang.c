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
 * The module exports appropriate configuration options in
 * /proc/net/tempesta/frang directory.
 * 	- options with names *_rate define requests/connections rate per second.
 * 	- *_burst are temporal burst for 1/FRANG_FREQ of second.
 * 	- http_* are static limits for contents of a HTTP request.
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

/* Limits (zero means unlimited). */
static unsigned int frang_req_rate = 0;
static unsigned int frang_req_burst = 0;
static unsigned int frang_conn_rate = 0;
static unsigned int frang_conn_burst = 0;
static unsigned int frang_conn_max = 0;

/* Limits for HTTP request contents: uri, headers, body, etc. */
static unsigned int frang_http_uri_len = 0;
static unsigned int frang_http_field_len = 0;
static unsigned int frang_http_body_len = 0;
static unsigned long frang_http_methods_mask = 0;
static bool frang_http_ct_is_required = false;
static bool frang_http_host_is_required = false;

/* The list of allowed Content-Type values. */

typedef struct {
	char   *str;
	size_t len;	/* The pre-computed strlen(@str). */
} FrangCtVal;

static FrangCtVal *frang_http_ct_vals __rcu;

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

	if (frang_conn_max && ra->conn_curr > frang_conn_max)
		return TFW_BLOCK;
	if (frang_req_burst && ra->history[i].req > frang_req_burst)
		return TFW_BLOCK;

	/* Collect new connections sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			csum += ra->history[i].conn_new;
	if (frang_conn_rate && csum > frang_conn_rate)
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

	if (frang_req_burst && ra->history[i].req > frang_req_burst)
		goto block;

	/* Collect current request sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			rsum += ra->history[i].req;
	if (frang_req_rate && rsum > frang_req_rate)
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
	if (frang_http_uri_len && tfw_str_len(&req->uri) > frang_http_uri_len) {
		TFW_DBG("frang: http_uri_len limit is reached\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_http_field_len_limit(const TfwHttpReq *req)
{
	const TfwStr *field, *end;

	if (!frang_http_field_len)
		return TFW_PASS;

	TFW_HTTP_FOR_EACH_HDR_FIELD(field, end, req) {
		if (tfw_str_len(field) > frang_http_field_len) {
			TFW_DBG("frang: http_field_len limit is reached\n");
			return TFW_BLOCK;
		}
	}

	return TFW_PASS;
}

static int
frang_http_body_len_limit(const TfwHttpReq *req)
{
	if (frang_http_body_len &&
	    tfw_str_len(&req->body) > frang_http_body_len) {
		TFW_DBG("frang: http_body_len limit is reached\n");
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_http_len_limit(const TfwHttpReq *req)
{
	int r;

	r = frang_http_uri_len_limit(req);
	if (r)
		return r;
	r = frang_http_field_len_limit(req);
	if (r)
		return r;
	r = frang_http_body_len_limit(req);
	if (r)
		return r;

	return 0;
}

static int
frang_http_methods_check(const TfwHttpReq *req)
{
	unsigned long m = (1 << req->method);

	if (frang_http_methods_mask && (frang_http_methods_mask & m))
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

	if (!frang_http_ct_is_required || req->method != TFW_HTTP_METH_POST)
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
	rcu_read_lock();
	for (curr = rcu_dereference(frang_http_ct_vals); curr->str; ++curr) {
		if (tfw_str_eq_kv(ct, _CT, _CTLEN, ':', curr->str, curr->len,
				  TFW_STR_EQ_PREFIX_CASEI))
			break;
	}
	rcu_read_unlock();

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

	if (!frang_http_host_is_required || req->method != TFW_HTTP_METH_POST)
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
	TfwHttpReq *req = container_of(c->msg, TfwHttpReq, msg);

	r = frang_account_do(c->sess->cli->sock, frang_req_limit);
	if (r)
		return r;
	r = frang_http_len_limit(req);
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

static int
frang_http_chunk_handler(void *obj, unsigned char *data, size_t len)
{
	int r;
	TfwConnection *c = (TfwConnection *)obj;
	TfwHttpReq *req = container_of(c->msg, TfwHttpReq, msg);

	r = frang_http_methods_check(req);
	if (r)
		return r;
	r = frang_http_len_limit(req);
	if (r)
		return r;

	return 0;
}

static TfwClassifier frang_class_ops = {
	.classify_conn_estab	= frang_conn_new,
	.classify_conn_close	= frang_conn_close,
};

static int
frang_parse_int(char *tmp_buf, int *out_val)
{
	char *p;
	int val = 0;

	for (p = tmp_buf; *p; ++p) {
		if (!isdigit(*p)) {
			TFW_ERR("not a digit: '%c'\n", *p);
			return -EINVAL;
		}
		val = val * 10 + *p - '0';
	}

	*out_val = val;
	return 0;
}

static int
frang_parse_bool(char *tmp_buf, bool *out_bool)
{
	char c = *tmp_buf;

	/* XXX: should we support true/false/etc instead of 0/1 here? */
	if (c != '0' && c != '1') {
		TFW_ERR("invalid boolean value: %s\n", tmp_buf);
		return -EINVAL;
	}

	*out_bool = c - '0';
	return 0;
}

/* TODO: refactoring: get rid of these sysctl handlers,
 * replace them with Tempesta's cfg framework. */

static int
frang_find_idx_by_str(const char **str_vec, size_t vec_size, const char *str)
{
	int i;
	const char *curr_str;

	for (i = 0; i < vec_size; ++i) {
		curr_str = str_vec[i];
		BUG_ON(!curr_str);
		if (!strcasecmp(curr_str, str))
			return i;
	}

	return -1;
}

#define FRANG_TOKEN_SEPARATORS	" \r\n\t"

static char *
frang_tokenize(char **tmp_buf)
{
	char *token = strsep(tmp_buf, FRANG_TOKEN_SEPARATORS);

	/* Unlike strsep(), don't return empty tokens. */
	if (token && !*token)
		token = NULL;

	return token;
}

static int
frang_count_tokens(char *str)
{
	int n = 0;

	while (*str) {
		str += strspn(str, FRANG_TOKEN_SEPARATORS);
		if (*str)
			++n;
		str += strcspn(str, FRANG_TOKEN_SEPARATORS);
	}

	return n;
}

static int
frang_parse_methods_mask(char *tmp_buf, unsigned long *out_mask)
{
	static const char *strs[_TFW_HTTP_METH_COUNT] = {
		[TFW_HTTP_METH_GET] = "get",
		[TFW_HTTP_METH_POST] = "post",
		[TFW_HTTP_METH_HEAD] = "head",
	};
	char *token;
	int idx;
	unsigned long methods_mask;

	token = tmp_buf;
	methods_mask = 0;
	while ((token = frang_tokenize(&tmp_buf))) {
		idx = frang_find_idx_by_str(strs, ARRAY_SIZE(strs), token);
		if (idx < 0) {
			TFW_ERR("frang: invalid method: '%s'\n", token);
			return -EINVAL;
		}

		TFW_DBG("frang: parsed method: %s => %d\n", token, idx);
		methods_mask |= (1 << idx);
	}

	TFW_DBG("parsed methods_mask: %#lx\n", methods_mask);
	*out_mask = methods_mask;
	return 0;
}

static int
frang_parse_ct_vals(char *tmp_buf, void *unused)
{
	void *mem;
	char *token, *strs, *strs_pos;
	size_t tokens_n, vals_size, strs_size;
	FrangCtVal *vals, *vals_pos, *old_vals;

	tokens_n = frang_count_tokens(tmp_buf);
	if (!tokens_n) {
		TFW_ERR("the frang_http_ct_vals is empty\n");
		return -EINVAL;
	}

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
	strs_size = strlen(tmp_buf) + 1;
	vals_size = sizeof(FrangCtVal) * (tokens_n + 1);
	mem = kzalloc(vals_size + strs_size, GFP_KERNEL);
	vals = mem;
	strs = mem + vals_size;

	/* Copy tokens from tmp_buf to the vals/strs list. */
	/* TODO: validate tokens, they should look like: "text/plain". */
	vals_pos = vals;
	strs_pos = strs;
	while ((token = frang_tokenize(&tmp_buf))) {
		size_t len = strlen(token) + 1;
		BUG_ON(!len);

		memcpy(strs_pos, token, len);
		vals_pos->str = strs_pos;
		vals_pos->len = (len - 1);
		TFW_DBG("parsed Content-Type value: '%s'\n", strs_pos);

		vals_pos++;
		strs_pos += len;
	}
	BUG_ON(vals_pos != (vals + tokens_n));
	BUG_ON(strs_pos > (strs + strs_size));

	/* Replace the old list of allowed Content-Type values. */
	/* TODO: sort values to make binary search possible. */
	old_vals = frang_http_ct_vals;
	rcu_assign_pointer(frang_http_ct_vals, vals);
	synchronize_rcu();
	kfree(old_vals);
	return 0;
}

static int
frang_sysctl_handle(ctl_table *ctl, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int r, len;
	char *tmp_buf, *trimmed_buf;
	void *parse_dest;
	int (*parse_fn)(const char *tmp_buf, void *dest);

	tmp_buf = NULL;
	parse_fn = ctl->extra1;
	parse_dest = ctl->extra2;
	BUG_ON(!parse_fn);

	if (write) {
		tmp_buf = kzalloc(ctl->maxlen + 1, GFP_KERNEL);
		if (!tmp_buf) {
			TFW_ERR("frang: can't allocate temporary buffer\n");
			r = -ENOMEM;
			goto out;
		}

		len =  min(ctl->maxlen, (int)*lenp);
		if (copy_from_user(tmp_buf, buffer, len)) {
			TFW_ERR("frang: can't copy data from userspace\n");
			r = -EFAULT;
			goto out;
		}

		trimmed_buf = strim(tmp_buf);
		if (parse_fn(trimmed_buf, parse_dest)) {
			TFW_ERR("frang: can't parse input data\n");
			r = -EINVAL;
			goto out;
		}
	}

	r = proc_dostring(ctl, write, buffer, lenp, ppos);
	if (r)
		TFW_ERR("frang: sysctl error\n");
out:
	if (r)
		TFW_ERR("frang: can't read/write parameter: %s\n",
			ctl->procname);
	kfree(tmp_buf);
	return r;
}

#define FRANG_INT_LEN		10
#define FRANG_STR_LEN		255
#define FRANG_LONG_STR_LEN	1024

char frang_req_rate_str[FRANG_INT_LEN];
char frang_req_burst_str[FRANG_INT_LEN];
char frang_conn_rate_str[FRANG_INT_LEN];
char frang_conn_burst_str[FRANG_INT_LEN];
char frang_conn_max_str[FRANG_INT_LEN];
char frang_http_uri_len_str[FRANG_INT_LEN];
char frang_http_field_len_str[FRANG_INT_LEN];
char frang_http_body_len_str[FRANG_INT_LEN];
char frang_http_methods_str[FRANG_STR_LEN];
char frang_http_ct_is_required_str[FRANG_INT_LEN];
char frang_http_content_types_str[FRANG_LONG_STR_LEN];
char frang_http_host_is_required_str[FRANG_INT_LEN];

static ctl_table frang_ctl_table[] = {
	{
		.procname	= "request_rate",
		.data		= frang_req_rate_str,
		.maxlen		= sizeof(frang_req_rate_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_req_rate,
	},
	{
		.procname	= "request_burst",
		.data		= frang_req_burst_str,
		.maxlen		= sizeof(frang_req_burst_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_req_burst,
	},
	{
		.procname	= "new_connection_rate",
		.data		= frang_conn_rate_str,
		.maxlen		= sizeof(frang_conn_rate_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_conn_rate,
	},
	{
		.procname	= "new_connection_burst",
		.data		= frang_conn_burst_str,
		.maxlen		= sizeof(frang_conn_burst_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_conn_burst,
	},
	{
		.procname	= "concurrent_connections",
		.data		= frang_conn_max_str,
		.maxlen		= sizeof(frang_conn_max_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_conn_max,
	},
	{
		.procname 	= "http_uri_len",
		.data		= frang_http_uri_len_str,
		.maxlen		= sizeof(frang_http_uri_len_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_http_uri_len,
	},
	{
		.procname 	= "http_field_len",
		.data		= frang_http_field_len_str,
		.maxlen		= sizeof(frang_http_field_len_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_http_field_len,
	},
	{
		.procname 	= "http_body_len",
		.data		= frang_http_body_len_str,
		.maxlen		= sizeof(frang_http_body_len_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_int,
		.extra2		= &frang_http_body_len,
	},
	{
		.procname	= "http_methods",
		.data		= frang_http_methods_str,
		.maxlen		= sizeof(frang_http_methods_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_methods_mask,
		.extra2		= &frang_http_methods_mask,
	},
	{
		.procname 	= "http_ct_is_required",
		.data		= frang_http_ct_is_required_str,
		.maxlen		= sizeof(frang_http_ct_is_required_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_bool,
		.extra2		= &frang_http_ct_is_required,
	},
	{
		.procname	= "http_ct_vals",
		.data		= frang_http_content_types_str,
		.maxlen		= sizeof(frang_http_content_types_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_ct_vals,
	},
	{
		.procname	= "http_host_is_required",
		.data		= frang_http_host_is_required_str,
		.maxlen		= sizeof(frang_http_host_is_required_str),
		.mode		= 0644,
		.proc_handler	= frang_sysctl_handle,
		.extra1		= frang_parse_bool,
		.extra2		= &frang_http_host_is_required
	},
	{}
};
static struct ctl_path __tfw_path[] = {
	{ .procname = "net/tempesta/req_conn_limit", },
	{}
};

static int __init
frang_init(void)
{
	int r;
	struct ctl_table_header *frang_ctl;

	frang_mem_cache = KMEM_CACHE(frang_account_t, 0);
	if (!frang_mem_cache) {
		TFW_ERR("frang: can't create cache\n");
		return -EINVAL;
	}

	frang_ctl = register_net_sysctl(&init_net, "net/tempesta/frang",
				      frang_ctl_table);
	if (!frang_ctl) {
		TFW_ERR("frang: can't register sysctl table\n");
		r = -1;
		goto err_sysctl;
	}

	r = tfw_classifier_register(&frang_class_ops);
	if (r) {
		TFW_ERR("frang: can't register classifier\n");
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
	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG_REQ, frang_http_req_handler);
	if (r) {
		TFW_ERR("frang: can't register fsm: req\n");
		goto err_fsm_req;
	}
	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG_CHUNK, frang_http_chunk_handler);
	if (r) {
		TFW_ERR("frang: can't register fsm: chunk\n");
		goto err_fsm_chunk;
	}

	r = tfw_gfsm_register_hook(TFW_FSM_HTTP, TFW_GFSM_HOOK_PRIORITY_ANY,
				   TFW_HTTP_FSM_REQ_MSG, 0,
				   TFW_FSM_FRANG_REQ);
	if (r) {
		TFW_ERR("frang: can't register gfsm hook: req\n");
		goto err_hook_req;
	}
	r = tfw_gfsm_register_hook(TFW_FSM_HTTP, TFW_GFSM_HOOK_PRIORITY_ANY,
				   TFW_HTTP_FSM_REQ_CHUNK, 0,
				   TFW_FSM_FRANG_CHUNK);
	if (r) {
		TFW_ERR("frang: can't register gfsm hook: chunk\n");
		TFW_ERR("frang: can't recover\n");
		BUG();
	}

	TFW_WARN("frang mudule can't be unloaded, "
		 "so all allocated resources won't freed\n");

	return 0;
err_hook_req:
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_CHUNK);
err_fsm_chunk:
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_REQ);
err_fsm_req:
	tfw_classifier_unregister();
err_class:
	unregister_sysctl_table(frang_ctl);
err_sysctl:
	kmem_cache_destroy(frang_mem_cache);
	return r;
}

module_init(frang_init);
