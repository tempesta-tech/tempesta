/**
 *		Tempesta FW
 *
 * Simple classification module that enforces the following limits:
 *
 * Time-related limits per client:
 *	- HTTP requests rate (number of requests per second);
 *	- HTTP requests burst (maximum rate per 1/FRANG_FREQ of a second);
 *	- new connections rate (number of new connections per second);
 *	- new connections burst (maximum rate per 1/FRANG_FREQ of a second);
 *	- number of concurrent connections;
 *	- maximum time for receiving the whole HTTP message header;
 *	- maximum time between receiving parts of HTTP message body;
 *
 * Static limits for contents of HTTP request:
 * 	- maximum length of URI, single HTTP header, HTTP request body;
 * 	- presence of certain mandatory header fields;
 *	- restrictions on values of HTTP method and Content-Type
 *	  (check that the value is one of those defined by a user);
 *
 * Also, there are certain restrictions that are not user-controlled.
 * For instance, if Host: header is present it may not contain an IP address.
 * Or, that singular header fields may not be duplicated in an HTTP header.
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

#include "../tempesta_fw.h"
#include "../addr.h"
#include "../classifier.h"
#include "../client.h"
#include "../connection.h"
#include "../gfsm.h"
#include "../http_msg.h"
#include "../log.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta static limiting classifier");
MODULE_VERSION("0.1.3");
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

/**
 * Main descriptor of client resource accounting.
 * @lock can be removed if RSS is tuned to schedule packets based on
 * <proto, src_ip> touple. However, the hashing could produce bad CPU load
 * balancing so, such settings are not desireble.
 *
 * @last_ts	- last access time to the descriptor;
 * @conn_curr	- current connections number;
 * @addr	- client IPv6 address (w/o port);
 * @history	- bursts history organized as a ring-buffer;
 */
typedef struct frang_account_t {
	struct hlist_node	hentry;
	unsigned long		last_ts;
	unsigned int		conn_curr;
	spinlock_t		lock;
	struct in6_addr		addr;
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

	/*
	 * Limits on time it takes to receive
	 * a full header or a body chunk.
	 */
	unsigned long	clnt_hdr_timeout;
	unsigned long	clnt_body_timeout;

	/* Limits for HTTP request contents: uri, headers, body, etc. */
	unsigned int 	http_uri_len;
	unsigned int 	http_field_len;
	unsigned int 	http_body_len;
	unsigned int	http_hchunk_cnt;
	unsigned int	http_bchunk_cnt;
	bool 		http_ct_required;
	bool 		http_host_required;
	/* The bitmask of allowed HTTP Method values. */
	unsigned long 	http_methods_mask;
	/* The list of allowed Content-Type values. */
	FrangCtVal	*http_ct_vals;
} FrangCfg;

static FrangCfg frang_cfg __read_mostly;
/* GFSM hooks priorities. */
int prio0, prio1;

#define frang_msg(check, addr, fmt, ...)				\
do {									\
	TfwAddr a = { .family = AF_INET6 };				\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	memcpy(&a.v6.sin6_addr, addr, sizeof(a.v6.sin6_addr));		\
	tfw_addr_ntop(&a, abuf, TFW_ADDR_STR_BUF_SIZE);			\
	TFW_WARN("frang: %s for %s" fmt, check, abuf, ##__VA_ARGS__);	\
} while (0)

#define frang_limmsg(lim_name, curr_val, lim, addr)			\
	frang_msg(lim_name " exceeded", addr, ": %ld (lim=%ld)\n",	\
		  (long)curr_val, (long)lim)

/**
 * Lookups and allocate in necessary client resource accounting descriptor.
 * The descriptor is returned locked.
 */
static FrangAcc *
frang_get_clnt_ra(struct sock *sk)
{
	unsigned int key;
	FrangHashBucket *hb;
	struct hlist_node *tmp;
	FrangAcc *ra;
	TfwAddr addr;

	tfw_addr_get_sk_saddr(sk, &addr);
	key = addr.v6.sin6_addr.s6_addr32[0] ^ addr.v6.sin6_addr.s6_addr32[1]
	      ^ addr.v6.sin6_addr.s6_addr32[2] ^ addr.v6.sin6_addr.s6_addr32[3];

	hb = &frang_hash[hash_min(key, FRANG_HASH_BITS)];

	spin_lock(&hb->lock);

	hlist_for_each_entry_safe(ra, tmp, &hb->list, hentry) {
		if (ipv6_addr_equal(&addr.v6.sin6_addr, &ra->addr))
			goto found;
		/* Collect garbage. */
		if (ra->last_ts + GC_TO < jiffies / HZ) {
			hash_del(&ra->hentry);
			kmem_cache_free(frang_mem_cache, ra);
		}
	}

	ra = kmem_cache_alloc(frang_mem_cache, GFP_ATOMIC | __GFP_ZERO);
	if (!ra) {
		TFW_WARN("frang: Unable to allocate account record\n");
		spin_unlock(&hb->lock);
		return NULL;
	}

	memcpy(&ra->addr, &addr.v6.sin6_addr, sizeof(addr.v6.sin6_addr));

	spin_lock_init(&ra->lock);
	ra->last_ts = jiffies;

	hlist_add_head(&ra->hentry, &hb->list);
found:
	spin_lock(&ra->lock);

	spin_unlock(&hb->lock);

	return ra;
}

static int
frang_conn_limit(FrangAcc *ra, struct sock *unused)
{
	unsigned long ts = (jiffies * FRANG_FREQ) / HZ;
	unsigned int csum = 0;
	int i = ts % FRANG_FREQ;

	if (ra->history[i].ts != ts) {
		ra->history[i].ts = ts;
		ra->history[i].conn_new = 0;
		ra->history[i].req = 0;
	}

	/*
	 * Increment connection counters even if we return TFW_BLOCK.
	 * Linux will call sk_free() from inet_csk_clone_lock(),
	 * so our frang_conn_close() is also called. conn_curr is
	 * decremented there, but conn_new is not changed. We count
	 * both failed connection attempts and connections that were
	 * successfully established.
	 */
	ra->history[i].conn_new++;
	ra->conn_curr++;

	if (frang_cfg.conn_max && ra->conn_curr > frang_cfg.conn_max) {
		frang_limmsg("connections max num.", ra->conn_curr,
			     frang_cfg.conn_max, &ra->addr);
		return TFW_BLOCK;
	}

	if (frang_cfg.conn_burst
	    && ra->history[i].conn_new > frang_cfg.conn_burst)
	{
		frang_limmsg("new connections burst", ra->history[i].conn_new,
			     frang_cfg.conn_burst, &ra->addr);
		return TFW_BLOCK;
	}

	/* Collect current connection sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			csum += ra->history[i].conn_new;
	if (frang_cfg.conn_rate && csum > frang_cfg.conn_rate) {
		frang_limmsg("new connections rate", csum, frang_cfg.conn_rate,
			     &ra->addr);
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_conn_new(struct sock *sk)
{
	int r;
	FrangAcc *ra;

	ra = frang_get_clnt_ra(sk);
	if (unlikely(!ra))
		return TFW_BLOCK;

	sk->sk_security = ra;

	r = frang_conn_limit(ra, sk);

	spin_unlock(&ra->lock);

	return r;
}

/**
 * Just update current connection count for a user.
 */
static void
frang_conn_close(struct sock *sk)
{
	FrangAcc *ra = sk->sk_security;

	BUG_ON(!ra);

	spin_lock(&ra->lock);

	ra->last_ts = jiffies;

	BUG_ON(!ra->conn_curr);
	ra->conn_curr--;

	spin_unlock(&ra->lock);
}

static int
frang_req_limit(FrangAcc *ra)
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

	if (frang_cfg.req_burst && ra->history[i].req > frang_cfg.req_burst) {
		frang_limmsg("requests burst", ra->history[i].req,
			     frang_cfg.req_burst, &ra->addr);
		return TFW_BLOCK;
	}
	/* Collect current request sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			rsum += ra->history[i].req;
	if (frang_cfg.req_rate && rsum > frang_cfg.req_rate) {
		frang_limmsg("request rate", rsum, frang_cfg.req_rate,
			     &ra->addr);
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_http_uri_len(const TfwHttpReq *req, FrangAcc *ra)
{
	if (req->uri_path.len > frang_cfg.http_uri_len) {
		frang_limmsg("HTTP URI length", req->uri_path.len,
			     frang_cfg.http_uri_len, &ra->addr);
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

/**
 * Check all parsed headers in request headers table.
 * We observe all headers many times, actually on each data chunk.
 * However, the check is relatively fast, so that should be Ok.
 * It's necessary to run the ckecks on each data chunk to prevent memory
 * exhausing DoS attack on many large header fields, since we don't know
 * which headers were read on each data chunk.
 *
 * TODO Probably it's better to embedd a hook to HTTP parser directly to
 * catch the long headers immediately.
 */
static int
__frang_http_field_len(const TfwHttpReq *req, FrangAcc *ra)
{
	const TfwStr *field, *end, *dup, *dup_end;

	FOR_EACH_HDR_FIELD(field, end, req) {
		TFW_STR_FOR_EACH_DUP(dup, field, dup_end) {
			if (field->len > frang_cfg.http_field_len) {
				frang_limmsg("HTTP field length", field->len,
					     frang_cfg.http_field_len,
					     &ra->addr);
				return TFW_BLOCK;
			}
		}
	}

	return TFW_PASS;
}

static int
frang_http_field_len(const TfwHttpReq *req, FrangAcc *ra)
{
	if (req->parser.hdr.len > frang_cfg.http_field_len) {
		frang_limmsg("HTTP in-progress field length",
			     req->parser.hdr.len, frang_cfg.http_field_len,
			     &ra->addr);
		return TFW_BLOCK;
	}

	return __frang_http_field_len(req, ra);
}

static int
frang_http_methods(const TfwHttpReq *req, FrangAcc *ra)
{
	unsigned long mbit = (1 << req->method);

	if (!(frang_cfg.http_methods_mask & mbit)) {
		frang_msg("restricted HTTP method", &ra->addr,
			  ": %u (%#lxu)\n", req->method, mbit);
		return TFW_BLOCK;
	}
	return TFW_PASS;
}

static int
frang_http_ct_check(const TfwHttpReq *req, FrangAcc *ra)
{
	TfwStr field, *s;
	FrangCtVal *curr;

	if (req->method != TFW_HTTP_METH_POST)
		return TFW_PASS;

	if (TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE])) {
		frang_msg("Content-Type header field", &ra->addr,
			  " is missed\n");
		return TFW_BLOCK;
	}

	tfw_http_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
			     TFW_HTTP_HDR_CONTENT_TYPE, &field);

	/*
	 * Verify that Content-Type value is on the list of allowed values.
	 *
	 * TODO: possible improvement: binary search.
	 * Generally binary search is more efficient, but linear search
	 * is usually faster for small sets of values. Perhaps we should
	 * switch between the two if performance is critical here,
	 * but benchmarks should be done to measure the impact.
	 */
	for (curr = frang_cfg.http_ct_vals; curr->str; ++curr) {
		if (tfw_str_eq_cstr(&field, curr->str, curr->len,
				    TFW_STR_EQ_PREFIX_CASEI))
			return TFW_PASS;
	}

	/* Take first chunk only for logging. */
	s = TFW_STR_CHUNK(&field, 0);
	if (s) {
		frang_msg("restricted Content-Type", &ra->addr,
			  ": %.*s\n", s->len, (char *)s->ptr);
	} else {
		frang_msg("restricted empty Content-Type", &ra->addr, "\n");
	}

	return TFW_BLOCK;
}

static int
frang_http_host_check(const TfwHttpReq *req, FrangAcc *ra)
{
	TfwAddr addr;
	TfwStr field;
	char *buf;
	int len;

	if (TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST])) {
		frang_msg("Host header field", &ra->addr, " is missed\n");
		return TFW_BLOCK;
	}

	tfw_http_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
			     TFW_HTTP_HDR_HOST, &field);

	/*
	 * FIXME: here should be a check that the Host value is not an IP
	 * address. Need a fast routine that supports compound TfwStr.
	 * Perhaps should implement a tiny FSM or postpone the task until we
	 * have a good regex library.
	 * For now just linearize the Host header field TfwStr{} string.
	 */
	len = field.len + 1;
	if ((buf = tfw_pool_alloc(req->pool, len)) == NULL)
		return TFW_BLOCK;
	tfw_str_to_cstr(&field, buf, len);
	if (!tfw_addr_pton(buf, &addr)) {
		frang_msg("Host header field contains IP address",
			  &ra->addr, "\n");
		return TFW_BLOCK;
	}
	return TFW_PASS;
}

/*
 * The GFSM states aren't hookable, so don't open the states definitions and
 * only start and finish states are present.
 */
#define TFW_GFSM_FRANG_STATE(s)	((TFW_FSM_FRANG << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	TFW_FRANG_FSM_INIT	= TFW_GFSM_FRANG_STATE(0),
	TFW_FRANG_FSM_DONE	= TFW_GFSM_FRANG_STATE(TFW_GFSM_STATE_LAST)
};

enum {
	Frang_Req_0,

	Frang_Req_Hdr_Start,
	Frang_Req_Hdr_Method,
	Frang_Req_Hdr_UriLen,
	Frang_Req_Hdr_FieldDup,
	Frang_Req_Hdr_FieldLen,
	Frang_Req_Hdr_FieldLenFinal,
	Frang_Req_Hdr_Crlf,
	Frang_Req_Hdr_Host,
	Frang_Req_Hdr_ContentType,

	Frang_Req_Hdr_NoState,

	Frang_Req_Body_Start,
	Frang_Req_Body_Timeout,
	Frang_Req_Body_ChunkCnt,
	Frang_Req_Body_Len,

	Frang_Req_Body_NoState,

	Frang_Req_Done
};

#define FSM_HDR_STATE(state)						\
	((state > Frang_Req_Hdr_Start) && (state < Frang_Req_Hdr_NoState))

#define __FRANG_FSM_INIT()						\
int __fsm_const_state = Frang_Req_0; /* make compiler happy */

#define __FRANG_FSM_START(st)						\
switch(st)

#define __FRANG_FSM_FINISH()						\
done:									\
	TFW_DBG("Finish FRANG FSM at state %d\n", __fsm_const_state);	\
	TFW_DBG("Frang return %s\n", r == TFW_PASS ? "PASS" : "BLOCK");	\
	req->frang_st = __fsm_const_state;

#define __FRANG_FSM_STATE(st)						\
case st:								\
st: __attribute__((unused))						\
	TFW_DBG("enter FRANG FSM at state %d\n", st);			\
	__fsm_const_state = st; /* optimized out to constant */

#define __FRANG_FSM_EXIT()	goto done;

#define __FRANG_FSM_JUMP(to)	goto to;
#define __FRANG_FSM_MOVE(to)						\
	if (r)								\
		__FRANG_FSM_EXIT();					\
	goto to;

#define __FRANG_FSM_JUMP_EXIT(to)					\
	__fsm_const_state = to; /* optimized out to constant */		\
	__FRANG_FSM_EXIT()

static int
frang_http_req_handler(void *obj, struct sk_buff *skb, unsigned int off)
{
	int r = TFW_PASS;
	TfwConnection *conn = (TfwConnection *)obj;
	TfwHttpReq *req = container_of(conn->msg, TfwHttpReq, msg);
	struct sk_buff *head_skb = ss_skb_peek(&req->msg.skb_list);
	FrangAcc *ra = conn->sk->sk_security;
	__FRANG_FSM_INIT();

	BUG_ON(!ra);

	spin_lock(&ra->lock);

	ra->last_ts = jiffies;

	/*
	 * There's no need to check for header timeout if this is the very
	 * first chunk of a request (first full separate SKB with data).
	 * The FSM is guaranteed to go through the initial states and then
	 * either block or move to one of header states. Then header timeout
	 * is checked on each consecutive SKB with data - while we're still
	 * in one of header processing states.
	 *
	 * Why is this not one of FSM states? Basically, that's to avoid
	 * going through unnecessary FSM states each time this is run. When
	 * there's a slowris attack, we may stay long in Hdr_Method or in
	 * Hdr_UriLen states, and that would require including the header
	 * timeout state in the loop. But when we're past these states, we
	 * don't want to run through them on each run again, and just want
	 * to loop in FieldDup and FieldLen states. I guess that can be
	 * done with some clever FSM programming, but this is just simpler.
	 */
	if (frang_cfg.clnt_hdr_timeout
	    && (skb != head_skb) && FSM_HDR_STATE(req->frang_st))
	{
		unsigned long start = req->tm_header;
		unsigned long delta = frang_cfg.clnt_hdr_timeout;

		if (time_is_before_jiffies(start + delta)) {
			frang_limmsg("client header timeout", jiffies - start,
				     delta, &ra->addr);
			spin_unlock(&ra->lock);
			return TFW_BLOCK;
		}
	}

	/* Сheck for chunk count here to account for possible fragmentation
	 * in HTTP status line. The rationale for not making this one of FSM
	 * states is the same as for the code block above.
	 */
	if (frang_cfg.http_hchunk_cnt && FSM_HDR_STATE(req->frang_st)) {
		req->chunk_cnt++;
		if (req->chunk_cnt > frang_cfg.http_hchunk_cnt) {
			frang_limmsg("HTTP header chunk count", req->chunk_cnt,
				     frang_cfg.http_hchunk_cnt, &ra->addr);
			spin_unlock(&ra->lock);
			return TFW_BLOCK;
		}
	}

	__FRANG_FSM_START(req->frang_st) {

	/*
	 * New HTTP request. Initial state. Check the limits that
	 * do not depend on contents of HTTP request. Note that
	 * connection-related limits are implemented as callbacks
	 * that run when a connection is established or destroyed.
	 */
	__FRANG_FSM_STATE(Frang_Req_0) {
		if (frang_cfg.req_burst || frang_cfg.req_rate)
			r = frang_req_limit(ra);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Start);
	}

	/*
	 * Prepare for HTTP request header checks. Set the time
	 * the header started coming in. Set starting position
	 * for checking raw (non-special) headers.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Start) {
		if (frang_cfg.clnt_hdr_timeout) {
			req->tm_header = jiffies;
		}
		__FRANG_FSM_JUMP(Frang_Req_Hdr_Method);
	}

	/*
	 * Ensure that HTTP request method is one of those
	 * defined by a user.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Method) {
		if (frang_cfg.http_methods_mask) {
			if (req->method == TFW_HTTP_METH_NONE) {
				__FRANG_FSM_EXIT();
			}
			r = frang_http_methods(req, ra);
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_UriLen);
	}

	/* Ensure that length of URI is within limits. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_UriLen) {
		if (frang_cfg.http_uri_len) {
			if (!(req->uri_path.flags & TFW_STR_COMPLETE)) {
				__FRANG_FSM_EXIT();
			}
			r = frang_http_uri_len(req, ra);
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_FieldDup);
	}

	/* Ensure that singular header fields are not duplicated. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_FieldDup) {
		if (req->flags & TFW_HTTP_FIELD_DUPENTRY) {
			frang_msg("duplicate header field found",
				  &ra->addr, "\n");
			r = TFW_BLOCK;
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_FieldLen);
	}

	/* Ensure that length of all parsed headers fields is within limits. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_FieldLen) {
		if (frang_cfg.http_field_len)
			r = frang_http_field_len(req, ra);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Crlf);
	}

	/*
	 * See if the full HTTP header is processed.
	 * If not, continue checks on header fields.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Crlf) {
		if (!TFW_STR_EMPTY(&req->crlf))
			__FRANG_FSM_JUMP(Frang_Req_Hdr_FieldLenFinal);
		__FRANG_FSM_JUMP_EXIT(Frang_Req_Hdr_FieldDup);
	}

	/*
	 * Full HTTP header has been processed, and any possible
	 * header faields are collected. Run final checks on them.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_FieldLenFinal) {
		if (frang_cfg.http_field_len)
			r = __frang_http_field_len(req, ra);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Host);
	}

	/* Ensure presence and the value of Host: header field. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Host) {
		if (frang_cfg.http_host_required)
			r = frang_http_host_check(req, ra);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_ContentType);
	}

	/*
	 * Ensure presence of Content-Type: header field.
	 * Ensure that the value is one of those defined by a user.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_ContentType) {
		if (frang_cfg.http_ct_required || frang_cfg.http_ct_vals)
			r = frang_http_ct_check(req, ra);
		__FRANG_FSM_MOVE(Frang_Req_Body_Start);
	}

	/*
	 * Prepare for HTTP request body checks.
	 * Set the time the body started coming in.
	 */
	__FRANG_FSM_STATE(Frang_Req_Body_Start) {
		if (frang_cfg.http_body_len || frang_cfg.clnt_body_timeout
		    || frang_cfg.http_bchunk_cnt)
		{
			req->chunk_cnt = 0; /* start counting body chunks now */
			req->tm_bchunk = jiffies;
			__FRANG_FSM_MOVE(Frang_Req_Body_ChunkCnt);
		}
		__FRANG_FSM_JUMP_EXIT(Frang_Req_Done);
	}

	/*
	 * Ensure that HTTP request body is coming without delays.
	 * The timeout is between chunks of the body, so reset
	 * the start time after each check.
	 */
	__FRANG_FSM_STATE(Frang_Req_Body_Timeout) {
		/*
		 * Note that this state is skipped on the first data SKB
		 * with body part as obviously no timeout has occured yet.
		 */
		if (frang_cfg.clnt_body_timeout) {
			unsigned long start = req->tm_bchunk;
			unsigned long delta = frang_cfg.clnt_body_timeout;

			if (time_is_before_jiffies(start + delta)) {
				frang_limmsg("client body timeout",
					     jiffies - start, delta,
					     &ra->addr);
				r = TFW_BLOCK;
			}
			req->tm_bchunk = jiffies;
		}
		__FRANG_FSM_MOVE(Frang_Req_Body_ChunkCnt);
	}

	/* Limit number of chunks in request body */
	__FRANG_FSM_STATE(Frang_Req_Body_ChunkCnt) {
		req->chunk_cnt++;
		if (frang_cfg.http_bchunk_cnt
		    && req->chunk_cnt > frang_cfg.http_bchunk_cnt)
		{
			frang_limmsg("HTTP body chunk count", req->chunk_cnt,
				     frang_cfg.http_bchunk_cnt, &ra->addr);
			r = TFW_BLOCK;
		}
		__FRANG_FSM_MOVE(Frang_Req_Body_Len);
	}

	/* Ensure that the length of HTTP request body is within limits. */
	__FRANG_FSM_STATE(Frang_Req_Body_Len) {
		if (frang_cfg.http_body_len
		    && (req->body.len > frang_cfg.http_body_len))
		{
			frang_limmsg("HTTP body length", req->body.len,
				     frang_cfg.http_body_len, &ra->addr);
			r = TFW_BLOCK;
		}
		__FRANG_FSM_JUMP_EXIT(Frang_Req_Body_Timeout);
	}

	/* All limits are verified for current request. */
	__FRANG_FSM_STATE(Frang_Req_Done) {
		tfw_gfsm_move(&req->msg.state, TFW_FRANG_FSM_DONE, skb, off);
		__FRANG_FSM_EXIT();
	}

	}
	__FRANG_FSM_FINISH();

	spin_unlock(&ra->lock);

	return r;
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

static int
frang_start(void)
{
	/* Convert these timeouts to jiffies for convenience */
	frang_cfg.clnt_hdr_timeout =
		*(unsigned int *)&frang_cfg.clnt_hdr_timeout * HZ;
	frang_cfg.clnt_body_timeout =
		*(unsigned int *)&frang_cfg.clnt_body_timeout * HZ;
	return 0;
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
		"connection_rate", "0",
		tfw_cfg_set_int,
		&frang_cfg.conn_rate,
	},
	{
		"connection_burst", "0",
		tfw_cfg_set_int,
		&frang_cfg.conn_burst,
	},
	{
		"concurrent_connections", "0",
		tfw_cfg_set_int,
		&frang_cfg.conn_max,
	},
	{
		"client_header_timeout", "0",
		tfw_cfg_set_int,
		(unsigned int *)&frang_cfg.clnt_hdr_timeout,
	},
	{
		"client_body_timeout", "0",
		tfw_cfg_set_int,
		(unsigned int *)&frang_cfg.clnt_body_timeout,
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
		"http_header_chunk_cnt", "0",
		tfw_cfg_set_int,
		&frang_cfg.http_hchunk_cnt,
	},
	{
		"http_body_chunk_cnt", "0",
		tfw_cfg_set_int,
		&frang_cfg.http_bchunk_cnt,
	},
	{
		"http_host_required", "false",
		tfw_cfg_set_bool,
		&frang_cfg.http_host_required,
	},
	{
		"http_ct_required", "false",
		tfw_cfg_set_bool,
		&frang_cfg.http_ct_required,
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
		.name = "frang_limits",
		.handler = tfw_cfg_handle_children,
		.dest = &frang_cfg_section_specs
	},
	{}
};

static TfwCfgMod frang_cfg_mod = {
	.name = "frang",
	.start = frang_start,
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

	tfw_classifier_register(&frang_class_ops);

	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG, frang_http_req_handler);
	if (r) {
		TFW_ERR("frang: can't register fsm\n");
		goto err_fsm;
	}

	prio0 = tfw_gfsm_register_hook(TFW_FSM_HTTP,
				       TFW_GFSM_HOOK_PRIORITY_ANY,
				       TFW_HTTP_FSM_REQ_MSG, TFW_FSM_FRANG,
				       TFW_FRANG_FSM_INIT);
	if (prio0 < 0) {
		TFW_ERR("frang: can't register gfsm msg hook\n");
		goto err_hook;
	}
	prio1 = tfw_gfsm_register_hook(TFW_FSM_HTTP,
				       TFW_GFSM_HOOK_PRIORITY_ANY,
				       TFW_HTTP_FSM_REQ_CHUNK, TFW_FSM_FRANG,
				       TFW_FRANG_FSM_INIT);
	if (prio1 < 0) {
		TFW_ERR("frang: can't register gfsm chunk hook\n");
		goto err_hook2;
	}

	return 0;
err_hook2:
	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio0, TFW_HTTP_FSM_REQ_MSG);
err_hook:
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG);
err_fsm:
	tfw_classifier_unregister();
	tfw_cfg_mod_unregister(&frang_cfg_mod);
err_cfg:
	kmem_cache_destroy(frang_mem_cache);
	return r;
}

static void __exit
frang_exit(void)
{
	int i;

	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio1, TFW_HTTP_FSM_REQ_CHUNK);
	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio0, TFW_HTTP_FSM_REQ_MSG);
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG);
	tfw_classifier_unregister();
	tfw_cfg_mod_unregister(&frang_cfg_mod);

	/*
	 * Free all accounting records before the cache destruction.
	 * There are still could be some users.
	 */
	for (i = 0; i < (1 << FRANG_HASH_BITS); ++i) {
		FrangAcc *ra;
		struct hlist_node *tmp;
		FrangHashBucket *hb = &frang_hash[i];

		spin_lock(&hb->lock);

		hlist_for_each_entry_safe(ra, tmp, &hb->list, hentry) {
			hash_del(&ra->hentry);
			kmem_cache_free(frang_mem_cache, ra);
		}

		spin_unlock(&hb->lock);
	}

	kmem_cache_destroy(frang_mem_cache);
}

module_init(frang_init);
module_exit(frang_exit);
