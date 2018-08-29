/**
 *		Tempesta FW
 *
 * Interface to classification modules.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
/*
 * TODO:
 * -- add socket/connection options adjusting to change client QoS
 */

#include <linux/ctype.h>
#include <linux/spinlock.h>

#include "tdb.h"

#include "tempesta_fw.h"
#include "addr.h"
#include "http_limits.h"
#include "client.h"
#include "connection.h"
#include "filter.h"
#include "gfsm.h"
#include "http_msg.h"
#include "vhost.h"
#include "log.h"

/*
 * ------------------------------------------------------------------------
 *	Generic classifier functionality.
 * ------------------------------------------------------------------------
 */

static struct {
	__be16		ports[DEF_MAX_PORTS];
	unsigned int	count;
} tfw_inports __read_mostly;

static TfwClassifier __rcu *classifier = NULL;

/**
 * Shrink client connections hash and/or reduce QoS for blocked clients to
 * lower back-end servers or local system load.
 */
void
tfw_classify_shrink(void)
{
	/* TODO: delete a connection from the LRU */
}

int
tfw_classify_ipv4(struct sk_buff *skb)
{
	int r;
	TfwClassifier *clfr;

	rcu_read_lock();

	clfr = rcu_dereference(classifier);
	r = (clfr && clfr->classify_ipv4)
	    ? clfr->classify_ipv4(skb)
	    : TFW_PASS;

	rcu_read_unlock();

	return r;
}

int
tfw_classify_ipv6(struct sk_buff *skb)
{
	int r;
	TfwClassifier *clfr;

	rcu_read_lock();

	clfr = rcu_dereference(classifier);
	r = (clfr && clfr->classify_ipv6)
	    ? clfr->classify_ipv6(skb)
	    : TFW_PASS;

	rcu_read_unlock();

	return r;
}

void
tfw_classifier_add_inport(__be16 port)
{
	BUG_ON(tfw_inports.count == DEF_MAX_PORTS - 1);

	tfw_inports.ports[tfw_inports.count++] = port;
}

void
tfw_classifier_cleanup_inport(void)
{
	memset(&tfw_inports, 0, sizeof(tfw_inports));
}

static int
tfw_classify_conn_estab(struct sock *sk)
{
	int i;
	unsigned short sport = tfw_addr_get_sk_sport(sk);
	TfwClassifier *clfr;

	/* Pass the packet if it's not for us. */
	for (i = 0; i < tfw_inports.count; ++i)
		if (sport == tfw_inports.ports[i])
			goto ours;
	return TFW_PASS;

ours:
	rcu_read_lock();

	clfr = rcu_dereference(classifier);
	i = (clfr && clfr->classify_conn_estab)
	    ? clfr->classify_conn_estab(sk)
	    : TFW_PASS;

	rcu_read_unlock();

	return i;
}

static void
tfw_classify_conn_close(struct sock *sk)
{
	TfwClassifier *clfr = rcu_dereference(classifier);

	if (clfr && clfr->classify_conn_close)
		clfr->classify_conn_close(sk);
}

/**
 * Called from sk_filter() called from tcp_v4_rcv() and tcp_v6_rcv(),
 * i.e. when IP fragments are already assembled and we can process TCP.
 */
static int
tfw_classify_tcp(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	TfwClassifier *clfr = rcu_dereference(classifier);

	return clfr && clfr->classify_tcp ? clfr->classify_tcp(th) : TFW_PASS;
}

/*
 * tfw_classifier_register() and tfw_classifier_unregister()
 * are called at Tempesta start/stop time. The execution is
 * serialized with a mutex. There's no need for additional
 * protection of rcu_assign_pointer() from concurrent use.
 */
void
tfw_classifier_register(TfwClassifier *mod)
{
	TFW_LOG("Registering new classifier: %s\n", mod->name);

	BUG_ON(classifier);
	rcu_assign_pointer(classifier, mod);
}

void
tfw_classifier_unregister(void)
{
	TFW_LOG("Unregistering classifier: %s\n", classifier->name);

	rcu_assign_pointer(classifier, NULL);
	synchronize_rcu();
}

static TempestaOps tempesta_ops = {
	.sk_alloc	= tfw_classify_conn_estab,
	.sk_free	= tfw_classify_conn_close,
	.sock_tcp_rcv	= tfw_classify_tcp,
};

/*
 * ------------------------------------------------------------------------
 *	Frang classifier - static http limits implementation.
 * ------------------------------------------------------------------------
 */

/* We account users with FRANG_FREQ frequency per second. */
#define FRANG_FREQ	8

typedef struct {
	unsigned long	ts;
	unsigned int	conn_new;
	unsigned int	req;
} FrangRates;

/**
 * Response code record.
 *
 * @cnt	- Amount of responses in a time frame part;
 * @ts	- Response time in seconds. Four bytes could be used to store enough
 *   number of seconds in the assumption that there won't be delays between user
 *   responses longer than 68 years;
 */
typedef struct {
	unsigned int	cnt;
	unsigned int	ts;
} __attribute__((packed)) FrangRespCodeStat;

/**
 * Main descriptor of client resource accounting.
 * @lock can be removed if RSS is tuned to schedule packets based on
 * <proto, src_ip> tuple. However, the hashing could produce bad CPU load
 * balancing so, such settings are not desirable.
 *
 * @conn_curr		- current connections number;
 * @history		- bursts history organized as a ring-buffer;
 * @resp_code_stat	- response code record
 */
typedef struct {
	unsigned int		conn_curr;
	spinlock_t		lock;
	FrangRates		history[FRANG_FREQ];
	FrangRespCodeStat	resp_code_stat[FRANG_FREQ];
} FrangAcc;

/* GFSM hooks priorities. */
int prio0, prio1, prio3;

#define FRANG_CLI2ACC(c)	((FrangAcc *)(&(c)->class_prvt))
#define FRANG_ACC2CLI(a)	container_of((TfwClassifierPrvt *)a,	\
					     TfwClient, class_prvt)
/*
 * Get frang configuration variable from request's location;
 * if variable is zero or request has no location, use global
 * frang configuration.
 */
#define __FRANG_CFG_VAR(name, member)					\
	const typeof(((FrangCfg *)0)->member) name =			\
		(req->location && req->location->frang_cfg->member	\
		? req->location->frang_cfg->member			\
		: tfw_vhost_global_frang_cfg()->member)

#define frang_msg(check, addr, fmt, ...)				\
	TFW_WARN_MOD_ADDR6(frang, check, addr, fmt, ##__VA_ARGS__)

#define frang_limmsg(lim_name, curr_val, lim, addr)			\
	frang_msg(lim_name " exceeded", (addr), ": %ld (lim=%ld)\n",	\
		  (long)curr_val, (long)lim)

#ifdef DEBUG
#define frang_dbg(fmt_msg, addr, ...)					\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	tfw_addr_fmt_v6(&(addr)->v6.sin6_addr, 0, abuf);		\
	TFW_DBG("frang: " fmt_msg, abuf, ##__VA_ARGS__);		\
} while (0)
#else
#define frang_dbg(...)
#endif

static int
frang_conn_limit(FrangAcc *ra, struct sock *unused, FrangCfg *conf)
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
	 * Increment connection counters even when we return TFW_BLOCK.
	 * Linux will call sk_free() from inet_csk_clone_lock(), so our
	 * frang_conn_close() is also called. @conn_curr is decremented
	 * there, but @conn_new is not changed. We count both failed
	 * connection attempts and connections that were successfully
	 * established.
	 */
	ra->history[i].conn_new++;
	ra->conn_curr++;

	if (conf->conn_max && ra->conn_curr > conf->conn_max) {
		frang_limmsg("connections max num.", ra->conn_curr,
			     conf->conn_max, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	if (conf->conn_burst && ra->history[i].conn_new > conf->conn_burst) {
		frang_limmsg("new connections burst", ra->history[i].conn_new,
			     conf->conn_burst, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	/* Collect current connection sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (ra->history[i].ts + FRANG_FREQ >= ts)
			csum += ra->history[i].conn_new;
	if (conf->conn_rate && csum > conf->conn_rate) {
		frang_limmsg("new connections rate", csum, conf->conn_rate,
			     &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static void
__frang_init_acc(TfwClient *cli)
{
	FrangAcc *ra = FRANG_CLI2ACC(cli);

	spin_lock_init(&ra->lock);
}

static int
frang_conn_new(struct sock *sk)
{
	int r;
	FrangAcc *ra;
	TfwClient *cli;
	FrangCfg *conf = tfw_vhost_global_frang_cfg();

	cli = tfw_client_obtain(sk, __frang_init_acc);
	if (unlikely(!cli)) {
		TFW_ERR("can't obtain a client for frang accounting\n");
		return TFW_BLOCK;
	}

	ra = FRANG_CLI2ACC(cli);

	spin_lock(&ra->lock);

	/*
	 * sk->sk_user_data references TfwConn{} which in turn references
	 * TfwPeer, so basically we can get FrangAcc from TfwConn{}.
	 * However, socket can live (for a short period of time, when kernel
	 * just allocated the socket and called tempesta_new_clntsk()) w/o
	 * TfwConn{} and vise versa - TfwConn{} can leave w/o socket
	 * (e.g. server connections during failover). Thus to keep design
	 * consistent we have two references to TfwPeer: from socket and
	 * TfwConn{}.
	 */
	sk->sk_security = ra;

	r = frang_conn_limit(ra, sk, conf);
	if (r == TFW_BLOCK && conf->ip_block) {
		tfw_filter_block_ip(&cli->addr.v6.sin6_addr);
		tfw_client_put(cli);
	}

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

	BUG_ON(!ra->conn_curr);
	ra->conn_curr--;

	spin_unlock(&ra->lock);

	tfw_client_put(FRANG_ACC2CLI(ra));
}

static int
frang_time_in_frame(const unsigned long tcur, const unsigned long tprev)
{
	return tprev + FRANG_FREQ > tcur;
}

static int
frang_req_limit(FrangAcc *ra, unsigned int req_burst, unsigned int req_rate)
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

	if (req_burst && ra->history[i].req > req_burst) {
		frang_limmsg("requests burst", ra->history[i].req,
			     req_burst, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}
	/* Collect current request sum. */
	for (i = 0; i < FRANG_FREQ; i++)
		if (frang_time_in_frame(ts, ra->history[i].ts))
			rsum += ra->history[i].req;
	if (req_rate && rsum > req_rate) {
		frang_limmsg("request rate", rsum, req_rate,
			     &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

static int
frang_http_uri_len(const TfwHttpReq *req, FrangAcc *ra, unsigned int uri_len)
{
	if (req->uri_path.len > uri_len) {
		frang_limmsg("HTTP URI length", req->uri_path.len,
			     uri_len, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	return TFW_PASS;
}

/**
 * Check all parsed headers in request headers table.
 * We observe all headers many times, actually on each data chunk.
 * However, the check is relatively fast, so that should be Ok.
 * It's necessary to run the checks on each data chunk to prevent memory
 * exhausting DoS attack on many large header fields, since we don't know
 * which headers were read on each data chunk.
 *
 * TODO Probably it's better to embed a hook to HTTP parser directly to
 * catch the long headers immediately.
 */
static int
__frang_http_field_len(const TfwHttpReq *req, FrangAcc *ra,
		       unsigned int field_len)
{
	const TfwStr *field, *end, *dup, *dup_end;
	__FRANG_CFG_VAR(hdr_cnt, http_hdr_cnt);

	if (hdr_cnt && req->h_tbl->off >= hdr_cnt) {
		frang_limmsg("HTTP headers number", req->h_tbl->off,
			     hdr_cnt, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	FOR_EACH_HDR_FIELD(field, end, req) {
		TFW_STR_FOR_EACH_DUP(dup, field, dup_end) {
			if (dup->len > field_len) {
				frang_limmsg("HTTP field length",
					     dup->len, field_len,
					     &FRANG_ACC2CLI(ra)->addr);
				return TFW_BLOCK;
			}
		}
	}

	return TFW_PASS;
}

static int
frang_http_field_len(const TfwHttpReq *req, FrangAcc *ra, unsigned int field_len)
{
	if (req->conn->parser.hdr.len > field_len) {
		frang_limmsg("HTTP in-progress field length",
			     req->conn->parser.hdr.len, field_len,
			     &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	return __frang_http_field_len(req, ra, field_len);
}

static int
frang_http_methods(const TfwHttpReq *req, FrangAcc *ra, unsigned long m_mask)
{
	unsigned long mbit = (1UL << req->method);

	if (!(m_mask & mbit)) {
		frang_msg("restricted HTTP method", &FRANG_ACC2CLI(ra)->addr,
			  ": %u (%#lxu)\n", req->method, mbit);
		return TFW_BLOCK;
	}
	return TFW_PASS;
}

static int
frang_http_ct_check(const TfwHttpReq *req, FrangAcc *ra, FrangCtVal *ct_vals)
{
	TfwStr field, *s;
	FrangCtVal *curr;

	if (req->method != TFW_HTTP_METH_POST)
		return TFW_PASS;

	if (TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE])) {
		frang_msg("Content-Type header field", &FRANG_ACC2CLI(ra)->addr,
			  " is missed\n");
		return TFW_BLOCK;
	}

	tfw_http_msg_clnthdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 TFW_HTTP_HDR_CONTENT_TYPE, &field);

	/*
	 * Verify that Content-Type value is on the list of allowed values.
	 * Use prefix match to allow parameters, see RFC 7231 3.1.1:
	 *
	 *	Content-Type = media-type
	 *	media-type = type "/" subtype *( OWS ";" OWS parameter )
	 *
	 * FIXME this matching is too permissive, e.g. we can pass
	 * "text/plain1", which isn't a correct subtype. Strong FSM processing
	 * is required. Or HTTP parser must pass only known types and Frang
	 * decides which of them are allowed.
	 * See also comment in frang_set_ct_vals().
	 *
	 * TODO: possible improvement: binary search.
	 * Generally binary search is more efficient, but linear search
	 * is usually faster for small sets of values. Perhaps we should
	 * switch between the two if performance is critical here,
	 * but benchmarks should be done to measure the impact.
	 */
	for (curr = ct_vals; curr->str; ++curr) {
		if (tfw_str_eq_cstr(&field, curr->str, curr->len,
				    TFW_STR_EQ_PREFIX_CASEI))
			return TFW_PASS;
	}

	/* Take first chunk only for logging. */
	s = TFW_STR_CHUNK(&field, 0);
	if (s) {
		frang_msg("restricted Content-Type", &FRANG_ACC2CLI(ra)->addr,
			  ": %.*s\n", PR_TFW_STR(s));
	} else {
		frang_msg("restricted empty Content-Type",
			  &FRANG_ACC2CLI(ra)->addr, "\n");
	}

	return TFW_BLOCK;
}

/**
 * Require host header in HTTP request (RFC 7230 5.4).
 * Block HTTP/1.1 requests w/o host header,
 * but just print warning for older HTTP.
 */
static int
frang_http_host_check(const TfwHttpReq *req, FrangAcc *ra)
{
	TfwAddr addr;
	TfwStr field;
	int ret = TFW_PASS;

	BUG_ON(!req);
	BUG_ON(!req->h_tbl);

	/*
	 * Host header must be presented,
	 * but don't enforce the policy for HTTP older than 1.1.
	 */
	if (TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST])) {
		frang_msg("Host header field", &FRANG_ACC2CLI(ra)->addr,
			  " is missed\n");
		return req->version > TFW_HTTP_VER_10 ? TFW_BLOCK : TFW_PASS;
	}

	tfw_http_msg_clnthdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
				 TFW_HTTP_HDR_HOST, &field);
	if (!TFW_STR_EMPTY(&field)) {
		/* Check that host header is not a IP address. */
		if (!tfw_addr_pton(&field, &addr)) {
			frang_msg("Host header field contains IP address",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			return TFW_BLOCK;
		}
	}

	if (test_bit(TFW_HTTP_URI_FULL, req->flags)) {
		char *hdrhost;

		/* If host in URI is empty, host header also must be empty. */
		if (TFW_STR_EMPTY(&field) + TFW_STR_EMPTY(&req->host) == 1) {
			frang_msg("Host header and URI host mismatch",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			return TFW_BLOCK;
		}

		hdrhost = tfw_pool_alloc(req->pool, field.len + 1);
		if (unlikely(!hdrhost)) {
			TFW_ERR("Can not allocate memory\n");
			return TFW_BLOCK;
		}
		tfw_str_to_cstr(&field, hdrhost, field.len + 1);

		/*
		 * If URI has form "http://host:port/path",
		 * then host header must be equal to host in URI.
		 */
		if (!tfw_str_eq_cstr(&req->host, hdrhost, field.len,
				     TFW_STR_EQ_CASEI))
		{
			frang_msg("Host header is not equal to host in URL",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			ret = TFW_BLOCK;
		}

		tfw_pool_free(req->pool, hdrhost, field.len + 1);
	}
	else if (TFW_STR_EMPTY(&field)) {
		/* If URI has form "/path", then host is not empty. */
		frang_msg("Host header is empty",
			  &FRANG_ACC2CLI(ra)->addr, "\n");
		ret = TFW_BLOCK;
	}

	return ret;
}

/**
 * Monotonically increasing time quantums. The configured @tframe
 * is divided by FRANG_FREQ slots to get the quantums granularity.
 */
static unsigned int
frang_resp_quantum(unsigned short tframe)
{
	return jiffies * FRANG_FREQ / (tframe * HZ);
}

static int
frang_bad_resp_limit(FrangAcc *ra, FrangHttpRespCodeBlock *resp_cblk)
{
	FrangRespCodeStat *stat = ra->resp_code_stat;
	unsigned long cnt = 0;
	const unsigned int ts = frang_resp_quantum(resp_cblk->tf);
	int i = 0;

	for (; i < FRANG_FREQ; ++i) {
		if (frang_time_in_frame(ts, stat[i].ts))
			cnt += stat[i].cnt;
	}
	if (cnt > resp_cblk->limit) {
		frang_limmsg("http_resp_code_block limit", cnt,
			     resp_cblk->limit, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}
	return TFW_PASS;
}

/*
 * The GFSM states aren't hookable, so don't open the states definitions and
 * only start and finish states are present.
 */
#define TFW_GFSM_FRANG_STATE(s)	((TFW_FSM_FRANG_REQ << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	TFW_FRANG_REQ_FSM_INIT	= TFW_GFSM_FRANG_STATE(0),
	TFW_FRANG_REQ_FSM_DONE	= TFW_GFSM_FRANG_STATE(TFW_GFSM_STATE_LAST)
};

enum {
	Frang_Req_0 = 0,

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

enum {
	TFW_FRANG_RESP_FSM_INIT	= TFW_FSM_FRANG_RESP << TFW_GFSM_FSM_SHIFT
};

#define FSM_HDR_STATE(state)						\
	((state > Frang_Req_Hdr_Start) && (state < Frang_Req_Hdr_NoState))

#define __FRANG_FSM_INIT()						\
int __fsm_const_state = Frang_Req_0; /* make compiler happy */

#define __FRANG_FSM_START(st)						\
switch(st)

#if defined(DEBUG) && (DEBUG >= 3)
const char *__state_name_array[] = {
	"Frang_Req_0",

	"Frang_Req_Hdr_Start",
	"Frang_Req_Hdr_Method",
	"Frang_Req_Hdr_UriLen",
	"Frang_Req_Hdr_FieldDup",
	"Frang_Req_Hdr_FieldLen",
	"Frang_Req_Hdr_FieldLenFinal",
	"Frang_Req_Hdr_Crlf",
	"Frang_Req_Hdr_Host",
	"Frang_Req_Hdr_ContentType",

	"Frang_Req_Hdr_NoState",

	"Frang_Req_Body_Start",
	"Frang_Req_Body_Timeout",
	"Frang_Req_Body_ChunkCnt",
	"Frang_Req_Body_Len",

	"Frang_Req_Body_NoState",

	"Frang_Req_Done"
};

#define __state_name(state) ((state >= 0 && state <= Frang_Req_Done) ?	\
				__state_name_array[state] :		\
				"Wrong state")
#endif /* defined(DEBUG) && (DEBUG >= 3) */

/* NOTE: we use the fact, that if DEBUG < 3, TFW_DBG3() is empty, so
 * we can use it with undefined arguments, such as
 * __state_name(__fsm_const_state), which is defined only when DEBUG >= 3
 */
#define __FRANG_FSM_FINISH()						\
done:									\
	TFW_DBG3("Finish FRANG FSM at state %d = %s\n",			\
		__fsm_const_state, __state_name(__fsm_const_state));	\
	TFW_DBG3("Frang return %s\n", r == TFW_PASS ? "PASS" : "BLOCK");\
	req->frang_st = __fsm_const_state;

#define __FRANG_FSM_STATE(st)						\
case st:								\
st: __attribute__((unused))						\
	TFW_DBG3("enter FRANG FSM at state %d = %s\n", st, __state_name(st));\
	__fsm_const_state = st; /* optimized out to constant */

#define __FRANG_FSM_EXIT()	goto done;

#define __FRANG_FSM_JUMP(to)	goto to;
#define __FRANG_FSM_MOVE(to)						\
do {									\
	if (r)								\
		__FRANG_FSM_EXIT();					\
	goto to;							\
} while (0)

#define __FRANG_FSM_JUMP_EXIT(to)					\
do {									\
	__fsm_const_state = to; /* optimized out to constant */		\
	__FRANG_FSM_EXIT();						\
} while (0)

static int
frang_http_req_process(FrangAcc *ra, TfwConn *conn, const TfwFsmData *data)
{
	int r = TFW_PASS;
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	struct sk_buff *skb = data->skb;
	struct sk_buff *head_skb = req->msg.skb_head;
	__FRANG_CFG_VAR(hdr_tmt, clnt_hdr_timeout);
	__FRANG_CFG_VAR(hchnk_cnt, http_hchunk_cnt);
	__FRANG_FSM_INIT();

	BUG_ON(!ra);
	BUG_ON(req != container_of(conn->msg, TfwHttpReq, msg));
	frang_dbg("check request for client %s, acc=%p\n",
		  &FRANG_ACC2CLI(ra)->addr, ra);

	spin_lock(&ra->lock);

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
	if (hdr_tmt && (skb != head_skb) && FSM_HDR_STATE(req->frang_st))
	{
		unsigned long start = req->tm_header;
		unsigned long delta = hdr_tmt;

		if (time_is_before_jiffies(start + delta)) {
			frang_limmsg("client header timeout", jiffies - start,
				     delta, &FRANG_ACC2CLI(ra)->addr);
			spin_unlock(&ra->lock);
			return TFW_BLOCK;
		}
	}

	/* Check for chunk count here to account for possible fragmentation
	 * in HTTP status line. The rationale for not making this one of FSM
	 * states is the same as for the code block above.
	 */
	if (hchnk_cnt && FSM_HDR_STATE(req->frang_st)) {
		req->chunk_cnt++;
		if (req->chunk_cnt > hchnk_cnt) {
			frang_limmsg("HTTP header chunk count", req->chunk_cnt,
				     hchnk_cnt, &FRANG_ACC2CLI(ra)->addr);
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
		__FRANG_CFG_VAR(req_burst, req_burst);
		__FRANG_CFG_VAR(req_rate, req_rate);
		__FRANG_CFG_VAR(resp_cblk, http_resp_code_block);
		if (req_burst || req_rate)
			r = frang_req_limit(ra, req_burst, req_rate);
		if (r == TFW_PASS && resp_cblk)
			r = frang_bad_resp_limit(ra, resp_cblk);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Start);
	}

	/*
	 * Prepare for HTTP request header checks. Set the time
	 * the header started coming in. Set starting position
	 * for checking raw (non-special) headers.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Start) {
		if (hdr_tmt) {
			req->tm_header = jiffies;
		}
		__FRANG_FSM_JUMP(Frang_Req_Hdr_Method);
	}

	/*
	 * Ensure that HTTP request method is one of those
	 * defined by a user.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Method) {
		__FRANG_CFG_VAR(m_mask, http_methods_mask);
		if (m_mask) {
			if (req->method == _TFW_HTTP_METH_NONE) {
				__FRANG_FSM_EXIT();
			}
			r = frang_http_methods(req, ra, m_mask);
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_UriLen);
	}

	/* Ensure that length of URI is within limits. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_UriLen) {
		__FRANG_CFG_VAR(uri_len, http_uri_len);
		if (uri_len) {
			r = frang_http_uri_len(req, ra, uri_len);
			if (!(req->uri_path.flags & TFW_STR_COMPLETE))
				__FRANG_FSM_JUMP_EXIT(Frang_Req_Hdr_UriLen);
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_FieldDup);
	}

	/* Ensure that singular header fields are not duplicated. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_FieldDup) {
		if (test_bit(TFW_HTTP_FIELD_DUPENTRY, req->flags)) {
			frang_msg("duplicate header field found",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			r = TFW_BLOCK;
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_FieldLen);
	}

	/* Ensure that length of all parsed headers fields is within limits. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_FieldLen) {
		__FRANG_CFG_VAR(field_len, http_field_len);
		if (field_len)
			r = frang_http_field_len(req, ra, field_len);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Crlf);
	}

	/*
	 * See if the full HTTP header is processed.
	 * If not, continue checks on header fields.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Crlf) {
		if (req->crlf.flags & TFW_STR_COMPLETE)
			__FRANG_FSM_JUMP(Frang_Req_Hdr_FieldLenFinal);
		__FRANG_FSM_JUMP_EXIT(Frang_Req_Hdr_FieldDup);
	}

	/*
	 * Full HTTP header has been processed, and any possible
	 * header fields are collected. Run final checks on them.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_FieldLenFinal) {
		__FRANG_CFG_VAR(field_len, http_field_len);
		if (field_len)
			r = __frang_http_field_len(req, ra, field_len);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Host);
	}

	/* Ensure presence and the value of Host: header field. */
	__FRANG_FSM_STATE(Frang_Req_Hdr_Host) {
		__FRANG_CFG_VAR(host_required, http_host_required);
		if (host_required)
			r = frang_http_host_check(req, ra);
		__FRANG_FSM_MOVE(Frang_Req_Hdr_ContentType);
	}

	/*
	 * Ensure presence of Content-Type: header field.
	 * Ensure that the value is one of those defined by a user.
	 */
	__FRANG_FSM_STATE(Frang_Req_Hdr_ContentType) {
		__FRANG_CFG_VAR(ct_required, http_ct_required);
		__FRANG_CFG_VAR(ct_vals, http_ct_vals);
		if (ct_required || ct_vals)
			r = frang_http_ct_check(req, ra, ct_vals);
		__FRANG_FSM_MOVE(Frang_Req_Body_Start);
	}

	/*
	 * Prepare for HTTP request body checks.
	 * Set the time the body started coming in.
	 */
	__FRANG_FSM_STATE(Frang_Req_Body_Start) {
		__FRANG_CFG_VAR(body_len, http_body_len);
		__FRANG_CFG_VAR(body_timeout, clnt_body_timeout);
		__FRANG_CFG_VAR(bchunk_cnt, http_bchunk_cnt);
		if (body_len || body_timeout || bchunk_cnt) {
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
		 * with body part as obviously no timeout has occurred yet.
		 */
		__FRANG_CFG_VAR(body_timeout, clnt_body_timeout);
		if (body_timeout) {
			unsigned long start = req->tm_bchunk;
			unsigned long delta = body_timeout;

			if (time_is_before_jiffies(start + delta)) {
				frang_limmsg("client body timeout",
					     jiffies - start, delta,
					     &FRANG_ACC2CLI(ra)->addr);
				r = TFW_BLOCK;
			}
		}
		__FRANG_FSM_MOVE(Frang_Req_Body_ChunkCnt);
	}

	/* Limit number of chunks in request body */
	__FRANG_FSM_STATE(Frang_Req_Body_ChunkCnt) {
		__FRANG_CFG_VAR(bchunk_cnt, http_bchunk_cnt);
		req->chunk_cnt++;
		if (bchunk_cnt && req->chunk_cnt > bchunk_cnt) {
			frang_limmsg("HTTP body chunk count", req->chunk_cnt,
				     bchunk_cnt, &FRANG_ACC2CLI(ra)->addr);
			r = TFW_BLOCK;
		}
		__FRANG_FSM_MOVE(Frang_Req_Body_Len);
	}

	/* Ensure that the length of HTTP request body is within limits. */
	__FRANG_FSM_STATE(Frang_Req_Body_Len) {
		__FRANG_CFG_VAR(body_len, http_body_len);
		if (body_len && (req->body.len > body_len)) {
			frang_limmsg("HTTP body length", req->body.len,
				     body_len, &FRANG_ACC2CLI(ra)->addr);
			r = TFW_BLOCK;
		}
		__FRANG_FSM_JUMP_EXIT(Frang_Req_Body_Timeout);
	}

	/* All limits are verified for current request. */
	__FRANG_FSM_STATE(Frang_Req_Done) {
		tfw_gfsm_move(&conn->state, TFW_FRANG_REQ_FSM_DONE, data);
		__FRANG_FSM_EXIT();
	}

	}
	__FRANG_FSM_FINISH();

	spin_unlock(&ra->lock);

	return r;
}

static int
frang_http_req_handler(void *obj, const TfwFsmData *data)
{
	int r;
	TfwConn *conn = (TfwConn *)obj;
	FrangAcc *ra = conn->sk->sk_security;
	bool ip_block = tfw_vhost_global_frang_cfg()->ip_block;

	if (test_bit(TFW_HTTP_WHITELIST, ((TfwHttpReq *)data->req)->flags))
		return TFW_PASS;

	r = frang_http_req_process(ra, conn, data);
	if (r == TFW_BLOCK && ip_block)
		tfw_filter_block_ip(&FRANG_ACC2CLI(ra)->addr.v6.sin6_addr);

	return r;
}

/*
 * Check response code and record it if it's listed in the filter.
 * Called from tfw_http_resp_fwd() by tfw_gfsm_move()
 * Always returns TFW_PASS because this handler is needed
 * for collecting purposes only.
 */
static int
frang_resp_handler(void *obj, const TfwFsmData *data)
{
	unsigned int ts, i;
	FrangAcc *ra;
	FrangRespCodeStat *stat;
	TfwHttpResp *resp;
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	__FRANG_CFG_VAR(conf, http_resp_code_block);

	if (!conf)
		return TFW_PASS;

	resp = (TfwHttpResp *)data->resp;
	ra = (FrangAcc *)req->conn->sk->sk_security;
	stat = ra->resp_code_stat;
	frang_dbg("client %s check response %d, acc=%p\n",
		  &FRANG_ACC2CLI(ra)->addr, resp->status, ra);

	if (!tfw_http_resp_code_range(resp->status)
	    || !test_bit(HTTP_CODE_BIT_NUM(resp->status), conf->codes))
		return TFW_PASS;

	spin_lock(&ra->lock);

	ts = frang_resp_quantum(conf->tf);
	i = ts % FRANG_FREQ;
	if (ts != stat[i].ts) {
		stat[i].ts = ts;
		stat[i].cnt = 1;
	} else {
		++stat[i].cnt;
	}

	spin_unlock(&ra->lock);

	return TFW_PASS;
}

static TfwClassifier frang_class_ops = {
	.name			= "frang",
	.classify_conn_estab	= frang_conn_new,
	.classify_conn_close	= frang_conn_close,
};

/*
 * ------------------------------------------------------------------------
 *	Init/exit procedures for http limits.
 * ------------------------------------------------------------------------
 */

int __init
tfw_http_limits_init(void)
{
	int r;

	tempesta_register_ops(&tempesta_ops);

	BUILD_BUG_ON((sizeof(FrangAcc) > sizeof(TfwClassifierPrvt)));

	tfw_classifier_register(&frang_class_ops);

	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG_REQ, frang_http_req_handler);
	if (r) {
		TFW_ERR_NL("frang: can't register request fsm\n");
		goto err_fsm;
	}

	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG_RESP, frang_resp_handler);
	if (r) {
		TFW_ERR_NL("frang: can't register response fsm\n");
		goto err_fsm_resp;
	}

	prio0 = tfw_gfsm_register_hook(TFW_FSM_HTTP,
				       TFW_GFSM_HOOK_PRIORITY_ANY,
				       TFW_HTTP_FSM_REQ_MSG, TFW_FSM_FRANG_REQ,
				       TFW_FRANG_REQ_FSM_INIT);
	if (prio0 < 0) {
		TFW_ERR_NL("frang: can't register gfsm msg hook\n");
		r = prio0;
		goto err_hook;
	}
	prio1 = tfw_gfsm_register_hook(TFW_FSM_HTTP,
				       TFW_GFSM_HOOK_PRIORITY_ANY,
				       TFW_HTTP_FSM_REQ_CHUNK, TFW_FSM_FRANG_REQ,
				       TFW_FRANG_REQ_FSM_INIT);
	if (prio1 < 0) {
		TFW_ERR_NL("frang: can't register gfsm chunk hook\n");
		r = prio1;
		goto err_hook2;
	}
	prio3 = tfw_gfsm_register_hook(TFW_FSM_HTTP,
				       TFW_GFSM_HOOK_PRIORITY_ANY,
				       TFW_HTTP_FSM_RESP_MSG_FWD,
				       TFW_FSM_FRANG_RESP,
				       TFW_FRANG_RESP_FSM_INIT);
	if (prio3 < 0) {
		TFW_ERR_NL("frang: can't register gfsm msg fwd hook\n");
		r = prio3;
		goto err_hook3;
	}

	return 0;
err_hook3:
	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio1, TFW_HTTP_FSM_REQ_CHUNK);
err_hook2:
	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio0, TFW_HTTP_FSM_REQ_MSG);
err_hook:
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_RESP);
err_fsm_resp:
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_REQ);
err_fsm:
	tfw_classifier_unregister();
	tempesta_unregister_ops(&tempesta_ops);
	return r;
}

void
tfw_http_limits_exit(void)
{
	TFW_DBG("frang exit\n");

	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio3, TFW_HTTP_FSM_RESP_MSG_FWD);
	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio1, TFW_HTTP_FSM_REQ_CHUNK);
	tfw_gfsm_unregister_hook(TFW_FSM_HTTP, prio0, TFW_HTTP_FSM_REQ_MSG);
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_RESP);
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_REQ);
	tfw_classifier_unregister();
	tempesta_unregister_ops(&tempesta_ops);
}
