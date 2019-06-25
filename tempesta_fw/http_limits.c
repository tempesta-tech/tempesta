/**
 *		Tempesta FW
 *
 * Interface to classification modules.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
 * TODO: #488 add socket/connection options adjusting to change client QoS
 */
#include <linux/ctype.h>
#include <linux/spinlock.h>

#include "lib/fsm.h"
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

#define FRANG_CLI2ACC(c)	((FrangAcc *)(&(c)->class_prvt))
#define FRANG_ACC2CLI(a)	container_of((TfwClassifierPrvt *)a,	\
					     TfwClient, class_prvt)

#define frang_msg(check, addr, fmt, ...)				\
	TFW_WARN_MOD_ADDR(frang, check, addr, TFW_NO_PORT, fmt, ##__VA_ARGS__)

/*
 * Client actions has triggered a security event. Log the client addr and
 * Frang limit name.
 */
#define frang_limmsg(lim_name, curr_val, lim, addr)			\
	frang_msg(lim_name " exceeded", (addr), ": %ld (lim=%ld)\n",	\
		  (long)curr_val, (long)lim)
/*
 * Local subsystem has triggered a security event, mostly it's a
 * misconfiguration issue. Log the event and subsystem name.
 */
#define frang_limmsg_local(lim_name, curr_val, lim, system)		\
	T_WARN("frang: " lim_name " exceeded for '%s' subsystem: "	\
	       "%ld (lim=%ld)\n",					\
	       system, (long)curr_val, (long)lim)

#ifdef DEBUG
#define frang_dbg(fmt_msg, addr, ...)					\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	tfw_addr_fmt(addr, TFW_NO_PORT, abuf);				\
	T_DBG("frang: " fmt_msg, abuf, ##__VA_ARGS__);			\
} while (0)
#else
#define frang_dbg(...)
#endif

static int
frang_conn_limit(FrangAcc *ra, FrangGlobCfg *conf)
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
__frang_init_acc(void *data)
{
	TfwClient *cli = (TfwClient *)data;
	FrangAcc *ra = FRANG_CLI2ACC(cli);

	spin_lock_init(&ra->lock);
}

static int
frang_conn_new(struct sock *sk)
{
	int r = TFW_BLOCK;
	FrangAcc *ra;
	TfwClient *cli;
	TfwAddr addr;
	TfwVhost *dflt_vh = tfw_vhost_lookup_default();

	/*
	 * Default vhost configuration stores global frang settings, it's always
	 * available even on reload under heavy load. But the pointer comes
	 * from other module, take care of probable null-dereferences.
	 */
	if (WARN_ON_ONCE(!dflt_vh))
		return TFW_BLOCK;

	ss_getpeername(sk, &addr);
	cli = tfw_client_obtain(addr, NULL, NULL, __frang_init_acc);
	if (unlikely(!cli)) {
		T_ERR("can't obtain a client for frang accounting\n");
		tfw_vhost_put(dflt_vh);
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
	/*
	 * TBD: Since we can determine vhost by SNI field in TLS headers, there
	 * will be a desire to make all frang limits per-vhost. After some
	 * thinking I have found this counter-intuitive: The way, how the
	 * frang limits work will depend on too many conditions. E.g.
	 * TLS-enabled clients will use higher limits than non-TLS clients;
	 * the same client can break security rules for one vhost, but be a
	 * legitimate client for other vhosts, so it's a big question how to
	 * block him by IP or by connection resets; if multy-domain certificate
	 * (SAN) is configured, TLS clients will behave as non-TLS. Too
	 * complicated for administrator to understand how client is blocked
	 * and to configure it, while making some of the limits to be global
	 * for a single client is absolutely straight-forward.
	 */
	r = frang_conn_limit(ra, dflt_vh->frang_gconf);
	if (r == TFW_BLOCK && dflt_vh->frang_gconf->ip_block) {
		tfw_filter_block_ip(&cli->addr);
		tfw_client_put(cli);
	}

	spin_unlock(&ra->lock);
	tfw_vhost_put(dflt_vh);

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

	if (!req_burst && !req_rate)
		return TFW_PASS;

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
		       unsigned int field_len,  unsigned int hdr_cnt)
{
	const TfwStr *field, *end, *dup, *dup_end;

	if (hdr_cnt && req->h_tbl->off >= hdr_cnt) {
		frang_limmsg("HTTP headers number", req->h_tbl->off,
			     hdr_cnt, &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}
	if (!field_len)
		return TFW_PASS;

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
frang_http_field_len(const TfwHttpReq *req, FrangAcc *ra, unsigned int field_len,
		     unsigned int hdr_cnt)
{
	TfwHttpParser *parser = &req->conn->parser;

	if (field_len && (parser->hdr.len > field_len)) {
		frang_limmsg("HTTP in-progress field length",
			     parser->hdr.len, field_len,
			     &FRANG_ACC2CLI(ra)->addr);
		return TFW_BLOCK;
	}

	return __frang_http_field_len(req, ra, field_len, hdr_cnt);
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

	if (test_bit(TFW_HTTP_B_URI_FULL, req->flags)) {
		char *hdrhost;

		/* If host in URI is empty, host header also must be empty. */
		if (TFW_STR_EMPTY(&field) + TFW_STR_EMPTY(&req->host) == 1) {
			frang_msg("Host header and URI host mismatch",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			return TFW_BLOCK;
		}

		hdrhost = tfw_pool_alloc(req->pool, field.len + 1);
		if (unlikely(!hdrhost)) {
			T_ERR("Can not allocate memory\n");
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

/*
 * The GFSM states aren't hookable, so don't open the states definitions and
 * only start and finish states are present.
 */
#define TFW_GFSM_FRANG_REQ_STATE(s)					\
	((TFW_FSM_FRANG_REQ << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	TFW_FRANG_REQ_FSM_INIT	= TFW_GFSM_FRANG_REQ_STATE(0),
	TFW_FRANG_REQ_FSM_DONE	= TFW_GFSM_FRANG_REQ_STATE(TFW_GFSM_STATE_LAST)
};

enum {
	Frang_Req_0 = 0,

	Frang_Req_Hdr_Method,
	Frang_Req_Hdr_UriLen,
	Frang_Req_Hdr_Check,

	Frang_Req_Hdr_NoState,

	Frang_Req_Body_Start,
	Frang_Req_Body_End,

	Frang_Req_Body_NoState,

	Frang_Req_Trailer,

	Frang_Req_Done
};

#define TFW_GFSM_FRANG_RESP_STATE(s)					\
	((TFW_FSM_FRANG_RESP << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	TFW_FRANG_RESP_FSM_INIT	= TFW_GFSM_FRANG_RESP_STATE(0),
	TFW_FRANG_RESP_FSM_FWD	= TFW_GFSM_FRANG_RESP_STATE(1),
	TFW_FRANG_RESP_FSM_DONE	= TFW_GFSM_FRANG_RESP_STATE(TFW_GFSM_STATE_LAST)
};

#define __FRANG_FSM_MOVE(st)	T_FSM_MOVE(st, if (r) T_FSM_EXIT(); )

#define __FRANG_FSM_JUMP_EXIT(st)					\
do {									\
	__fsm_const_state = st; /* optimized out to constant */		\
	T_FSM_EXIT();							\
} while (0)

static int
frang_http_req_incomplete_hdrs_check(FrangAcc *ra, TfwFsmData *data,
				     FrangGlobCfg *fg_cfg)
{
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	struct sk_buff *skb = data->skb;
	struct sk_buff *head_skb = req->msg.skb_head;
	unsigned int hchnk_cnt = fg_cfg->http_hchunk_cnt;

	frang_dbg("check incomplete request headers for client %s, acc=%p\n",
		  &FRANG_ACC2CLI(ra)->addr, ra);
	/*
	 * There's no need to check for header timeout if this is the very
	 * first chunk of a request (first full separate SKB with data).
	 * The FSM is guaranteed to go through the initial states and then
	 * either block or move to one of header states. Then header timeout
	 * is checked on each consecutive SKB with data - while we're still
	 * in one of header processing states.
	 */
	if (fg_cfg->clnt_hdr_timeout && (skb != head_skb)) {
		unsigned long start = req->tm_header;
		unsigned long delta = fg_cfg->clnt_hdr_timeout;

		if (time_is_before_jiffies(start + delta)) {
			frang_limmsg("client header timeout",
				     jiffies_to_msecs(jiffies - start),
				     jiffies_to_msecs(delta),
				     &FRANG_ACC2CLI(ra)->addr);
			goto block;
		}
	}

	if (hchnk_cnt && (req->chunk_cnt > hchnk_cnt)) {
		frang_limmsg("HTTP header chunk count", req->chunk_cnt,
			     hchnk_cnt, &FRANG_ACC2CLI(ra)->addr);
		goto block;
	}

	return TFW_PASS;
block:
	return TFW_BLOCK;
}

static int
frang_http_req_incomplete_body_check(FrangAcc *ra, TfwFsmData *data,
				     FrangGlobCfg *fg_cfg, FrangCfg *f_cfg)
{
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	unsigned int body_len = f_cfg->http_body_len;
	unsigned int bchunk_cnt = fg_cfg->http_bchunk_cnt;
	unsigned long body_timeout = fg_cfg->clnt_body_timeout;
	struct sk_buff *skb = data->skb;

	frang_dbg("check incomplete request body for client %s, acc=%p\n",
		  &FRANG_ACC2CLI(ra)->addr, ra);

	/* CLRF after headers was parsed, but the body didn't arrive yet. */
	if (TFW_STR_EMPTY(&req->body))
		return TFW_PASS;
	/*
	 * Ensure that HTTP request body is coming without delays.
	 * The timeout is between chunks of the body, so reset
	 * the start time after each check.
	 */
	if (body_timeout && req->tm_bchunk && (skb != req->body.skb)) {
		unsigned long start = req->tm_bchunk;
		unsigned long delta = body_timeout;

		if (time_is_before_jiffies(start + delta)) {
			frang_limmsg("client body timeout",
				     jiffies_to_msecs(jiffies - start),
				     jiffies_to_msecs(delta),
				     &FRANG_ACC2CLI(ra)->addr);
			goto block;
		}
		req->tm_bchunk = jiffies;
	}

	/* Limit number of chunks in request body */
	if (bchunk_cnt && (req->chunk_cnt > bchunk_cnt)) {
		frang_limmsg("HTTP body chunk count", req->chunk_cnt,
			     bchunk_cnt, &FRANG_ACC2CLI(ra)->addr);
		goto block;
	}

	if (body_len && (req->body.len > body_len)) {
		frang_limmsg("HTTP body length", req->body.len,
			     body_len, &FRANG_ACC2CLI(ra)->addr);
		goto block;
	}

	return TFW_PASS;
block:
	return TFW_BLOCK;
}

/*
 * RFC 7230 Section-4.1.2:
 * When a chunked message containing a non-empty trailer is received,
 * the recipient MAY process the fields.
 *
 * RFC 7230 Section-4.1.2:
 * ...a server SHOULD NOT
 * generate trailer fields that it believes are necessary for the user
 * agent to receive.  Without a TE containing "trailers", the server
 * ought to assume that the trailer fields might be silently discarded
 * along the path to the user agent.  This requirement allows
 * intermediaries to forward a de-chunked message to an HTTP/1.0
 * recipient without buffering the entire response.
 *
 * RFC doesn't prohibit trailers in request, but it always speaks about
 * trailers in response context. But request with trailer headers
 * are valid http messages. Support for them is not documented,
 * and implementation-dependent. E.g. Apache doesn't care about trailer
 * headers, but ModSecurity for Apache does.
 * https://swende.se/blog/HTTPChunked.html
 * Some discussions also highlights that trailer headers are poorly
 * supported on both servers and clients, while CDNs tend to add
 * trailers. https://github.com/whatwg/fetch/issues/34
 *
 * Since RFC doesn't speak clearly about trailer headers in requests, the
 * following assumptions was used:
 * - Our intermediaries on client side doesn't care about trailers and send
 *   them in the manner as the body. Thus frang's body limitations are used,
 *   not headers ones.
 * - Same header may have different values depending on how the servers works
 *   with the trailer. Administrator can block that behaviour.
 */
static int
frang_http_req_trailer_check(FrangAcc *ra, TfwFsmData *data,
			     FrangGlobCfg *fg_cfg, FrangCfg *f_cfg)
{
	int r = TFW_PASS;
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	const TfwStr *field, *end, *dup, *dup_end;

	if (!test_bit(TFW_HTTP_B_CHUNKED_TRAILER, req->flags))
		return TFW_PASS;
	/*
	 * Don't use special settings for the trailer part, keep on
	 * using body limits.
	 */
	r = frang_http_req_incomplete_body_check(ra, data, fg_cfg, f_cfg);
	if (test_bit(TFW_HTTP_B_FIELD_DUPENTRY, req->flags)) {
		frang_msg("duplicate header field found",
			  &FRANG_ACC2CLI(ra)->addr, "\n");
		return TFW_BLOCK;
	}
	if (!r)
		r = frang_http_field_len(req, ra, f_cfg->http_field_len,
					 f_cfg->http_hdr_cnt);
	if (r)
		return r;

	if (!tfw_http_parse_is_done((TfwHttpMsg *)req))
		return TFW_POSTPONE;
	/*
	 * Block request if the same header appear in both main and
	 * trailer headers part. Some intermediates doesn't read trailers, so
	 * request processing may depend on implementation.
	 */
	if (!f_cfg->http_trailer_split)
		return TFW_PASS;

	FOR_EACH_HDR_FIELD(field, end, req) {
		int trailers = 0, dups = 0;
		TFW_STR_FOR_EACH_DUP(dup, field, dup_end) {
			trailers += !!(dup->flags & TFW_STR_TRAILER);
			dups += 1;
		}
		if (trailers && (dups != trailers)) {
			frang_msg("HTTP field appear in header and trailer "
				  "for client %p",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			return TFW_BLOCK;
		}
	}

	return r;
}

static int
frang_http_req_process(FrangAcc *ra, TfwConn *conn, TfwFsmData *data,
		       TfwVhost *dvh)
{
	int r = TFW_PASS;
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	FrangCfg *f_cfg = NULL;
	FrangGlobCfg *fg_cfg = NULL;
	T_FSM_INIT(Frang_Req_0, "frang");

	BUG_ON(!ra);
	BUG_ON(req != container_of(conn->msg, TfwHttpReq, msg));
	frang_dbg("check request for client %s, acc=%p\n",
		  &FRANG_ACC2CLI(ra)->addr, ra);

	if (req->vhost) {
		/* Default vhost has no 'vhost_dflt' member set. */
		fg_cfg = req->vhost->vhost_dflt
				? req->vhost->vhost_dflt->frang_gconf
				: req->vhost->frang_gconf;
		f_cfg = req->location ? req->location->frang_cfg
				      : req->vhost->loc_dflt->frang_cfg;
	}
	else {
		fg_cfg = dvh->frang_gconf;
		f_cfg = dvh->loc_dflt->frang_cfg;
	}
	if (WARN_ON_ONCE(!fg_cfg || !f_cfg))
		return TFW_BLOCK;

	spin_lock(&ra->lock);

	/*
	 * Detect slowris attack first, and then proceed with more precise
	 * checks. This is not an FSM state, because the checks are required
	 * every time a new request chunk is received and will be present in
	 * every FSM state.
	 */
	if (req->frang_st < Frang_Req_Hdr_NoState)
		r = frang_http_req_incomplete_hdrs_check(ra, data, fg_cfg);
	else
		r = frang_http_req_incomplete_body_check(ra, data, fg_cfg,
							 f_cfg);
	if (r) {
		spin_unlock(&ra->lock);
		return r;
	}

	T_FSM_START(req->frang_st) {

	/*
	 * New HTTP request. Initial state. Check the limits that
	 * do not depend on contents of HTTP request. Note that
	 * connection-related limits are implemented as callbacks
	 * that run when a connection is established or destroyed.
	 */
	T_FSM_STATE(Frang_Req_0) {
		r = frang_req_limit(ra, fg_cfg->req_burst, fg_cfg->req_rate);
		/* Set the time the header started coming in. */
		req->tm_header = jiffies;
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Method);
	}

	/* Ensure that HTTP request method is one of those defined by a user. */
	T_FSM_STATE(Frang_Req_Hdr_Method) {
		if (f_cfg->http_methods_mask) {
			if (req->method == _TFW_HTTP_METH_NONE) {
				T_FSM_EXIT();
			}
			r = frang_http_methods(req, ra,
					       f_cfg->http_methods_mask);
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_UriLen);
	}

	/* Ensure that length of URI is within limits. */
	T_FSM_STATE(Frang_Req_Hdr_UriLen) {
		if (f_cfg->http_uri_len) {
			r = frang_http_uri_len(req, ra, f_cfg->http_uri_len);
			if (!(req->uri_path.flags & TFW_STR_COMPLETE))
				__FRANG_FSM_JUMP_EXIT(Frang_Req_Hdr_UriLen);
		}
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Check);
	}

	/*
	 * Headers are not fully parsed, a new request chunk was received.
	 * Test that all currently received headers doesn't overcome frang
	 * limits.
	 */
	T_FSM_STATE(Frang_Req_Hdr_Check) {
		if (test_bit(TFW_HTTP_B_FIELD_DUPENTRY, req->flags)) {
			frang_msg("duplicate header field found",
				  &FRANG_ACC2CLI(ra)->addr, "\n");
			r = TFW_BLOCK;
			T_FSM_EXIT();
		}
		r = frang_http_field_len(req, ra, f_cfg->http_field_len,
					 f_cfg->http_hdr_cnt);
		if (r)
			T_FSM_EXIT();

		/* Headers are not fully parsed yet. */
		if (!(req->crlf.flags & TFW_STR_COMPLETE))
			__FRANG_FSM_JUMP_EXIT(Frang_Req_Hdr_UriLen);
		/*
		* Full HTTP header has been processed, and any possible
		* header fields are collected. Run final checks on them.
		*/

		/* Ensure presence and the value of Host: header field. */
		if (f_cfg->http_host_required
		    && (r = frang_http_host_check(req, ra)))
		{
			T_FSM_EXIT();
		}
		/*
		* Ensure presence of Content-Type: header field.
		* Ensure that the value is one of those defined by a user.
		*/
		if (f_cfg->http_ct_required || f_cfg->http_ct_vals)
			r = frang_http_ct_check(req, ra, f_cfg->http_ct_vals);

		__FRANG_FSM_MOVE(Frang_Req_Body_Start);
	}

	/*
	 * Prepare for HTTP request body checks.
	 * Set the time the body started coming in.
	 */
	T_FSM_STATE(Frang_Req_Body_Start) {
		req->chunk_cnt = 0; /* start counting body chunks now. */
		req->tm_bchunk = jiffies;
		r = frang_http_req_incomplete_body_check(ra, data, fg_cfg,
							 f_cfg);
		__FRANG_FSM_MOVE(Frang_Req_Body_End);
	}

	/*
	 * Body is not fully parsed, a new body chunk was received.
	 */
	T_FSM_STATE(Frang_Req_Body_End) {

		/* Body is not fully parsed yet. */
		if (!(req->body.flags & TFW_STR_COMPLETE))
			__FRANG_FSM_JUMP_EXIT(Frang_Req_Body_End);

		__FRANG_FSM_MOVE(Frang_Req_Trailer);
	}

	/* Trailer headers. */
	T_FSM_STATE(Frang_Req_Trailer) {
		r = frang_http_req_trailer_check(ra, data, fg_cfg, f_cfg);
		__FRANG_FSM_MOVE(Frang_Req_Done);
	}

	/* All limits are verified for current request. */
	T_FSM_STATE(Frang_Req_Done) {
		tfw_gfsm_move(&conn->state, TFW_FRANG_REQ_FSM_DONE, data);
		T_FSM_EXIT();
	}

	}
	T_FSM_FINISH(r, req->frang_st);

	spin_unlock(&ra->lock);

	return r;
}

static int
frang_http_req_handler(void *obj, TfwFsmData *data)
{
	int r;
	TfwConn *conn = (TfwConn *)obj;
	FrangAcc *ra = conn->sk->sk_security;
	TfwVhost *dvh = NULL;
	TfwHttpReq *req = (TfwHttpReq *)data->req;

	if (req->peer)
		ra = FRANG_CLI2ACC(req->peer);

	if (test_bit(TFW_HTTP_B_WHITELIST, ((TfwHttpReq *)data->req)->flags))
		return TFW_PASS;

	dvh = tfw_vhost_lookup_default();
	if (WARN_ON_ONCE(!dvh))
		return TFW_BLOCK;
	r = frang_http_req_process(ra, conn, data, dvh);
	if (r == TFW_BLOCK && dvh->frang_gconf->ip_block)
		tfw_filter_block_ip(&FRANG_ACC2CLI(ra)->addr);
	tfw_vhost_put(dvh);

	return r;
}

/**
 * Check that response suits frang limits. Called when a part or whole response
 * is parsed.
 */
static int
frang_resp_process(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwAddr *cli_addr = NULL;
	TfwLocation *loc = req->location ? : req->vhost->loc_dflt;
	unsigned long body_len = loc->frang_cfg->http_body_len;
	int r = TFW_PASS;

	if (!body_len)
		return TFW_PASS;

	if (likely(req->conn)) {
		if (req->peer)
			cli_addr = &req->peer->addr;
		else
			cli_addr = &req->conn->peer->addr;
	}

	/* Ensure message body size doesn't overcome acceptable limits. */
	if ((resp->content_length > body_len) || (resp->body.len > body_len)) {
		if (cli_addr) {
			frang_limmsg("HTTP response body length",
				     resp->body.len, body_len, cli_addr);
		}
		else {
			frang_limmsg_local("HTTP response body length",
					   resp->body.len, body_len,
					   "Health Monitor");
		}
		r = TFW_BLOCK;
	}

	return r;
}

/**
 * Monotonically increasing time quantums. The configured @tframe
 * is divided by FRANG_FREQ slots to get the quantums granularity.
 * To reduce calculations, tframe is already stored as result of multiplication
 * operation, see __tfw_cfgop_frang_rsp_code_block().
 */
static inline unsigned int
frang_resp_quantum(unsigned short tframe)
{
	return jiffies / tframe;
}

static int
frang_resp_code_limit(FrangAcc *ra, FrangHttpRespCodeBlock *resp_cblk)
{
	FrangRespCodeStat *stat = ra->resp_code_stat;
	unsigned long cnt = 0;
	const unsigned int ts = frang_resp_quantum(resp_cblk->tf);
	int i = 0;

	i = ts % FRANG_FREQ;
	if (ts != stat[i].ts) {
		stat[i].ts = ts;
		stat[i].cnt = 1;
	} else {
		++stat[i].cnt;
	}
	for (i = 0; i < FRANG_FREQ; ++i) {
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

/**
 * Block client connection if not allowed response code appears too frequently
 * in responses for that client. Called from tfw_http_resp_fwd() by
 * tfw_gfsm_move().
 * Always returns TFW_PASS because there is no error in processing response,
 * client may do something illegal and is to be blocked. Allow upper levels
 * to continue working with the response and the server connection.
 */
static int
frang_resp_fwd_process(TfwHttpResp *resp)
{
	int r;
	FrangAcc *ra;
	TfwHttpReq *req = resp->req;
	FrangCfg *fcfg = req->location ? req->location->frang_cfg
				       : req->vhost->loc_dflt->frang_cfg;
	FrangHttpRespCodeBlock *conf = fcfg->http_resp_code_block;

	/*
	 * Requests originated by Health Monitor are generated by Tempesta,
	 * there is no reason to limit them. Such requests have no connection
	 * attached.
	 */
	if (unlikely(!resp->req->conn) || !conf)
		return TFW_PASS;

	ra = (FrangAcc *)req->conn->sk->sk_security;
	if (req->peer)
		ra = FRANG_CLI2ACC(req->peer);
	frang_dbg("client %s check response %d, acc=%p\n",
		  &FRANG_ACC2CLI(ra)->addr, resp->status, ra);

	if (!tfw_http_resp_code_range(resp->status)
	    || !test_bit(HTTP_CODE_BIT_NUM(resp->status), conf->codes))
		return TFW_PASS;

	spin_lock(&ra->lock);
	/*
	 * According to backend response code attacker may be trying to crack
	 * the password. This security event must be triggered when the response
	 * received, and can't be triggered on request context because client
	 * can send a huge number of pipelined requests to crack the password
	 * and wait for the results. If the attack is spotted, block the client
	 * and wipe all it's received but not responded requests ASAP.
	 */
	r = frang_resp_code_limit(ra, conf);
	spin_unlock(&ra->lock);

	if (r == TFW_BLOCK) {
		/* Default vhost has no 'vhost_dflt' member set. */
		FrangGlobCfg *fg_cfg = req->vhost->vhost_dflt
				? req->vhost->vhost_dflt->frang_gconf
				: req->vhost->frang_gconf;
		tfw_cli_conn_close_all_sync((TfwClient *)req->conn->peer);
		if (fg_cfg->ip_block)
			tfw_filter_block_ip(&FRANG_ACC2CLI(ra)->addr);
	}

	return TFW_PASS;
}

static int
frang_resp_handler(void *obj, TfwFsmData *data)
{
	TfwHttpResp *resp = (TfwHttpResp *)data->resp;
	TfwConn *conn = (TfwConn *)obj;
	int r = TFW_PASS;

	switch (TFW_GFSM_STATE(&conn->state)) {

	case TFW_FRANG_RESP_FSM_INIT:
		r = frang_resp_process(resp);
		break;

	case TFW_FRANG_RESP_FSM_FWD:
		r = frang_resp_fwd_process(resp);
		break;

	default:
		break;
	}

	if (r != TFW_PASS)
		return r;
	r = tfw_gfsm_move(&conn->state, TFW_FRANG_RESP_FSM_DONE, data);

	return r;
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

typedef struct {
	int			prio;
	int			hook_state;
	int			st0;
	unsigned short		fsm_id;
	const char		*name;
} FrangGfsmHook;

static FrangGfsmHook frang_gfsm_hooks[] = {
	{
		.prio		= -1,
		.hook_state	= TFW_HTTP_FSM_REQ_MSG,
		.fsm_id		= TFW_FSM_FRANG_REQ,
		.st0		= TFW_FRANG_REQ_FSM_INIT,
		.name		= "request_msg_end",
	},
	{
		.prio		= -1,
		.hook_state	= TFW_HTTP_FSM_REQ_CHUNK,
		.fsm_id		= TFW_FSM_FRANG_REQ,
		.st0		= TFW_FRANG_REQ_FSM_INIT,
		.name		= "request_skb_end",
	},
	{
		.prio		= -1,
		.hook_state	= TFW_HTTP_FSM_RESP_MSG,
		.fsm_id		= TFW_FSM_FRANG_RESP,
		.st0		= TFW_FRANG_RESP_FSM_INIT,
		.name		= "response_msg_end",
	},
	{
		.prio		= -1,
		.hook_state	= TFW_HTTP_FSM_RESP_CHUNK,
		.fsm_id		= TFW_FSM_FRANG_RESP,
		.st0		= TFW_FRANG_RESP_FSM_INIT,
		.name		= "response_skb_end",
	},
	{
		.prio		= -1,
		.hook_state	= TFW_HTTP_FSM_RESP_MSG_FWD,
		.fsm_id		= TFW_FSM_FRANG_RESP,
		.st0		= TFW_FRANG_RESP_FSM_INIT,
		.name		= "response_fwd",
	},
};

void
tfw_http_limits_hooks_remove(void)
{
	int i;

	for (i = ARRAY_SIZE(frang_gfsm_hooks) - 1; i >= 0; i--) {
		FrangGfsmHook *h = &frang_gfsm_hooks[i];
		if (h->prio == -1)
			continue;
		tfw_gfsm_unregister_hook(TFW_FSM_HTTP, h->prio, h->hook_state);
		h->prio = -1;
	}
}

int
tfw_http_limits_hooks_register(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(frang_gfsm_hooks); i++) {
		FrangGfsmHook *h = &frang_gfsm_hooks[i];

		h->prio = tfw_gfsm_register_hook(TFW_FSM_HTTP,
						 TFW_GFSM_HOOK_PRIORITY_ANY,
						 h->hook_state, h->fsm_id,
						 h->st0);
		if (h->prio < 0) {
			T_ERR_NL("frang: can't register %s hook\n", h->name);
			return -EINVAL;
		}
	}

	return 0;
}

int __init
tfw_http_limits_init(void)
{
	int r;

	tempesta_register_ops(&tempesta_ops);

	BUILD_BUG_ON((sizeof(FrangAcc) > sizeof(TfwClassifierPrvt)));

	tfw_classifier_register(&frang_class_ops);

	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG_REQ, frang_http_req_handler);
	if (r) {
		T_ERR_NL("frang: can't register request fsm\n");
		goto err_fsm;
	}

	r = tfw_gfsm_register_fsm(TFW_FSM_FRANG_RESP, frang_resp_handler);
	if (r) {
		T_ERR_NL("frang: can't register response fsm\n");
		goto err_fsm_resp;
	}

	r = tfw_http_limits_hooks_register();
	if (r)
		goto err_hooks;

	return 0;
err_hooks:
	tfw_http_limits_hooks_remove();
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
	T_DBG("frang exit\n");

	tfw_http_limits_hooks_remove();
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_RESP);
	tfw_gfsm_unregister_fsm(TFW_FSM_FRANG_REQ);
	tfw_classifier_unregister();
	tempesta_unregister_ops(&tempesta_ops);
}
