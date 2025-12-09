/**
 *		Tempesta FW
 *
 * Interface to classification modules.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#include <linux/bitmap.h>

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
#include "procfs.h"
#include "vhost.h"
#include "log.h"
#include "hash.h"
#include "http_match.h"
#include "http.h"
#include "http_sess.h"

/*
 * ------------------------------------------------------------------------
 *	Frang classifier - static http limits implementation.
 * ------------------------------------------------------------------------
 */

/**
 * @ts	- Timestamp in seconds/8 (125 ms).
 */
typedef struct {
	unsigned long	ts;
	unsigned int	conn_new;
	unsigned int	req;
	unsigned int	tls_sess_new;
	unsigned int	tls_sess_incomplete;
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
	T_WARN_MOD_ADDR(frang, check, addr, TFW_NO_PORT, fmt, ##__VA_ARGS__)

#define frang_msg_lock(lock, check, addr, fmt, ...)			\
do {									\
	spin_lock(lock);						\
	frang_msg(check, addr, fmt, ##__VA_ARGS__);			\
	spin_unlock(lock);						\
} while(0)

/*
 * Client actions has triggered a security event. Log the client addr and
 * Frang limit name.
 */
#define frang_limmsg(lim_name, curr_val, lim, addr)			\
	frang_msg(lim_name " exceeded", (addr), ": %ld (lim=%ld)\n",	\
		  (long)curr_val, (long)lim)

#define frang_limmsg_lock(lock, lim_name, curr_val, lim, addr)		\
do {									\
	spin_lock(lock);						\
	frang_limmsg(lim_name, curr_val, lim, addr);			\
	spin_unlock(lock);						\
} while(0)

/*
 * Local subsystem has triggered a security event, mostly it's a
 * misconfiguration issue. Log the event and subsystem name.
 */
#define frang_limmsg_local(lim_name, curr_val, lim, system)		\
	T_WARN("frang: " lim_name " exceeded for '%s' subsystem: "	\
	       "%ld (lim=%ld)\n",					\
	       system, (long)curr_val, (long)lim)

#ifdef DEBUG
#define frang_dbg_lock(lock, fmt_msg, addr, ...)			\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	spin_lock(lock);						\
	tfw_addr_fmt(addr, TFW_NO_PORT, abuf);				\
	T_DBG("frang: " fmt_msg, abuf, ##__VA_ARGS__);			\
	spin_unlock(lock);						\
} while(0)
#else
#define frang_dbg_lock(...)
#endif

static inline bool
frang_sk_is_whitelisted(struct sock *sk)
{
	return (unsigned long)tempesta_sock(sk)->class_prvt & 1;
}

static inline void
frang_sk_mark_whitelisted(struct sock *sk)
{
	unsigned long d = (unsigned long)tempesta_sock(sk)->class_prvt;

	/* Should be initialized first by ra. */
	BUG_ON(!d);
	/*
	 * We can use first bit of the pointer, because it is
	 * always equal to zero.
	 */
	d |= 1;
	tempesta_sock(sk)->class_prvt = (void *)d;
}

static inline FrangAcc *
frang_acc_from_sk(struct sock *sk)
{
	return frang_ptr_from_sk(sk);
}

bool
frang_req_is_whitelisted(TfwHttpReq *req)
{
	return frang_sk_is_whitelisted(req->conn->sk);
}

static void
frang_acc_history_init(FrangAcc *ra, unsigned long ts)
{
	int i = ts % FRANG_FREQ;

	if (ra->history[i].ts != ts) {
		bzero_fast(&ra->history[i], sizeof(ra->history[i]));
		ra->history[i].ts = ts;
	}

	/*
	 * Increment connection counters even when we return T_BLOCK.
	 * We call tfw_classify_conn_close() even for failed connections.
	 * @conn_curr is decremented there, but @conn_new is not changed.
	 * We count both failed connection attempts and connections that were
	 * successfully established.
	 */
	ra->history[i].conn_new++;
	ra->conn_curr++;
	if (ra->conn_curr == 1)
		TFW_INC_STAT_BH(clnt.online);
}

/**
 * Monotonically increasing time quantums. The configured @tframe
 * is divided by FRANG_FREQ slots to get the quantums granularity.
 * To reduce calculations, tframe is already stored as result of multiplication
 * operation, see __tfw_cfgop_frang_rsp_code_block().
 */
static inline unsigned int
frang_time_quantum(unsigned short tframe)
{
	return jiffies / tframe;
}

static int
frang_conn_limit(FrangAcc *ra, FrangGlobCfg *conf)
{
	const unsigned long ts = frang_time_quantum(conf->conn_rate_tf);
	const int i = ts % FRANG_FREQ;

	spin_lock(&ra->lock);

	frang_acc_history_init(ra, ts);

	if (conf->conn_max && unlikely(ra->conn_curr > conf->conn_max)) {
		frang_limmsg("connections max num.", ra->conn_curr,
			     conf->conn_max, &FRANG_ACC2CLI(ra)->addr);
		spin_unlock(&ra->lock);
		return T_BLOCK;
	}

	if (conf->conn_burst
	    && unlikely(ra->history[i].conn_new > conf->conn_burst))
	{
		frang_limmsg("new connections burst", ra->history[i].conn_new,
			     conf->conn_burst, &FRANG_ACC2CLI(ra)->addr);
		spin_unlock(&ra->lock);
		return T_BLOCK;
	}

	if (conf->conn_rate) {
		unsigned int csum = 0;

		/* Collect current connection sum. */
		for (int j = 0; j < FRANG_FREQ; j++)
			if (frang_time_in_frame(ts, ra->history[j].ts))
				csum += ra->history[j].conn_new;

		if (unlikely(csum > conf->conn_rate)) {
			frang_limmsg("new connections rate",
				     csum, conf->conn_rate,
				     &FRANG_ACC2CLI(ra)->addr);
			spin_unlock(&ra->lock);
			return T_BLOCK;
		}
	}

	spin_unlock(&ra->lock);

	return T_OK;
}

static void
__frang_init_acc(void *data)
{
	TfwClient *cli = (TfwClient *)data;
	FrangAcc *ra = FRANG_CLI2ACC(cli);

	spin_lock_init(&ra->lock);
}

static int
frang_conn_new(struct sock *sk, struct sk_buff *skb)
{
	int r = T_OK;
	FrangAcc *ra;
	TfwClient *cli;
	TfwAddr addr;
	TfwVhost *dflt_vh = tfw_vhost_lookup_default();

	/* The new socket is allocated by inet_csk_clone_lock(). */
	assert_spin_locked(&sk->sk_lock.slock);

	/*
	 * Default vhost configuration stores global frang settings, it's always
	 * available even on reload under heavy load. But the pointer comes
	 * from other module, take care of probable null-dereferences.
	 */
	if (WARN_ON_ONCE(!dflt_vh))
		return T_BLOCK;

	ss_getpeername(sk, &addr);
	cli = tfw_client_obtain(addr, NULL, NULL, __frang_init_acc);
	if (unlikely(!cli)) {
		T_ERR("can't obtain a client for frang accounting\n");
		tfw_vhost_put(dflt_vh);
		return T_BLOCK;
	}

	ra = FRANG_CLI2ACC(cli);

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
	tempesta_sock(sk)->class_prvt = ra;
	if (tfw_http_mark_is_in_whitlist(skb->mark)) {
		/*
		 * Netfilter works on TCP/IP level, so once we observe a
		 * whitelisted skb, this means that the whole TCP connection is
		 * whitelisted and we mark it as such.
		 */
		frang_sk_mark_whitelisted(sk);

		spin_lock(&ra->lock);
		frang_acc_history_init(ra, (jiffies * FRANG_FREQ) / HZ);
		spin_unlock(&ra->lock);

		goto finish;
	}

	/*
	 * TBD: Since we can determine vhost by SNI field in TLS headers, there
	 * will be a desire to make all frang limits per-vhost. After some
	 * thinking I have found this counter-intuitive: The way, how the
	 * frang limits work will depend on too many conditions. E.g.
	 * TLS-enabled clients will use higher limits than non-TLS clients;
	 * the same client can break security rules for one vhost, but be a
	 * legitimate client for other vhosts, so it's a big question how to
	 * block him by IP or by connection resets; if multi-domain certificate
	 * (SAN) is configured, TLS clients will behave as non-TLS. Too
	 * complicated for administrator to understand how client is blocked
	 * and to configure it, while making some of the limits to be global
	 * for a single client is absolutely straight-forward.
	 */
	r = frang_conn_limit(ra, dflt_vh->frang_gconf);
	if (unlikely(r == T_BLOCK) && dflt_vh->frang_gconf->ip_block)
		tfw_filter_block_ip(cli);

finish:
	tfw_vhost_put(dflt_vh);

	return r;
}

/**
 * Just update current connection count for a user.
 */
void
tfw_classify_conn_close(struct sock *sk)
{
	FrangAcc *ra = frang_acc_from_sk(sk);

	if (unlikely(!sock_flag(sk, SOCK_TEMPESTA)))
		return;

	if(ra == NULL)
		return;

	spin_lock(&ra->lock);

	BUG_ON(ra->conn_curr == 0);
	ra->conn_curr--;

	if (!ra->conn_curr)
		TFW_DEC_STAT_BH(clnt.online);

	spin_unlock(&ra->lock);

	tempesta_sock(sk)->class_prvt = NULL;

	tfw_client_put(FRANG_ACC2CLI(ra));
}

static int
frang_req_limit(FrangAcc *ra, unsigned int req_burst, unsigned int req_rate,
		unsigned short tf)
{
	const unsigned int ts = frang_time_quantum(tf);
	const int i = ts % FRANG_FREQ;

	if (!req_burst && !req_rate)
		return T_OK;

	spin_lock(&ra->lock);

	if (ra->history[i].ts != ts) {
		bzero_fast(&ra->history[i], sizeof(ra->history[i]));
		ra->history[i].ts = ts;
	}
	ra->history[i].req++;

	if (req_burst && unlikely(ra->history[i].req > req_burst)) {
		frang_limmsg("requests burst", ra->history[i].req,
			     req_burst, &FRANG_ACC2CLI(ra)->addr);
		spin_unlock(&ra->lock);
		return T_BLOCK;
	}

	if (req_rate) {
		unsigned int rsum = 0;

		/* Collect current request sum. */
		for (int j = 0; j < FRANG_FREQ; j++)
			if (frang_time_in_frame(ts, ra->history[j].ts))
				rsum += ra->history[j].req;
		if (unlikely(rsum > req_rate)) {
			frang_limmsg("request rate", rsum, req_rate,
				     &FRANG_ACC2CLI(ra)->addr);
			spin_unlock(&ra->lock);
			return T_BLOCK;
		}
	}

	spin_unlock(&ra->lock);

	return T_OK;
}

static int
frang_http_uri_len(const TfwHttpReq *req, FrangAcc *ra, unsigned int uri_len)
{
	if (unlikely(req->uri_path.len > uri_len)) {
		frang_limmsg_lock(&ra->lock, "HTTP URI length",
				  req->uri_path.len, uri_len,
				  &FRANG_ACC2CLI(ra)->addr);
		return T_BLOCK;
	}

	return T_OK;
}

static int
frang_http_methods(const TfwHttpReq *req, FrangAcc *ra, unsigned long m_mask)
{
	unsigned long mbit = (1UL << req->method);

	if (unlikely(!(m_mask & mbit))) {
		frang_msg_lock(&ra->lock, "restricted HTTP method",
			       &FRANG_ACC2CLI(ra)->addr,
			       ": %u (%#lxu)\n", req->method, mbit);
		return T_BLOCK;
	}

	return T_OK;
}

static int
frang_http_methods_override(const TfwHttpReq *req, FrangAcc *ra,
			    FrangVhostCfg *f_cfg)
{
	unsigned long mbit = (1UL << req->method_override);

	if (!req->method_override)
		return T_OK;
	if (!f_cfg->http_method_override
	    || (f_cfg->http_methods_mask &&
		unlikely(!(f_cfg->http_methods_mask & mbit))))
	{
		frang_msg_lock(&ra->lock, "restricted overridden HTTP method",
			       &FRANG_ACC2CLI(ra)->addr, ": %u (%#lxu)\n",
			       req->method_override, mbit);
		return T_BLOCK;
	}

	return T_OK;
}

static int
frang_http_upgrade_websocket(const TfwHttpReq *req, FrangAcc *ra,
			     FrangVhostCfg *f_cfg)
{
	BUG_ON(!req);

	switch (req->version) {
	/*
	 * TODO #755: upgrade websocket checks for h2 as described in RFC8441
	 */
	case TFW_HTTP_VER_20:
		break;
	/*
	 * Tempesta FW MUST block requests with Upgrade header but without
	 * upgrade option in Connection header. Tempesta FW MUST ignore
	 * Upgrade header for HTTP version less then HTTP/1.1.
	 * See RFC7230#section-6.1.
	 */
	case TFW_HTTP_VER_11:
	case TFW_HTTP_VER_10:
	case TFW_HTTP_VER_09:
		if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags)
		    && !test_bit(TFW_HTTP_B_CONN_UPGRADE, req->flags))
		{
			frang_msg_lock(&ra->lock, "upgrade request without"
				       " connection option",
				       &FRANG_ACC2CLI(ra)->addr,
				       ": protocol: %s\n", "websocket");
			return T_BLOCK;
		}
		if (req->version < TFW_HTTP_VER_11)
		{
			clear_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
				  ((TfwHttpReq *)req)->flags);
		}
		break;
	default:
		return T_BLOCK;
	}

	return T_OK;
}

static int
frang_http_ct_check(const TfwHttpReq *req, FrangAcc *ra, FrangCtVals *ct_vals)
{
	TfwStr field, *s;
	FrangCtVal *curr;

	if (req->method != TFW_HTTP_METH_POST)
		return T_OK;

	if (TFW_STR_EMPTY(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE])) {
		frang_msg_lock(&ra->lock, "Content-Type header field",
			       &FRANG_ACC2CLI(ra)->addr, " is missed\n");
		return T_BLOCK;
	}

	if (!ct_vals) {
		/*
		 * Configuration does not provide a list of allowed types for
		 * Content-Type, so everything is permitted.
		 */
		return T_OK;
	}

	tfw_http_msg_clnthdr_val(req,
				 &req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 TFW_HTTP_HDR_CONTENT_TYPE, &field);

	/*
	 * Verify that Content-Type value is on the list of allowed values.
	 * Use prefix match to allow parameters, see RFC 7231 3.1.1:
	 *
	 *	Content-Type = media-type
	 *	media-type = type "/" subtype *( OWS ";" OWS parameter )
	 *
	 * TODO this matching is too permissive, e.g. we can pass
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
	for (curr = ct_vals->vals; curr->str; ++curr) {
		if (tfw_str_eq_cstr(&field, curr->str, curr->len,
				    TFW_STR_EQ_PREFIX_CASEI))
			return T_OK;
	}

	/* Take first chunk only for logging. */
	s = TFW_STR_CHUNK(&field, 0);
	if (s) {
		frang_msg_lock(&ra->lock, "restricted Content-Type",
			       &FRANG_ACC2CLI(ra)->addr,
			       ": %.*s\n", PR_TFW_STR(s));
	} else {
		frang_msg_lock(&ra->lock, "restricted empty Content-Type",
			       &FRANG_ACC2CLI(ra)->addr, "\n");
	}

	return T_BLOCK;
}

/**
 * Get Host value. Host can be defined:
 * - in h2 requests in Host header, in authority pseudo header. The latter SHOULD
 *   be used, but RFC 7540 still allows to use Host header.
 * - in http/1 requests in Host header and inside URI.
 *
 * @req		- request handle;
 * @hid		- header id, -1 for req->host;
 * @trimmed	- trimmed host value without spaces.
 * @name_only	- host value without port component.
 */
static void
frang_get_host_header(const TfwHttpReq *req, int hid, TfwStr *trimmed,
			TfwStr *name_only)
{
	TfwStr raw_val, hdr_trim = { 0 }, hdr_name = { 0 }, *c, *end;
	bool got_delim = false;

	/* Parser will block duplicated headers for this hids. */
	if (hid > 0) {
		tfw_http_msg_clnthdr_val(req, &req->h_tbl->tbl[hid], hid,
					 &raw_val);
	}
	else {
		/*
		 * Only used for http/1.1 requests. Always must be identical
		 * to Host: header, so we can keep parser cleaner and faster.
		 */
		*trimmed = req->host;
		*name_only = req->host;
		return;
	}

	hdr_name.chunks = hdr_trim.chunks = raw_val.chunks;
	hdr_name.flags =  hdr_trim.flags  = raw_val.flags;

	TFW_STR_FOR_EACH_CHUNK(c, &raw_val, end) {
		if (c->flags & TFW_STR_VALUE) {
			if (!got_delim) {
				hdr_name.nchunks++;
				hdr_name.len += c->len;
			}
			hdr_trim.nchunks++;
			hdr_trim.len += c->len;
		}
		/*
		 * When host is IPv6 addr, a 1-byte long chunk with ':' may
		 * also represent a part of IP address, but it is marked with
		 * TFW_STR_VALUE and checked in condition above.
		 */
		else if (c->len == 1 && c->data[0] == ':') {
			got_delim = true;
			hdr_trim.nchunks++;
			hdr_trim.len += c->len;
		}
	}

	*trimmed = hdr_trim;
	*name_only = hdr_name;
}

/**
 * Fin vhost by authority, increment vhost reference counter.
 * It is a caller responsibility to put vhost reference counter.
 */
static TfwVhost*
__lookup_vhost_by_authority(TfwPool *pool, const TfwStr *authority)
{
	char small_buf[64];
	BasicStr name;
	const TfwStr *chunk, *_;

	name.len = 0;
	/* Cut port from authority. */
	TFW_STR_FOR_EACH_CHUNK(chunk, authority, _) {
		if (!(chunk->flags & TFW_STR_VALUE))
			break;
		name.len += chunk->len;
	}

	/* Prepare buffer */
	if (likely(name.len < sizeof(small_buf))) {
		name.data = small_buf;
	} else {
		name.data = tfw_pool_alloc(pool, name.len + 1);
		if (unlikely(name.data == NULL)) {
			T_WARN("Can't allocate temporary buffer of %zu bytes"
			       " for HTTP domain fronting check",
			       name.len + 1);
			return NULL;
		}
	}

	/* Make linear lower-case name */
	tfw_str_to_cstr(authority, name.data, name.len + 1);
	tfw_cstrtolower_inplace(name.data, name.len);

	return tfw_tls_find_vhost_by_name(&name);
}

static int
frang_http_domain_fronting_check(const TfwHttpReq *req, FrangAcc *ra)
{
	TlsCtx *tctx;
	TfwVhost *tls_vhost;
	BasicStr tls_name, req_name;
	static BasicStr null_name = {"NULL", 4};

	if (!(TFW_CONN_TYPE(req->conn) & TFW_FSM_HTTPS))
		return T_OK;

	tctx = tfw_tls_context(req->conn);
	/* tfw_tls_sni() has to pick any existing vhost in order to proceed */
	BUG_ON(!tctx->vhost);

	if (tctx->vhost == req->vhost)
		return T_OK;

	/* Special case of default vhosts */
	if (!req->vhost && tfw_vhost_is_default(tctx->vhost))
		return T_OK;

	/*
	 * Last (and slowest case): we have to look for TLS certificate
	 * by authority and make sure that req->vhost is reachable by
	 * picked authority name.
	 */
	tls_vhost = __lookup_vhost_by_authority(req->pool, &req->host);
	if (tls_vhost != tctx->vhost) {
		tls_name = tctx->vhost ? ((TfwVhost *)tctx->vhost)->name
				       : null_name;
		req_name = req->vhost ? req->vhost->name : null_name;
		frang_msg_lock(&ra->lock, "vhost by SNI doesn't match"
			       " vhost by authority", &FRANG_ACC2CLI(ra)->addr,
			       " ('%.*s' vs '%.*s')\n",
			       PR_TFW_STR(&tls_name), PR_TFW_STR(&req_name));
		tfw_vhost_put(tls_vhost);
		return T_BLOCK;
	}

	tfw_vhost_put(tls_vhost);
	return T_OK;
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
	unsigned short host_port;
	unsigned short uri_port;
	unsigned short real_port;
	TfwStr authority, host;
	TfwStr prim_trim = { 0 }, prim_name = { 0 }; /* primary source */

	BUG_ON(!req);
	BUG_ON(!req->h_tbl);

	if (TFW_CONN_TLS(req->conn)) {
		host_port = req->host_port ? : 443;
		uri_port = req->uri_port ? : 443;
	} else {
		host_port = req->host_port ? : 80;
		uri_port = req->uri_port ? : 80;
	}

	switch (req->version) {
	case TFW_HTTP_VER_20:
		__h2_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY],
		                 &authority);
		__h2_msg_hdr_val(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST], &host);
		/* https://datatracker.ietf.org/doc/html/rfc9113#section-8.3.1
		 * A server SHOULD treat a request as malformed if it contains
		 * a Host header field that identifies an entity that differs
		 * from the entity in the ":authority" pseudo-header field.
                 *
                 * Note: check_authority_correctness() already ensures that
                 * at least one of :authority or Host headers are not empty.
		 */
		if (!TFW_STR_EMPTY(&authority) && !TFW_STR_EMPTY(&host)
                    && tfw_strcmp(&authority, &host) != 0) {
			frang_msg_lock(&ra->lock, "Request :authority differs"
				       " from Host", &FRANG_ACC2CLI(ra)->addr,
				       "\n");
                        return T_BLOCK;
                }
                break;
	case TFW_HTTP_VER_11:
		/*
		 * This is pure HTTP/1.1 check, that would never trigger for
		 * HTTP/2 because it cannot have an absolute URI.
		 */
		if (test_bit(TFW_HTTP_B_ABSOLUTE_URI, req->flags)) {
			TfwStr host;

			tfw_http_msg_clnthdr_val(req,
						&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
						TFW_HTTP_HDR_HOST, &host);

			/* Check that ports are the same. */
			if (unlikely(uri_port != host_port)) {
				frang_msg_lock(&ra->lock, "port from host header doesn't"
					       " match port from uri",
					       &FRANG_ACC2CLI(ra)->addr,
					       ": %u (%u)\n", host_port,
					       uri_port);
				return T_BLOCK;
			}

			if (tfw_stricmpspn(&req->host, &host, ':') != 0) {
				frang_msg_lock(&ra->lock, "Request host from"
					       " absolute URI differs from Host"
					       " header",
					       &FRANG_ACC2CLI(ra)->addr, "\n");
				return T_BLOCK;
			}
		}
		break;
	/*
	 * Old protocols may have no 'host' header, if presents it's a usual
	 * header with no special meaning. But in installations of servers with
	 * modern protocols its use for routing decisions is very common.
	 * It's suspicious, when modern features are used with obsoleted
	 * protocols, block the request to avoid possible confusion of HTTP
	 * routing on backends.
	 */
	case TFW_HTTP_VER_10:
	case TFW_HTTP_VER_09:
		frang_get_host_header(req, TFW_HTTP_HDR_HOST,
				      &prim_trim, &prim_name);
		if (TFW_STR_EMPTY(&req->host) && TFW_STR_EMPTY(&prim_trim))
			return T_OK;
		frang_msg_lock(&ra->lock, "Host header field in protocol prior"
			       " to HTTP/1.1", &FRANG_ACC2CLI(ra)->addr, "\n");
		return T_BLOCK;
	default:
		return T_BLOCK;
	}

	/* Check that host header is not a IP address. */
	if (!TFW_STR_EMPTY(&req->host)
	    && unlikely(!tfw_addr_pton(&req->host, &addr))) {
		frang_msg_lock(&ra->lock, "Host header field contains"
			       " IP address", &FRANG_ACC2CLI(ra)->addr,
			       "\n");
		return T_BLOCK;
	}

	/*
	 * TfwClient instance can be reused across multiple connections,
	 * check the port number of the current connection, not the first one.
	 */
	real_port = be16_to_cpu(inet_sk(req->conn->sk)->inet_sport);
	if (unlikely(host_port != real_port)) {
		frang_msg_lock(&ra->lock, "port from host header doesn't"
			       " match real port", &FRANG_ACC2CLI(ra)->addr,
			       ": %u (%u)\n", host_port, real_port);
		return T_BLOCK;
	}

	return frang_http_domain_fronting_check(req, ra);
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
	Frang_Req_Body,

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

	frang_dbg_lock(&ra->lock, "check incomplete request headers"
		       " for client %s," " acc=%p\n",
		       &FRANG_ACC2CLI(ra)->addr, ra);
	/*
	 * There's no need to check for header timeout if this is the very
	 * first chunk of a request (first full separate SKB with data).
	 * The FSM is guaranteed to go through the initial states and then
	 * either block or move to one of header states. Then header timeout
	 * is checked on each consecutive SKB with data - while we're still
	 * in one of header processing states.
	 */
	if (fg_cfg->clnt_hdr_timeout && unlikely((skb != head_skb))) {
		unsigned long start = req->tm_header;
		unsigned long delta = fg_cfg->clnt_hdr_timeout;

		if (time_is_before_jiffies(start + delta)) {
			frang_limmsg_lock(&ra->lock, "client header timeout",
					  jiffies_to_msecs(jiffies - start),
					  jiffies_to_msecs(delta),
					  &FRANG_ACC2CLI(ra)->addr);
			goto block;
		}
	}

	if (hchnk_cnt && unlikely(req->chunk_cnt > hchnk_cnt)) {
		frang_limmsg_lock(&ra->lock, "HTTP header chunk count",
				  req->chunk_cnt, hchnk_cnt,
				  &FRANG_ACC2CLI(ra)->addr);
		goto block;
	}

	return T_OK;
block:
	return T_BLOCK;
}

static int
frang_http_req_incomplete_body_check(FrangAcc *ra, TfwFsmData *data,
				     FrangGlobCfg *fg_cfg, FrangVhostCfg *f_cfg)
{
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	unsigned long body_len = f_cfg->http_body_len;
	unsigned int bchunk_cnt = fg_cfg->http_bchunk_cnt;
	unsigned long body_timeout = fg_cfg->clnt_body_timeout;
	struct sk_buff *skb = data->skb;

	frang_dbg_lock(&ra->lock, "check incomplete request body"
		       " for client %s, acc=%p\n",
		       &FRANG_ACC2CLI(ra)->addr, ra);

	/* CLRF after headers was parsed, but the body didn't arrive yet. */
	if (TFW_STR_EMPTY(&req->body))
		return T_OK;
	/*
	 * Ensure that HTTP request body is coming without delays.
	 * The timeout is between chunks of the body, so reset
	 * the start time after each check.
	 */
	if (body_timeout && req->tm_bchunk && (skb != req->body.skb)) {
		unsigned long start = req->tm_bchunk;
		unsigned long delta = body_timeout;

		if (unlikely(time_is_before_jiffies(start + delta))) {
			frang_limmsg_lock(&ra->lock, "client body timeout",
					  jiffies_to_msecs(jiffies - start),
					  jiffies_to_msecs(delta),
					  &FRANG_ACC2CLI(ra)->addr);
			goto block;
		}
		req->tm_bchunk = jiffies;
	}

	/* Limit number of chunks in request body */
	if (bchunk_cnt && unlikely(req->chunk_cnt > bchunk_cnt)) {
		frang_limmsg_lock(&ra->lock, "HTTP body chunk count",
				  req->chunk_cnt, bchunk_cnt,
				  &FRANG_ACC2CLI(ra)->addr);
		goto block;
	}

	if (body_len && unlikely(req->body.len > body_len)) {
		frang_limmsg_lock(&ra->lock, "HTTP body length",
				  req->body.len, body_len,
				  &FRANG_ACC2CLI(ra)->addr);
		goto block;
	}

	return T_OK;
block:
	return T_BLOCK;
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
 * trailers in response context. But requests with trailer headers
 * are valid http messages. Support for them is not documented,
 * and implementation-dependent. E.g. Apache doesn't care about trailer
 * headers, but ModSecurity for Apache does.
 * https://swende.se/blog/HTTPChunked.html
 * Some discussions also highlight that trailer headers are poorly
 * supported on both servers and clients, while CDNs tend to add
 * trailers. https://github.com/whatwg/fetch/issues/34
 *
 * Since RFC doesn't speak clearly about trailer headers in requests, the
 * following assumptions were used:
 * - Our intermediaries on client side do not care about trailers and send
 *   them in the manner as the body. Thus frang's body limitations are used,
 *   not headers ones.
 * - Same header may have different values depending on how the servers work
 *   with the trailer. Administrator can block that behaviour.
 */
static int
frang_http_req_trailer_check(FrangAcc *ra, TfwFsmData *data,
			     FrangGlobCfg *fg_cfg, FrangVhostCfg *f_cfg)
{
	int r = T_OK;
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	const TfwStr *field, *end, *dup, *dup_end;

	if (!tfw_http_parse_is_done((TfwHttpMsg *)req))
		return T_POSTPONE;

	if (!test_bit(TFW_HTTP_B_CHUNKED_TRAILER, req->flags))
		return T_OK;
	/*
	 * Don't use special settings for the trailer part, keep on
	 * using body limits.
	 */
	r = frang_http_req_incomplete_body_check(ra, data, fg_cfg, f_cfg);
	if (unlikely(test_bit(TFW_HTTP_B_FIELD_DUPENTRY, req->flags))) {
		frang_msg_lock(&ra->lock, "duplicate header field found",
			       &FRANG_ACC2CLI(ra)->addr, "\n");
		return T_BLOCK;
	}
	if (unlikely(r))
		return r;

	/*
	 * Block request if the same header appear in both main and trailer
	 * headers part. Some intermediates doesn't read trailers, so request
	 * processing may depend on implementation.
	 *
	 * NOTE: we check only regular headers (without HTTP/2-specific
	 * pseudo-header fields), since pseudo-headers must not appear in
	 * trailers (RFC 7540 section 8.1.2.1), and during parsing stage, in
	 * @H2_MSG_VERIFY(), we have already verified that.
	 */
	if (f_cfg->http_trailer_split)
		return T_OK;

	FOR_EACH_HDR_FIELD_FROM(field, end, req, TFW_HTTP_HDR_REGULAR) {
		int trailers = 0, dups = 0;
		TFW_STR_FOR_EACH_DUP(dup, field, dup_end) {
			trailers += !!(dup->flags & TFW_STR_TRAILER);
			dups += 1;
		}
		if (trailers && unlikely(dups != trailers)) {
			frang_msg_lock(&ra->lock, "HTTP field appear in"
				       " header and trailer for client",
				       &FRANG_ACC2CLI(ra)->addr, "\n");
			return T_BLOCK;
		}
	}

	return r;
}

static int
frang_http_req_process(FrangAcc *ra, TfwConn *conn, TfwFsmData *data,
		       TfwVhost *dvh)
{
	int r = T_OK;
	TfwHttpReq *req = (TfwHttpReq *)data->req;
	FrangVhostCfg *f_cfg = NULL;
	FrangGlobCfg *fg_cfg = NULL;
	T_FSM_INIT(Frang_Req_0, "frang");

	if (WARN_ON_ONCE(!ra))
		return T_BLOCK;
	/*
	 * If a request is detached from stream before frang callback
	 * happen, it usually means that a response is already created and bound
	 * with the request, but the request is taken to further processing in
	 * upper levels. Or stream is already closed and no processing is
	 * required, probably because of the errors. Anyway it's suspicious
	 * that we got here with such a request. The stream objects contains
	 * parser required for some checks. Probably we know what we're
	 * doing if a response is already prepared and shouldn't block that
	 * request. Block the request otherwise, no further processing for
	 * already closed streams is required.
	 */
	if (WARN_ON_ONCE(!req->stream))
		return req->resp ? T_OK : T_BLOCK;
	frang_dbg_lock(&ra->lock, "check request for client %s, acc=%p\n",
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
		return T_BLOCK;

	/*
	 * Detect slowloris attack first, and then proceed with more precise
	 * checks. This is not an FSM state, because the checks are required
	 * every time a new request chunk is received and will be present in
	 * every FSM state.
	 */
	if (req->frang_st < Frang_Req_Hdr_NoState)
		r = frang_http_req_incomplete_hdrs_check(ra, data, fg_cfg);
	else
		r = frang_http_req_incomplete_body_check(ra, data, fg_cfg,
							 f_cfg);
	if (unlikely(r))
		return r;

	T_FSM_START(req->frang_st) {

	/*
	 * New HTTP request. Initial state. Check the limits that
	 * do not depend on contents of HTTP request. Note that
	 * connection-related limits are implemented as callbacks
	 * that run when a connection is established or destroyed.
	 */
	T_FSM_STATE(Frang_Req_0) {
		r = frang_req_limit(ra, fg_cfg->req_burst, fg_cfg->req_rate,
				    fg_cfg->req_rate_tf);
		/* Set the time the header started coming in. */
		req->tm_header = jiffies;
		__FRANG_FSM_MOVE(Frang_Req_Hdr_Method);
	}

	/* Ensure that HTTP request method is one of those defined by a user. */
	T_FSM_STATE(Frang_Req_Hdr_Method) {
		if (req->method == _TFW_HTTP_METH_NONE ||
		    req->method == _TFW_HTTP_METH_INCOMPLETE) {
			T_FSM_EXIT();
		}
		r = frang_http_methods(req, ra,
				       f_cfg->http_methods_mask);

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
	 * Test that all currently received headers do not exceed frang limits.
	 */
	T_FSM_STATE(Frang_Req_Hdr_Check) {
		if (test_bit(TFW_HTTP_B_FIELD_DUPENTRY, req->flags)) {
			frang_msg_lock(&ra->lock, "duplicate header"
				       " field found",
				       &FRANG_ACC2CLI(ra)->addr, "\n");
			r = T_BLOCK;
			T_FSM_EXIT();
		}
		/* Headers are not fully parsed yet. */
		if (!test_bit(TFW_HTTP_B_HEADERS_PARSED, req->flags))
			__FRANG_FSM_JUMP_EXIT(Frang_Req_Hdr_Check);
		/*
		* Full HTTP header has been processed, and any possible
		* header fields are collected. Run final checks on them.
		*/

		/* Ensure presence and the value of Host: header field. */
		if (f_cfg->http_strict_host_checking
		    && unlikely(r = frang_http_host_check(req, ra)))
		{
			T_FSM_EXIT();
		}
		/* Ensure overridden HTTP method suits restrictions. */
		r = frang_http_methods_override(req, ra, f_cfg);
		if (unlikely(r))
			T_FSM_EXIT();
		/*
		* Ensure presence of Content-Type: header field.
		* Ensure that the value is one of those defined by a user.
		*/
		if ((f_cfg->http_ct_required || f_cfg->http_ct_vals)
		    && unlikely(r = frang_http_ct_check(req, ra,
		    					f_cfg->http_ct_vals)))
		{
			T_FSM_EXIT();
		}

		/* Do checks for websocket upgrade */
		if (test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags)
		    && unlikely((r = frang_http_upgrade_websocket(req, ra,
		    						  f_cfg))))
		{
			T_FSM_EXIT();
		}

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
		__FRANG_FSM_MOVE(Frang_Req_Body);
	}

	/*
	 * Body is not fully parsed, a new body chunk was received.
	 */
	T_FSM_STATE(Frang_Req_Body) {
		/* Body is not fully parsed yet. */
		if (!(req->body.flags & TFW_STR_COMPLETE))
			__FRANG_FSM_JUMP_EXIT(Frang_Req_Body);

		__FRANG_FSM_MOVE(Frang_Req_Trailer);
	}

	/* Trailer headers. */
	T_FSM_STATE(Frang_Req_Trailer) {
		r = frang_http_req_trailer_check(ra, data, fg_cfg, f_cfg);
		__FRANG_FSM_MOVE(Frang_Req_Done);
	}

	/* All limits are verified for current request. */
	T_FSM_STATE(Frang_Req_Done) {
		frang_dbg_lock(&ra->lock, "checks done for client %s\n",
			       &FRANG_ACC2CLI(ra)->addr);
		tfw_gfsm_move(&conn->state, TFW_FRANG_REQ_FSM_DONE, data);
		T_FSM_EXIT();
	}

	}
	T_FSM_FINISH(r, req->frang_st);

	return r;
}

static int
frang_http_req_handler(TfwConn *conn, TfwFsmData *data)
{
	int r;
	FrangAcc *ra;
	TfwVhost *dvh = NULL;
	TfwHttpReq *req = (TfwHttpReq *)data->req;

	/*
	 * TODO #1350:
	 * If req has peer (because of x-forwarded-for header),
	 * we should check if this peer is also whitelisted or not.
	 */
	if (frang_sk_is_whitelisted(conn->sk))
		return T_OK;

	ra = frang_acc_from_sk(conn->sk);
	if (req->peer)
		ra = FRANG_CLI2ACC(req->peer);

	dvh = tfw_vhost_lookup_default();
	if (WARN_ON_ONCE(!dvh))
		return T_BLOCK;
	r = frang_http_req_process(ra, conn, data, dvh);
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
	unsigned long exceeded = 0;
	int r = T_OK;

	if (!body_len)
		return T_OK;

	if (likely(req->conn)) {
		if (req->peer)
			cli_addr = &req->peer->addr;
		else
			cli_addr = &req->conn->peer->addr;
	}

	if (unlikely(resp->content_length > body_len)) {
		exceeded = resp->content_length;
	} else if (unlikely(resp->body.len > body_len)) {
		exceeded = resp->body.len;
	}

	/* Ensure message body size doesn't overcome acceptable limits. */
	if (unlikely(exceeded)) {
		if (cli_addr) {
			frang_limmsg("HTTP response body length",
				     exceeded, body_len,
				     cli_addr);
		} else {
			frang_limmsg_local("HTTP response body length",
					   exceeded, body_len,
					   "Health Monitor");
		}
		r = T_BLOCK;
	}

	return r;
}

static int
frang_resp_code_limit(FrangAcc *ra, FrangHttpRespCodeBlock *resp_cblk)
{
	FrangRespCodeStat *stat = ra->resp_code_stat;
	unsigned long cnt = 0;
	const unsigned int ts = frang_time_quantum(resp_cblk->tf);
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
	if (unlikely(cnt > resp_cblk->limit)) {
		frang_limmsg("http_resp_code_block limit", cnt,
			     resp_cblk->limit, &FRANG_ACC2CLI(ra)->addr);
		return T_BLOCK;
	}

	return T_OK;
}

/**
 * Block client connection if not allowed response code appears too frequently
 * in responses for that client. Called from tfw_http_resp_fwd() by
 * tfw_gfsm_move().
 * Always returns T_OK because there is no error in processing response,
 * client may do something illegal and is to be blocked. Allow upper levels
 * to continue working with the response and the server connection.
 */
static int
frang_resp_fwd_process(TfwHttpResp *resp)
{
	int r;
	FrangAcc *ra;
	TfwHttpReq *req = resp->req;
	FrangVhostCfg *fcfg = req->location ? req->location->frang_cfg
					    : req->vhost->loc_dflt->frang_cfg;
	FrangHttpRespCodeBlock *conf = fcfg->http_resp_code_block;

	/*
	 * Requests originated by Health Monitor are generated by Tempesta,
	 * there is no reason to limit them. Such requests have no connection
	 * attached.
	 */
	if (unlikely(!resp->req->conn) || !conf)
		return T_OK;

	ra = frang_acc_from_sk(req->conn->sk);
	BUG_ON(!ra);

	if (req->peer)
		ra = FRANG_CLI2ACC(req->peer);

	frang_dbg_lock(&ra->lock, "client %s check response %d, acc=%p\n",
		       &FRANG_ACC2CLI(ra)->addr, resp->status, ra);

	if (!tfw_http_resp_code_range(resp->status)
	    || !test_bit(HTTP_CODE_BIT_NUM(resp->status), conf->codes))
		return T_OK;

	spin_lock(&ra->lock);
	/*
	 * According to the backend response code attacker may be trying to crack
	 * the password. This security event must be triggered when the response
	 * received, and can't be triggered on request context because client
	 * can send a huge number of pipelined requests to crack the password
	 * and wait for the results. If the attack is spotted, block the client
	 * and wipe all their received but not processed requests ASAP.
	 */
	r = frang_resp_code_limit(ra, conf);
	spin_unlock(&ra->lock);

	return r;
}

static int
frang_resp_handler(TfwConn *conn, TfwFsmData *data)
{
	TfwHttpResp *resp = (TfwHttpResp *)data->resp;
	int r = T_OK;

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

	if (r != T_OK)
		return r;
	r = tfw_gfsm_move(&conn->state, TFW_FRANG_RESP_FSM_DONE, data);

	return r;
}

static int
frang_tls_conn_limit(FrangAcc *ra, FrangGlobCfg *conf, int hs_state)
{
	unsigned long ts = (jiffies * FRANG_FREQ) / HZ;
	unsigned long sum_new = 0, sum_incomplete = 0;
	int i = ts % FRANG_FREQ;

	if (ra->history[i].ts != ts) {
		bzero_fast(&ra->history[i], sizeof(ra->history[i]));
		ra->history[i].ts = ts;
	}

	switch (hs_state) {
	case TTLS_HS_CB_FINISHED_NEW:
		ra->history[i].tls_sess_new++;

		if (conf->tls_new_conn_burst
		    && unlikely(ra->history[i].tls_sess_new >
				conf->tls_new_conn_burst))
		{
			frang_limmsg("new TLS connections burst",
				     ra->history[i].tls_sess_new,
				     conf->tls_new_conn_burst,
				     &FRANG_ACC2CLI(ra)->addr);
			return T_BLOCK_WITH_RST;
		}
		break;
	case TTLS_HS_CB_FINISHED_RESUMED:
		break;
	case TTLS_HS_CB_INCOMPLETE:
		ra->history[i].tls_sess_incomplete++;
		break;
	default:
		WARN_ONCE(1, "Frang: unknown tls state\n");
		return T_BLOCK_WITH_RST;
		break;
	}

	for (i = 0; i < FRANG_FREQ; i++)
		if (frang_time_in_frame(ts, ra->history[i].ts)) {
			sum_new += ra->history[i].tls_sess_new;
			sum_incomplete += ra->history[i].tls_sess_incomplete;
		}

	switch (hs_state) {
	case TTLS_HS_CB_FINISHED_NEW:
		if (conf->tls_new_conn_rate
		    && unlikely(sum_new > conf->tls_new_conn_rate))
		{
			frang_limmsg("new TLS connections rate", sum_new,
				     conf->tls_new_conn_rate,
				     &FRANG_ACC2CLI(ra)->addr);
			return T_BLOCK_WITH_RST;
		}
		break;
	case TTLS_HS_CB_INCOMPLETE:
		if (conf->tls_incomplete_conn_rate
		    && unlikely(sum_incomplete >
		    		conf->tls_incomplete_conn_rate))
		{
			frang_limmsg("incomplete TLS connections rate",
				     sum_incomplete,
				     conf->tls_incomplete_conn_rate,
				     &FRANG_ACC2CLI(ra)->addr);
			return T_BLOCK_WITH_RST;
		}
		break;
	default:
		break;
	}

	return T_OK;
}

int
frang_tls_handler(TlsCtx *tls, int state)
{
	TfwTlsConn *conn = container_of(tls, TfwTlsConn, tls);
	FrangAcc *ra = frang_acc_from_sk(conn->cli_conn.sk);
	TfwVhost *dflt_vh = tfw_vhost_lookup_default();
	int r;

	if (WARN_ON_ONCE(!dflt_vh))
		return T_BLOCK_WITH_RST;

	BUG_ON(!ra);

	spin_lock(&ra->lock);

	r = frang_tls_conn_limit(ra, dflt_vh->frang_gconf, state);

	spin_unlock(&ra->lock);

	if (unlikely(r == T_BLOCK_WITH_RST) && dflt_vh->frang_gconf->ip_block)
		tfw_filter_block_ip(FRANG_ACC2CLI(ra));

	tfw_vhost_put(dflt_vh);

	return r;
}

static int
__frang_http_hdr_len(FrangAcc *ra, TfwHttpReq *req, unsigned int new_hdr_len,
		     unsigned int max_hdr_len)
{
	unsigned int cur_hdr_len;

	cur_hdr_len = TFW_HTTP_MSG_HDR_OVERHEAD(req) + new_hdr_len;
	if (unlikely(cur_hdr_len > max_hdr_len)) {
		frang_limmsg_lock(&ra->lock, "HTTP header length", cur_hdr_len,
				  max_hdr_len, &FRANG_ACC2CLI(ra)->addr);
		return T_BLOCK;
	}

	return T_OK;
}

static int
__frang_http_hdr_cnt(FrangAcc *ra, TfwHttpReq *req, unsigned int hdr_cnt)
{
	if (unlikely(req->headers_cnt + 1 > hdr_cnt)) {
		frang_limmsg_lock(&ra->lock, "HTTP headers count",
				  req->headers_cnt + 1, hdr_cnt,
				  &FRANG_ACC2CLI(ra)->addr);
		return T_BLOCK;
	}

	return T_OK;
}

static int
__frang_http_hdr_list_size(FrangAcc *ra, TfwHttpReq *req,
			   unsigned int new_hdr_len,
			   unsigned int max_hdr_list_size)
{
	unsigned int cur_hdr_list_size;

	cur_hdr_list_size = req->header_list_sz +
		new_hdr_len + TFW_HTTP_MSG_HDR_OVERHEAD(req);

	if (unlikely(cur_hdr_list_size > max_hdr_list_size)) {
		frang_limmsg_lock(&ra->lock, "HTTP header list size",
				  cur_hdr_list_size, max_hdr_list_size,
				  &FRANG_ACC2CLI(ra)->addr);
		return T_BLOCK;
	}

	return T_OK;
}

static int
__frang_http_hdr_limit(FrangAcc *ra, TfwHttpReq *req, TfwVhost *dvh,
		       unsigned int new_hdr_len)
{
	FrangGlobCfg *f_cfg = dvh->frang_gconf;
	int r;

	if (WARN_ON_ONCE(!f_cfg))
		return T_BLOCK;

	if (f_cfg->http_hdr_len &&
	    unlikely((r = __frang_http_hdr_len(ra, req, new_hdr_len,
					       f_cfg->http_hdr_len))))
	{
		return r;
	}

	if (f_cfg->http_hdr_cnt &&
	    unlikely((r = __frang_http_hdr_cnt(ra, req, f_cfg->http_hdr_cnt))))
	{
		return r;
	}

	if (max_header_list_size &&
	    unlikely((r = __frang_http_hdr_list_size(ra, req, new_hdr_len,
						     max_header_list_size))))
	{
		return r;
	}

	return T_OK;
}

int
frang_http_hdr_limit(TfwHttpReq *req, unsigned int new_hdr_len)
{
	TfwConn *conn = req->conn;
	FrangAcc *ra;
	TfwVhost *dvh = NULL;
	int r;

	if (WARN_ON_ONCE(!conn || !conn->sk))
		return T_BLOCK;

	ra = frang_acc_from_sk(conn->sk);
	if (req->peer)
		ra = FRANG_CLI2ACC(req->peer);

	dvh = tfw_vhost_lookup_default();
	if (WARN_ON_ONCE(!dvh))
		return T_BLOCK;

	r = __frang_http_hdr_limit(ra, req, dvh, new_hdr_len);

	tfw_vhost_put(dvh);

	return r;

}

static int
frang_sticky_cookie_limit(FrangAcc *ra, TfwCliConn *conn,
			  unsigned int max_misses)
{
	unsigned long ts = jiffies * FRANG_FREQ / HZ;
	int i = ts % FRANG_FREQ;
	unsigned int msum = 0;

	if (!max_misses)
		return T_OK;

	if (tfw_cli_conn_get_js_ts(conn, i) != ts) {
		tfw_cli_conn_set_js_ts(conn, i, ts);
		tfw_cli_conn_set_js_max_misses(conn, i, 0);
	}
	tfw_cli_conn_inc_js_max_misses(conn, i);
	/* Warning in case of overflow. */
	WARN_ON_ONCE(!tfw_cli_conn_get_js_max_misses(conn, i));

	/* Collect current max_misses sum. */
	for (i = 0; i < FRANG_FREQ; i++) {
		if (frang_time_in_frame(ts, tfw_cli_conn_get_js_ts(conn, i)))
			msum += tfw_cli_conn_get_js_max_misses(conn, i);
	}

	if (unlikely(msum > max_misses)) {
		frang_limmsg_lock(&ra->lock, "max rmisses", msum, max_misses,
				  &FRANG_ACC2CLI(ra)->addr);
		return T_BLOCK;
	}

	return T_OK;
}

int
frang_sticky_cookie_handler(TfwHttpReq *req)
{
	TfwConn *conn = req->conn;
	FrangAcc *ra;
	TfwStickyCookie *sticky;

	if (WARN_ON_ONCE(!req->vhost || !conn || !conn->sk))
		return T_BLOCK;

	ra = frang_acc_from_sk(conn->sk);
	if (req->peer)
		ra = FRANG_CLI2ACC(req->peer);

	sticky = req->vhost->cookie;
	/*
	 * All whitelisted requests should not execute JS
	 * challenge. Also this function is called only for
	 * client connections.
	 */
	BUG_ON(frang_req_is_whitelisted(req));
	BUG_ON(!sticky->enforce);
	BUG_ON(!(TFW_CONN_TYPE(conn) & Conn_Clnt));

	return frang_sticky_cookie_limit(ra, (TfwCliConn *)conn,
					 sticky->max_misses);
}

/*
 * ------------------------------------------------------------------------
 *	Generic classifier functionality.
 * ------------------------------------------------------------------------
 */

static DECLARE_BITMAP(tfw_inports, 65536) __read_mostly;

void
tfw_classifier_add_inport(__be16 port)
{
	set_bit(port, tfw_inports);
}

void
tfw_classifier_remove_inport(__be16 port)
{
	clear_bit(port, tfw_inports);
}

void
tfw_classifier_cleanup_inport(void)
{
	bitmap_zero(tfw_inports, 65536);
}

static int
tfw_classify_conn_estab(struct sock *sk, struct sk_buff *skb)
{
	if (test_bit(tfw_addr_get_sk_sport(sk), tfw_inports)
	    && sock_flag(sk, SOCK_TEMPESTA))
		return frang_conn_new(sk, skb);

	return T_OK;
}

/**
 * TODO #488: call from sk_filter() called from tcp_v4_rcv() and tcp_v6_rcv(),
 * i.e. when IP fragments are already assembled and we can process TCP.
 */
static int
tfw_classify_tcp(struct sock *sk, struct sk_buff *skb)
{
	/* Just a hint. Be careful calling not only for Tempesta's socket. */
	if (!sock_flag(sk, SOCK_TEMPESTA))
		return T_OK;
	return T_OK;
}

/*
 * ------------------------------------------------------------------------
 *	Init/exit procedures for http limits.
 * ------------------------------------------------------------------------
 */
typedef struct {
	int			prio;
	int			hook_fsm;
	int			hook_state;
	int			st0;
	unsigned short		fsm_id;
	const char		*name;
} FrangGfsmHook;

static FrangGfsmHook frang_gfsm_hooks[] = {
	{
		.prio		= -1,
		.hook_fsm	= TFW_FSM_HTTP,
		.hook_state	= TFW_HTTP_FSM_REQ_MSG,
		.fsm_id		= TFW_FSM_FRANG_REQ,
		.st0		= TFW_FRANG_REQ_FSM_INIT,
		.name		= "request_msg_end",
	},
	{
		.prio		= -1,
		.hook_fsm	= TFW_FSM_HTTP,
		.hook_state	= TFW_HTTP_FSM_REQ_CHUNK,
		.fsm_id		= TFW_FSM_FRANG_REQ,
		.st0		= TFW_FRANG_REQ_FSM_INIT,
		.name		= "request_skb_end",
	},
	{
		.prio		= -1,
		.hook_fsm	= TFW_FSM_HTTP,
		.hook_state	= TFW_HTTP_FSM_RESP_MSG,
		.fsm_id		= TFW_FSM_FRANG_RESP,
		.st0		= TFW_FRANG_RESP_FSM_INIT,
		.name		= "response_msg_end",
	},
	{
		.prio		= -1,
		.hook_fsm	= TFW_FSM_HTTP,
		.hook_state	= TFW_HTTP_FSM_RESP_CHUNK,
		.fsm_id		= TFW_FSM_FRANG_RESP,
		.st0		= TFW_FRANG_RESP_FSM_INIT,
		.name		= "response_skb_end",
	},
	{
		.prio		= -1,
		.hook_fsm	= TFW_FSM_HTTP,
		.hook_state	= TFW_HTTP_FSM_RESP_MSG_FWD,
		.fsm_id		= TFW_FSM_FRANG_RESP,
		.st0		= TFW_FRANG_RESP_FSM_FWD,
		.name		= "response_fwd",
	},
};

static void
tfw_http_limits_hooks_remove(void)
{
	int i;

	for (i = ARRAY_SIZE(frang_gfsm_hooks) - 1; i >= 0; i--) {
		FrangGfsmHook *h = &frang_gfsm_hooks[i];
		if (h->prio == -1)
			continue;
		tfw_gfsm_unregister_hook(h->hook_fsm, h->prio, h->hook_state);
		h->prio = -1;
	}
}

static int
tfw_http_limits_hooks_register(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(frang_gfsm_hooks); i++) {
		FrangGfsmHook *h = &frang_gfsm_hooks[i];

		h->prio = tfw_gfsm_register_hook(h->hook_fsm,
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

static TempestaOps tempesta_ops = {
	.sk_alloc	= tfw_classify_conn_estab,
	.sk_free        = tfw_classify_conn_close,
	.sock_tcp_rcv	= tfw_classify_tcp,
};

int __init
tfw_http_limits_init(void)
{
	int r;

	tempesta_register_ops(&tempesta_ops);

	BUILD_BUG_ON((sizeof(FrangAcc) > sizeof(TfwClassifierPrvt)));

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
	tempesta_unregister_ops(&tempesta_ops);
}
