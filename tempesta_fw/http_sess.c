/*
 *		Tempesta FW
 *
 * HTTP session management.
 *
 * Typically Web applications identify HTTP sessions using special session ID
 * cookies. Tempesta does this using sticky cookies. So HTTP session contains
 * at least its timestamp and secure HMAC over User-Agent, client IP address
 * and the timestamp - the hash is used to identify the session.
 *
 * HTTP sessions are used for client security identification (e.g. DDoS cookie
 * challenge), safe load balancing for session oriented Web apps and so on.
 * The term 'Client' is actually vague. Different human clients can be behind
 * shared proxy having the same source IP (i.e. the same TfwClient descriptor).
 * The same human client can use different browsers, so they send different
 * User-Agent headers and use different sticky cookies. X-Forwarded-For header
 * value can be used to cope the non anonymous forward proxy problem and
 * identify real clients.
 *
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include <crypto/hash.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/vmalloc.h>

#include "lib/hash.h"
#include "lib/str.h"
#include "addr.h"
#include "cfg.h"
#include "client.h"
#include "hash.h"
#include "http_msg.h"
#include "http_sess.h"
#include "vhost.h"
#include "filter.h"
#include "tdb.h"

static struct {
	unsigned int	db_size;
	const char	*db_path;
} sess_db_cfg __read_mostly;

static TDB *sess_db;

typedef struct {
	TfwHttpSess	sess;
} TfwSessEntry;

/**
 * Temporal storage for calculated redirection mark value.
 *
 * @att_no		- number of redirection attempts;
 * @ts			- timestamp for the first redirection attempt;
 * @hmac		- calculated HMAC value for redirection mark;
 */
typedef struct {
	unsigned int	att_no;
	unsigned long	ts;
	unsigned char	hmac[STICKY_KEY_HMAC_LEN];
} __attribute__((packed)) RedirMarkVal;

/**
 * Temporal storage for calculated sticky cookie values.
 *
 * @ts			- timestamp of the session beginning;
 * @hmac		- calculated HMAC value for cookie value;
 */
typedef struct {
	unsigned long	ts;
	unsigned char	hmac[STICKY_KEY_HMAC_LEN];
} __attribute__((packed)) StickyVal;

/**
 * Context for TDB operations over sessions.
 *
 * @sv		- sticky value, calculated for a client by Tempesta;
 * @cookie_val	- sticky cookie value learned from backend server;
 * @req		- currently processed request;
 * @resp	- currently processed response;
 * @jsch_rcode	- JS challenge pass result;
 */
typedef struct {
	StickyVal	sv;
	TfwStr		cookie_val;
	TfwHttpReq	*req;
	TfwHttpResp	*resp;
	int		jsch_rcode;
} TfwSessEqCtx;

/*
 * Redirection mark in the URI. Can't be defined per-vhost, since the mark is
 * parsed at very first request symbols - URI, when it's not possible to
 * determine target vhost.
 */
static const DEFINE_TFW_STR(redir_mark_eq, "__tfw=");
static bool redir_mark_enabled, redir_mark_enabled_reconfig;

void tfw_http_sess_redir_enable(void)
{
	redir_mark_enabled_reconfig = true;
}

static inline bool
tfw_http_sess_cookie_enabled(TfwHttpReq *req)
{
	return req->vhost ? !TFW_STR_EMPTY(&req->vhost->cookie->name) : false;
}

/**
 * Normal browser must be able to execute the challenge: not all requests
 * can be challenged, e.g. images - a browser won't execute the JS code if
 * receives the challenge. Send redirect only for requests with
 * 'Accept: text/html' and GET method.
 */
static bool
tfw_http_sticky_redirect_applied(TfwHttpReq *req)
{
	if (!req->vhost->cookie->js_challenge)
		return true;

	return (req->method == TFW_HTTP_METH_GET)
		&& test_bit(TFW_HTTP_B_ACCEPT_HTML, req->flags);
}

/*
 * Create redirect mark in following form:
 *
 *	<attempt_no> | <timestamp> | HMAC(Secret, attempt_no, timestamp)
 *
 * Field <attempt_no> is required to track redirection limit, and <timestamp> is
 * needed to detect bots, who repeat initial redirect mark in all subsequent
 * requests.
 */
static void
tfw_http_redir_mark_prepare(RedirMarkVal *mv, char *buf, unsigned int buf_len,
			    TfwStr *chunks, unsigned int ch_len, TfwStr *rmark,
			    TfwStr *cookie_name)
{
	unsigned int att_be32 = cpu_to_be32(mv->att_no);
	unsigned long ts_be64 = cpu_to_be64(mv->ts);
	DEFINE_TFW_STR(s_sl, "/");
	DEFINE_TFW_STR(s_eq, "=");

	bin2hex(buf, &att_be32, sizeof(att_be32));
	bin2hex(&buf[sizeof(att_be32) * 2], &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[(sizeof(att_be32) + sizeof(ts_be64)) * 2],
		mv->hmac, sizeof(mv->hmac));

	bzero_fast(chunks, ch_len);
	chunks[0] = s_sl;
	chunks[1] = *cookie_name;
	chunks[2] = s_eq;
	chunks[3].data = buf;
	chunks[3].len = buf_len;

	rmark->chunks = chunks;
	rmark->len = chunks[0].len;
	rmark->len += chunks[1].len;
	rmark->len += chunks[2].len;
	rmark->len += chunks[3].len;
	rmark->nchunks = 4;
}

static int
tfw_http_sticky_build_redirect(TfwHttpReq *req, StickyVal *sv, RedirMarkVal *mv)
{
	unsigned long ts_be64 = cpu_to_be64(sv->ts);
	TfwStr c_chunks[4], m_chunks[4], cookie = { 0 }, rmark = { 0 };
	DEFINE_TFW_STR(s_eq, "=");
	TfwHttpResp *resp;
	char c_buf[sizeof(*sv) * 2], m_buf[sizeof(*mv) * 2];
	TfwStr *body = NULL;
	TfwStickyCookie *sticky;
	int r;

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));
	if (WARN_ON_ONCE(!req->vhost))
		return TFW_HTTP_SESS_FAILURE;

	sticky = req->vhost->cookie;
	if (sticky->js_challenge)
		body = &sticky->js_challenge->body;

	/*
	 * TODO: #598 rate limit requests with invalid cookie value.
	 * Non-challengeable requests also must be rate limited.
	 */

	if (!tfw_http_sticky_redirect_applied(req))
		return TFW_HTTP_SESS_JS_NOT_SUPPORTED;

	if (TFW_MSG_H2(req)) {
		/*
		 * TODO #309: add separate flow for HTTP/2 response preparing
		 * and sending (HPACK index, encode in HTTP/2 format, add frame
		 * headers and send via @tfw_h2_resp_fwd()).
		 */
		return TFW_HTTP_SESS_REDIRECT_NEED;
	}

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		return TFW_HTTP_SESS_FAILURE;

	if (mv)
		tfw_http_redir_mark_prepare(mv, m_buf, sizeof(m_buf), m_chunks,
					    sizeof(m_chunks), &rmark,
					    &sticky->name);
	/*
	 * Form the cookie as:
	 *
	 * 	<timestamp> | HMAC(Secret, User-Agent, timestamp, Client IP)
	 *
	 * Open <timestamp> is required to be able to recalculate secret HMAC.
	 * Since the secret is unknown for the attackers, they're still unable
	 * to recalculate HMAC while we don't need to store session information
	 * until we receive correct cookie value.
	 */
	bin2hex(c_buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&c_buf[sizeof(ts_be64) * 2], sv->hmac, sizeof(sv->hmac));

	bzero_fast(c_chunks, sizeof(c_chunks));
	c_chunks[0] = sticky->name;
	c_chunks[1] = s_eq;
	c_chunks[2].data = c_buf;
	c_chunks[2].len = sizeof(*sv) * 2;
	c_chunks[3] = sticky->options;

	cookie.chunks = c_chunks;
	cookie.len = c_chunks[0].len + c_chunks[1].len + c_chunks[2].len;
	cookie.nchunks = 3;
	if (!TFW_STR_EMPTY(&sticky->options)) {
		cookie.len += sticky->options.len;
		cookie.nchunks++;
	}

	r = tfw_http_prep_redirect((TfwHttpMsg *)resp, sticky->redirect_code,
				   &rmark, &cookie, body);
	if (r) {
		tfw_http_msg_free((TfwHttpMsg *)resp);
		return TFW_HTTP_SESS_FAILURE;
	}

	/*
	 * Don't send @resp now: cookie check take place on very early @req
	 * processing stage, store @resp as @req->resp, the response will be
	 * sent as soon as @req will be fully processed.
	 */
	return TFW_HTTP_SESS_REDIRECT_NEED;
}

/*
 * Search for cookie defined in @sticky configuration in `Set-Cookie`/`Cookie`
 * header value @cookie and save the cookie value into @val. @is_resp_hdr flag
 * identifies the header name: true for `Set-Cookie`, false for `Cookie`.
 */
static int
search_cookie(TfwStickyCookie *sticky, const TfwStr *cookie, TfwStr *val,
	      bool is_resp_hdr)
{
	const char *const cstr = sticky->name_eq.data;
	const unsigned long clen = sticky->name_eq.len;
	TfwStr *chunk, *end;
	TfwStr tmp = { .flags = 0, };
	unsigned int n = cookie->nchunks;

	BUG_ON(!TFW_STR_PLAIN(&sticky->name_eq));

	/* Search cookie name. */
	end = cookie->chunks + cookie->nchunks;
	for (chunk = cookie->chunks; chunk != end; ++chunk, --n) {
		if (!(chunk->flags & TFW_STR_NAME))
			continue;
		/*
		 * Create a temporary compound string, starting with this
		 * chunk. The total string length is not used here, so it
		 * is not set.
		 */
		tmp.chunks = chunk;
		tmp.nchunks = n;
		if (tfw_str_eq_cstr(&tmp, cstr, clen, TFW_STR_EQ_PREFIX))
			break;
		/*
		 * 'Cookie' header has multiple name-value pairs while the
		 * 'Set-Cookie' has only one.
		 */
		if (unlikely(is_resp_hdr))
			return 0;
	}
	if (chunk == end)
		return 0;

	/* Search cookie value, starting with next chunk. */
	for (++chunk; chunk != end; ++chunk)
		if (chunk->flags & TFW_STR_VALUE)
			break;
	/*
	 * The party can send us zero-value cookie,
	 * treat this as not found cookie.
	 */
	if (unlikely(chunk == end))
		return 0;

	tfw_str_collect_cmp(chunk, end, val, ";");

	return 1;
}

/*
 * Find Tempesta sticky cookie in an HTTP request.
 *
 * Return 1 if the cookie is found.
 * Return 0 if the cookie is NOT found.
 */
static int
tfw_http_sticky_get_req(TfwHttpReq *req, TfwStr *cookie_val)
{
	TfwStr value = { 0 };
	TfwStr *hdr;

	/*
	 * Find a 'Cookie:' header field in the request. Then search for
	 * Tempesta sticky cookie within the field. Note that there can
	 * be only one "Cookie:" header field. See RFC 6265 section 5.4.
	 * NOTE: Irrelevant here, but there can be multiple 'Set-Cookie"
	 * header fields as an exception. See RFC 7230 section 3.2.2.
	 */
	hdr = &req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
	if (TFW_STR_EMPTY(hdr))
		return 0;
	tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_COOKIE, &value);

	return search_cookie(req->vhost->cookie, &value, cookie_val, false);
}

#ifdef DEBUG
#define T_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)				\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	char hbuf[STICKY_KEY_HMAC_LEN * 2] = {0};				\
	tfw_addr_fmt(addr, TFW_NO_PORT, abuf);				\
	bin2hex(hbuf, sticky->key, STICKY_KEY_HMAC_LEN);			\
	T_DBG("http_sess: calculate sticky cookie for %s,"		\
	      " ts=%#lx(now=%#lx)...\n", abuf, (sv)->ts, jiffies);	\
	T_DBG("\t...secret: %.*s\n", (int)STICKY_KEY_HMAC_LEN * 2, hbuf);	\
	tfw_str_dprint(ua, "\t...User-Agent");				\
} while (0)
#else
#define T_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)
#endif

/*
 * Create Tempesta sticky cookie value.
 *
 * Tempesta sticky cookie is based on:
 * - HTTP request source IP address;
 * - HTTP request User-Agent string;
 * - Current timestamp;
 * - The secret key;
 */
static int
__sticky_calc(TfwHttpReq *req, StickyVal *sv)
{
	int r;
	TfwStr ua_value = { 0 };
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *hdr, *c, *end;
	TfwStickyCookie *sticky = req->vhost->cookie;
	SHASH_DESC_ON_STACK(shash_desc, sticky->shash);

	/* User-Agent header field is not mandatory and may be missing. */
	hdr = &req->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT];
	if (!TFW_STR_EMPTY(hdr))
		tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_USER_AGENT,
					 &ua_value);

	shash_desc->tfm = sticky->shash;
	shash_desc->flags = 0;

	T_DBG_PRINT_STICKY_COOKIE(addr, &ua_value, sv);

	if ((r = crypto_shash_init(shash_desc)))
		return r;

	r = crypto_shash_update(shash_desc, (u8 *)tfw_addr_sa(addr),
	                        tfw_addr_sa_len(addr));
	if (r)
		return r;
	if (ua_value.len) {
		TFW_STR_FOR_EACH_CHUNK(c, &ua_value, end) {
			r = crypto_shash_update(shash_desc, c->data, c->len);
			if (r)
				return r;
		}
	}
	return crypto_shash_finup(shash_desc, (u8 *)&sv->ts, sizeof(sv->ts),
				  sv->hmac);
}

static int
tfw_http_sticky_calc(TfwHttpReq *req, StickyVal *sv)
{
	sv->ts = jiffies;

	return __sticky_calc(req, sv);
}

/*
 * Add Tempesta sticky cookie to an HTTP response.
 *
 * Create a complete 'Set-Cookie:' header field, and add it
 * to the HTTP response' header block.
 */
static int
tfw_http_sticky_add(TfwHttpResp *resp)
{
	static const unsigned int len = sizeof(StickyVal) * 2;
	int r;
	TfwHttpSess *sess = resp->req->sess;
	unsigned long ts_be64 = cpu_to_be64(sess->ts);
	char buf[len];
	TfwStickyCookie *sticky = resp->req->vhost->cookie;
	size_t cookie_len = sticky->name_eq.len;
	TfwStr set_cookie = {
		.chunks = (TfwStr []) {
			{ .data = S_F_SET_COOKIE, .len = SLEN(S_F_SET_COOKIE) },
			{ .data = sticky->name_eq.data,
			  .len =  cookie_len },
			{ .data = buf, .len = len },
		},
		.len = SLEN(S_F_SET_COOKIE) + cookie_len + len,
		.eolen = 2,
		.nchunks = 3
	};

	/* See comment from tfw_http_sticky_build_redirect(). */
	bin2hex(buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[sizeof(ts_be64) * 2], sess->hmac, sizeof(sess->hmac));

	T_DBG("%s: \"" S_F_SET_COOKIE "%.*s=%.*s\"\n", __func__,
	      PR_TFW_STR(&sticky->name), len, buf);

	r = tfw_http_msg_hdr_add((TfwHttpMsg *)resp, &set_cookie);
	if (r)
		T_WARN("Cannot add \"" S_F_SET_COOKIE "%.*s=%.*s\"\n",
		       PR_TFW_STR(&sticky->name), len, buf);
	return r;
}

/*
 * Calculate HMAC value for redirection mark.
 *
 * HMAC value is based on:
 * - Number of attempts for session establishing;
 * - Timestamp of first attempt;
 * - Secret key.
 */
static int
__redir_hmac_calc(TfwHttpReq *req, RedirMarkVal *mv)
{
	int r;
	TfwStickyCookie *sticky = req->vhost->cookie;
	SHASH_DESC_ON_STACK(shash_desc, sticky->shash);

	shash_desc->tfm = sticky->shash;
	shash_desc->flags = 0;

	T_DBG("http_sess: calculate redirection mark: ts=%#lx(now=%#lx),"
	      " att_no=%#x\n", mv->ts, jiffies, mv->att_no);

	if ((r = crypto_shash_init(shash_desc)))
		return r;
	r = crypto_shash_update(shash_desc, (u8 *)&mv->att_no, sizeof(mv->att_no));
	if (r)
		return r;
	return crypto_shash_finup(shash_desc, (u8 *)&mv->ts, sizeof(mv->ts),
				  mv->hmac);
}

static int
tfw_http_redir_mark_get(TfwHttpReq *req, TfwStr *out_val)
{
	TfwStr *mark = &req->mark;
	TfwStr *c, *end;

	if (TFW_STR_EMPTY(mark))
		return 0;

	/* Find the value chunk. */
	end = mark->chunks + mark->nchunks;
	for (c = mark->chunks; c != end; ++c)
		if (c->flags & TFW_STR_VALUE)
			break;

	BUG_ON(c == end);

	tfw_str_collect_cmp(c, end, out_val, NULL);

	return 1;
}

#define sess_warn(check, addr, fmt, ...)				\
	T_WARN_MOD_ADDR(http_sess, check, addr, TFW_NO_PORT, fmt,	\
	                  ##__VA_ARGS__)

/* The set of macros for parsing hex strings of following format:
 *
 *    <value_1> | <value_2> | ... | <value_n> | HMAC_value
 *
 * and HMAC value verification. In 'HEX_STR_TO_BIN_HMAC()' macro the
 * 'hmac' parameter must contain newly recalculated HMAC value.
 */
#define HEX_STR_TO_BIN_INIT(tr, c, str, end)				\
	tr = NULL;							\
	TFW_STR_FOR_EACH_CHUNK_INIT(c, str, end);

#define HEX_STR_TO_BIN_GET(obj, f)					\
({									\
	int count = 0;							\
	if (c >= end)							\
		goto end_##f;						\
	if (!tr)							\
		tr = c->data;						\
	for (;;) {							\
		for ( ; tr < (unsigned char *)c->data + c->len; ++tr) {	\
			if (count++ == sizeof((obj)->f) * 2)		\
				goto end_##f;				\
			(obj)->f = ((obj)->f << 4) + hex_to_bin(*tr);	\
		}							\
		++c;							\
		if (c >= end)						\
			break;						\
		tr = c->data;						\
	}								\
end_##f:								\
	;								\
})

#define HEX_STR_TO_BIN_HMAC(hmac, ts, addr)				\
({									\
	unsigned char b;						\
	int i = 0, hi = 1, r = TFW_HTTP_SESS_SUCCESS;			\
									\
	if (c >= end)							\
		goto end;						\
	for (;;) {							\
		for ( ; tr < (unsigned char *)c->data + c->len; ++tr) {	\
			b = hi ? hex_asc_hi((hmac)[i])			\
			       : hex_asc_lo((hmac)[i]);			\
			if (b != *tr) {					\
				int n = sizeof(hmac) * 2;		\
				char buf[n];				\
				bin2hex(buf, hmac, sizeof(hmac));	\
				sess_warn("bad received HMAC value",	\
					  addr, ": %c(pos=%d),"		\
					  " ts=%#lx orig_hmac=[%.*s]\n", \
					  *tr, i, ts, n, buf);		\
				r = TFW_HTTP_SESS_VIOLATE;		\
				goto end;				\
			}						\
			hi = !hi;					\
			i += hi;					\
		}							\
		++c;							\
		if (c >= end)						\
			break;						\
		tr = c->data;						\
	}								\
	BUG_ON(i != STICKY_KEY_HMAC_LEN);				\
end:									\
	r;								\
})

/**
 * Verify found redirection mark.
 */
static int
tfw_http_redir_mark_verify(TfwHttpReq *req, TfwStr *mark_val, RedirMarkVal *mv)
{
	unsigned char *tr;
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *c, *end;

	T_DBG("Redirection mark found%s: \"%.*s\"\n",
	      TFW_STR_PLAIN(mark_val) ? "" : ", starts with",
	      TFW_STR_PLAIN(mark_val) ?
		      (int)mark_val->len :
		      (int)mark_val->chunks->len,
	      TFW_STR_PLAIN(mark_val) ?
		      mark_val->data :
		      mark_val->chunks->data);

	if (mark_val->len != sizeof(RedirMarkVal) * 2) {
		sess_warn("bad length of redirection mark", addr,
			  ": %lu(%lu)\n", mark_val->len,
			  sizeof(RedirMarkVal) * 2);
		return TFW_HTTP_SESS_VIOLATE;
	}

	HEX_STR_TO_BIN_INIT(tr, c, mark_val, end);
	HEX_STR_TO_BIN_GET(mv, att_no);
	HEX_STR_TO_BIN_GET(mv, ts);

	if (__redir_hmac_calc(req, mv))
		return TFW_HTTP_SESS_VIOLATE;

	return HEX_STR_TO_BIN_HMAC(mv->hmac, mv->ts, addr);
}

/*
 * Find special redirection mark in request, calculate actual mark,
 * match them and check redirection counts and timestamp (if configured).
 * If limits are exceeded, the IP-address of corresponding client will
 * be blocked. This verifications are intended only for enforce mode.
 */
static int
tfw_http_sess_check_redir_mark(TfwHttpReq *req, RedirMarkVal *mv)
{
	TfwStr mark_val = {};
	unsigned int max_misses = req->vhost->cookie->max_misses;
	unsigned long tmt = HZ * (unsigned long)req->vhost->cookie->tmt_sec;

	if (tfw_http_redir_mark_get(req, &mark_val)) {
		if (tfw_http_redir_mark_verify(req, &mark_val, mv)
		    || ++mv->att_no > max_misses
		    || (tmt && mv->ts + tmt < jiffies))
		{
			tfw_filter_block_ip(&req->conn->peer->addr);
			return TFW_HTTP_SESS_VIOLATE;
		}
		bzero_fast(mv->hmac, sizeof(mv->hmac));
	} else {
		mv->ts = jiffies;
		mv->att_no = 1;
	}

	if (__redir_hmac_calc(req, mv))
		return TFW_HTTP_SESS_FAILURE;

	return TFW_HTTP_SESS_SUCCESS;
}

/*
 * No Tempesta sticky cookie found.
 *
 * Calculate Tempesta sticky cookie and send redirection to the client if
 * enforcement is configured. Since the client can be malicious, we don't
 * store anything for now. HTTP session will be created when the client
 * is successfully solves the cookie challenge. Also, in enforcement
 * configured case the count of requests without cookie and timeout are
 * checked (via special mark set in front of location URI in the response
 * of during redirection); if the configured limit or timeout is exhausted,
 * client will be blocked.
 */
static int
tfw_http_sticky_notfound(TfwHttpReq *req)
{
	int r;
	StickyVal sv = {};
	RedirMarkVal mv = {}, *mvp = NULL;
	TfwStickyCookie *sticky = req->vhost->cookie;

	/*
	 * In enforced mode, ensure that backend server receives
	 * requests that always carry Tempesta sticky cookie.
	 * If cookie is absent in request, return an HTTP 302
	 * response to the client that has the same host, URI,
	 * and includes 'Set-Cookie' header. If enforced mode
	 * is disabled, forward request to a backend server.
	 */
	if (!sticky->enforce)
		return TFW_HTTP_SESS_SUCCESS;

	/*
	 * If configured, ensure that limit for requests without
	 * cookie and timeout for redirections are not exhausted.
	 */
	if (sticky->max_misses) {
		mvp = &mv;
		if ((r = tfw_http_sess_check_redir_mark(req, mvp)))
			return r;
	}

	/* Create Tempesta sticky cookie and store it */
	if (tfw_http_sticky_calc(req, &sv) != 0)
		return TFW_HTTP_SESS_FAILURE;

	return tfw_http_sticky_build_redirect(req, &sv, mvp);
}

/**
 * Verify found Tempesta sticky cookie.
 */
static int
tfw_http_sticky_verify(TfwHttpReq *req, TfwStr *value, StickyVal *sv)
{
	int r;
	unsigned char *tr;
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *c, *end;
	TfwStickyCookie *sticky = req->vhost->cookie;

	T_DBG("Sticky cookie found: \"%.*s\" = \"%.*s\"%s\n",
	      PR_TFW_STR(&sticky->name),
	      TFW_STR_PLAIN(value) ?
		      (int)value->len :
		      (int)value->chunks->len,
	      TFW_STR_PLAIN(value) ?
		      value->data :
		      value->chunks->data,
	      TFW_STR_PLAIN(value) ? "" : "<truncated>");

	if (sticky->learn)
		return TFW_HTTP_SESS_SUCCESS;

	if (value->len != sizeof(StickyVal) * 2) {
		sess_warn("bad sticky cookie length", addr, ": %lu(%lu)\n",
			  value->len, sizeof(StickyVal) * 2);
		tfw_http_sticky_calc(req, sv);
		return TFW_HTTP_SESS_VIOLATE;
	}

	HEX_STR_TO_BIN_INIT(tr, c, value, end);
	HEX_STR_TO_BIN_GET(sv, ts);

	if (__sticky_calc(req, sv))
		return TFW_HTTP_SESS_VIOLATE;

	if ((r = HEX_STR_TO_BIN_HMAC(sv->hmac, sv->ts, addr)))
		return r;

	/* The cookie is valid but already expired, reject it. */
	if (jiffies > sv->ts + (unsigned long)sticky->sess_lifetime * HZ)
		return TFW_HTTP_SESS_VIOLATE;

	/* Sticky cookie is found and verified, now we can set the flag. */
	__set_bit(TFW_HTTP_B_HAS_STICKY, req->flags);

	return r;
}

/*
 * Process Tempesta sticky cookie in an HTTP request.
 */
static int
tfw_http_sticky_req_process(TfwHttpReq *req, StickyVal *sv, TfwStr *cookie_val)
{
	int r;

	/*
	 * See if the Tempesta sticky cookie is present in the request,
	 * and act depending on the result.
	 */
	r = tfw_http_sticky_get_req(req, cookie_val);
	if (r < 0)
		return r;
	if (r == 0)
		return tfw_http_sticky_notfound(req);
	if (r == 1) {
		/*
		 * Verify sticky cookie value: if it's wrong, then this can be
		 * an attack as well as changed Tempesta or whatever else.
		 * The first case must be properly handled by Frang limit
		 * (TODO #598), your ever can limit number of invalid sticky
		 * cookie tries to 1. While we just send normal 302 redirect to
		 * keep user experience intact.
		 */
		if (tfw_http_sticky_verify(req, cookie_val, sv)) {
			RedirMarkVal mv = {}, *mvp = NULL;
			if (req->vhost->cookie->max_misses) {
				mvp = &mv;
				if ((r = tfw_http_sess_check_redir_mark(req, mvp)))
					return r;
			}
			return tfw_http_sticky_build_redirect(req, sv, mvp);
		}
		return TFW_HTTP_SESS_SUCCESS;
	}
	T_WARN("Multiple Tempesta sticky cookies found: %d\n", r);

	return TFW_HTTP_SESS_FAILURE;
}

/*
 *  Remove redirection mark from request.
 */
int
tfw_http_sess_req_process(TfwHttpReq *req)
{
	TfwStickyCookie *sticky = req->vhost->cookie;

	if (!sticky->max_misses || TFW_STR_EMPTY(&req->mark))
		return 0;
	return tfw_http_msg_del_str((TfwHttpMsg *)req, &req->mark);
}

/*
 * Add Tempesta sticky cookie to an HTTP response if needed.
 */
int
tfw_http_sess_resp_process(TfwHttpResp *resp)
{
	TfwHttpReq *req = resp->req;
	TfwStickyCookie *sticky = req->vhost->cookie;

	if (TFW_STR_EMPTY(&sticky->name)
	    || sticky->learn
	    || test_bit(TFW_HTTP_B_WHITELIST, req->flags))
	{
		return 0;
	}
	BUG_ON(!req->sess);

	/*
	 * RFC 6265 4.1.1 and 4.1.2 says that we should not set session cookie
	 * if it's not necessary. Since client didn't send up the cookie and
	 * it seems that we don't enforce them, we can just set the cookie in
	 * each response forwarded to the client.
	 */
	if (test_bit(TFW_HTTP_B_HAS_STICKY, req->flags))
		return 0;
	return tfw_http_sticky_add(resp);
}

/**
 * Release pinned server to allow destroying servers and groups removed from
 * current configuration.
 */
static void
tfw_http_sess_unpin_srv(TfwHttpSess *sess)
{
	TfwServer *srv;

	if (!sess->srv_conn)
		return;

	srv = (TfwServer *)sess->srv_conn->peer;
	sess->srv_conn = NULL;
	tfw_server_unpin_sess(srv);
}

static inline void
tfw_http_sess_set_expired(TfwHttpSess *sess)
{
	atomic64_set(&sess->expires, 0);
}

static inline void
tfw_http_sess_prolong(TfwHttpSess *sess, TfwStickyCookie *sticky)
{
	if (!sticky->learn)
		return;
	atomic64_set(&sess->expires,
		     jiffies + (unsigned long)sticky->sess_lifetime * HZ);
}

void
tfw_http_sess_put(TfwHttpSess *sess)
{
	if (atomic_dec_and_test(&sess->users)) {
		/*
		 * Use counter reached 0, so session already expired and evicted
		 * from the hash table.
		 */
		tfw_http_sess_unpin_srv(sess);
		if (sess->vhost)
			tfw_vhost_put(sess->vhost);
		tfw_http_sess_set_expired(sess);
	}
}

bool
tfw_http_sess_max_misses(void)
{
	return redir_mark_enabled;
}

unsigned int
tfw_http_sess_mark_size(void)
{
	return redir_mark_enabled ? (sizeof(RedirMarkVal) * 2) : 0;
}

const TfwStr *
tfw_http_sess_mark_name(void)
{
	return redir_mark_enabled ? &redir_mark_eq : NULL;
}

/**
 * Remove a session from tdb. @sess may become invalid after the
 * function call.
 */
static void
tfw_http_sess_remove(TfwHttpSess *sess)
{
	tfw_http_sess_put(sess);
}

/**
 * Challenged client must not send request before challenging timeout passed.
 */
static int
tfw_http_sess_check_jsch(StickyVal *sv, TfwHttpReq* req)
{
	unsigned long min_time, max_time;
	TfwCfgJsCh *js_ch = req->vhost->cookie->js_challenge;

	if (!js_ch)
		return 0;

	/*
	 * When a client calculates it's own random delay, it uses range value
	 * encoded as msecs, we have to use the same, to have exactly the same
	 * calculation results. See etc/js_challenge.js.tpl .
	 */
	min_time = sv->ts + js_ch->delay_min
			+ msecs_to_jiffies(sv->ts % js_ch->delay_range);
	max_time = min_time + js_ch->delay_limit;
	if (time_in_range(req->jrxtstamp, min_time, max_time))
		return 0;

	if (tfw_http_sticky_redirect_applied(req)) {
		T_DBG("sess: jsch block: request received outside allowed "
		      "time range.\n");
		return TFW_HTTP_SESS_VIOLATE;
	}
	else {
		T_DBG("sess: jsch drop: non-challegeable resource was "
		      "requested outside allowed time range.\n");
		return TFW_HTTP_SESS_JS_NOT_SUPPORTED;
	}
}

static bool
tfw_http_sess_eq(TdbRec *rec, void *data)
{
	TfwSessEntry *ent = (TfwSessEntry *)rec->data;
	TfwHttpSess *sess = &ent->sess;
	TfwSessEqCtx *ctx = (TfwSessEqCtx *)data;
	TfwStickyCookie *sticky = ctx->req->vhost->cookie;

	/*
	 * Expired  or invalid session is not usable, leave it for garbage
	 * collector.
	 */
	if (((unsigned long)atomic64_read(&sess->expires) < jiffies)
	    || !sess->vhost)
	{
		return false;
	}

	if (sticky->learn) {
		TfwStr sess_id = { .data = sess->cval, .len = sess->key_len };
		if (tfw_strcmp(&sess_id, &ctx->cookie_val))
			return false;
	}
	else {
		if (memcmp_fast(ctx->sv.hmac, sess->hmac, sizeof(ctx->sv.hmac)))
			return false;
	}

	read_lock(&sess->lock);
	/*
	 * Vhosts are removed and added at runtime, so can't
	 * compare pointers here.
	 */
	if (tfw_stricmp(&sess->vhost->name, &ctx->req->vhost->name)) {
		read_unlock(&sess->lock);
		return false;
	}
	/*
	 * if sess->vhost != req->vhost, then B_REMOVED is set
	 * for sess->vhost.
	 */
	if (unlikely(test_bit(TFW_VHOST_B_REMOVED,
			      &sess->vhost->flags)
		     && (sess->vhost != ctx->req->vhost)))
	{
		/*
		 * The session holds the last reference to the
		 * vhost. The latter is not a part of the active
		 * configuration anymore and therefore is not
		 * useful to us at all. We can only release it
		 * to free associated resources.
		 */
		read_unlock(&sess->lock);
		tfw_http_sess_pin_vhost(sess, ctx->req->vhost);
		goto found;
	}
	read_unlock(&sess->lock);
found:
	T_DBG("http_sess was found in tdb, %pK\n", sess);
	return true;
}

static int
tfw_http_sess_precreate(void *data)
{
	TfwSessEqCtx *ctx = (TfwSessEqCtx *)data;
	TfwHttpReq *req = ctx->req;
	StickyVal *sv = &ctx->sv;
	/*
	 * When the cookie is learned from backend, it's created on processing
	 * responses, not requests.
	 */
	if (req->vhost->cookie->learn)
		return -1;

	if ((ctx->jsch_rcode = tfw_http_sess_check_jsch(sv, req)))
		return -1;

	return 0;
}

static void
tfw_sess_ent_init(TdbRec *rec, void *data)
{
	TfwSessEntry *ent = (TfwSessEntry *)rec->data;
	TfwHttpSess *sess = &ent->sess;
	TfwSessEqCtx *ctx = (TfwSessEqCtx *)data;
	TfwStickyCookie *sticky = ctx->req->vhost->cookie;

	bzero_fast(sess, sizeof(TfwHttpSess));

	if (sticky->learn) {
		tfw_str_to_cstr(&ctx->cookie_val, sess->cval, sizeof(sess->cval));
		sess->key_len = ctx->cookie_val.len;

		sess->srv_conn = (TfwSrvConn *)ctx->resp->conn;
		sess->ts = jiffies;
	}
	else {
		memcpy_fast(sess->hmac, ctx->sv.hmac, sizeof(ctx->sv.hmac));
		sess->ts = ctx->sv.ts;
	}

	atomic_set(&sess->users, 1);
	atomic64_set(&sess->expires,
		     sess->ts + (unsigned long)sticky->sess_lifetime * HZ);
	sess->vhost = ctx->req->vhost;
	tfw_vhost_get(sess->vhost);
	rwlock_init(&sess->lock);

	T_DBG("http_sess was newly created, %pK\n", sess);
}

/**
 * Obtains appropriate HTTP session for the request based on Sticky cookies.
 * Gets a reference of vhost if it was stored in the session.
 * Return TFW_HTTP_SESS_* enum or error code on internal errors.
 */
int
tfw_http_sess_obtain(TfwHttpReq *req)
{
	int r;
	unsigned long key;
	TfwHttpSess *sess;
	TfwSessEqCtx ctx = { 0 };
	StickyVal *sv = &ctx.sv;
	TfwStr *c_val = &ctx.cookie_val;
	TdbRec *rec;
	TdbGetAllocCtx tdb_ctx = { 0 };

	/*
	 * If vhost is not known, then request is to be dropped. Don't save the
	 * session even if the client has passed a cookie challenge.
	 */
	if (!req->vhost
	    || TFW_STR_EMPTY(&req->vhost->cookie->name)
	    || test_bit(TFW_HTTP_B_WHITELIST, req->flags))
	{
		return TFW_HTTP_SESS_SUCCESS;
	}
	/*
	 * Sticky cookie can be not enforced and we still have to allocate new
	 * session for requests w/o session cookie. It means that malicious user
	 * can always send us requests w/o session cookie. HMAC will be
	 * different due to different ingress timestamps, so DoS is very
	 * possible. The only thing which we can do is to enforce the cookie.
	 * However, we can lose innocent clients w/ disabled cookies.
	 * We leave this for administrator decision or more progressive DDoS
	 * mitigation techniques.
	 */
	if ((r = tfw_http_sticky_req_process(req, sv, c_val)))
		return r;

	if (req->vhost->cookie->learn) {
		key = tfw_hash_str(c_val);
	}
	else /* TempestaFw native cookie */ {
		if (!sv->ts)
			/* No sticky cookie in request and no enforcement. */
			if (tfw_http_sticky_calc(req, sv))
				return TFW_HTTP_SESS_FAILURE;

		key = hash_calc(sv->hmac, sizeof(sv->hmac));
	}
	ctx.req = req;
	tdb_ctx.eq_rec = tfw_http_sess_eq;
	tdb_ctx.precreate_rec = tfw_http_sess_precreate;
	tdb_ctx.init_rec = tfw_sess_ent_init;
	tdb_ctx.ctx = &ctx;
	tdb_ctx.len = sizeof(TfwSessEntry);

	rec = tdb_rec_get_alloc(sess_db, key, &tdb_ctx);
	BUG_ON(tdb_ctx.len < sizeof(TfwSessEntry));
	if (!rec) {
		if (req->vhost->cookie->learn)
			return TFW_HTTP_SESS_SUCCESS;
		if (ctx.jsch_rcode)
			return ctx.jsch_rcode;
		T_WARN("cannot allocate TDB space for http session\n");
		return TFW_HTTP_SESS_FAILURE;
	}
	sess = &((TfwSessEntry *)rec->data)->sess;

	atomic_inc(&sess->users);
	req->sess = sess;
	tfw_http_sess_prolong(sess, req->vhost->cookie);

	if (!tdb_ctx.is_new)
		/*
		 * The record doesn't change its location in TDB, since it is
		 * larger than TDB_HTRIE_MINDREC, and we need to unlock the
		 * bucket with the session as soon as possible.
		 */
		tdb_rec_put(rec);

	return TFW_HTTP_SESS_SUCCESS;
}

/*
 * Find Learnable sticky cookie in an HTTP response.
 *
 * Return 1 if the cookie is found.
 * Return 0 if the cookie is NOT found.
 */
static int
tfw_http_sticky_get_resp(TfwHttpResp *resp, TfwStr *cookie_val)
{
	TfwStickyCookie *sticky = resp->req->vhost->cookie;
	TfwStr *hdr, *dup, *dup_end;
	/*
	 * Each cookie in set header is placed in its own `Set-Cookie` header,
	 * need to look through all of them
	 */
	hdr = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];
	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		TfwStr value = { 0 };

		if (TFW_STR_EMPTY(dup))
			continue;
		tfw_http_msg_srvhdr_val(dup, TFW_HTTP_HDR_SET_COOKIE, &value);
		if (search_cookie(sticky, &value, cookie_val, true))
			return 1;
	}

	return 0;
}

/*
 * Learn HTTP session created on backend server. Even if the session exists,
 * backend may want to create a new for the client.
 */
void
tfw_http_sess_learn(TfwHttpResp *resp)
{
	TfwStickyCookie *sticky;
	int r;
	unsigned long key;
	TfwSessEqCtx ctx = { 0 };
	TdbGetAllocCtx tdb_ctx = { 0 };
	TfwStr *c_val = &ctx.cookie_val;
	TdbRec *rec;

	if (WARN_ON_ONCE(!resp->req || !resp->req->vhost))
		return;
	sticky = resp->req->vhost->cookie;
	if (!sticky->learn || TFW_STR_EMPTY(&sticky->name_eq))
		return;

	r = tfw_http_sticky_get_resp(resp, c_val);
	if (!r)
		return;
	/*
	 * TODO: Set session as expired if server tries to remove the cookie.
	 *
	 * RFC 6265 3.1
	 * Finally, to remove a cookie, the server returns a Set-Cookie header
	 * with an expiration date in the past.  The server will be successful
	 * in removing the cookie only if the Path and the Domain attribute in
	 * the Set-Cookie header match the values used when the cookie was
	 * created.
	 *
	 * Max-Age <= 0 can also be used to remove the cookie:
	 * RFC 6265 4.1.2.2
	 * If delta-seconds is less than or equal to zero (0), let expiry-time
	 * be the earliest representable date and time.
	 *
	 * Empty string is allowed cookie value, but it can't be used to learn
	 * and track the sessions. At the same time, empty value is pretty often
	 * used during cookie removals. So if a backend requests the client to
	 * replace the cookie with something we can't track - expire the session.
	 * https://thoughtbot.com/blog/lucky-cookies#expiration-and-removal
	 */
	if (unlikely(TFW_STR_EMPTY(c_val))) {
		if (resp->req->sess)
			tfw_http_sess_set_expired(resp->req->sess);
		return;
	}
	if (unlikely(c_val->len > STICKY_KEY_MAX_LEN)) {
		T_WARN("http_sess: too long cookie value: %li (%d).\n",
		       c_val->len, STICKY_KEY_MAX_LEN);
		return;
	}

	key = tfw_hash_str(c_val);
	ctx.req = resp->req;
	ctx.resp = resp;
	tdb_ctx.eq_rec = tfw_http_sess_eq;
	/* no tdb_ctx.precreate_rec hook. */
	tdb_ctx.init_rec = tfw_sess_ent_init;
	tdb_ctx.ctx = &ctx;
	tdb_ctx.len = sizeof(TfwSessEntry);

	rec = tdb_rec_get_alloc(sess_db, key, &tdb_ctx);
	BUG_ON(tdb_ctx.len < sizeof(TfwSessEntry));
	if (!rec) {
		T_WARN("cannot allocate TDB space for learned http session\n");
		return;
	}
	/*
	 * The session is not required now, it's enough to have a new
	 * session in tdb. Leave new_sess->users as is.
	 */
	if (!tdb_ctx.is_new)
		/*
		 * The record doesn't change its location in TDB, since it is
		 * larger than TDB_HTRIE_MINDREC, and we need to unlock the
		 * bucket with the session as soon as possible.
		 */
		tdb_rec_put(rec);
}

/**
 * Try to reuse last used connection or last used server.
 */
static inline TfwSrvConn *
__try_conn(TfwMsg *msg, TfwSrvConn *srv_conn)
{
	TfwServer *srv;

	if (unlikely(!srv_conn))
		return NULL;

	srv = (TfwServer *)srv_conn->peer;
	if (tfw_srv_suspended(srv))
		return NULL;

	if (!tfw_srv_conn_restricted(srv_conn)
	    && !tfw_srv_conn_busy(srv_conn)
	    && !tfw_srv_conn_queue_full(srv_conn)
	    && !tfw_srv_conn_hasnip(srv_conn)
	    && tfw_srv_conn_get_if_live(srv_conn))
	{
		return srv_conn;
	}

	/*
	 * Try to sched from the same server. The server may be removed from
	 * server group, see comment for TfwHttpSess.
	 */
	return srv->sg->sched->sched_srv_conn(msg, srv);
}

/**
 * Pin HTTP session to specified server. Called under write lock.
 */
static void
tfw_http_sess_pin_srv(TfwHttpSess *sess, TfwSrvConn *srv_conn)
{
	TfwServer *srv;

	tfw_http_sess_unpin_srv(sess);

	if (!srv_conn)
		return;

	srv = (TfwServer *)srv_conn->peer;
	tfw_server_pin_sess(srv);
	sess->srv_conn = srv_conn;
}

/**
 * Saves a reference to a vhost in the session.
 */
void
tfw_http_sess_pin_vhost(TfwHttpSess *sess, TfwVhost *vhost)
{
	if (!sess)
		return;

	write_lock(&sess->lock);
	if (sess->vhost)
		tfw_vhost_put(sess->vhost);
	if (vhost)
		tfw_vhost_get(vhost);
	sess->vhost = vhost;
	write_unlock(&sess->lock);
}

static inline bool
tfw_http_sticky_sess_enabled(TfwMsg *msg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;

	return test_bit(TFW_VHOST_B_STICKY_SESS, &req->vhost->flags);
}

static inline bool
tfw_http_sticky_sess_failover_enabled(TfwMsg *msg)
{
	TfwHttpReq *req = (TfwHttpReq *)msg;

	return test_bit(TFW_VHOST_B_STICKY_SESS_FAILOVER, &req->vhost->flags);
}

/**
 * Find an outgoing connection for client with Tempesta sticky cookie.
 * @sess is not null when calling the function.
 *
 * Reuse req->sess->srv_conn if it is alive. If not,
 * then get a new connection for the same server.
 */
TfwSrvConn *
tfw_http_sess_get_srv_conn(TfwMsg *msg)
{
	TfwHttpSess *sess = ((TfwHttpReq *)msg)->sess;
	TfwSrvConn *srv_conn;

	BUG_ON(!sess);

	read_lock(&sess->lock);

	/*
	 * If sess->srv_conn != 0 -> Session was pinned to a server in our
	 * previous configuration. Keep pinning enabled even if it's disabled
	 * in current configuration. Pin an unpinned session if the new
	 * configuration require that.
	 */
	if (!sess->srv_conn && !tfw_http_sticky_sess_enabled(msg)) {
		read_unlock(&sess->lock);
		return tfw_vhost_get_srv_conn(msg);
	}
	/*
	 * In unlikely but possible situations the same session will be tried
	 * on multiple cpus, use locking to guarantee theat the srv_conn
	 * will point to the same server for all of them, or requests from the
	 * same session might be forwarded to different servers.
	 */
	if ((srv_conn = __try_conn(msg, sess->srv_conn))) {
		read_unlock(&sess->lock);
		return srv_conn;
	}

	read_unlock(&sess->lock);
	write_lock(&sess->lock);
	/*
	 * Sessions was pinned to a new connection (or server returned back
	 * online) while we were trying for a lock.
	 */
	if ((srv_conn = __try_conn(msg, sess->srv_conn))) {
		write_unlock(&sess->lock);
		return srv_conn;
	}

	if (sess->srv_conn) {
		/* Failed to sched from the same server. */
		TfwServer *srv = (TfwServer *)sess->srv_conn->peer;
		char addr_str[TFW_ADDR_STR_BUF_SIZE] = { 0 };

		tfw_addr_ntop(&srv->addr, addr_str, sizeof(addr_str));

		if (!tfw_http_sticky_sess_failover_enabled(msg)) {
			/*
			 * Server is removed and disconnected, it will never
			 * go up again, expire session to force releasing of
			 * the server instance. unpin_srv() will be called in
			 * session destructor (tfw_http_sess_put()).
			 */
			if (unlikely(test_bit(TFW_CFG_B_DEL, &srv->flags))) {
				T_LOG("sticky sched: server %s"
				      " was removed, set session expired\n",
				      addr_str);
				tfw_http_sess_set_expired(sess);
				goto err;
			}
			T_WARN("sticky sched: pinned server %s in group '%s'"
			       " is down\n",
			       addr_str, srv->sg->name);
			goto err;
		}
		T_LOG("sticky sched: pinned server %s in group '%s'"
		      " is down, try find other server\n",
		      addr_str, srv->sg->name);
	}

	srv_conn = tfw_vhost_get_srv_conn(msg);
	tfw_http_sess_pin_srv(sess, srv_conn);
err:
	write_unlock(&sess->lock);

	return srv_conn;
}

static int
tfw_http_sess_cfgstart(void)
{
	redir_mark_enabled_reconfig = false;
	return 0;
}

static int
tfw_http_sess_start(void)
{
	redir_mark_enabled = redir_mark_enabled_reconfig;

	if (tfw_runstate_is_reconfig())
		return 0;
	/*
	 * The TfwSessEntry is used as a direct pointer to data inside a TDB
	 * entry. Small entries may be moved between locations as index tree
	 * grows, while big ones has constant location.
	 */
	BUILD_BUG_ON(sizeof(TfwSessEntry) <= TDB_HTRIE_MINDREC);
	sess_db = tdb_open(sess_db_cfg.db_path, sess_db_cfg.db_size,
			   sizeof(TfwSessEntry), numa_node_id());
	if (!sess_db)
		return -EINVAL;

	return 0;
}

static int
tfw_http_sess_release_entry(void *data)
{
	TfwHttpSess *sess = &((TfwSessEntry *)data)->sess;

	tfw_http_sess_remove(sess);

	return 0;
}

static void
tfw_http_sess_stop(void)
{
	if (!sess_db)
		return;

	tdb_entry_walk(sess_db, tfw_http_sess_release_entry);
	tdb_close(sess_db);
}

static TfwCfgSpec tfw_http_sess_specs_table[] = {
	{
		.name = "sessions_tbl_size",
		.deflt = "16777216",
		.handler = tfw_cfg_set_int,
		.dest = &sess_db_cfg.db_size,
		.spec_ext = &(TfwCfgSpecInt) {
			.multiple_of = PAGE_SIZE,
			.range = { PAGE_SIZE, (1 << 30) },
		}
	},
	{
		.name = "sessions_db",
		.deflt = "/opt/tempesta/db/sessions.tdb",
		.handler = tfw_cfg_set_str,
		.dest = &sess_db_cfg.db_path,
		.spec_ext = &(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{ 0 }
};

TfwMod tfw_http_sess_mod = {
	.name		= "http_sess",
	.cfgstart	= tfw_http_sess_cfgstart,
	.start		= tfw_http_sess_start,
	.stop		= tfw_http_sess_stop,
	.specs		= tfw_http_sess_specs_table,
};

int __init
tfw_http_sess_init(void)
{
	tfw_mod_register(&tfw_http_sess_mod);

	return 0;
}

void
tfw_http_sess_exit(void)
{
	tfw_mod_unregister(&tfw_http_sess_mod);
}
