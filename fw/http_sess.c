/**
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
 * JS challenge is a method that is used in DDoS mitigation to filter out
 * requests that are characteristic of a botnet or other malicious computer.
 * When JS challenge is enabled we pass each request through our session
 * module. If request doesn't contain cookie or cookie is invalid (because
 * of incorrect HMAC or an expired date) we increment special counter
 * 'max_misses' and if this counter is not exceeded the limit restart JS
 * challenge. We store this counter on our side because if we store it
 * in cookie on the client side, the client could always send a request
 * without cookie and ignore JS challenge. After receveing response with
 * JS challenge client should execute it and send new request with
 * appropriate cookie just in time.
 *
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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

#undef DEBUG
#if DBG_HTTP_SESS > 0
#define DEBUG DBG_HTTP_SESS
#endif

#include "lib/hash.h"
#include "lib/str.h"
#include "addr.h"
#include "cfg.h"
#include "client.h"
#include "hash.h"
#include "http_msg.h"
#include "http_match.h"
#include "http_sess.h"
#include "http_sess_conf.h"
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

static int
tfw_http_sticky_build_redirect(TfwHttpReq *req, StickyVal *sv, bool jsch_allow)
{
	unsigned long ts_be64 = cpu_to_be64(sv->ts);
	TfwStr c_chunks[3], cookie = { 0 };
	TfwHttpResp *resp;
	char c_buf[sizeof(*sv) * 2];
	TfwStr body = { 0 };
	TfwStickyCookie *sticky;
	int r, code;

	WARN_ON_ONCE(!list_empty(&req->fwd_list));
	WARN_ON_ONCE(!list_empty(&req->nip_list));
	if (WARN_ON_ONCE(!req->vhost))
		return TFW_HTTP_SESS_FAILURE;

	if (!(resp = tfw_http_msg_alloc_resp_light(req)))
		return TFW_HTTP_SESS_FAILURE;

	sticky = req->vhost->cookie;
	if (sticky->js_challenge && jsch_allow)
		body = sticky->js_challenge->body;

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
	c_chunks[0] = sticky->name_eq;
	c_chunks[1].data = c_buf;
	c_chunks[1].len = sizeof(*sv) * 2;
	c_chunks[2] = sticky->options;

	cookie.chunks = c_chunks;
	cookie.len = c_chunks[0].len + c_chunks[1].len;
	cookie.nchunks = 2;
	if (!TFW_STR_EMPTY(&sticky->options)) {
		cookie.len += sticky->options.len;
		cookie.nchunks++;
	}

	code = jsch_allow ? sticky->redirect_code: TFW_REDIR_STATUS_CODE_DFLT;
	r = tfw_http_prep_redir(resp, code, &cookie, &body);
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
 * Find Tempesta sticky cookie in an HTTP request.
 *
 * Return the number of found cookies.
 */
static int
tfw_http_sticky_get_req(TfwHttpReq *req, TfwStr *cookie_val)
{
	TfwStr *hdr, *end, *dup;
	int r = 0;

	/*
	 * Find a 'Cookie:' header field in the request. Then search for
	 * Tempesta sticky cookie within the field. In HTTP/1.x requests
	 * all cookies are stored in the only "Cookie:" header (RFC 6265
	 * section 5.4), HTTP/2 requests may use either a single header
	 * or multiple headers (RFC 7540 Section 8.1.2.5).
	 * Don't need to worry about multiple headers over HTTP/1.x connections
	 * here, parser blocks such requests.
	 * NOTE: Irrelevant here, but there can be multiple 'Set-Cookie"
	 * header fields as an exception. See RFC 7230 section 3.2.2.
	 */
	hdr = &req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
	if (TFW_STR_EMPTY(hdr))
		return 0;

	BUG_ON(!TFW_STR_PLAIN(&req->vhost->cookie->name_eq));

	TFW_STR_FOR_EACH_DUP(dup, hdr, end) {
		TfwStr value = { 0 };
		TfwStr *pos, *end;
		const char *cstr = req->vhost->cookie->name_eq.data;
		unsigned long clen = req->vhost->cookie->name_eq.len;

		tfw_http_msg_clnthdr_val(req, dup, TFW_HTTP_HDR_COOKIE, &value);
		pos = value.chunks;
		end = value.chunks + value.nchunks;

		while (pos != end) {
			r += tfw_http_search_cookie(cstr, clen, &pos,
						    end, cookie_val,
						    TFW_HTTP_MATCH_O_EQ,
						    false);
			/*
			 * We don't expect more than one cookie, so we
			 * can immediately return here.
			 */
			if (r > 1)
				return r;
		}
	}

	return r;
}

#ifdef DEBUG
#define T_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)				\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	char hbuf[STICKY_KEY_HMAC_LEN * 2] = {0};			\
	tfw_addr_fmt(addr, TFW_NO_PORT, abuf);				\
	bin2hex(hbuf, sticky->key, STICKY_KEY_HMAC_LEN);		\
	T_DBG("http_sess: calculate sticky cookie for %s,"		\
	      " ts=%#lx(now=%#lx)...\n", abuf, (sv)->ts, jiffies);	\
	T_DBG("\t...secret: %.*s\n", (int)STICKY_KEY_HMAC_LEN * 2, hbuf); \
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
		tfw_http_msg_clnthdr_val(req, hdr, TFW_HTTP_HDR_USER_AGENT,
					 &ua_value);

	shash_desc->tfm = sticky->shash;

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
 * Create a complete 'set-cookie' header field, and add it
 * to the HTTP response' header block.
 */
static int
tfw_http_sticky_add(TfwHttpResp *resp, bool cache)
{
	int r;
	static const unsigned int len = sizeof(StickyVal) * 2;
	char buf[sizeof(StickyVal) * 2];
	bool to_h2 = TFW_MSG_H2(resp->req);
	char *name = to_h2 ? S_SET_COOKIE : S_F_SET_COOKIE;
	unsigned int nm_len = to_h2 ? SLEN(S_SET_COOKIE) : SLEN(S_F_SET_COOKIE);
	TfwHttpSess *sess = resp->req->sess;
	unsigned long ts_be64 = cpu_to_be64(sess->ts);
	TfwStickyCookie *sticky = resp->req->vhost->cookie;
	size_t cookie_len = sticky->name_eq.len;
	TfwStr set_cookie = {
		.chunks = (TfwStr []) {
			{ .data = name, .len = nm_len },
			{ .data = sticky->name_eq.data,
			  .len = cookie_len },
			{ .data = buf, .len = len },
		},
		.len = nm_len + cookie_len + len,
		.eolen = 2,
		.nchunks = 3
	};

	/* See comment from tfw_http_sticky_build_redirect(). */
	bin2hex(buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[sizeof(ts_be64) * 2], sess->hmac, sizeof(sess->hmac));

	T_DBG("%s: name=%s, val='%.*s=%.*s'\n", __func__, name,
	      PR_TFW_STR(&sticky->name), len, buf);

	if (to_h2) {
		set_cookie.hpack_idx = 55;
		r = tfw_hpack_encode(resp, &set_cookie, !cache, !cache);
	}
	else if (cache) {
		TfwHttpTransIter *mit = &resp->mit;
		struct sk_buff **skb_head = &resp->msg.skb_head;
		TfwStr crlf = { .data = S_CRLF, .len = SLEN(S_CRLF) };

		r = tfw_http_msg_expand_data(&mit->iter, skb_head,
					     &set_cookie, NULL);
		if (!r)
			r = tfw_http_msg_expand_data(&mit->iter, skb_head,
						     &crlf, NULL);
	}
	else {
		r = tfw_http_msg_hdr_add((TfwHttpMsg *)resp, &set_cookie);
	}

	if (unlikely(r))
		T_WARN("Cannot add '%s' header: val='%.*s=%.*s'\n", name,
		       PR_TFW_STR(&sticky->name), len, buf);

	return r;
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
				char buf[sizeof(hmac) * 2];		\
				bin2hex(buf, hmac, sizeof(hmac));	\
				sess_warn("bad received HMAC value",	\
					  addr, " %c(pos=%d),"		\
					  " ts=%#lx orig_hmac=[%.*s]\n", \
					  *tr, i, ts,			\
					  (int)sizeof(hmac) * 2, buf);	\
				r = TFW_HTTP_SESS_BAD_COOKIE;		\
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

static inline int
tfw_http_sticky_challenge_start(TfwHttpReq *req)
{
	StickyVal sv = {};

	/*
	 * First check if request is not challengeble
	 * and immediately return, to prevent incrementing
	 * max_misses, because we decide to serve such
	 * requests from cache.
	 */
	if (!tfw_http_sticky_redirect_applied(req))
		return TFW_HTTP_SESS_JS_NOT_SUPPORTED;

	/*
	 * Increment max_misses and if limit is exceeded
	 * return error, otherwise try to restart challenge.
	 */
	if (frang_sticky_cookie_handler(req) != T_OK)
		return TFW_HTTP_SESS_VIOLATE;

	if (tfw_http_sticky_calc(req, &sv) != 0)
		return TFW_HTTP_SESS_FAILURE;

	return tfw_http_sticky_build_redirect(req, &sv, true);
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
		sess_warn("bad sticky cookie length", addr, " %lu(%lu)\n",
			  value->len, sizeof(StickyVal) * 2);
		tfw_http_sticky_calc(req, sv);
		return TFW_HTTP_SESS_BAD_COOKIE;
	}

	HEX_STR_TO_BIN_INIT(tr, c, value, end);
	HEX_STR_TO_BIN_GET(sv, ts);

	if (__sticky_calc(req, sv)) {
		sess_warn("cannot compute sticky cookie value", addr, "\n");
		return TFW_HTTP_SESS_FAILURE;
	}

	if ((r = HEX_STR_TO_BIN_HMAC(sv->hmac, sv->ts, addr)))
		return r;

	/* The cookie is valid but already expired, reject it. */
	if (jiffies > sv->ts + (unsigned long)sticky->sess_lifetime * HZ) {
		sess_warn("sticky cookie value expired", addr,
			  " (issued=%lu lifetime=%lu now=%lu)\n", sv->ts,
			  (unsigned long)sticky->sess_lifetime * HZ, jiffies);
		return TFW_HTTP_SESS_BAD_COOKIE;
	}

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
	if (r == 0) {
		return !req->vhost->cookie->enforce ?
			TFW_HTTP_SESS_SUCCESS : TFW_HTTP_SESS_COOKIE_NOT_FOUND;
	}
	if (r == 1) {
		if ((r = tfw_http_sticky_verify(req, cookie_val, sv)))
			return r;

		return TFW_HTTP_SESS_SUCCESS;
	}
	T_WARN("Multiple Tempesta sticky cookies found in request: %d\n", r);

	return TFW_HTTP_SESS_FAILURE;
}

/*
 * Add Tempesta sticky cookie to an HTTP response if needed.
 */
int
tfw_http_sess_resp_process(TfwHttpResp *resp, bool cache)
{
	TfwHttpReq *req = resp->req;
	TfwStickyCookie *sticky = req->vhost->cookie;

	if (TFW_STR_EMPTY(&sticky->name)
	    || sticky->learn
	    || frang_req_is_whitelisted(req)
	    || test_bit(TFW_HTTP_B_JS_NOT_SUPPORTED, req->flags))
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
	return tfw_http_sticky_add(resp, cache);
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
	unsigned long min_time;
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
	if (time_after_eq(req->jrxtstamp, min_time))
		return 0;

	sess_warn("jsch redirect received too early",
		  &req->conn->peer->addr, " (%lu is not after %lu)\n",
		  req->jrxtstamp, min_time);

	return TFW_HTTP_SESS_JS_DOES_NOT_PASS;
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
	if (basic_stricmp_fast(&sess->vhost->name, &ctx->req->vhost->name)) {
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
		tfw_server_pin_sess((TfwServer *)sess->srv_conn->peer);
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
 * Return TFW_HTTP_SESS_* enum.
 * The main logic of this function here is that we try to get request cookie,
 * if cookie is present and correct, we check that request comes in time
 * (according js challenge script). In case of any error (cookie not found or
 * incorrect, or request comes not in time) we increment max_misses and if
 * it is not exceeded the limit restart js challenge.
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
	    || frang_req_is_whitelisted(req))
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
	r = tfw_http_sticky_req_process(req, sv, c_val);
	switch (r) {
	case TFW_HTTP_SESS_SUCCESS:
		break;
	case TFW_HTTP_SESS_FAILURE:
		return r;
	default:
		/*
		 * Any js challenge processing error: cookie not found
		 * or invalid or request comes not in time. We increment
		 * max_misses and restart js challenge.
		 */
		BUG_ON(r < __TFW_HTTP_SESS_PUB_CODE_MAX);
		return tfw_http_sticky_challenge_start(req);
	}

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
			return tfw_http_sticky_challenge_start(req);
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
		tdb_rec_put(sess_db, rec);

	return TFW_HTTP_SESS_SUCCESS;
}

/*
 * Find Learnable sticky cookie in an HTTP response.
 *
 * Return count of cookies.
 */
static int
tfw_http_sticky_get_resp(TfwHttpResp *resp, TfwStr *cookie_val)
{
	TfwStickyCookie *sticky = resp->req->vhost->cookie;
	TfwStr *hdr, *dup, *dup_end;
	int r = 0;

	BUG_ON(!TFW_STR_PLAIN(&sticky->name_eq));
	/*
	 * Each cookie in set header is placed in its own `Set-Cookie` header,
	 * need to look through all of them
	 */
	hdr = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];

	TFW_STR_FOR_EACH_DUP(dup, hdr, dup_end) {
		TfwStr value = { 0 };
		TfwStr *pos, *end;
		const char *cstr = sticky->name_eq.data;
		unsigned long clen = sticky->name_eq.len;

		if (TFW_STR_EMPTY(dup))
			continue;
		tfw_http_msg_srvhdr_val(dup, TFW_HTTP_HDR_SET_COOKIE, &value);
		pos = value.chunks;
		end = value.chunks + value.nchunks;
		cstr = sticky->name_eq.data;

		while (pos != end) {
			r += tfw_http_search_cookie(cstr, clen, &pos,
						    end, cookie_val,
						    TFW_HTTP_MATCH_O_EQ,
						    true);
			/*
			 * We don't expect more than one cookie, so we
			 * can immediately return here.
			 */
			if (r > 1)
				return r;
		}
	}

	return r;
}

/*
 * Learn HTTP session created on backend server. Even if the session exists,
 * backend may want to create a new for the client.
 */
int
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
		return -EINVAL;
	sticky = resp->req->vhost->cookie;
	if (!sticky->learn || TFW_STR_EMPTY(&sticky->name_eq))
		return 0;

	r = tfw_http_sticky_get_resp(resp, c_val);
	switch (r) {
	case 0:
		return 0;
	case 1:
		break;
	default:
		T_WARN("Multiple sticky cookies found in response: %d\n", r);
		return -EINVAL;
	}

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
		return 0;
	}
	if (unlikely(c_val->len > STICKY_KEY_MAX_LEN)) {
		T_WARN("http_sess: too long cookie value: %li (%d).\n",
		       c_val->len, STICKY_KEY_MAX_LEN);
		return -EINVAL;
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
		return -ENOMEM;
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
		tdb_rec_put(sess_db, rec);

	return 0;
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

	if (tfw_srv_conn_get_if_live(srv_conn)) {
		if (tfw_srv_conn_suitable_common(srv_conn)
		    && !tfw_srv_conn_hasnip(srv_conn))
			return srv_conn;
		tfw_connection_put((TfwConn *)srv_conn);
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
	 * on multiple cpus, use locking to guarantee that the srv_conn
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
tfw_http_sess_start(void)
{
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
		.deflt = "16M",
		.handler = tfw_cfg_set_mem,
		.dest = &sess_db_cfg.db_size,
		.spec_ext = &(TfwCfgSpecMem) {
			.multiple_of = "4K",
			.range = { "4K", "1G" },
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
	tfw_http_sess_cfgend();
	tfw_mod_unregister(&tfw_http_sess_mod);
}
