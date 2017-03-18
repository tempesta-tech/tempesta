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
 * The same human client can use differnt browsers, so they send different
 * User-Agent headers and use different sticky cookies. X-Forwarded-For header
 * value can be used to cope the non anonymous forward proxy problem and
 * identify real clients.
 *
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/time.h>

#include "addr.h"
#include "cfg.h"
#include "client.h"
#include "hash.h"
#include "http_msg.h"

#define STICKY_NAME_MAXLEN	(32)
#define STICKY_NAME_DEFAULT	"__tfw"
#define STICKY_KEY_MAXLEN	FIELD_SIZEOF(TfwHttpSess, hmac)

#define SESS_HASH_BITS		17
#define SESS_HASH_SZ		(1 << SESS_HASH_BITS)

/**
 * @name		- name of sticky cookie;
 * @name_eq		- @name plus "=" to make some operations faster;
 * @sess_lifetime	- sesscion lifetime in seconds;
 */
typedef struct {
	TfwStr		name;
	TfwStr		name_eq;
	unsigned int	sess_lifetime;
	u_int		enabled : 1,
			enforce : 1;
} TfwCfgSticky;

/**
 * Temporal storage for calculated sticky cookie values.
 */
typedef struct {
	unsigned long	ts;
	unsigned char	hmac[STICKY_KEY_MAXLEN];
} __attribute__((packed)) StickyVal;

typedef struct {
	struct hlist_head	list;
	spinlock_t		lock;
} SessHashBucket;

static TfwCfgSticky tfw_cfg_sticky;
/* Secret server value to genrate reliable client identifiers. */
static struct crypto_shash *tfw_sticky_shash;
static char tfw_sticky_key[STICKY_KEY_MAXLEN];

SessHashBucket sess_hash[SESS_HASH_SZ] = {
	[0 ... (SESS_HASH_SZ - 1)] = {
		HLIST_HEAD_INIT,
	}
};

static struct kmem_cache *sess_cache;

static int
tfw_http_sticky_send_302(TfwHttpReq *req, StickyVal *sv)
{
	unsigned long ts_be64 = cpu_to_be64(sv->ts);
	TfwStr chunks[3], cookie = { 0 };
	DEFINE_TFW_STR(s_eq, "=");
	TfwHttpMsg *hmresp;
	char buf[sizeof(*sv) * 2];

	if (!(hmresp = tfw_http_msg_alloc(Conn_Srv)))
		return -ENOMEM;
	/*
	 * Form the cookie as:
	 *
	 * 	<timestamp> | HMAC(Secret, User-Agent, timestamp, Client IP)
	 *
	 * Open <timestamp> is required to be able to recalculate secret HMAC.
	 * Since the secret is unknown for the attacke, they're still unable to
	 * recalculate HMAC while we don't need to store session information
	 * until we receive correct cookie value.
	 */
	bin2hex(buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[sizeof(ts_be64) * 2], sv->hmac, sizeof(sv->hmac));

	memset(chunks, 0, sizeof(chunks));
	chunks[0] = tfw_cfg_sticky.name;
	chunks[1] = s_eq;
	chunks[2].ptr = buf;
	chunks[2].len = sizeof(*sv) * 2;

	cookie.ptr = chunks;
	cookie.len = chunks[0].len + chunks[1].len + chunks[2].len;
	__TFW_STR_CHUNKN_SET(&cookie, 3);

	if (tfw_http_prep_302(hmresp, req, &cookie))
		return -1;

	tfw_http_resp_fwd(req, (TfwHttpResp *)hmresp);

	return 0;
}

static int
search_cookie(TfwPool *pool, const TfwStr *cookie, TfwStr *val)
{
	const char *const cstr = tfw_cfg_sticky.name_eq.ptr;
	const unsigned int clen = tfw_cfg_sticky.name_eq.len;
	TfwStr *chunk, *end, *next;
	TfwStr tmp = { .flags = 0, };
	unsigned int n = TFW_STR_CHUNKN(cookie);

	BUG_ON(!TFW_STR_PLAIN(&tfw_cfg_sticky.name_eq));

	/* Search cookie name. */
	end = (TfwStr*)cookie->ptr + TFW_STR_CHUNKN(cookie);
	for (chunk = cookie->ptr; chunk != end; ++chunk, --n) {
		if (!(chunk->flags & TFW_STR_NAME))
			continue;
		/*
		 * Create a temporary compound string, starting with this
		 * chunk. The total string length is not used here, so it
		 * is not set.
		 */
		tmp.ptr = (void *)chunk;
		__TFW_STR_CHUNKN_SET(&tmp, n);
		if (tfw_str_eq_cstr(&tmp, cstr, clen, TFW_STR_EQ_PREFIX))
			break;
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

	/* Check if value is plain string, just return it in this case. */
	next = chunk + 1;
	if (likely(next == end || *(char *)next->ptr == ';')) {
		TFW_DBG3("%s: plain cookie value: %.*s\n", __func__,
			 (int)chunk->len, (char *)chunk->ptr);
		*val = *chunk;
		return 1;
	}

	/* Add value chunks to out-string. */
	TFW_DBG3("%s: compound cookie value found\n", __func__);
	val->ptr = chunk;
	TFW_STR_CHUNKN_ADD(val, 1);
	val->len = chunk->len;
	for (; chunk != end; ++chunk) {
		if (*(char *)chunk->ptr == ';')
			/* value chunks exhausted */
			break;
		TFW_STR_CHUNKN_ADD(val, 1);
		val->len += chunk->len;
	}
	BUG_ON(TFW_STR_CHUNKN(val) < 2);

	return 1;
}

/*
 * Find Tempesta sticky cookie in an HTTP message.
 *
 * Return 1 if the cookie is found.
 * Return 0 if the cookie is NOT found.
 */
static int
tfw_http_sticky_get(TfwHttpReq *req, TfwStr *cookie_val)
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

	return search_cookie(req->pool, &value, cookie_val);
}

#ifdef DEBUG
#define TFW_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)			\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	char hbuf[STICKY_KEY_MAXLEN * 2] = {0};				\
	tfw_addr_fmt_v6(&(addr)->v6.sin6_addr, 0, abuf);		\
	bin2hex(hbuf, tfw_sticky_key, STICKY_KEY_MAXLEN);		\
	TFW_DBG("http_sess: calculate sticky cookie for %s,"		\
		" ts=%#lx(now=%#lx)...\n", abuf, (sv)->ts, jiffies);	\
	TFW_DBG("\t...secret: %.*s\n", (int)STICKY_KEY_MAXLEN * 2, hbuf);\
	tfw_str_dprint(ua, "\t...User-Agent");				\
} while (0)
#else
#define TFW_DBG_PRINT_STICKY_COOKIE(addr, ua, sv)
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
	int r, addr_len;
	TfwStr ua_value = { 0 };
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *hdr, *c, *end;
	char desc[sizeof(struct shash_desc)
		  + crypto_shash_descsize(tfw_sticky_shash)]
		  CRYPTO_MINALIGN_ATTR;
	struct shash_desc *shash_desc = (struct shash_desc *)desc;

	/* User-Agent header field is not mandatory and may be missing. */
	hdr = &req->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT];
	if (!TFW_STR_EMPTY(hdr))
		tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_USER_AGENT,
					 &ua_value);

	addr_len = tfw_addr_sa_len(addr);

	memset(desc, 0, sizeof(desc));
	shash_desc->tfm = tfw_sticky_shash;
	shash_desc->flags = 0;

	TFW_DBG_PRINT_STICKY_COOKIE(addr, &ua_value, sv);

	if ((r = crypto_shash_init(shash_desc)))
		return r;
	if ((r = crypto_shash_update(shash_desc, (u8 *)&addr->sa, addr_len)))
		return r;
	if (ua_value.len) {
		TFW_STR_FOR_EACH_CHUNK(c, &ua_value, end) {
			r = crypto_shash_update(shash_desc, c->ptr, c->len);
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
tfw_http_sticky_add(TfwHttpResp *resp, TfwHttpReq *req)
{
	static const unsigned int len = sizeof(StickyVal) * 2;
	unsigned int r;
	TfwHttpSess *sess = req->sess;
	unsigned long ts_be64 = cpu_to_be64(sess->ts);
	char buf[len];
	TfwStr set_cookie = {
		.ptr = (TfwStr []) {
			{ .ptr = S_F_SET_COOKIE, .len = SLEN(S_F_SET_COOKIE) },
			{ .ptr = tfw_cfg_sticky.name_eq.ptr,
			  .len = tfw_cfg_sticky.name_eq.len },
			{ .ptr = buf, .len = len },
		},
		.len = SLEN(S_F_SET_COOKIE) + tfw_cfg_sticky.name_eq.len + len,
		.eolen = 2,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	/* See comment from tfw_http_sticky_send_302(). */
	bin2hex(buf, &ts_be64, sizeof(ts_be64));
	bin2hex(&buf[sizeof(ts_be64) * 2], sess->hmac, sizeof(sess->hmac));

	TFW_DBG("%s: \"" S_F_SET_COOKIE "%.*s=%.*s\"\n", __func__,
		PR_TFW_STR(&tfw_cfg_sticky.name), len, buf);

	r = tfw_http_msg_hdr_add((TfwHttpMsg *)resp, &set_cookie);
	if (r)
		TFW_WARN("Cannot add \"" S_F_SET_COOKIE "%.*s=%.*s\"\n",
			 PR_TFW_STR(&tfw_cfg_sticky.name), len, buf);
	return r;
}

/*
 * No Tempesta sticky cookie found.
 *
 * Calculate Tempesta sticky cookie and send redirection to the client if
 * enforcement is configured. Since the client can be malicious, we don't
 * store anything for now. HTTP session will be created when the client
 * is successfully solves the cookie challenge.
 */
static int
tfw_http_sticky_notfound(TfwHttpReq *req)
{
	int r;
	StickyVal sv = {};

	/*
	 * If configured, ensure that backend server receives
	 * requests that always carry Tempesta sticky cookie.
	 * Return an HTTP 302 response to the client that has
	 * the same host, URI, and includes 'Set-Cookie' header.
	 * Otherwise, forward the request to a backend server.
	 */
	if (!tfw_cfg_sticky.enforce)
		return 0;

	/* Create Tempesta sticky cookie and store it */
	if (tfw_http_sticky_calc(req, &sv) != 0)
		return -1;

	r = tfw_http_sticky_send_302(req, &sv);

	return r ? : 1;
}

#define sess_warn(check, addr, fmt, ...)				\
do {									\
	char abuf[TFW_ADDR_STR_BUF_SIZE] = {0};				\
	tfw_addr_fmt_v6(&(addr)->v6.sin6_addr, 0, abuf);		\
	TFW_WARN("http_sess: %s for %s" fmt, check, abuf, ##__VA_ARGS__); \
} while (0)

/**
 * Verify found Tempesta sticky cookie.
 */
static int
tfw_http_sticky_verify(TfwHttpReq *req, TfwStr *value, StickyVal *sv)
{
	int i = 0, hi;
	unsigned char *p, b;
	TfwAddr *addr = &req->conn->peer->addr;
	TfwStr *c, *end;

	TFW_DBG("Sticky cookie found%s: \"%.*s\"\n",
		TFW_STR_PLAIN(value) ? "" : ", starts with",
		TFW_STR_PLAIN(value) ?
			(int)value->len :
			(int)((TfwStr*)value->ptr)->len,
		TFW_STR_PLAIN(value) ?
			(char*)value->ptr :
			(char*)((TfwStr*)value->ptr)->ptr);

	if (value->len != sizeof(StickyVal) * 2) {
		sess_warn("bad sticky cookie length", addr, ": %lu(%lu)\n",
			  value->len, sizeof(StickyVal) * 2);
		return TFW_BLOCK;
	}

	TFW_STR_FOR_EACH_CHUNK(c, value, end) {
		for (p = c->ptr; p < (unsigned char *)c->ptr + c->len; ++p) {
			if (i++ == sizeof(sv->ts) * 2)
				goto ts_finished;
			sv->ts = (sv->ts << 4) + hex_to_bin(*p);
		}
	}
ts_finished:

	if (__sticky_calc(req, sv))
		return TFW_BLOCK;
	for (i = 0, hi = 1; (c) < end; ++(c)) {
		for ( ; p < (unsigned char *)c->ptr + c->len; ++p) {
			b = hi ? hex_asc_hi(sv->hmac[i])
			       : hex_asc_lo(sv->hmac[i]);
			if (b != *p) {
				int n = sizeof(sv->hmac) * 2;
				char buf[n];
				bin2hex(buf, sv->hmac, sizeof(sv->hmac));
				sess_warn("bad sticky cookie value",
					  addr, ": %c(pos=%d),"
					  " ts=%#lx orig_hmac=[%.*s]\n",
					  *p, i, sv->ts, n, buf);
				return TFW_BLOCK;
			}
			hi = !hi;
			i += hi;
		}
	}
	BUG_ON(i != STICKY_KEY_MAXLEN);

	/* Sticky cookie is found and verified, now we can set the flag. */
	req->flags |= TFW_HTTP_HAS_STICKY;

	return TFW_PASS;
}

/*
 * Process Tempesta sticky cookie in an HTTP request.
 */
static int
tfw_http_sticky_req_process(TfwHttpReq *req, StickyVal *sv)
{
	int r;
	TfwStr cookie_val = {};

	/*
	 * See if the Tempesta sticky cookie is present in the request,
	 * and act depending on the result.
	 */
	r = tfw_http_sticky_get(req, &cookie_val);
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
		if (tfw_http_sticky_verify(req, &cookie_val, sv))
			return tfw_http_sticky_send_302(req, sv) ? : 1;
		return 0;
	}
	TFW_WARN("Multiple Tempesta sticky cookies found: %d\n", r);

	return -1;
}

/*
 * Add Tempesta sticky cookie to an HTTP response if needed.
 */
int
tfw_http_sess_resp_process(TfwHttpResp *resp, TfwHttpReq *req)
{
	if (!tfw_cfg_sticky.enabled)
		return 0;
	BUG_ON(!req->sess);

	/*
	 * RFC 6265 4.1.1 and 4.1.2 says that we should not set session cookie
	 * if it's not necessary. Since client didn't send up the cookie and
	 * it seems that we don't enforce them, we can just set the cookie in
	 * each response forwarded to the client.
	 */
	if (req->flags & TFW_HTTP_HAS_STICKY)
		return 0;
	return tfw_http_sticky_add(resp, req);
}

void
tfw_http_sess_put(TfwHttpSess *sess)
{
	if (atomic_dec_and_test(&sess->users))
		/*
		 * Use counter reached 0, so session already expired and evicted
		 * from the hash table.
		 */
		kmem_cache_free(sess_cache, sess);
}

/**
 * Obtains appropriate HTTP session for the request based on Sticky cookies.
 */
int
tfw_http_sess_obtain(TfwHttpReq *req)
{
	int r;
	unsigned long key = 0, crc_tmp = 0;
	TfwHttpSess *sess;
	SessHashBucket *hb;
	struct hlist_node *tmp;
	StickyVal sv = { };

	if (!tfw_cfg_sticky.enabled)
		return 0;

	if ((r = tfw_http_sticky_req_process(req, &sv)))
		return r;

	/*
	 * Sticky cookie can be not enforced and we still have to allocate new
	 * session for requests w/o session cookie. It means that malicious user
	 * can always send us requests w/o session cookie. HMAC will be
	 * different due to different ingress timestamps, so DoS is very
	 * possible. The only thing which we can do is to enforce the cookie.
	 * However, we cal loose innocent clients w/ disabled cookies.
	 * We leave this for administrator decision or more progressive DDoS
	 * mitigation techniques.
	 */

	if (!sv.ts) {
		/* No sticky cookie in request and no enforcement. */
		if (tfw_http_sticky_calc(req, &sv))
			return -1;
	}

	__tdb_hash_calc(&key, &crc_tmp, sv.hmac, sizeof(sv.hmac));
	key |= crc_tmp << 32;

	hb = &sess_hash[hash_min(key, SESS_HASH_BITS)];

	spin_lock(&hb->lock);

	hlist_for_each_entry_safe(sess, tmp, &hb->list, hentry) {
		/* Collect garbage first to not to return expired session. */
		if (sess->expires < jiffies) {
			hash_del(&sess->hentry);
			tfw_http_sess_put(sess);
		}

		if (!memcmp(sv.hmac, sess->hmac, sizeof(sess->hmac)))
			goto found;
	}

	if (!(sess = kmem_cache_alloc(sess_cache, GFP_ATOMIC))) {
		spin_unlock(&hb->lock);
		return -ENOMEM;
	}

	memcpy(sess->hmac, sv.hmac, sizeof(sv.hmac));
	hlist_add_head(&sess->hentry, &hb->list);
	/*
	 * Sessions are removed by the garbage collection above, so the hash
	 * table is initial user of the session plus to the function caller.
	 */
	atomic_set(&sess->users, 1);
	sess->ts = sv.ts;
	sess->expires = tfw_cfg_sticky.sess_lifetime
			? sv.ts + tfw_cfg_sticky.sess_lifetime * HZ
			: 0;
	sess->srv_conn = NULL; /* TODO #593 not scheduled yet */

	TFW_DBG("new session %p\n", sess);

found:
	atomic_inc(&sess->users);

	spin_unlock(&hb->lock);

	req->sess = sess;

	return 0;
}

int __init
tfw_http_sess_init(void)
{
	int ret, i;
	u_char *ptr;

	if ((ptr = kzalloc(STICKY_NAME_MAXLEN + 1, GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	tfw_cfg_sticky.name.ptr = tfw_cfg_sticky.name_eq.ptr = ptr;
	tfw_cfg_sticky.name.len = tfw_cfg_sticky.name_eq.len = 0;

	tfw_sticky_shash = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(tfw_sticky_shash)) {
		pr_err("shash allocation failed\n");
		return  PTR_ERR(tfw_sticky_shash);
	}

	get_random_bytes(tfw_sticky_key, sizeof(tfw_sticky_key));
	ret = crypto_shash_setkey(tfw_sticky_shash,
				  (u8 *)tfw_sticky_key,
				  sizeof(tfw_sticky_key));
	if (ret) {
		crypto_free_shash(tfw_sticky_shash);
		return ret;
	}

	sess_cache = kmem_cache_create("tfw_sess_cache", sizeof(TfwHttpSess),
				       0, 0, NULL);
	if (!sess_cache) {
		crypto_free_shash(tfw_sticky_shash);
		return -ENOMEM;
	}

	/*
	 * Dynamically initialize hash table spinlocks to avoid lockdep leakage
	 * (see Troubleshooting in Documentation/locking/lockdep-design.txt).
	 */
	for (i = 0; i < SESS_HASH_SZ; ++i)
		spin_lock_init(&sess_hash[i].lock);

	return 0;
}

void
tfw_http_sess_exit(void)
{
	int i;

	for (i = 0; i < SESS_HASH_SZ; ++i) {
		TfwHttpSess *s;
		struct hlist_node *tmp;
		SessHashBucket *hb = &sess_hash[i];

		hlist_for_each_entry_safe(s, tmp, &hb->list, hentry) {
			hash_del(&s->hentry);
			kmem_cache_free(sess_cache, s);
		}
	}
	kmem_cache_destroy(sess_cache);

	kfree(tfw_cfg_sticky.name.ptr);
	memset(&tfw_cfg_sticky, 0, sizeof(tfw_cfg_sticky));
	crypto_free_shash(tfw_sticky_shash);
}

static int
tfw_cfg_sess_start(void)
{
	tfw_cfg_sticky.enabled = !TFW_STR_EMPTY(&tfw_cfg_sticky.name);

	return 0;
}

static void
tfw_cfg_sess_stop(void)
{
	tfw_cfg_sticky.enabled = 0;
}

static int
tfw_http_sticky_cfg(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i, len;
	const char *val;

	val = tfw_cfg_get_attr(ce, "name", STICKY_NAME_DEFAULT);
	len = strlen(val);
	if (len == 0 || len > STICKY_NAME_MAXLEN)
		return -EINVAL;
	memcpy(tfw_cfg_sticky.name.ptr, val, len);
	tfw_cfg_sticky.name.len = len;
	((char*)tfw_cfg_sticky.name_eq.ptr)[len] = '=';
	tfw_cfg_sticky.name_eq.len = len + 1;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		 if (!strcasecmp(val, "enforce")) {
			tfw_cfg_sticky.enforce = 1;
			break;
		}
	}

	return 0;
}

static int
tfw_http_sticky_secret_cfg(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r, len = strlen(ce->vals[0]);

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;
	if (len > STICKY_KEY_MAXLEN)
		return -EINVAL;

	memset(tfw_sticky_key, 0, STICKY_KEY_MAXLEN);
	memcpy(tfw_sticky_key, ce->vals[0], len);
	r = crypto_shash_setkey(tfw_sticky_shash, (u8 *)tfw_sticky_key, len);
	if (r) {
		crypto_free_shash(tfw_sticky_shash);
		return r;
	}
	return 0;
}

static int
tfw_http_sticky_sess_lifetime_cfg(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r = tfw_cfg_set_int(cs, ce);

	/* @sess_lifetime value of 0 means unlimited. */
	if (!r && !tfw_cfg_sticky.sess_lifetime)
		tfw_cfg_sticky.sess_lifetime = UINT_MAX;

	return r;
}

TfwCfgMod tfw_http_sess_cfg_mod = {
	.name = "http_sticky",
	.start = tfw_cfg_sess_start,
	.stop = tfw_cfg_sess_stop,
	.specs = (TfwCfgSpec[]) {
		{
			.name = "sticky",
			.handler = tfw_http_sticky_cfg,
			.allow_none = true,
		},
		{
			.name = "sticky_secret",
			.handler = tfw_http_sticky_secret_cfg,
			.allow_none = true,
		},
		{
			/* Value is parsed as int, set max to INT_MAX*/
			.name = "sess_lifetime",
			.deflt = "0",
			.handler = tfw_http_sticky_sess_lifetime_cfg,
			.dest = &tfw_cfg_sticky.sess_lifetime,
			.spec_ext = &(TfwCfgSpecInt) {
				.range = { 0, INT_MAX },
			},
			.allow_none = true,
		},
		{ 0 }
	}
};
