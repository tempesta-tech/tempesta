/*
 *		Tempesta FW
 *
 * Handling of Tempesta sticky cookie.
 *
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include <net/tcp.h>
#include <net/inet_common.h>
#include <linux/ctype.h>
#include <linux/time.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#include "addr.h"
#include "cfg.h"
#include "client.h"
#include "http_msg.h"

#define STICKY_NAME_MAXLEN	(32)
#define STICKY_NAME_DEFAULT	"__tfw"
#define STICKY_KEY_MAXLEN	(sizeof(((TfwClient *)0)->cookie.hmac))

/**
 * @name       - name of sticky cookie;
 * @name_eq    - @name plus "=" to make some operations faster;
 */
typedef struct sticky {
	TfwStr		name;
	TfwStr		name_eq;
	u_int		enabled : 1,
			enforce : 1;
} TfwCfgSticky;

static TfwCfgSticky tfw_cfg_sticky;
static struct crypto_shash *tfw_sticky_shash;
static char tfw_sticky_key[STICKY_KEY_MAXLEN];

static int
tfw_http_sticky_send_302(TfwHttpMsg *hm)
{
	TfwConnection *conn = hm->conn;
	TfwClient *client = (TfwClient *)hm->conn->peer;
	TfwStr chunks[3], cookie = { 0 };
	DEFINE_TFW_STR(s_eq, "=");
	TfwHttpMsg resp;
	char buf[sizeof(client->cookie.hmac) * 2];

	tfw_http_prep_hexstring(buf, client->cookie.hmac,
				sizeof(client->cookie.hmac));

	memset(chunks, 0, sizeof(chunks));
	chunks[0] = tfw_cfg_sticky.name;
	chunks[1] = s_eq;
	chunks[2].data = buf;
	chunks[2].len = sizeof(client->cookie.hmac) * 2;

	cookie.chunks = (struct TfwStr *)chunks;
	cookie.len = chunks[0].len + chunks[1].len + chunks[2].len;
	__TFW_STR_CHUNKN_SET(&cookie, 3);

	if (tfw_http_prep_302(&resp, hm, &cookie))
		return -1;
	tfw_cli_conn_send(conn, (TfwMsg *)&resp, true);

	return 0;
}

static int
search_cookie(TfwPool *pool, const TfwStr *cookie, TfwStr *val)
{
	const char *const cstr = tfw_cfg_sticky.name_eq.data;
	const unsigned int clen = tfw_cfg_sticky.name_eq.len;
	TfwStr *chunk, *end, *next;
	TfwStr tmp = { .flags = 0, };
	unsigned int n = TFW_STR_CHUNKN(cookie);

	BUG_ON(!TFW_STR_PLAIN(&tfw_cfg_sticky.name_eq));

	/* Search cookie name. */
	end = (TfwStr*)cookie->chunks + TFW_STR_CHUNKN(cookie);
	for (chunk = ( TfwStr *)cookie->chunks; chunk != end; ++chunk, --n) {
		if (chunk->flags & TFW_STR_NAME) {
			/*
			 * Create temporary compound string, starting
			 * with this chunk.
			 * We do not use it's overall length now,
			 * so do not set it.
			 */
			tmp.chunks = (struct TfwStr *)chunk;
			__TFW_STR_CHUNKN_SET(&tmp, n);
			if (tfw_str_eq_cstr(&tmp, cstr, clen,
					    TFW_STR_EQ_PREFIX))
				break;
		}
	}
	if (chunk == end)
		return 0;

	/* Search cookie value, starting with next chunk. */
	for (++chunk; chunk != end; ++chunk)
		if (chunk->flags & TFW_STR_VALUE)
			break;
	BUG_ON(chunk == end);

	/* Check if value is plain string, just return it in this case. */
	next = chunk + 1;
	if (likely(next == end || *(char *)next->data == ';')) {
		TFW_DBG3("%s: plain cookie value: %.*s\n", __func__,
			 (int)chunk->len, (char *)chunk->data);
		*val = *chunk;
		return 1;
	}

	/* Add value chunks to out-string. */
	TFW_DBG3("%s: compound cookie value found\n", __func__);
	val->chunks = (struct TfwStr *)chunk;
	TFW_STR_CHUNKN_ADD(val, 1);
	val->len = chunk->len;
	for (; chunk != end; ++chunk) {
		if (*(char *)chunk->data == ';')
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
 */
static int
tfw_http_sticky_get(TfwHttpMsg *hm, TfwStr *cookie)
{
	TfwStr value = { 0 };
	TfwStr *hdr;

	/*
	 * Find a 'Cookie:' header field in the request.
	 * Then search for Tempesta sticky cookie within the field.
	 * NOTE: there can be only one "Cookie:" header field.
	 * See RFC 6265 section 5.4.
	 * NOTE: Irrelevant here, but there can be multiple 'Set-Cookie"
	 * header fields as an exception. See RFC 7230 section 3.2.2.
	 * In this case, client merges them into one 'Cookie' header field
	 * in response.
	 */
	hdr = &hm->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
	if (TFW_STR_EMPTY(hdr))
		return 0;
	tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_COOKIE, &value);

	return search_cookie(hm->pool, &value, cookie);
}

/*
 * Create Tempesta sticky cookie value and set it for the client.
 *
 * Tempesta sticky cookie is based on:
 * - HTTP request source IP address;
 * - HTTP request User-Agent string;
 * - Current timestamp;
 */
static int
tfw_http_sticky_set(TfwHttpMsg *hm)
{
	int addr_len;
	TfwStr ua_value = { 0 };
	TfwClient *client = (TfwClient *)hm->conn->peer;
	TfwStr *hdr, *c, *end;

	char desc[sizeof(struct shash_desc)
		  + crypto_shash_descsize(tfw_sticky_shash)]
		  CRYPTO_MINALIGN_ATTR;
	struct shash_desc *shash_desc = (struct shash_desc *)desc;

	/* User-Agent header field is not mandatory and may be missing. */
	hdr = &hm->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT];
	if (!TFW_STR_EMPTY(hdr))
		tfw_http_msg_clnthdr_val(hdr, TFW_HTTP_HDR_USER_AGENT,
					 &ua_value);

	/* Set only once per client's session */
	if (!client->cookie.ts.tv_sec) {
		getnstimeofday(&client->cookie.ts);
	}
	addr_len = tfw_addr_sa_len(&client->addr);

	memset(desc, 0, sizeof(desc));
	shash_desc->tfm = tfw_sticky_shash;
	shash_desc->flags = 0;

	crypto_shash_init(shash_desc);
	crypto_shash_update(shash_desc, (u8 *)&client->addr.sa, addr_len);
	if (ua_value.len) {
		TFW_STR_FOR_EACH_CHUNK(c, &ua_value, end)
			crypto_shash_update(shash_desc, (u8 *)c->data, c->len);
	}
	crypto_shash_finup(shash_desc, (u8 *)&client->cookie.ts,
					sizeof(client->cookie.ts),
					client->cookie.hmac);
	hm->flags |= TFW_HTTP_STICKY_SET;
	return 0;
}

/*
 * Add Tempesta sticky cookie to an HTTP response.
 *
 * Create a complete 'Set-Cookie:' header field, and add it
 * to the HTTP response' header block.
 */
#define S_SET_COOKIE_MAXLEN					\
	SLEN(S_F_SET_COOKIE)					\
	+ STICKY_NAME_MAXLEN + 1 + STICKY_KEY_MAXLEN * 2 + 2

static int
tfw_http_sticky_add(TfwHttpMsg *hmresp, TfwHttpMsg *hmreq)
{
	unsigned int r, len = sizeof(((TfwClient *)0)->cookie.hmac);
	TfwClient *client = (TfwClient *)hmreq->conn->peer;
	char buf[len * 2];
	TfwStr set_cookie = {
		.chunks = (struct TfwStr *)(TfwStr []) {
			{ .data = S_F_SET_COOKIE, .len = SLEN(S_F_SET_COOKIE) },
			{ .data = tfw_cfg_sticky.name_eq.data,
			  .len = tfw_cfg_sticky.name_eq.len },
			{ .data = buf, .len = len * 2 },
			{ .data = "\r\n", .len = 2 }
		},
		.len = SLEN(S_F_SET_COOKIE) + tfw_cfg_sticky.name_eq.len
		       + 2 + len * 2,
		.flags = 4
	};

	tfw_http_prep_hexstring(buf, client->cookie.hmac, len);

	TFW_DBG("%s: \"" S_F_SET_COOKIE "%.*s=%.*s\"\n", __func__,
		PR_TFW_STR(&tfw_cfg_sticky.name), len * 2, buf);

	r = tfw_http_msg_hdr_add(hmresp, &set_cookie);
	if (r)
		TFW_WARN("Cannot add \"" S_F_SET_COOKIE "%.*s=%.*s\"\n",
			 PR_TFW_STR(&tfw_cfg_sticky.name), len * 2, buf);
	return r;
}

/*
 * No Tempesta sticky cookie found.
 *
 * Create Tempesta sticky cookie value, and store it for future use.
 * If configured, enforce Tempesta sticky cookie presence in requests.
 */
static int
tfw_http_sticky_notfound(TfwHttpMsg *hm)
{
	int ret;

	/* Create Tempesta sticky cookie and store it */
	if (tfw_http_sticky_set(hm) != 0)
		return tfw_http_send_502(hm);

	/*
	 * If configured, ensure that backend server receives
	 * requests that always carry Tempesta sticky cookie.
	 * Return an HTTP 302 response to the client that has
	 * the same host, URI, and includes 'Set-Cookie' header.
	 * Otherwise, forward the request to a backend server.
	 */
	if (tfw_cfg_sticky.enforce) {
		if ((ret = tfw_http_sticky_send_302(hm)) != 0) {
			return ret;
		}
		return 1;
	}

	return 0;
}

/*
 * Found Tempesta sticky cookie.
 */
static int
tfw_http_sticky_found(TfwHttpMsg *hm, TfwStr *value)
{
	hm->flags &= ~TFW_HTTP_STICKY_SET;
	/*
	 * Do nothing for now. The request is passed to a backend server.
	 */
	TFW_DBG("Sticky cookie found%s: \"%.*s\"\n",
		TFW_STR_PLAIN(value) ? "" : ", starts with",
		TFW_STR_PLAIN(value) ?
			(int)value->len :
			(int)((TfwStr*)value->chunks)->len,
		TFW_STR_PLAIN(value) ?
			(char*)value->data :
			(char*)((TfwStr*)value->chunks)->data);

	return 0;
}

/*
 * Process Tempesta sticky cookie in an HTTP request.
 */
int
tfw_http_sticky_req_process(TfwHttpMsg *hm)
{
	int ret;
	TfwStr value = { 0 };

	if (!tfw_cfg_sticky.enabled)
		return 0;

	/*
	 * See if the Tempesta sticky cookie is present in the request,
	 * and act depending on the result.
	 */
	ret = tfw_http_sticky_get(hm, &value);
	if (ret < 0) {
		return ret;
	} else if (ret == 0) {
		return tfw_http_sticky_notfound(hm);
	} else if (ret == 1) {
		return tfw_http_sticky_found(hm, &value);
	}
	TFW_WARN("Multiple Tempesta sticky cookies found: %d\n", ret);
	return -1;
}

/*
 * Add Tempesta sticky cookie to an HTTP response if needed.
 */
int
tfw_http_sticky_resp_process(TfwHttpMsg *hmresp, TfwHttpMsg *hmreq)
{
	if (!tfw_cfg_sticky.enabled) {
		return 0;
	}
	if (!(hmreq->flags & TFW_HTTP_STICKY_SET)) {
		return 0;
	}
	return tfw_http_sticky_add(hmresp, hmreq);
}

int __init
tfw_http_sticky_init(void)
{
	int ret;
	u_char *ptr;

	if ((ptr = kzalloc(STICKY_NAME_MAXLEN + 1, GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	tfw_cfg_sticky.name.data = tfw_cfg_sticky.name_eq.data = ptr;
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

	return 0;
}

void
tfw_http_sticky_exit(void)
{
	kfree(tfw_cfg_sticky.name.data);
	memset(&tfw_cfg_sticky, 0, sizeof(tfw_cfg_sticky));
	crypto_free_shash(tfw_sticky_shash);
}

static int
tfw_cfg_sticky_start(void)
{
	tfw_cfg_sticky.enabled = !TFW_STR_EMPTY(&tfw_cfg_sticky.name);

	return 0;
}

static void
tfw_cfg_sticky_stop(void)
{
	tfw_cfg_sticky.enabled = 0;
}

/* THIS IS A COPY OF tfw_cfg_get_attr() FROM FAILOVER BRANCH */
static const char *
tfw_http_sticky_get_attr(const TfwCfgEntry *ce, const char *attr_key,
						const char *dflt_val)
{
	size_t i;
	const char *key, *val;

	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, attr_key)) {
			return val;
		}
	}
	return dflt_val;
}

static int
tfw_http_sticky_cfg(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	size_t i, len;
	const char *val;

	val = tfw_http_sticky_get_attr(ce, "name", STICKY_NAME_DEFAULT);
	len = strlen(val);
	if (len == 0 || len > STICKY_NAME_MAXLEN)
		return -EINVAL;
	memcpy(tfw_cfg_sticky.name.data, val, len);
	tfw_cfg_sticky.name.len = len;
	((char*)tfw_cfg_sticky.name_eq.data)[len] = '=';
	tfw_cfg_sticky.name_eq.len = len + 1;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		 if (!strcasecmp(val, "enforce")) {
			tfw_cfg_sticky.enforce = 1;
			break;
		}
	}

	return 0;
}

TfwCfgMod tfw_http_sticky_cfg_mod = {
	.name = "http_sticky",
	.start = tfw_cfg_sticky_start,
	.stop = tfw_cfg_sticky_stop,
	.specs = (TfwCfgSpec[]) {
		{
			.name = "sticky",
			.deflt = NULL,
			.handler = tfw_http_sticky_cfg,
			.allow_repeat = false,
			.allow_none = true,
			.cleanup = NULL
		},
		{}
	}
};
