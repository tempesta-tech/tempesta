/*
 *              Tempesta FW
 *
 * Handling of Tempesta sticky cookie.
 *
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

typedef struct sticky {
	TfwStr		name;
	u_int		enabled : 1;
	u_int		enforce : 1;
} TfwCfgSticky;

static TfwCfgSticky tfw_cfg_sticky;
static struct crypto_shash *tfw_sticky_shash;
static char tfw_sticky_key[STICKY_KEY_MAXLEN];


static int
tfw_http_sticky_send_302(TfwHttpMsg *hm)
{
	TfwHttpMsg *resp;
	TfwConnection *conn = hm->conn;
	TfwStr chunks[3], cookie = { 0 };
	DEFINE_TFW_STR(s_eq, "=");
	TfwClient *client = (TfwClient *)hm->conn->peer;
	char buf[sizeof(client->cookie.hmac) * 2];

	tfw_http_prep_hexstring(buf, client->cookie.hmac,
				sizeof(client->cookie.hmac));

	memset(chunks, 0, sizeof(chunks));
	chunks[0] = tfw_cfg_sticky.name;
	chunks[1] = s_eq;
	chunks[2].ptr = buf;
	chunks[2].len = sizeof(client->cookie.hmac) * 2;

	cookie.ptr = chunks;
	cookie.len = chunks[0].len + chunks[1].len + chunks[2].len;
	__TFW_STR_CHUNKN_SET(&cookie, 3);

	if ((resp = tfw_http_prep_302(hm, &cookie)) == NULL) {
		return -1;
	}
	tfw_connection_send(conn, (TfwMsg *)resp, true);
	tfw_http_msg_free(resp);

	return 0;
}

/*
 * Find a specific non-special header field in an HTTP message.
 *
 * This function assumes that the header field name is stored
 * in TfwStr{} after an HTTP message is parsed.
 */
static TfwStr *
tfw_http_field_raw(TfwHttpMsg *hm, const char *field_name, size_t len)
{
	int i;

	for (i = TFW_HTTP_HDR_RAW; i < hm->h_tbl->size; i++) {
		TfwStr *hdr_field = &hm->h_tbl->tbl[i];
		if (tfw_str_eq_cstr(hdr_field, field_name, len,
				    TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI))
			return hdr_field;
	}

	return NULL;
}

static int
tfw_http_field_value(TfwHttpMsg *hm, const TfwStr *field_name, TfwStr *value)
{
	char *buf, *ptr;
	size_t len;
	TfwStr *hdr_field;

	hdr_field = tfw_http_field_raw(hm, field_name->ptr, field_name->len);
	if (hdr_field == NULL) {
		return 0;
	}

	if (TFW_STR_PLAIN(hdr_field)) {
		buf = (char *)hdr_field->ptr + field_name->len;
		len = hdr_field->len - field_name->len;

		while (len > 0 && isspace(*buf)) {
			buf++;
			len--;
		}
		while (len > 0 && isspace(*(buf + len - 1)))
			len--;

		value->ptr = buf;
		value->len = len;
		value->flags = hdr_field->flags;
		return 1;
	}

	/* field consists of multiple chunks */
	len = hdr_field->len + 1;
	if ((buf = tfw_pool_alloc(hm->pool, len)) == NULL) {
		return -ENOMEM;
	}
	len = tfw_str_to_cstr(hdr_field, buf, len);
	ptr = strim(buf + field_name->len);
	value->ptr = ptr;
	value->len = len - (ptr - buf);

	return 1;
}

/*
 * Find Tempesta sticky cookie in an HTTP message.
 */
static int
tfw_http_sticky_get(TfwHttpMsg *hm, TfwStr *cookie)
{
	int ret;
	u_char *valptr, *endptr;
	const DEFINE_TFW_STR(s_field_name, "Cookie:");
	TfwStr value = { 0 };

	/*
	 * Find a 'Cookie:' header field in the request.
	 * Then search for Tempesta sticky cookie within the field.
	 * NOTE: there can be only one "Cookie:" header field.
	 * See RFC 6265 section 5.4.
	 * NOTE: Irrelevant here, but there can be multiple 'Set-Cookie"
	 * header fields as an exception. See RFC 7230 section 3.2.2.
	 */
	if ((ret = tfw_http_field_value(hm, &s_field_name, &value)) <= 0) {
		return ret;
	}
	/*
	 * XXX The following code assumes that TfwStr is linear.
	 */
	BUG_ON(!TFW_STR_PLAIN(&value));
	valptr = strnstr(value.ptr, tfw_cfg_sticky.name.ptr, value.len);
	if (!valptr)
		return 0;
	cookie->ptr = valptr + tfw_cfg_sticky.name.len + 1;

	valptr = cookie->ptr;
	endptr = value.ptr + value.len;
	while((valptr < endptr) && (*valptr != ';') && !isspace(*valptr))
		valptr++;
	cookie->len = valptr - (u_char *)cookie->ptr;

	return 1;
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
	int ret, addr_len;
	TfwStr ua_value = { 0 };
	const DEFINE_TFW_STR(s_field_name, "User-Agent:");
	TfwClient *client = (TfwClient *)hm->conn->peer;

	char desc[sizeof(struct shash_desc)
		  + crypto_shash_descsize(tfw_sticky_shash)]
		  CRYPTO_MINALIGN_ATTR;
	struct shash_desc *shash_desc = (struct shash_desc *)desc;

	/*
	 * XXX The code below assumes that ua_value is a linear TfwStr{}
	 */
	/* User-Agent header field is not mandatory and may be missing. */
	if ((ret = tfw_http_field_value(hm, &s_field_name, &ua_value)) < 0) {
		return ret;
	}

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
	if (ua_value.len)
		crypto_shash_update(shash_desc, (u8 *)ua_value.ptr,
						      ua_value.len);
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
#define S_F_SET_COOKIE		"Set-Cookie: "
#define SLEN(s)			(sizeof(s) - 1)

#define S_SET_COOKIE_MAXLEN					\
	SLEN(S_F_SET_COOKIE)					\
	+ STICKY_NAME_MAXLEN + 1 + STICKY_KEY_MAXLEN * 2 + 2

static int
tfw_http_sticky_add(TfwHttpMsg *hmresp, TfwHttpMsg *hmreq)
{
	unsigned int len = sizeof(((TfwClient *)0)->cookie.hmac);
	TfwClient *client = (TfwClient *)hmreq->conn->peer;
	char buf[len * 2];
	TfwStr set_cookie = {
		.ptr = (TfwStr []) {
			{ .ptr = S_F_SET_COOKIE, .len = SLEN(S_F_SET_COOKIE) },
			{ .ptr = tfw_cfg_sticky.name.ptr,
			  .len = tfw_cfg_sticky.name.len },
			{ .ptr = "=", .len = 1 },
			{ .ptr = buf, .len = len * 2 },
			{ .ptr = "\r\n", .len = 2 }
		},
		.len = SLEN(S_F_SET_COOKIE) + tfw_cfg_sticky.name.len
		       + 3 + len * 2,
		.flags = 5 << TFW_STR_CN_SHIFT
	};

	tfw_http_prep_hexstring(buf, client->cookie.hmac, len);

	TFW_DBG("%s: \"" S_F_SET_COOKIE "%.*s=%.*s\"\n", __func__,
		tfw_cfg_sticky.name.len, (char *)tfw_cfg_sticky.name.ptr,
		len * 2, buf);

	return tfw_http_msg_hdr_add(hmresp, &set_cookie);
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
	/* XXX This assumes that 'value' is a linear TfwStr{}. */
	TFW_DBG("Sticky cookie found: \"%.*s\"\n",
		(int)value->len, (char *)value->ptr);

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

	if (!tfw_cfg_sticky.enabled) {
		return 0;
	}
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

	if ((ptr = kzalloc(STICKY_NAME_MAXLEN, GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	tfw_cfg_sticky.name.ptr = ptr;
	tfw_cfg_sticky.name.len = 0;

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
	u_char *ptr = tfw_cfg_sticky.name.ptr;
	memset(&tfw_cfg_sticky, 0, sizeof(tfw_cfg_sticky));
	if (ptr) {
		kfree(ptr);
	}
	crypto_free_shash(tfw_sticky_shash);
}

static int
tfw_cfg_sticky_start(void)
{
	if (tfw_cfg_sticky.name.len) {
		tfw_cfg_sticky.enabled = 1;
	}
	return 0;
}

static void
tfw_cfg_sticky_stop(void)
{
	u_char *ptr = tfw_cfg_sticky.name.ptr;
	memset(&tfw_cfg_sticky, 0, sizeof(tfw_cfg_sticky));
	tfw_cfg_sticky.name.ptr = ptr;
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
	if ((len == 0) || (len > STICKY_NAME_MAXLEN))
		return -EINVAL;
	memcpy(tfw_cfg_sticky.name.ptr, val, len);
	tfw_cfg_sticky.name.len = len;

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

