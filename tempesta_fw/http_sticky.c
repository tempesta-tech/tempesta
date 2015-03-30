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
#include <linux/ctype.h>
#include <linux/time.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include "cfg.h"
#include "client.h"
#include "http.h"
#include "http_msg.h"

typedef struct tfw_str {
	u_char	*ptr;
	size_t	 len;
} tfw_str_t;

typedef struct sticky {
	tfw_str_t	name;
	u_int		enabled : 1;
	u_int		enforce : 1;
} TfwCfgSticky;

#define STICKY_NAME_MAX		(32)
#define STICKY_DFLT_KEY		"Tempesta FW Default Key"

#define tfw_string(v)		{ (v), sizeof(v) - 1 }

TfwCfgSticky tfw_cfg_sticky;
static struct crypto_shash *tfw_sticky_shash;

/*
 * Build a Tempesta HTTP message from pieces of data.
 *
 * The functions tfw_http_msg_setup() and tfw_http_msg_add_data()
 * are designed to work together. The objective is to avoid error
 * processing when putting stream data in the SKBs piece by piece.
 *
 * Errors may be returned by memory allocation functions,
 * so that part is done in tfw_http_msg_setup(). Given the total
 * HTTP message length, it allocates an appropriate number of SKBs
 * and page fragments to hold the payload, and sets them up in
 * a Tempesta message.
 *
 * The SKBs are created complely headerless. The linear part of
 * SKBs is set apart for headers, and stream data is placed in
 * paged fragments. Lower layers will take care of prepending
 * all necessary headers.
 *
 * tfw_http_msg_add_data() adds a piece of data to the message,
 * forming a data stream piece by piece. All memory for the data
 * has been allocated and set up by tfw_http_msg_setup(), so any
 * errors that we may get are considered critical.
 *
 * State is kept between calls to these functions to facilitate
 * quick access to current SKB and page fragment. State is passed
 * and updated on each call to these functions.
 */
typedef struct tfw_msg_add_state {
	struct sk_buff *skb;
	unsigned int	fragnum;
} tfw_mastate_t;

static void
tfw_http_msg_add_data(tfw_mastate_t *state, TfwMsg *msg, char *data, size_t len)
{
	skb_frag_t *frag;
	struct sk_buff *skb = state->skb;
	unsigned int i_frag = state->fragnum;
	size_t copy_size, page_offset, data_offset = 0;

	BUG_ON(skb == NULL);
	BUG_ON(i_frag >= MAX_SKB_FRAGS);

	while (len) {
		if (i_frag >= MAX_SKB_FRAGS) {
			skb = ss_skb_next(&msg->skb_list, skb);
			state->skb = skb;
			state->fragnum = 0;
			i_frag = 0;
			BUG_ON(skb == NULL);
		}
		for (; len && (i_frag < MAX_SKB_FRAGS); i_frag++) {
			frag = &skb_shinfo(skb)->frags[i_frag];
			page_offset = skb_frag_size(frag);
			copy_size = min(len, PAGE_SIZE - page_offset);
			memcpy(page_address(frag->page.p) + page_offset,
			       data + data_offset, copy_size);
			skb_frag_size_add(frag, copy_size);
			data_offset += copy_size;
			len -= copy_size;
		}
		/*
		 * The above for() loop runs at least once,
		 * which means that i_frags is always incremented.
		 */
		state->fragnum = i_frag - 1;
	}
	/* In the end, data_offset equals the initial len value */
	skb->len += data_offset;
	skb->data_len += data_offset;
}

static int
tfw_http_msg_setup(tfw_mastate_t *state, TfwMsg *msg, size_t len)
{
	struct page *page;
	struct sk_buff *skb;
	int i_frag, i_skb, nr_skb_frags;
	int nr_frags = DIV_ROUND_UP(len, PAGE_SIZE);
	int nr_skbs = DIV_ROUND_UP(nr_frags, MAX_SKB_FRAGS);

	/*
	 * TODO: Make sure to create SKBs with payload size <= MSS
	 */
	for (i_skb = 0; i_skb < nr_skbs; i_skb++) {
		if ((skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC)) == NULL) {
			return -ENOMEM;
		}
		skb_reserve(skb, MAX_TCP_HEADER);
		ss_skb_queue_tail(&msg->skb_list, skb);

		nr_skb_frags = min_t(size_t, nr_frags, MAX_SKB_FRAGS);
		for (i_frag = 0; i_frag < nr_skb_frags; i_frag++) {
			if ((page = alloc_page(GFP_ATOMIC)) == NULL) {
				return -ENOMEM;
			}
			get_page(page);
			skb_fill_page_desc(skb, i_frag, page, 0, 0);
			skb->truesize += PAGE_SIZE;
			skb_shinfo(skb)->nr_frags++;
		}
		nr_frags -= nr_skb_frags;
	}
	/* Set up initial state */
	state->skb = ss_skb_peek(&msg->skb_list);
	state->fragnum = 0;

	return 0;
}

#define S_CRLF		"\r\n"
#define S_CRLFCRLF	"\r\n\r\n"
#define S_HTTP		"http://"

#define S_302		"HTTP/1.1 302 Found"
#define S_502		"HTTP/1.1 502 Bad Gateway"

#define S_F_HOST		"Host: "
#define S_F_DATE		"Date: "
#define S_F_CONTENT_LENGTH	"Content-Length: "
#define S_F_LOCATION		"Location: "
#define S_F_CONNECTION		"Connection: "
#define S_F_SET_COOKIE		"Set-Cookie: "

#define S_V_DATE		"Sun, 06 Nov 1994 08:49:37 GMT"
#define S_V_CONTENT_LENGTH	"9999"

#define SLEN(s)		(sizeof(s) - 1)

#define	S_302_FIXLEN							\
	SLEN(S_302)							\
	+ SLEN(S_CRLF)							\
	+ SLEN(S_F_DATE) + SLEN(S_V_DATE)				\
	+ SLEN(S_CRLF)							\
	+ SLEN(S_F_CONTENT_LENGTH) + SLEN(S_V_CONTENT_LENGTH)		\
	+ SLEN(S_CRLF)							\
	+ SLEN(S_F_LOCATION) + SLEN(S_HTTP)				\
	+ SLEN(S_CRLF)							\
	+ SLEN(S_F_SET_COOKIE)						\
	+ SLEN(S_CRLFCRLF)

static size_t
tfw_http_prep_date(u_char *buf)
{
	/* TODO: put in the current date stamp */
	memcpy(buf, S_V_DATE, SLEN(S_V_DATE));
	return SLEN(S_V_DATE);
}

static size_t
tfw_http_prep_sticky(u_char *buf, u_char *value, size_t len)
{
	u_char *ptr = buf;

	while (len--) {
		snprintf(ptr, 100, "%02x", (*value++ & 0x0FF));
		ptr += 2;
	}
	return (ptr - buf);
}

/*
 * Send an HTTP 302 response to the client. The response redirects
 * the client to the same URI as the original request, but includes
 * 'Set-Cookie:' header field that sets Tempesta sticky cookie.
 */
static int
tfw_http_send_302(TfwHttpMsg *hm)
{
	u_char buf[256];
	TfwMsg *msg;
	TfwStr *chunk;
	TfwHttpResp *resp;
	tfw_mastate_t state = { 0 };
	TfwHttpReq *req = (TfwHttpReq *)hm;
	size_t len, data_len = S_302_FIXLEN;
	TfwConnection *conn = hm->conn;
	TfwClient *client = (TfwClient *)conn->peer;

	if (client->cookie.len == 0) {
		return -1;
	}
	if ((resp = (TfwHttpResp *) tfw_http_msg_alloc(Conn_Srv)) == NULL) {
		return -1;
	}
	msg = (TfwMsg *)resp;
	data_len += req->uri_path.len
		    + tfw_cfg_sticky.name.len + 1 + sizeof(client->hmac) * 2;
	if (req->host.len) {
		data_len += req->host.len;
	} else {
		data_len += hm->h_tbl->tbl[TFW_HTTP_HDR_HOST].field.len;
	}

	if (tfw_http_msg_setup(&state, msg, data_len) != 0) {
		tfw_http_msg_free((TfwHttpMsg *)resp);
		return -1;
	}

	tfw_http_msg_add_data(&state, msg, S_302, SLEN(S_302));
	tfw_http_msg_add_data(&state, msg, S_CRLF, SLEN(S_CRLF));

	tfw_http_msg_add_data(&state, msg, S_F_DATE, SLEN(S_F_DATE));
	len = tfw_http_prep_date(buf);
	tfw_http_msg_add_data(&state, msg, buf, len);
	tfw_http_msg_add_data(&state, msg, S_CRLF, SLEN(S_CRLF));

	tfw_http_msg_add_data(&state, msg, S_F_CONTENT_LENGTH,
					   SLEN(S_F_CONTENT_LENGTH));
	tfw_http_msg_add_data(&state, msg, "0", 1);
	tfw_http_msg_add_data(&state, msg, S_CRLF, SLEN(S_CRLF));

	tfw_http_msg_add_data(&state, msg, S_F_LOCATION, SLEN(S_F_LOCATION));
	tfw_http_msg_add_data(&state, msg, S_HTTP, SLEN(S_HTTP));
	if (req->host.len) {
		TFW_STR_FOR_EACH_CHUNK(chunk, &req->host) {
			tfw_http_msg_add_data(&state, msg, chunk->ptr,
							   chunk->len);
		}
	} else {
		TfwStr *hdr = &hm->h_tbl->tbl[TFW_HTTP_HDR_HOST].field;
		/*
		 * HOST is a special header in Tempesta, and it should not
		 * contain the actual "Host: " prefix. But it does now.
		 * Work around it.
		 */
		if (TFW_STR_IS_PLAIN(hdr)) {
			tfw_http_msg_add_data(&state, msg,
					      hdr->ptr + SLEN(S_F_HOST),
					      hdr->len - SLEN(S_F_HOST));
		} else  {
			/*
			 * Per RFC 1035, 2181, max length of FQDN is 255.
			 * What if it is UTF-8 encoded?
			 */
			tfw_str_to_cstr(hdr + SLEN(S_F_HOST),
					buf, hdr->len - SLEN(S_F_HOST));
			tfw_http_msg_add_data(&state, msg, buf,
					      hdr->len - SLEN(S_F_HOST));
		}
	}
	TFW_STR_FOR_EACH_CHUNK(chunk, &req->uri_path) {
		tfw_http_msg_add_data(&state, msg, chunk->ptr, chunk->len);
	}
	tfw_http_msg_add_data(&state, msg, S_CRLF, SLEN(S_CRLF));

	tfw_http_msg_add_data(&state, msg, S_F_SET_COOKIE,
					   SLEN(S_F_SET_COOKIE));
	tfw_http_msg_add_data(&state, msg, tfw_cfg_sticky.name.ptr,
					   tfw_cfg_sticky.name.len);
	tfw_http_msg_add_data(&state, msg, "=", 1);
	len = tfw_http_prep_sticky(buf, client->hmac, sizeof(client->hmac));
	tfw_http_msg_add_data(&state, msg, buf, len);
	tfw_http_msg_add_data(&state, msg, S_CRLFCRLF, SLEN(S_CRLFCRLF));

bh_unlock_sock(client->sock); /* TEMPORARY TO SEE IT WORKING */
	tfw_connection_send_cli(conn, (TfwMsg *)resp);
	tfw_http_msg_free((TfwHttpMsg *)resp);

	return 0;
}

#define	S_502_FIXLEN							\
	SLEN(S_502)							\
	+ SLEN(S_CRLF)							\
	+ SLEN(S_F_DATE) + SLEN(S_V_DATE)				\
	+ SLEN(S_CRLF)							\
	+ SLEN(S_F_CONTENT_LENGTH) + SLEN(S_V_CONTENT_LENGTH)		\
	+ SLEN(S_CRLFCRLF)
/*
 * Send an HTTP 502 response to the client. It tells the client that
 * Tempesta is unable to forward the request to the designated server.
 */
int
tfw_http_send_502(TfwHttpMsg *hm)
{
	u_char buf[256];
	TfwMsg *msg;
	TfwHttpResp *resp;
	tfw_mastate_t state = { 0 };
	size_t len, data_len = S_502_FIXLEN;
	TfwConnection *conn = hm->conn;

	if ((resp = (TfwHttpResp *) tfw_http_msg_alloc(Conn_Srv)) == NULL) {
		return -1;
	}
	msg = (TfwMsg *)resp;

	if (tfw_http_msg_setup(&state, msg, data_len) != 0) {
		tfw_http_msg_free((TfwHttpMsg *)resp);
		return -1;
	}

	tfw_http_msg_add_data(&state, msg, S_502, SLEN(S_502));
	tfw_http_msg_add_data(&state, msg, S_CRLF, SLEN(S_CRLF));

	tfw_http_msg_add_data(&state, msg, S_F_DATE, SLEN(S_F_DATE));
	len = tfw_http_prep_date(buf);
	tfw_http_msg_add_data(&state, msg, buf, len);
	tfw_http_msg_add_data(&state, msg, S_CRLF, SLEN(S_CRLF));

	tfw_http_msg_add_data(&state, msg, S_F_CONTENT_LENGTH,
					   SLEN(S_F_CONTENT_LENGTH));
	tfw_http_msg_add_data(&state, msg, "0", 1);
	tfw_http_msg_add_data(&state, msg, S_CRLFCRLF, SLEN(S_CRLFCRLF));

	tfw_connection_send_cli(conn, (TfwMsg *)resp);
	tfw_http_msg_free((TfwHttpMsg *)resp);

	return 0;
}

static void
tfw_http_strim(tfw_str_t *s)
{
	u_char *sptr, *eptr;

	if (!s->len)
		return;

	eptr = s->ptr + s->len - 1;
	while (eptr >= s->ptr && isspace(*eptr))
		eptr--;
	s->len = eptr - s->ptr + 1;

	sptr = skip_spaces(s->ptr);
	s->len -= sptr - s->ptr;
	s->ptr = sptr;
}

static TfwStr *
tfw_http_field(TfwHttpMsg *hm, const char *field, size_t len)
{
	int i;
	TfwStr *hdr;

	for (i = 0; i < hm->h_tbl->size; i++) {
		hdr = &hm->h_tbl->tbl[i].field;
		if (tfw_str_eq_cstr(hdr, field, len,
				    TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI)) {
			break;
		}
	}
	if (i < hm->h_tbl->size) {
		/* DIRTY HACK TO COMPENSATE FOR PARSER BUG */
		const tfw_str_t s_cookie = tfw_string("Cookie:");
		if (!strncmp(field, s_cookie.ptr, s_cookie.len))
			hdr->len += 3;
		return hdr;
	}
	return NULL;
}

static int
tfw_http_field_val(TfwHttpMsg *hm, const tfw_str_t *field, tfw_str_t *value)
{
	char *buf;
	size_t len;
	TfwStr *hdr;

	if ((hdr = tfw_http_field(hm, field->ptr, field->len)) == NULL) {
		return 0;
	}
	len = tfw_str_len(hdr) + 1;
	if ((buf = tfw_pool_alloc(hm->pool, len)) == NULL) {
		return -ENOMEM;
	}
	len = tfw_str_to_cstr(hdr, buf, len);
	value->ptr = buf + field->len;
	value->len = len - field->len;
	tfw_http_strim(value);

	return 1;
}

/*
 * Find Tempesta sticky cookie in an HTTP message.
 */
static int
tfw_http_sticky_get(TfwHttpMsg *hm, tfw_str_t *cookie)
{
	int ret;
	u_char *valptr, *endptr;
	const tfw_str_t s_field = tfw_string("Cookie:");
	tfw_str_t value = { 0 };

	/*
	 * Find a 'Cookie:' header field in the request.
	 * The search for Tempesta sticky cookie within the field.
	 * Note that there can be only one "Cookie:" header field.
	 */
	if ((ret = tfw_http_field_val(hm, &s_field, &value)) <= 0) {
		return ret;
	}
	valptr = strnstr(value.ptr, tfw_cfg_sticky.name.ptr, value.len);
	if (!valptr)
		return 0;
	cookie->ptr = valptr + tfw_cfg_sticky.name.len + 1;

	valptr = cookie->ptr;
	endptr = value.ptr + value.len;
	while((valptr < endptr) && (*valptr != ';') && !isspace(*valptr))
		valptr++;
	cookie->len = valptr - cookie->ptr;

	return 1;
}

/*
 * Set up complete 'Set-Cookie:' header field for a connection.
 */
	tfw_str_t value = {
		.len = sizeof("test") - 1,
		.ptr = "test"
	};
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
	int ret;
	uint64_t nsecs;
	struct timespec ts;
	tfw_str_t ua_value = { 0 };
	const tfw_str_t s_field = tfw_string("User-Agent:");
	TfwClient *client = (TfwClient *)hm->conn->peer;

	char desc[sizeof(struct shash_desc)
		  + crypto_shash_descsize(tfw_sticky_shash)]
		  CRYPTO_MINALIGN_ATTR;
	struct shash_desc *shash_desc = (struct shash_desc *)desc;

	memset(desc, 0, sizeof(desc));
	shash_desc->tfm = tfw_sticky_shash;
	shash_desc->flags = 0;

	if ((ret = tfw_http_field_val(hm, &s_field, &ua_value)) <= 0) {
		return ret;
	}

	getnstimeofday(&ts);
	nsecs = 1000ULL * 1000 * 1000 * ts.tv_sec + ts.tv_nsec;

//	client->sock->sk_socket

	crypto_shash_init(shash_desc);
	crypto_shash_update(shash_desc, (u8 *)ua_value.ptr, ua_value.len);
	crypto_shash_finup(shash_desc, (u8 *)&nsecs, sizeof(nsecs), client->hmac);

	return 0;
}

/*
 * Add Tempesta sticky cookie to an HTTP response.
 *
 * Create a complete 'Set-Cookie:' header field, and add it
 * to the HTTP response' header block.
 */
static int
tfw_http_sticky_add(TfwHttpMsg *hm, u_char *value, size_t len)
{
	int ret;
	char buf[256], *ptr = buf;

	/* Set up complete 'Set-Cookie:' header field */
	memcpy(ptr, S_F_SET_COOKIE, SLEN(S_F_SET_COOKIE));
	ptr += SLEN(S_F_SET_COOKIE);
	memcpy(ptr, tfw_cfg_sticky.name.ptr, tfw_cfg_sticky.name.len);
	ptr += tfw_cfg_sticky.name.len;
	*ptr++ = '=';
	ptr += tfw_http_prep_sticky(ptr, value, len);
	TFW_DBG("%s: \"%.*s\"\n", __FUNCTION__, (int)(ptr - buf), buf);

	if ((ret = tfw_http_hdr_add(hm, buf, ptr - buf)) != 0) {
		return ret;
	}

	return 0;
}

/*
 * No Tempesta sticky cookie found.
 *
 * Create Tempesta sticky cookie, and store it for future use.
 * If configured, enforce Tempesta sticky cookie presence in all requests.
 */
static int
tfw_http_sticky_notfound(TfwHttpMsg *hm)
{
	/* Create Tempesta sticky cookie and store it */
	if (tfw_http_sticky_set(hm) != 0) {
		return tfw_http_send_502(hm);
	}
	/*
	 * If configured, make sure that backend server receives requests
	 * that always have Tempesta sticky cookie. Return an HTTP 302
	 * response to the client that has the same host, URI, and inludes
	 * 'Set-Cookie' header field. Otherwise, forward the request to
	 * a backend server.
	 */
	if (tfw_cfg_sticky.enforce) {
		return tfw_http_send_302(hm);
	}

	return 0;
}

/*
 * Found Tempesta sticky cookie.
 */
static int
tfw_http_sticky_found(TfwHttpMsg *hm, tfw_str_t *value)
{
	TfwClient *client = (TfwClient *)hm->conn->peer;

	/*
	 * Do nothing for now. The request is passed to a backend server.
	 */
	TFW_DBG("Sticky cookie found: \"%.*s\"\n", (int)value->len, value->ptr);

	return 0;
}

/*
 * Process Tempesta sticky cookie in an HTTP request.
 */
int
tfw_http_sticky_req_process(TfwHttpMsg *hm)
{
	int ret;
	tfw_str_t value = { 0 };

	if (tfw_cfg_sticky.enabled == 0) {
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
	} else {
		TFW_WARN("Multiple Tempesta sticky cookies found: %d\n", ret);
		return -1;
	}
	/*NOTREACHED*/
	return -1;
}

/*
 * Add Tempesta sticky cookie to an HTTP response if needed.
 */
int
tfw_http_sticky_resp_process(TfwHttpMsg *hmresp, TfwHttpMsg *hmreq)
{
	TfwClient *client = (TfwClient *)hmreq->conn->peer;

	if (tfw_cfg_sticky.enabled == 0) {
		return 0;
	}
	if (client->cookie.len == 0) {
		return 0;
	}
	return tfw_http_sticky_add(hmresp, client->hmac, sizeof(client->hmac);
}

int __init
tfw_http_sticky_init(void)
{
	int ret;
	u_char *ptr;

	if ((ptr = kzalloc(STICKY_NAME_MAX, GFP_KERNEL)) == NULL) {
		return -ENOMEM;
	}
	tfw_cfg_sticky.name.ptr = ptr;
	tfw_cfg_sticky.name.len = 0;

	tfw_sticky_shash = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(tfw_sticky_shash)) {
		pr_err("shash allocation failed\n");
		return  PTR_ERR(tfw_sticky_shash);
	}

	ret = crypto_shash_setkey(tfw_sticky_shash,
				  (u8 *)STICKY_DFLT_KEY, SLEN(STICKY_DFLT_KEY));
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

	val = tfw_http_sticky_get_attr(ce, "name", "__tfw_sticky_cookie__");
	len = strlen(val);
	if ((len == 0) || (len > STICKY_NAME_MAX))
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
			.cleanup = NULL
		},
		{}
	}
};

