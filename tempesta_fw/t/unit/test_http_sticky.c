/**
 *		Tempesta FW
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
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/types.h>
#include <asm/fpu/api.h>
/* prevent exporting symbols */
#include <linux/module.h>
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(...)

#ifdef __read_mostly
#undef __read_mostly
#define __read_mostly
#endif

#ifdef __init
#undef __init
#define __init
#endif

#if DBG_SS == 0 || DBG_TLS == 0
#undef DEBUG
#endif
#include "http_msg.c"
#include "msg.c"
#include "http_sess.c"

#include "filter.c"
#include "sock.c"
#include "server.c"
#include "sock_srv.c"
#include "client.c"
#include "http_limits.c"
#include "http_stream.c"
#include "http_frame.c"
#include "tls.c"

/* rename original tfw_cli_conn_send(), a custom version will be used here */
#define tfw_cli_conn_send	divert_tfw_cli_conn_send
#include "sock_clnt.c"
#undef tfw_cli_conn_send

/* rename original tfw_http_resp_build_error(), a custom version will be used here */
#define tfw_http_resp_build_error	divert_tfw_http_resp_build_error
/*
 * TODO make working redefinition; current redefinition does not work as
 * the definition and the call of the function are in the same file.
 */
#include "http.c"
#undef tfw_http_resp_build_error

#include "hash.c"
#include "addr.c"
#include "ss_skb.c"
#include "sched.c"
#include "gfsm.c"
#include "cache.c"
#include "http_parser.c"
#include "str.c"
#include "work_queue.c"
#include "procfs.c"

/* rename original tfw_connection_send(), a custom version will be used here */
#define tfw_connection_send	divert_tfw_connection_send
#include "connection.c"
#undef tfw_connection_send

#include "vhost.h"
#include "test.h"
#include "helpers.h"
#include "tfw_str_helper.h"

#define TOK_NAME	"__test_name"
#define MAX_MISSES	"3"

/* Timestamp to include into Cookie header of request. */
#define COOKIE_TIMESTAMP	"4142434445464748"
#define COOKIE_TIMESTAMP_N	0x4142434445464748

/*
 * HMAC for 36 bytes, generated for zero timestamp, in order to violate cookie
 * verification (2 bytes for AF_INET6, 26 zero bytes for the rest of
 * struct sockaddr_in6, and 8 bytes for the timestamp):
 *
 * $ perl -e 'print(pack("Sx26Q", 0x0a, 0))' | openssl sha1 -hmac "top_secret"
 */
#define COOKIE_INVALID_HMAC	"6ea1411681e19057b7b66efda92632bf5c19f854"

/*
 * Valid HMAC for 36 bytes (2 bytes for AF_INET6, 26 zero bytes for the rest of
 * struct sockaddr_in6, and 8 bytes for the timestamp in little-endian order,
 * to match HMAC generated in TempestaFW code on x86):
 *
 * $ perl -e 'print(pack("Sx26Q", 0x0a, 0x4142434445464748));' |\
 * openssl sha1 -hmac "top_secret"
 */
#define COOKIE_VALID_HMAC	"b1112f024ffe4b85c95879be339facdc14badbea"

/* Redirection attempt number to insert into redirection mark before timestamp. */
#define RMARK_ATT_NO		"00000001"

/* Redirection mark timestamp to insert into redirection mark before HMAC. */
#define RMARK_TIMESTAMP		"535455565758595a"

/*
 * Valid HMAC for 12 bytes (first 4 bytes of ATT_NO value and 8 bytes with
 * timestamp; these values must be passed into HMAC calculation in little-endian
 * order to match HMAC generated in TempestaFW code on x86):
 *
 * $ perl -e 'print(pack("LQ", 0x00000001, 0x535455565758595a));' \|
 * openssl sha1 -hmac "top_secret"
 */
#define RMARK_VALID_HMAC	"9cf5585388196965871bf4240ef44a52d0ffb23d"

typedef struct {
	int	seen_set_header;
	int	seen;
	int	seen_val;
} TestHdrRes;

static struct {
	int		tfw_connection_send_was_called;
	TestHdrRes	cookie;
	TestHdrRes	loc_rmark;
	unsigned int	http_status;

	char		*cookie_val;
	char		*rmark_val;
	TfwHttpReq	*req;
	TfwHttpResp	*resp;
	TfwConn		conn_req;
	TfwConn		conn_resp;
	TfwClient	client;
	struct sock	sock;
} mock;

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

	for (i = TFW_HTTP_HDR_RAW; i < hm->h_tbl->off; i++) {
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

	hdr_field = tfw_http_field_raw(hm, field_name->data, field_name->len);
	if (hdr_field == NULL) {
		return 0;
	}
	/*
	 * XXX Linearize TfwStr{}. Should be eliminated
	 * when better TfwStr{} functions are implemented.
	 */
	len = hdr_field->len + 1;
	if ((buf = tfw_pool_alloc(hm->pool, len)) == NULL) {
		return -ENOMEM;
	}
	len = tfw_str_to_cstr(hdr_field, buf, len);
	ptr = strim(buf + field_name->len);
	value->data = ptr;
	value->len = len - (ptr - buf);

	return 1;
}

static void
test_http_hdr_check(const TfwStr *hdr_name, const char *val, TestHdrRes *res)
{
	const char *ptr;
	DEFINE_TFW_STR(hdr_value, NULL);

	res->seen_set_header =
		tfw_http_field_value((TfwHttpMsg *)mock.resp,
				     hdr_name, &hdr_value) > 0;

	if (!res->seen_set_header)
		return;

	/* XXX assuming string is linear */
	BUG_ON(!TFW_STR_PLAIN(&hdr_value));

	/* cookie name should be somewhere in Set-Cookie header value */
	ptr = strnstr(hdr_value.data, TOK_NAME, hdr_value.len);
	res->seen = ptr != NULL;

	if (ptr && val) {
		res->seen_val =
			strnstr(ptr, val,
				hdr_value.len - (ptr - hdr_value.data))
			!= NULL;
	}
}

/* custom version for testing purposes */
int
tfw_connection_send(TfwConn *conn, TfwMsg *msg)
{
	struct sk_buff *skb;
	unsigned int parsed = 0, chunks = 0;
	const DEFINE_TFW_STR(s_set_cookie, "Set-Cookie:");
	const DEFINE_TFW_STR(s_set_loc, "Location:");

	BUG_ON(!msg);
	BUG_ON(!msg->skb_head);
	BUG_ON(!conn);

	mock.tfw_connection_send_was_called += 1;

	skb = msg->skb_head;
	do {
		ss_skb_process(skb, 0, 0, tfw_http_parse_resp, mock.resp,
			       &chunks, &parsed);
		skb = skb->next;
	} while (skb != msg->skb_head);

	mock.http_status = mock.resp->status;

	test_http_hdr_check(&s_set_cookie, mock.cookie_val, &mock.cookie);
	test_http_hdr_check(&s_set_loc, mock.rmark_val, &mock.loc_rmark);

	return 0;
}

/* Custom version for testing purposes. */
int tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg)
{
	return tfw_connection_send((TfwConn *)cli_conn, msg);
}

/* Custom version for testing purposes. */
void
tfw_http_resp_build_error(TfwHttpReq *req)
{
	(void)req;
}

int
test_helper_sticky_start(const char *name, unsigned int misses)
{
	size_t len = strlen(name);

	BUG_ON(!len || len > STICKY_NAME_MAXLEN);

	tfw_cfg_sticky.name_eq.data = kzalloc(STICKY_NAME_MAXLEN + 1, GFP_KERNEL);
	if (!tfw_cfg_sticky.name_eq.data)
		return -ENOMEM;

	memcpy(tfw_cfg_sticky.name_eq.data, name, len);
	tfw_cfg_sticky.name_eq.data[len] = '=';
	tfw_cfg_sticky.name_eq.len = len + 1;

	tfw_cfg_sticky.enabled = 1;
	tfw_cfg_sticky.enforce = 1;
	tfw_cfg_sticky.max_misses = misses;

	return 0;
}

void
test_helper_sticky_stop(void)
{
	kfree(tfw_cfg_sticky.name_eq.data);
	memset(&tfw_cfg_sticky, 0, sizeof(tfw_cfg_sticky));
}

/* setup/teardown helpers */

static void
http_sticky_suite_setup(void)
{
	struct sk_buff *skb;
	TfwCliConn *cli_conn;

	BUG_ON(mock.req);
	BUG_ON(mock.resp);

	memset(&mock, 0, sizeof(mock));

	mock.req = (TfwHttpReq *)__tfw_http_msg_alloc(Conn_Clnt, true);
	mock.resp = tfw_http_msg_alloc_resp(mock.req);

	BUG_ON(!mock.req);
	BUG_ON(!mock.resp);

	skb = alloc_skb(PAGE_SIZE, GFP_ATOMIC);
	BUG_ON(!skb);
	skb_reserve(skb, MAX_TCP_HEADER);
	ss_skb_queue_tail(&mock.req->msg.skb_head, skb);

	skb = alloc_skb(PAGE_SIZE, GFP_ATOMIC);
	BUG_ON(!skb);
	skb_reserve(skb, MAX_TCP_HEADER);
	ss_skb_queue_tail(&mock.resp->msg.skb_head, skb);

	tfw_connection_init(&mock.conn_req);
	tfw_connection_init(&mock.conn_resp);
	TFW_CONN_TYPE(&mock.conn_req) |= Conn_Clnt;
	TFW_CONN_TYPE(&mock.conn_resp) |= Conn_Srv;

	cli_conn = (TfwCliConn *)&mock.conn_req;
	INIT_LIST_HEAD(&cli_conn->seq_queue);
	spin_lock_init(&cli_conn->seq_qlock);
	spin_lock_init(&cli_conn->ret_qlock);

	tfw_connection_revive(&mock.conn_req);
	mock.conn_req.peer = (TfwPeer *)&mock.client;
	mock.client.addr.sin6_family = AF_INET6;
	/*
	 * Rest of mock.client.addr was zero-filled, including sin6_addr and
	 * sin6_port earlier.
	 */
	mock.sock.sk_family = AF_INET6;
	mock.conn_req.sk = &mock.sock;

	mock.req->conn = &mock.conn_req;
	mock.resp->conn = &mock.conn_resp;
	tfw_http_init_parser_req(mock.req);
	tfw_http_init_parser_resp(mock.resp);
	mock.req->vhost = tfw_vhost_new(TFW_VH_DFT_NAME);

	tfw_http_req_add_seq_queue(mock.req);
	mock.req->resp = mock.resp;
}

static void
http_sticky_suite_teardown(void)
{
	if (mock.req) {
		tfw_connection_put(mock.req->conn);
		INIT_LIST_HEAD(&mock.req->msg.seq_list);
		INIT_LIST_HEAD(&mock.req->fwd_list);
		INIT_LIST_HEAD(&mock.req->nip_list);
		/* We have no server, so don't try to unpin a server session. */
		if (mock.req->sess && mock.req->sess->st_conn.srv_conn)
			mock.req->sess->st_conn.srv_conn = NULL;
		tfw_http_msg_free((TfwHttpMsg *)mock.req);
	}
	tfw_http_msg_free((TfwHttpMsg *)mock.resp);

	memset(&mock, 0, sizeof(mock));
}

TEST(http_sticky, test_cookie_constants_1)
{
	StickyVal sv = { .ts = COOKIE_TIMESTAMP_N };
	char cookie[sizeof(sv.hmac) * 2];
	char ts_str[sizeof(sv.ts) * 2];
	unsigned long ts_be64 = cpu_to_be64(sv.ts);

	EXPECT_EQ(__sticky_calc(mock.req, &sv), 0);

	bin2hex(cookie, sv.hmac, sizeof(sv.hmac));
	EXPECT_EQ(memcmp(cookie, COOKIE_VALID_HMAC, sizeof(cookie)), 0);

	bin2hex(ts_str, &ts_be64, sizeof(ts_be64));
	EXPECT_EQ(memcmp(ts_str, COOKIE_TIMESTAMP, sizeof(ts_str)), 0);
}

TEST(http_sticky, test_cookie_constants_2)
{
	StickyVal sv = { .ts = 0 };
	char cookie[sizeof(sv.hmac) * 2];

	EXPECT_EQ(__sticky_calc(mock.req, &sv), 0);

	bin2hex(cookie, sv.hmac, sizeof(sv.hmac));
	EXPECT_EQ(memcmp(cookie, COOKIE_INVALID_HMAC, sizeof(cookie)), 0);
}

TEST(http_sticky, sending_302_without_preparing)
{
	StickyVal sv = {};
	TfwConn *c = mock.req->conn;

	/* Cookie is calculated for zero HMAC. */
	EXPECT_EQ(tfw_http_sticky_build_redirect(mock.req, &sv, NULL),
		  TFW_HTTP_SESS_REDIRECT_NEED);
	EXPECT_NOT_NULL(mock.req->resp);
	if (!mock.req->resp)
		goto err;
	tfw_http_resp_fwd(mock.req->resp);

	EXPECT_TRUE(mock.tfw_connection_send_was_called);

err:
	tfw_connection_put(c);
	mock.req = NULL; /* already freed */
}

TEST(http_sticky, sending_302)
{
	create_str_pool();

	{
		StickyVal sv = { .ts = 1 };
		TfwConn *c = mock.req->conn;

		/*
		 * Need host header.
		 * It must be compound as a special header.
		 */
		TFW_STR2(hdr1, "Host: ", "localhost");

		mock.req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr1;

		EXPECT_EQ(__sticky_calc(mock.req, &sv), 0);
		EXPECT_EQ(tfw_http_sticky_build_redirect(mock.req, &sv, NULL),
			  TFW_HTTP_SESS_REDIRECT_NEED);
		EXPECT_NOT_NULL(mock.req->resp);
		if (!mock.req->resp)
			goto err;
		tfw_http_resp_fwd(mock.req->resp);

		EXPECT_TRUE(mock.tfw_connection_send_was_called);
		EXPECT_TRUE(mock.cookie.seen_set_header);
		EXPECT_TRUE(mock.cookie.seen);
		EXPECT_EQ(mock.http_status, 302);

err:
		tfw_connection_put(c);
		mock.req = NULL; /* already freed */
	}

	free_all_str();
}

TEST(http_sticky, sending_502)
{
	StickyVal sv = { .ts = 1 };
	TfwConn *c = mock.req->conn;

	EXPECT_EQ(__sticky_calc(mock.req, &sv), 0);
	tfw_http_send_resp(mock.req, 502, "sticky calculation");

	/* HTTP 502 response have no Set-Cookie header */
	EXPECT_TRUE(mock.tfw_connection_send_was_called);
	EXPECT_FALSE(mock.cookie.seen_set_header);
	EXPECT_FALSE(mock.cookie.seen);
	EXPECT_EQ(mock.http_status, 502);

	tfw_connection_put(c);
	mock.req = NULL; /* already freed */
}

static void
append_string_to_msg(TfwHttpMsg *hm, const char *s)
{
	struct sk_buff  *skb;
	void		*ptr;
	size_t		len;

	BUG_ON(!s);
	len = strlen(s);

	skb = hm->msg.skb_head;
	BUG_ON(!skb);

	ptr = skb_put(skb, len);
	BUG_ON(!ptr);
	memcpy(ptr, s, len);
}

static int
http_parse_helper(TfwHttpMsg *hm, ss_skb_actor_t actor)
{
	struct sk_buff *skb;
	unsigned int parsed = 0, chunks = 0;

	skb = hm->msg.skb_head;
	BUG_ON(!skb);
	while (1) {
		int r = ss_skb_process(skb, 0, 0, actor, hm, &chunks, &parsed);
		switch (r) {
		case TFW_POSTPONE:
			if (skb->next == hm->msg.skb_head)
				return -1;
			skb = skb->next;
			continue;

		case TFW_PASS:
			/* successfully parsed */
			return 0;

		default:
			return -1;
		}
	}
}

static int
http_parse_req_helper(void)
{
	/* XXX reset parser explicitly to be able to call it multiple times */
	tfw_http_init_parser_req(mock.req);
	mock.req->h_tbl->off = TFW_HTTP_HDR_RAW;
	memset(mock.req->h_tbl->tbl, 0, __HHTBL_SZ(1) * sizeof(TfwStr));
	TFW_STR_INIT(&mock.req->crlf);
	TFW_STR_INIT(&mock.req->body);
	TFW_STR_INIT(&mock.req->userinfo);
	TFW_STR_INIT(&mock.req->host);
	TFW_STR_INIT(&mock.req->uri_path);
	TFW_STR_INIT(&mock.req->mark);

	return http_parse_helper((TfwHttpMsg *)mock.req, tfw_http_parse_req);
}

static int
http_parse_resp_helper(void)
{
	/* XXX reset parser explicitly to be able to call it multiple times */
	tfw_http_init_parser_resp(mock.resp);
	mock.resp->h_tbl->off = TFW_HTTP_HDR_RAW;
	memset(mock.resp->h_tbl->tbl, 0, __HHTBL_SZ(1) * sizeof(TfwStr));
	TFW_STR_INIT(&mock.resp->crlf);
	TFW_STR_INIT(&mock.resp->body);
	TFW_STR_INIT(&mock.resp->s_line);

	return http_parse_helper((TfwHttpMsg *)mock.resp, tfw_http_parse_resp);
}

TEST(http_sticky, sticky_get_absent)
{
	TfwStr value = {};
	const char *s_req = "GET / HTTP/1.0\r\nHost: localhost\r\n"
			    "Cookie: __utmz=12345; q=aa\r\n\r\n";

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);

	/* expecting no cookie */
	EXPECT_EQ(tfw_http_sticky_get(mock.req, &value), 0);
}

static void
test_sticky_present_helper(const char *s_req)
{
	TfwStr	value = {};

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);

	EXPECT_EQ(tfw_http_sticky_get(mock.req, &value), 1);

	EXPECT_TRUE(value.len == 5);
	EXPECT_TRUE(value.data && memcmp(value.data, "67890", 5) == 0);
}

TEST(http_sticky, sticky_get_present_begin)
{
	const char *s_req = "GET / HTTP/1.0\r\nContent-Length: 0\r\n"
			    "Cookie: " TOK_NAME "=67890; __utmz=12345; "
			    "q=aa\r\n\r\n";

	test_sticky_present_helper(s_req);
}

TEST(http_sticky, sticky_get_present_middle)
{
	const char *s_req = "GET / HTTP/1.0\r\nContent-Length: 0\r\n"
			    "Cookie: __utmz=12345; " TOK_NAME "=67890; "
			    "q=aa\r\n\r\n";

	test_sticky_present_helper(s_req);
}

TEST(http_sticky, sticky_get_present_end)
{
	const char *s_req = "GET / HTTP/1.0\r\nContent-Length: 0\r\n"
			    "Cookie: __utmz=12345; q=aa; "
			    TOK_NAME "=67890\r\n\r\n";

	test_sticky_present_helper(s_req);
}

/* request have no sticky cookie */
TEST(http_sticky, req_no_cookie)
{
	const char *s_req = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
	const char *s_resp = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	append_string_to_msg((TfwHttpMsg *)mock.resp, s_resp);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(http_parse_resp_helper(), 0);

	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_SUCCESS);
	EXPECT_EQ(tfw_http_sess_resp_process(mock.resp), 0);

	/* with no cookie enforcement, only backend response will be modified */
	EXPECT_FALSE(mock.tfw_connection_send_was_called);

	/* since response was modified, we need to parse it again */
	EXPECT_EQ(http_parse_resp_helper(), 0);
	tfw_connection_send(&mock.conn_req, &mock.resp->msg);

	EXPECT_TRUE(mock.tfw_connection_send_was_called);
	EXPECT_TRUE(mock.cookie.seen_set_header);
	EXPECT_TRUE(mock.cookie.seen);
}

/* request have sticky cookie */
TEST(http_sticky, req_have_cookie)
{
	const char *s_req = "GET / HTTP/1.0\r\n"
			    "Host: localhost\r\n"
			    "Cookie: " TOK_NAME "="
			    COOKIE_TIMESTAMP
			    COOKIE_VALID_HMAC
			    "\r\n\r\n";
	const char *s_resp = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	append_string_to_msg((TfwHttpMsg *)mock.resp, s_resp);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(http_parse_resp_helper(), 0);

	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_SUCCESS);
	EXPECT_EQ(tfw_http_sess_resp_process(mock.resp), 0);

	/* expecting no immediate responses */
	EXPECT_FALSE(mock.tfw_connection_send_was_called);

	/* since response could be modified, we need to parse it again */
	EXPECT_EQ(http_parse_resp_helper(), 0);
	tfw_connection_send(&mock.conn_req, &mock.resp->msg);

	/* no Set-Cookie headers are expected */
	EXPECT_FALSE(mock.cookie.seen_set_header);
	EXPECT_FALSE(mock.cookie.seen);
}

/* request have no sticky cookie; enforce mode activated */
TEST(http_sticky, req_no_cookie_enforce)
{
	const char *s_req = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
	TfwConn *c = mock.req->conn;

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_REDIRECT_NEED);
	EXPECT_NOT_NULL(mock.req->resp);
	if (!mock.req->resp)
		goto err;
	tfw_http_resp_fwd(mock.req->resp);

	/* in enforce mode, 302 response is sent to a client by Tempesta
	 * before backend gets anything
	 */
	EXPECT_TRUE(mock.tfw_connection_send_was_called);
	EXPECT_TRUE(mock.cookie.seen_set_header);
	EXPECT_TRUE(mock.cookie.seen);

err:
	tfw_connection_put(c);
	mock.req = NULL; /* already freed */
}

/* request have sticky cookie set; enforce mode activated */
TEST(http_sticky, req_have_cookie_enforce)
{
	const char *s_req = "GET / HTTP/1.0\r\n"
			    "Host: localhost\r\n"
			    "Cookie: " TOK_NAME "="
			    COOKIE_TIMESTAMP
			    COOKIE_VALID_HMAC
			    "\r\n\r\n";
	const char *s_resp = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	append_string_to_msg((TfwHttpMsg *)mock.resp, s_resp);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(http_parse_resp_helper(), 0);

	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_SUCCESS);
	EXPECT_EQ(tfw_http_sess_resp_process(mock.resp), 0);

	/* expecting no immediate responses */
	EXPECT_FALSE(mock.tfw_connection_send_was_called);

	/* since response could be modified, we need to parse it again */
	EXPECT_EQ(http_parse_resp_helper(), 0);
	tfw_connection_send(&mock.conn_req, &mock.resp->msg);

	/* no Set-Cookie headers are expected */
	EXPECT_FALSE(mock.cookie.seen_set_header);
	EXPECT_FALSE(mock.cookie.seen);
}

/* request have invalid sticky cookie; enforce mode activated */
TEST(http_sticky, req_invalid_cookie_enforce)
{
	const char *s_req = "GET / HTTP/1.0\r\n"
			    "Host: localhost\r\n"
			    "Cookie: " TOK_NAME "="
			    COOKIE_TIMESTAMP
			    COOKIE_INVALID_HMAC
			    "\r\n\r\n";
	TfwConn *c = mock.req->conn;

	mock.cookie_val = COOKIE_TIMESTAMP COOKIE_VALID_HMAC;

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_REDIRECT_NEED);
	EXPECT_NOT_NULL(mock.req->resp);
	if (!mock.req->resp)
		goto err;
	tfw_http_resp_fwd(mock.req->resp);

	/* if cookie is invalid, then 302 response is sent to a client
	 * by Tempesta instead of forwarding request to backend
	 */
	EXPECT_TRUE(mock.tfw_connection_send_was_called);
	EXPECT_TRUE(mock.cookie.seen_set_header);
	EXPECT_TRUE(mock.cookie.seen);
	EXPECT_TRUE(mock.cookie.seen_val);
err:
	tfw_connection_put(c);
	mock.req = NULL; /* already freed */
}

/*
 * Request have no sticky cookie; extended (with redirection
 * mark verification) enforce mode activated.
 */
TEST(http_sticky, req_no_cookie_enforce_extented)
{
	const char *s_req = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
	TfwConn *c = mock.req->conn;

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_REDIRECT_NEED);
	EXPECT_NOT_NULL(mock.req->resp);
	if (!mock.req->resp)
		goto err;
	tfw_http_resp_fwd(mock.req->resp);

	/* in enforce mode, 302 response is sent to a client by Tempesta
	 * before backend gets anything
	 */
	EXPECT_TRUE(mock.tfw_connection_send_was_called);
	EXPECT_TRUE(mock.cookie.seen_set_header);
	EXPECT_TRUE(mock.cookie.seen);

	/* in extended enforce mode 302 response must contain 'Location'
	 * header with redirection mark set
	 */
	EXPECT_TRUE(mock.loc_rmark.seen_set_header);
	EXPECT_TRUE(mock.loc_rmark.seen);
err:
	tfw_connection_put(c);
	mock.req = NULL; /* already freed */
}

/*
 * Request have invalid sticky cookie and valid redirection mark; extended
 * (with redirection mark verification) enforce mode activated. 302 response
 * must be generated, but with changed redirection mark (attempts number will
 * be incremented), so we should verify it with new recalculated mark.
 */
TEST(http_sticky, req_invalid_cookie_enforce_extended)
{
/* New incremented attempt number and recalculated valid HMAC (timestamp
 * remain the same - see the beginning of this file for description of
 * calculation process).
 */
#define NEW_RMARK_ATT_NO	"00000002"
#define NEW_RMARK_VALID_HMAC	"63305131e09ab5f57ebca7285bc51a562964838b"

	const char *s_req = "GET " "/" TOK_NAME "="
			    RMARK_ATT_NO
			    RMARK_TIMESTAMP
			    RMARK_VALID_HMAC
			    "/ HTTP/1.0\r\n"
			    "Host: localhost\r\n"
			    "Cookie: " TOK_NAME "="
			    COOKIE_TIMESTAMP
			    COOKIE_INVALID_HMAC
			    "\r\n\r\n";
	TfwConn *c = mock.req->conn;

	mock.cookie_val = COOKIE_TIMESTAMP COOKIE_VALID_HMAC;
	mock.rmark_val = NEW_RMARK_ATT_NO RMARK_TIMESTAMP NEW_RMARK_VALID_HMAC;

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);
	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_REDIRECT_NEED);
	EXPECT_NOT_NULL(mock.req->resp);
	if (!mock.req->resp)
		goto err;
	tfw_http_resp_fwd(mock.req->resp);

	/* if cookie is invalid, then 302 response is sent to a client
	 * by Tempesta instead of forwarding request to backend
	 */
	EXPECT_TRUE(mock.tfw_connection_send_was_called);
	EXPECT_TRUE(mock.cookie.seen_set_header);
	EXPECT_TRUE(mock.cookie.seen);
	EXPECT_TRUE(mock.cookie.seen_val);

	/* in extended enforce mode 302 response must contain 'Location'
	 * header with redirection mark set
	 */
	EXPECT_TRUE(mock.loc_rmark.seen_set_header);
	EXPECT_TRUE(mock.loc_rmark.seen);
	EXPECT_TRUE(mock.loc_rmark.seen_val);
err:
	tfw_connection_put(c);
	mock.req = NULL; /* already freed */
}

/*
 * Request have valid sticky cookie and valid redirection mark; extended
 * (with redirection mark verification) enforce mode activated. 302 response
 * must not be generated, and request must be forwared to backend server.
 * Redirection mark must be deleted from request before sending to beckend.
 */
TEST(http_sticky, req_valid_cookie_enforce_extended)
{
	const char *s_req = "GET " "/" TOK_NAME "="
			    RMARK_ATT_NO
			    RMARK_TIMESTAMP
			    RMARK_VALID_HMAC
			    "/ HTTP/1.0\r\n"
			    "Host: localhost\r\n"
			    "Cookie: " TOK_NAME "="
			    COOKIE_TIMESTAMP
			    COOKIE_VALID_HMAC
			    "\r\n\r\n";

	append_string_to_msg((TfwHttpMsg *)mock.req, s_req);
	EXPECT_EQ(http_parse_req_helper(), 0);

	EXPECT_EQ(tfw_http_sess_obtain(mock.req), TFW_HTTP_SESS_SUCCESS);
	EXPECT_TRUE(!TFW_STR_EMPTY(&mock.req->mark));
	EXPECT_EQ(tfw_http_sess_req_process(mock.req), 0);

	/* expecting no immediate responses */
	EXPECT_FALSE(mock.tfw_connection_send_was_called);

	/* since request should be modified, we need to parse it again */
	EXPECT_EQ(http_parse_req_helper(), 0);

	/* redirection mark is not expected */
	EXPECT_TRUE(TFW_STR_EMPTY(&mock.req->mark));
}

TEST_SUITE(http_sticky)
{
	TfwCfgEntry ce_sticky = {
		.name = "sticky",
		.val_n = 1,
		.vals = { "enforce" },
		.attr_n = 1,
		.attrs = {
			{ .key = "name", .val = TOK_NAME },
			{ .key = "max_misses", .val = MAX_MISSES }
		},
		.have_children = false
	};
	TfwCfgEntry ce_secret = {
		.name = "sticky_secret",
		.val_n = 1,
		.vals = { "top_secret" },
	};

	kernel_fpu_end();

	TEST_SETUP(http_sticky_suite_setup);
	TEST_TEARDOWN(http_sticky_suite_teardown);

	tfw_http_sess_init();

	/* emulate configuration file */
	ce_sticky.val_n = 0; /* remove "enforce" parameter */
	tfw_cfgop_sticky(&tfw_http_sess_mod.specs[0], &ce_sticky);
	tfw_cfgop_sticky_secret(&tfw_http_sess_mod.specs[1], &ce_secret);
	tfw_http_sess_cfgend();

	tfw_http_sess_start();

	kernel_fpu_begin();

	TEST_RUN(http_sticky, test_cookie_constants_1);
	TEST_RUN(http_sticky, test_cookie_constants_2);

	TEST_RUN(http_sticky, sending_302_without_preparing);
	TEST_RUN(http_sticky, sending_302);
	TEST_RUN(http_sticky, sending_502);
	TEST_RUN(http_sticky, sticky_get_absent);
	TEST_RUN(http_sticky, sticky_get_present_begin);
	TEST_RUN(http_sticky, sticky_get_present_middle);
	TEST_RUN(http_sticky, sticky_get_present_end);
	TEST_RUN(http_sticky, req_no_cookie);
	TEST_RUN(http_sticky, req_have_cookie);

	/* test "enforce" mode */
	ce_sticky.val_n = 1; /* return "enforce" parameter */
	tfw_cfgop_sticky(&tfw_http_sess_mod.specs[0], &ce_sticky);
	TEST_RUN(http_sticky, req_no_cookie_enforce);
	TEST_RUN(http_sticky, req_have_cookie_enforce);
	TEST_RUN(http_sticky, req_invalid_cookie_enforce);

	/* set "max_misses" for redirection mark testing */
	ce_sticky.attr_n = 2;
	tfw_cfgop_sticky(&tfw_http_sess_mod.specs[0], &ce_sticky);
	TEST_RUN(http_sticky, req_no_cookie_enforce_extented);
	TEST_RUN(http_sticky, req_invalid_cookie_enforce_extended);
	TEST_RUN(http_sticky, req_valid_cookie_enforce_extended);

	kernel_fpu_end();

	/* Garbage collect all the sessions. */
	tfw_cfgop_cleanup_sticky(&tfw_http_sess_mod.specs[0]);
	tfw_http_sess_stop();
	tfw_http_sess_exit();

	kernel_fpu_begin();
}
