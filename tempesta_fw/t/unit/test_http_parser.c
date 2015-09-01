/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#include "http_msg.h"

#include "test.h"
#include "helpers.h"

TfwHttpReq *req;

static void
alloc_req(size_t data_len)
{
	BUG_ON(req);
	req = test_req_alloc(data_len);
}

static void
free_req(void)
{
	if (req)
		test_req_free(req);
	req = NULL;
}

static void
reset_req(size_t data_len)
{
	free_req();
	alloc_req(data_len);
}

/**
 * The function is designed to be called in a loop, e.g.
 *   while(!do_split_and_parse(req_str));
 *
 * On each iteration it splits the @req_str into two fragments and pushes
 * them to the HTTP parser.
 *
 * For example, given the request:
 *    "GET / HTTP/1.1\r\n"
 * The function (being called in a loop) will do the following:
 *     parse("GET / HTTP/1.1\r\n");
 *     parse("G"); parse("ET / HTTP/1.1\r\n");
 *     parse("GE"); parse("T / HTTP/1.1\r\n");
 *     parse("GET"); parse(" / HTTP/1.1\r\n");
 *     parse("GET "); parse("/ HTTP/1.1\r\n");
 *     parse("GET /"); parse(" HTTP/1.1\r\n");
 *     ...
 *     parse("GET / HTTP/1.1"); parse("\r\n");
 *     parse("GET / HTTP/1.1\r"); parse("\n");
 *
 * That is done because:
 *  - HTTP pipelining: the feature implies that such a "split" may occur at
 *    any position of the input string. THe HTTP parser should be able to handle
 *    that, and we would like to test it.
 *  - Code coverage: the parser contains some optimizations for non-fragmented
 *    data, so we need to generate all possible fragments to test both "fast
 *    path" and "slow path" execution.
 *
 * The function is stateful:
 *  - It puts the parsed request to the global variable @req (on each call).
 *  - It maintains the internal state between calls.
 *
 * Return value:
 *  == 0 - OK: current step of the loop is done without errors, proceed.
 *  <  0 - Error: the parsing is failed.
 *  >  0 - EOF: all possible fragments are parsed, terminate the loop.
 */
int
do_split_and_parse(unsigned char *req_str)
{
	static char head_buf[PAGE_SIZE];
	static char tail_buf[PAGE_SIZE];
	static size_t req_len, head_len, tail_len;
	int r;

	BUG_ON(!req_str);
	BUG_ON(head_len > req_len);
	BUG_ON(head_len > sizeof(head_buf));
	BUG_ON(tail_len > sizeof(tail_buf));
	reset_req(strlen(req_str));

	/* First iteration. */
	if (!req_len) {
		req_len = strlen(req_str);
		head_len = 0;
		tail_len = req_len - head_len;

		BUG_ON(req_len > sizeof(head_buf));
		memcpy(head_buf, req_str, req_len);

		/* Parse request as a single chunk on the first iteration. */
		return tfw_http_parse_req(req, head_buf, req_len);
	}

	++head_len;
	--tail_len;

	/* Done all iterations?. */
	if (head_len == req_len) {
		req_len = head_len = tail_len = 0;
		return 1;
	}

	/* Put data to a separate buffers to guard bounds. */
	memcpy(head_buf, req_str, head_len);
	memset(head_buf + head_len, 0, sizeof(head_buf) - head_len);
	memcpy(tail_buf, req_str + head_len, tail_len);
	memset(tail_buf + tail_len, 0, sizeof(tail_buf) - tail_len);

	TEST_LOG("split: head_len=%zu [%.*s], tail_len=%zu [%.*s]\n",
		 head_len, (int)head_len, head_buf,
		 tail_len, (int)tail_len, tail_buf);

	/* We expect that the parser requests more data. */
	r = tfw_http_parse_req(req, head_buf, head_len);
	if (r != TFW_POSTPONE)
		return r;

	/* Parse the tail. */
	return tfw_http_parse_req(req, tail_buf, tail_len);
}

#define TRY_PARSE_EXPECT_PASS(str)				\
({ 								\
	int _err = do_split_and_parse(str);			\
	if (_err < 0)						\
		TEST_FAIL("can't parse request (code=%d):\n%s",	\
			  _err, (str)); 			\
	!_err;							\
})

#define TRY_PARSE_EXPECT_BLOCK(str)		\
({						\
	int _err = do_split_and_parse(str);	\
	if (!_err)				\
		TEST_FAIL("request is not blocked as expected:\n%s", (str)); \
	(_err < 0);				\
})

#define FOR_REQ(req)						\
	TEST_LOG("=== request: [%s]\n", req);			\
	while(TRY_PARSE_EXPECT_PASS(req))

#define EXPECT_BLOCK_REQ(req)					\
do {								\
	TEST_LOG("=== request: [%s]\n", req);			\
	while(TRY_PARSE_EXPECT_BLOCK(req));			\
} while (0)

TEST(http_parser, parses_req_method)
{
	FOR_REQ("GET / HTTP/1.1\r\n\r\n")
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);

	FOR_REQ("HEAD / HTTP/1.1\r\n\r\n")
		EXPECT_EQ(req->method, TFW_HTTP_METH_HEAD);

	FOR_REQ("POST / HTTP/1.1\r\n\r\n")
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
}

#define EXPECT_TFWSTR_EQ(tfw_str, cstr) \
	EXPECT_EQ(true, tfw_str_eq_cstr(tfw_str, cstr, strlen(cstr), 0))

TEST(http_parser, parses_req_uri)
{
	/* Relative part of the URI only. */

	FOR_REQ("GET / HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");

	FOR_REQ("GET /foo/b_a_r/baz.html HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri_path, "/foo/b_a_r/baz.html");

	FOR_REQ("GET /a/b/c/dir/ HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri_path, "/a/b/c/dir/");

	FOR_REQ("GET /a/b/c/dir/?foo=1&bar=2#abcd HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri_path, "/a/b/c/dir/?foo=1&bar=2#abcd");

	/* Absolute URI. */
	/* NOTE: we don't include port to the req->host */

	FOR_REQ("GET http://natsys-lab.com/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com/foo/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/foo/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/cgi-bin/show.pl?entry=tempesta HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/cgi-bin/show.pl?entry=tempesta");
	}
}

TEST(http_parser, fills_hdr_tbl)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_user_agent, *h_accept, *h_xch, *h_dummy4, *h_dummy9, *h_cc;
	TfwStr h_host, h_connection, h_contlen, h_conttype, h_xff;

	/* Expected values for special headers. */
	const char *s_host = "localhost";
	const char *s_connection = "Keep-Alive";
	const char *s_xff = "127.0.0.1, example.com";
	const char *s_cl = "0";
	const char *s_ct = "text/html; charset=iso-8859-1";
	/* Expected values for raw headers. */
	const char *s_user_agent = "User-Agent: Wget/1.13.4 (linux-gnu)";
	const char *s_accept = "Accept: */*";
	const char *s_xch = "X-Custom-Hdr: custom header values";
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc  = "Cache-Control: max-age=0, private, min-fresh=42";

	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"Host: localhost\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Custom-Hdr: custom header values\r\n"
		"X-Forwarded-For: 127.0.0.1, example.com\r\n"
		"Dummy0: 0\r\n"
		"Dummy1: 1\r\n"
		"Dummy2: 2\r\n"
		"Dummy3: 3\r\n"
		"Dummy4: 4\r\n"  /* That is done to check table reallocation. */
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Length: 0\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n"
		"Dummy9: 9\r\n"
		"Cache-Control: max-age=0, private, min-fresh=42\r\n"
		"\r\n")
	{
		ht = req->h_tbl;

		/* Special headers: */
		tfw_http_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_HOST],
				     TFW_HTTP_HDR_HOST, &h_host);
		tfw_http_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_CONNECTION],
				     TFW_HTTP_HDR_CONNECTION, &h_connection);
		tfw_http_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH],
				     TFW_HTTP_HDR_CONTENT_LENGTH, &h_contlen);
		tfw_http_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				     TFW_HTTP_HDR_CONTENT_TYPE, &h_conttype);
		tfw_http_msg_hdr_val(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR],
				     TFW_HTTP_HDR_X_FORWARDED_FOR, &h_xff);

		/* Common (raw) headers: 14 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 14);

		h_user_agent = &ht->tbl[TFW_HTTP_HDR_RAW + 0];
		h_accept     = &ht->tbl[TFW_HTTP_HDR_RAW + 1];
		h_xch        = &ht->tbl[TFW_HTTP_HDR_RAW + 2];
		h_dummy4     = &ht->tbl[TFW_HTTP_HDR_RAW + 7];
		h_dummy9     = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_cc         = &ht->tbl[TFW_HTTP_HDR_RAW + 13];

		EXPECT_TRUE(tfw_str_eq_cstr(&h_host, s_host,
					    strlen(s_host), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_connection, s_connection,
					    strlen(s_connection), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_contlen, s_cl,
					    strlen(s_cl), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_conttype, s_ct,
					    strlen(s_ct), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_xff, s_xff,
					    strlen(s_xff), 0));

		EXPECT_TRUE(tfw_str_eq_cstr(h_user_agent, s_user_agent,
					    strlen(s_user_agent), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_accept, s_accept,
					    strlen(s_accept), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_xch, s_xch,
					    strlen(s_xch), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy4, s_dummy4,
					    strlen(s_dummy4), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy9, s_dummy9,
					    strlen(s_dummy9), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_cc, s_cc,
					    strlen(s_cc), 0));
	}
}

TEST(http_parser, blocks_suspicious_x_forwarded_for_hdrs)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"X-Forwarded-For:   [::1]:1234,5.6.7.8   ,  natsys-lab.com:65535  \r\n"
		"\r\n")
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		EXPECT_GT(h->len, 0);
	}

	EXPECT_BLOCK_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For: 1.2.3.4, , 5.6.7.8\r\n"
		"\r\n"
	);

	EXPECT_BLOCK_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For: foo!\r\n"
		"\r\n"
	);

	EXPECT_BLOCK_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For: \r\n"
		"\r\n"
	);
}

TEST(http_parser, parses_connection_value)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"\r\n")
		EXPECT_EQ(req->flags & __TFW_HTTP_CONN_MASK, TFW_HTTP_CONN_KA);

	FOR_REQ("GET / HTTP/1.1\r\n"
		"Connection: Close\r\n"
		"\r\n")
		EXPECT_EQ(req->flags & __TFW_HTTP_CONN_MASK, TFW_HTTP_CONN_CLOSE);
}

TEST_SUITE(http_parser)
{
	TEST_TEARDOWN(free_req);

	TEST_RUN(http_parser, parses_req_method);
	TEST_RUN(http_parser, parses_req_uri);
	TEST_RUN(http_parser, fills_hdr_tbl);
	TEST_RUN(http_parser, blocks_suspicious_x_forwarded_for_hdrs);
	TEST_RUN(http_parser, parses_connection_value);
}
