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
alloc_req(void)
{
	BUG_ON(req);
	req = test_req_alloc();
}

static void
free_req(void)
{
	if (req)
		test_req_free(req);
	req = NULL;
}

static void
reset_req(void)
{
	free_req();
	alloc_req();
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
	int ret;

	BUG_ON(!req_str);
	BUG_ON(head_len > req_len);
	BUG_ON(head_len > sizeof(head_buf));
	BUG_ON(tail_len > sizeof(tail_buf));
	reset_req();

	/* First iteration. */
	if (!req_len) {
		req_len = strlen(req_str);
		head_len = 0;
		tail_len = req_len - head_len;

		/* Parse request as a single chunk on the first iteration. */
		return tfw_http_parse_req(req, req_str, req_len);
	}

	++head_len;
	--tail_len;
	TFW_DBG("split: head_len=%zu, tail_len=%zu\n", head_len, tail_len);

	/* Done all iterations?. */
	if (head_len == req_len) {
		req_len = head_len = tail_len = 0;
		return 1;
	}

	/* Parse the head. Put it to a separate buffer to guard bounds. */
	memset(head_buf, 0xDEADDEAD, head_len);
	memcpy(head_buf, req_str, head_len);
	ret = tfw_http_parse_req(req, head_buf, head_len);
	/* We expect that the parser requests more data. */
	if (ret != TFW_POSTPONE)
		return -1;

	/* Parse the tail. */
	memset(tail_buf, 0xDEADDEAD, tail_len);
	memcpy(tail_buf, req_str + head_len, tail_len);
	ret = tfw_http_parse_req(req, tail_buf, tail_len);
	return ret;
}

#define FOR_REQ(raw_req_str) while(TRY_PARSE_EXPECT_PASS(raw_req_str))
#define EXPECT_BLOCK_REQ(raw_req_str) while(TRY_PARSE_EXPECT_BLOCK(raw_req_str))

#define TRY_PARSE_EXPECT_PASS(str)				\
({ 								\
	int _err = do_split_and_parse(str);			\
	if (_err < 0)						\
		TEST_FAIL("can't parse request:\n%s", (str)); 	\
	!_err;							\
})

#define TRY_PARSE_EXPECT_BLOCK(str)		\
({						\
	int _err = do_split_and_parse(str);	\
	if (!_err)				\
		TEST_FAIL("request is not blocked as expected:\n%s", (str)); \
	(_err < 0);				\
})

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
	TfwHttpHdrTbl *h_tbl;
	bool b1, b2, b3, b4, b5, b6, b7, b8;
	TfwStr *h_user_agent, *h_accept, *h_host, *h_connection,
		*h_xch, *h_xff, *h_dummy9, *h_cc;

	/* expected header values */
	const char *s_user_agent = "User-Agent: Wget/1.13.4 (linux-gnu)";
	const char *s_accept = "Accept: */*";
	const char *s_host = "Host: localhost";
	const char *s_connection = "Connection: Keep-Alive";
	const char *s_xch = "X-Custom-Hdr: custom header values";
	const char *s_xff = "X-Forwarded-For: 127.0.0.1, example.com";
	const char *s_dummy9 = "Dummy9: 9";
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
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n"
		"Dummy9: 9\r\n"
		"Cache-Control: max-age=0, private, min-fresh=42\r\n"
		"\r\n")
	{
		h_tbl = req->h_tbl;

		/* Special headers: */
		h_host       = &h_tbl->tbl[TFW_HTTP_HDR_HOST].field;
		h_connection = &h_tbl->tbl[TFW_HTTP_HDR_CONNECTION].field;
		h_xff        = &h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR].field;

		/* Common (raw) headers: 14 total, are 10 dummies. */
		EXPECT_EQ(h_tbl->off, TFW_HTTP_HDR_RAW + 14);
		h_user_agent = &h_tbl->tbl[TFW_HTTP_HDR_RAW + 0].field;
		h_accept     = &h_tbl->tbl[TFW_HTTP_HDR_RAW + 1].field;
		h_xch        = &h_tbl->tbl[TFW_HTTP_HDR_RAW + 2].field;
		h_dummy9     = &h_tbl->tbl[TFW_HTTP_HDR_RAW + 12].field;
		h_cc         = &h_tbl->tbl[TFW_HTTP_HDR_RAW + 13].field;

		b1 = tfw_str_eq_cstr(h_user_agent, s_user_agent, strlen(s_user_agent), 0);
		b2 = tfw_str_eq_cstr(h_accept, s_accept, strlen(s_accept), 0);
		b3 = tfw_str_eq_cstr(h_host, s_host, strlen(s_host), 0);
		b4 = tfw_str_eq_cstr(h_connection, s_connection, strlen(s_connection), 0);
		b5 = tfw_str_eq_cstr(h_xch, s_xch, strlen(s_xch), 0);
		b6 = tfw_str_eq_cstr(h_xff, s_xff, strlen(s_xff), 0);
		b7 = tfw_str_eq_cstr(h_dummy9, s_dummy9, strlen(s_dummy9), 0);
		b8 = tfw_str_eq_cstr(h_cc, s_cc, strlen(s_cc), 0);

		EXPECT_TRUE(b1);
		EXPECT_TRUE(b2);
		EXPECT_TRUE(b3);
		EXPECT_TRUE(b4);
		EXPECT_TRUE(b5);
		EXPECT_TRUE(b6);
		EXPECT_TRUE(b7);
		EXPECT_TRUE(b8);
	}
}

TEST(http_parser, blocks_suspicious_x_forwarded_for_hdrs)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"X-Forwarded-For:   [::1]:1234,5.6.7.8   ,  natsys-lab.com:65535  \r\n"
		"\r\n")
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR].field;
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


TEST_SUITE(http_parser)
{
	TEST_TEARDOWN(free_req);

	TEST_RUN(http_parser, parses_req_method);
	TEST_RUN(http_parser, parses_req_uri);
	TEST_RUN(http_parser, fills_hdr_tbl);
	TEST_RUN(http_parser, blocks_suspicious_x_forwarded_for_hdrs);
}
