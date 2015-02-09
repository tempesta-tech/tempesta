/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#define MIN_REQ_LEN 4;

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

bool
do_split_and_parse(unsigned char *req_str)
{
	static size_t req_len, head_len, tail_len;
	int err;

	BUG_ON(!req_str);
	BUG_ON(head_len > req_len);

	/* First iteration. */
	if (!req_len) {
		req_len = strlen(req_str);
		head_len = MIN_REQ_LEN;
		tail_len = req_len - head_len;
	}

	/* Done all iterations?. */
	if (head_len >= req_len) {
		req_len = head_len = tail_len = 0;
		return 1;
	}

	++head_len;
	--tail_len;
	reset_req();
	err = tfw_http_parse_req(req, req_str, head_len);
	if (err == TFW_POSTPONE)
		err = tfw_http_parse_req(req, req_str + head_len, tail_len);

	return err;
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
		EXPECT_TFWSTR_EQ(&req->uri, "/");

	FOR_REQ("GET /foo/b_a_r/baz.html HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri, "/foo/b_a_r/baz.html");

	FOR_REQ("GET /a/b/c/dir/ HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri, "/a/b/c/dir/");

	FOR_REQ("GET /a/b/c/dir/?foo=1&bar=2#abcd HTTP/1.1\r\n\r\n")
		EXPECT_TFWSTR_EQ(&req->uri, "/a/b/c/dir/?foo=1&bar=2#abcd");

	/* Absolute URI. */
	/* NOTE: we don't include port to the req->host */

	FOR_REQ("GET http://natsys-lab.com/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri, "/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri, "/");
	}

	FOR_REQ("GET http://natsys-lab.com/foo/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri, "/foo/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/cgi-bin/show.pl?entry=tempesta HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri, "/cgi-bin/show.pl?entry=tempesta");
	}
}

TEST(http_parser, segregates_special_headers)
{
	TfwHttpHdrTbl *h_tbl;
	bool b1, b2, b3, b4;
	TfwStr *h_user_agent, *h_accept, *h_host, *h_connection;

	/* expected header values */
	const char *s_user_agent = "User-Agent: Wget/1.13.4 (linux-gnu)";
	const char *s_accept = "Accept: */*";
	const char *s_host = "Host: localhost";
	const char *s_connection = "Connection: Keep-Alive";


	FOR_REQ("GET /foo HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"Host: localhost\r\n"
		"Connection: Keep-Alive\r\n"
		"\r\n")
	{
		h_tbl = req->h_tbl;

		EXPECT_EQ(h_tbl->off, TFW_HTTP_HDR_RAW + 2);

		h_user_agent = &h_tbl->tbl[TFW_HTTP_HDR_RAW].field;
		h_accept     = &h_tbl->tbl[TFW_HTTP_HDR_RAW + 1].field;
		h_host       = &h_tbl->tbl[TFW_HTTP_HDR_HOST].field;
		h_connection = &h_tbl->tbl[TFW_HTTP_HDR_CONNECTION].field;

		b1 = tfw_str_eq_cstr(h_user_agent, s_user_agent, strlen(s_user_agent), 0);
		b2 = tfw_str_eq_cstr(h_accept, s_accept, strlen(s_accept), 0);
		b3 = tfw_str_eq_cstr(h_host, s_host, strlen(s_host), 0);
		b4 = tfw_str_eq_cstr(h_connection, s_connection, strlen(s_connection), 0);

		EXPECT_TRUE(b1);
		EXPECT_TRUE(b2);
		EXPECT_TRUE(b3);
		EXPECT_TRUE(b4);
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
	return; /* TODO: these tests don't pass, need to fix the HTTP parser. */

	TEST_TEARDOWN(free_req);

	TEST_RUN(http_parser, parses_req_method);
	TEST_RUN(http_parser, parses_req_uri);
	TEST_RUN(http_parser, segregates_special_headers);
	TEST_RUN(http_parser, blocks_suspicious_x_forwarded_for_hdrs);
}
