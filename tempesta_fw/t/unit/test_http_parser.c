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

TfwHttpReq *parsed_req;

static void
allocate_msgs(void)
{
	parsed_req = test_req_alloc();
}

static void
free_msgs(void)
{
	test_req_free(parsed_req);
	parsed_req = NULL;
}

static void
reset_parsed_msgs(void)
{
	free_msgs();
	allocate_msgs();
}

#define PARSE_REQ(raw_req_str) \
	tfw_http_parse_req(parsed_req, raw_req_str, strlen(raw_req_str))

#define PARSE_REQ_PASS(raw_req_str) \
	EXPECT_EQ(TFW_PASS, PARSE_REQ(raw_req_str))

#define EXPECT_TFWSTR_EQ_CSTR(tfw_str, cstr) \
	EXPECT_TRUE(tfw_str_eq_cstr(tfw_str, cstr, strlen(cstr), 0))

TEST(http_parser, parses_method_get)
{
	PARSE_REQ_PASS("GET / HTTP/1.1\r\n\r\n);");
	EXPECT_EQ(parsed_req->method, TFW_HTTP_METH_GET);
}

TEST(http_parser, parses_method_head)
{
	PARSE_REQ_PASS("HEAD / HTTP/1.1\r\n\r\n);");
	EXPECT_EQ(parsed_req->method, TFW_HTTP_METH_HEAD);
}

TEST(http_parser, parses_method_post)
{
	PARSE_REQ_PASS("POST / HTTP/1.1\r\n\r\n);");
	EXPECT_EQ(parsed_req->method, TFW_HTTP_METH_POST);
}

TEST(http_parser, parses_uri_root)
{
	PARSE_REQ_PASS("GET / HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/");
}

TEST(http_parser, parses_uri_rel_file)
{
	PARSE_REQ_PASS("GET /foo/b_a_r/baz.html HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/foo/b_a_r/baz.html");
}

TEST(http_parser, parses_uri_rel_dir)
{
	PARSE_REQ_PASS("GET /a/b/c/dir/ HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/a/b/c/dir/");
}

TEST(http_parser, parses_uri_rel_dir_with_params)
{
	PARSE_REQ_PASS("GET /a/b/c/dir/?foo=1&bar=2#abcd HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/a/b/c/dir/?foo=1&bar=2#abcd");
}

TEST(http_parser, parses_uri_abs_host)
{
	PARSE_REQ_PASS("GET http://natsys-lab.com/ HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->host, "natsys-lab.com");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/");
}

TEST(http_parser, parses_uri_abs_host_port)
{
	PARSE_REQ_PASS("GET http://natsys-lab.com:8080/ HTTP/1.1\r\n\r\n);");
	/* NOTE: we don't include port to the parsed_req->host */
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->host, "natsys-lab.com");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/");
}

TEST(http_parser, parses_uri_abs_host_rel)
{
	PARSE_REQ_PASS("GET http://natsys-lab.com/foo/ HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->host, "natsys-lab.com");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/foo/");
}

TEST(http_parser, parses_uri_abs_host_port_rel_params)
{
	PARSE_REQ_PASS("GET http://natsys-lab.com:8080/cgi-bin/show.pl?entry=tempesta HTTP/1.1\r\n\r\n);");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->host, "natsys-lab.com");
	EXPECT_TFWSTR_EQ_CSTR(&parsed_req->uri, "/cgi-bin/show.pl?entry=tempesta");
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


	PARSE_REQ(
		"GET /foo HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"Host: localhost\r\n"
		"Connection: Keep-Alive\r\n"
		"\r\n"
	);

	h_tbl = parsed_req->h_tbl;

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

TEST(http_parser, blocks_suspicious_x_forwarded_for_hdrs)
{
	int r;

	r = PARSE_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For:   [::1]:1234,5.6.7.8   ,  natsys-lab.com:65535  \r\n"
		"\r\n"
	);
	EXPECT_EQ(r, TFW_PASS);

	reset_parsed_msgs();
	r = PARSE_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For: 1.2.3.4, , 5.6.7.8\r\n"
		"\r\n"
	);
	EXPECT_EQ(r, TFW_BLOCK);

	reset_parsed_msgs();
	r = PARSE_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For: foo!\r\n"
		"\r\n"
	);
	EXPECT_EQ(r, TFW_BLOCK);

	reset_parsed_msgs();
	r = PARSE_REQ(
		"GET / HTTP/1.1\r\n"
		"X-Forwarded-For: \r\n"
		"\r\n"
	);
	EXPECT_EQ(r, TFW_BLOCK);
}


TEST_SUITE(http_parser)
{
	TEST_SETUP(allocate_msgs);
	TEST_TEARDOWN(free_msgs);

	TEST_RUN(http_parser, parses_method_get);
	TEST_RUN(http_parser, parses_method_head);
	TEST_RUN(http_parser, parses_method_post);
	TEST_RUN(http_parser, parses_uri_root);
	TEST_RUN(http_parser, parses_uri_rel_file);
	TEST_RUN(http_parser, parses_uri_rel_dir);
	TEST_RUN(http_parser, parses_uri_rel_dir_with_params);
	TEST_RUN(http_parser, parses_uri_abs_host);
	TEST_RUN(http_parser, parses_uri_abs_host_port);
	TEST_RUN(http_parser, parses_uri_abs_host_rel);
	TEST_RUN(http_parser, parses_uri_abs_host_port_rel_params);
	TEST_RUN(http_parser, segregates_special_headers);
	TEST_RUN(http_parser, blocks_suspicious_x_forwarded_for_hdrs);
}
