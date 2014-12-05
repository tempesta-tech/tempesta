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

	TEST_RUN(http_parser, segregates_special_headers);
	TEST_RUN(http_parser, blocks_suspicious_x_forwarded_for_hdrs);
}
