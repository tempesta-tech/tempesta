/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include "http_msg.h"

#include "test.h"
#include "helpers.h"
#include "fuzzer.h"

TfwHttpReq *req;
TfwHttpResp *resp;

static int
split_and_parse_n(unsigned char *str, int type, size_t len, size_t chunks)
{
	size_t chlen = len / chunks, rem = len % chunks, pos = 0, step;
	int r = 0;

	while (pos < len) {
		step = chlen;
		if (rem) {
			step += rem;
			rem = 0;
		}

		TEST_LOG("split: len=%zu pos=%zu, chunks=%zu step=%zu\n",
			len, pos, chunks, step);
		if (type == FUZZ_REQ)
			r = tfw_http_parse_req(req, str + pos, step);
		else
			r = tfw_http_parse_resp(resp, str + pos, step);

		pos += step;

		if (r != TFW_POSTPONE)
			return r;
	}

	return r;
}

/**
 * The function is designed to be called in a loop, e.g.
 *   while(!do_split_and_parse(str, type));
 *
 * type may be FUZZ_REQ or FUZZ_RESP.
 *
 * On each iteration it splits the @str into fragments and pushes
 * them to the HTTP parser.
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
 *  - It puts the parsed request or response to the global variable
 *  @req or @resp (on each call, depending on the message type).
 *  - It maintains the internal state between calls.
 *
 * Return value:
 *  == 0 - OK: current step of the loop is done without errors, proceed.
 *  <  0 - Error: the parsing is failed.
 *  >  0 - EOF: all possible fragments are parsed, terminate the loop.
 */
static int chunks = 1;

static int
do_split_and_parse(unsigned char *str, int type)
{
	int r;
	static size_t len;

	BUG_ON(!str);

	if (chunks == 1)
		len = strlen(str);

	if (type == FUZZ_REQ) {
		if (req)
			test_req_free(req);

		req = test_req_alloc(len);
	}
	else if (type == FUZZ_RESP) {
		if (resp)
			test_resp_free(resp);

		resp = test_resp_alloc(len);
	}
	else {
		BUG();
	}

	r = split_and_parse_n(str, type, len, chunks);

#if 0
	/* FIXME #207: we can't process too chunked messages. */
	if (++chunks > len)
#else
	if (++chunks > 3)
#endif
		return TFW_STOP;

	return r;
}

#define TRY_PARSE_EXPECT_PASS(str, type)			\
({ 								\
	int _err = do_split_and_parse(str, type);		\
	if (_err == TFW_BLOCK || _err == TFW_POSTPONE) {	\
		chunks = 1;					\
		TEST_FAIL("can't parse %s (code=%d):\n%s",	\
			  (type == FUZZ_REQ ? "request" :	\
				              "response"),	\
			  _err, (str)); 			\
	}							\
	_err == TFW_PASS;					\
})

#define TRY_PARSE_EXPECT_BLOCK(str, type)			\
({								\
	int _err = do_split_and_parse(str, type);		\
	if (_err == TFW_PASS)					\
		TEST_FAIL("%s is not blocked as expected:\n%s",	\
			       (type == FUZZ_REQ ? "request" :	\
						   "response"),	\
			       (str));				\
	_err == TFW_BLOCK || _err == TFW_POSTPONE;		\
})

#define FOR_REQ(str)						\
	TEST_LOG("=== request: [%s]\n", str);			\
	chunks = 1;						\
	while(TRY_PARSE_EXPECT_PASS(str, FUZZ_REQ))

#define EXPECT_BLOCK_REQ(str)					\
do {								\
	TEST_LOG("=== request: [%s]\n", str);			\
	chunks = 1;						\
	while(TRY_PARSE_EXPECT_BLOCK(str, FUZZ_REQ));		\
} while (0)

#define FOR_RESP(str)						\
	TEST_LOG("=== response: [%s]\n", str);			\
	chunks = 1;						\
	while(TRY_PARSE_EXPECT_PASS(str, FUZZ_RESP))

#define EXPECT_BLOCK_RESP(str)					\
do {								\
	TEST_LOG("=== response: [%s]\n", str);			\
	chunks = 1;						\
	while(TRY_PARSE_EXPECT_BLOCK(str, FUZZ_RESP));		\
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

	FOR_REQ("GET http://natsys-lab.com HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/ HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080 HTTP/1.1\r\n\r\n") {
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "");
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

TEST(http_parser, fills_hdr_tbl_for_req)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_accept, *h_xch, *h_dummy4, *h_dummy9, *h_cc,
	       *h_te;
	TfwStr h_host, h_connection, h_contlen, h_conttype, h_xff,
		   h_user_agent, h_cookie;

	/* Expected values for special headers. */
	const char *s_host = "localhost";
	const char *s_connection = "Keep-Alive";
	const char *s_xff = "127.0.0.1, example.com";
	const char *s_cl = "0";
	const char *s_ct = "text/html; charset=iso-8859-1";
	const char *s_user_agent = "Wget/1.13.4 (linux-gnu)";
	const char *s_cookie = "session=42; theme=dark";
	/* Expected values for raw headers. */
	const char *s_accept = "Accept: */*";
	const char *s_xch = "X-Custom-Hdr: custom header values";
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc  = "Cache-Control: max-age=0, private, min-fresh=42";
	const char *s_te  = "Transfer-Encoding: compress, deflate, gzip";

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
		"Dummy4: 4\r\n"
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Length: 0\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n" /* That is done to check table reallocation. */
		"Dummy9: 9\r\n"
		"Cache-Control: max-age=0, private, min-fresh=42\r\n"
		"Transfer-Encoding: compress, deflate, gzip\r\n"
		"Cookie: session=42; theme=dark\r\n"
		"\r\n")
	{
		ht = req->h_tbl;

		/* Special headers: */
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_HOST],
					 TFW_HTTP_HDR_HOST, &h_host);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_CONNECTION],
					 TFW_HTTP_HDR_CONNECTION,
					 &h_connection);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH],
					 TFW_HTTP_HDR_CONTENT_LENGTH,
					 &h_contlen);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
					 TFW_HTTP_HDR_CONTENT_TYPE,
					 &h_conttype);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR],
					 TFW_HTTP_HDR_X_FORWARDED_FOR, &h_xff);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_USER_AGENT],
					 TFW_HTTP_HDR_USER_AGENT,
					 &h_user_agent);
		tfw_http_msg_clnthdr_val(&ht->tbl[TFW_HTTP_HDR_COOKIE],
					 TFW_HTTP_HDR_COOKIE, &h_cookie);

		/* Common (raw) headers: 14 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 14);

		h_accept     = &ht->tbl[TFW_HTTP_HDR_RAW + 0];
		h_xch        = &ht->tbl[TFW_HTTP_HDR_RAW + 1];
		h_dummy4     = &ht->tbl[TFW_HTTP_HDR_RAW + 6];
		h_dummy9     = &ht->tbl[TFW_HTTP_HDR_RAW + 11];
		h_cc         = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_te         = &ht->tbl[TFW_HTTP_HDR_RAW + 13];

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
		EXPECT_TRUE(tfw_str_eq_cstr(&h_user_agent, s_user_agent,
					    strlen(s_user_agent), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_cookie, s_cookie,
					    strlen(s_cookie), 0));

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
		EXPECT_TRUE(tfw_str_eq_cstr(h_te, s_te,
					    strlen(s_te), 0));
	}
}

TEST(http_parser, fills_hdr_tbl_for_resp)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_dummy4, *h_dummy9, *h_cc, *h_te;
	TfwStr h_connection, h_contlen, h_conttype, h_srv;

	/* Expected values for special headers. */
	const char *s_connection = "Keep-Alive";
	const char *s_cl = "0";
	const char *s_ct = "text/html; charset=iso-8859-1";
	const char *s_srv = "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"
			    " mod_fcgid/2.3.9";
	/* Expected values for raw headers. */
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc  = "Cache-Control: max-age=0, private, min-fresh=42";
	const char *s_te  = "Transfer-Encoding: compress, deflate, gzip";

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		"Connection: Keep-Alive\r\n"
		"Dummy0: 0\r\n"
		"Dummy1: 1\r\n"
		"Dummy2: 2\r\n"
		"Dummy3: 3\r\n"
		"Dummy4: 4\r\n"
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Length: 0\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n"
		"Cache-Control: max-age=0, private, min-fresh=42\r\n"
		"Dummy9: 9\r\n" /* That is done to check table reallocation. */
		"Expires: Tue, 31 Jan 2012 15:02:53 GMT\r\n"
		"Keep-Alive: timeout=600, max=65526\r\n"
		"Transfer-Encoding: compress, deflate, gzip\r\n"
		"Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"
		        " mod_fcgid/2.3.9\r\n"
		"\r\n")
	{
		ht = resp->h_tbl;

		/* Special headers: */
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONNECTION],
					TFW_HTTP_HDR_CONNECTION,
					&h_connection);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH],
					TFW_HTTP_HDR_CONTENT_LENGTH,
					&h_contlen);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
					TFW_HTTP_HDR_CONTENT_TYPE,
					&h_conttype);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_SERVER],
					TFW_HTTP_HDR_SERVER, &h_srv);

		/*
		 * Common (raw) headers: 10 dummies, Cache-Control,
		 * Expires, Keep-Alive, Transfer-Encoding.
		 */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 14);

		h_dummy4     = &ht->tbl[TFW_HTTP_HDR_RAW + 4];
		h_cc         = &ht->tbl[TFW_HTTP_HDR_RAW + 9];
		h_dummy9     = &ht->tbl[TFW_HTTP_HDR_RAW + 10];
		h_te         = &ht->tbl[TFW_HTTP_HDR_RAW + 13];

		EXPECT_TRUE(tfw_str_eq_cstr(&h_connection, s_connection,
					    strlen(s_connection), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_contlen, s_cl,
					    strlen(s_cl), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_conttype, s_ct,
					    strlen(s_ct), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(&h_srv, s_srv,
					    strlen(s_srv), 0));

		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy4, s_dummy4,
					    strlen(s_dummy4), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_cc, s_cc,
					    strlen(s_cc), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_dummy9, s_dummy9,
					    strlen(s_dummy9), 0));
		EXPECT_TRUE(tfw_str_eq_cstr(h_te, s_te,
					    strlen(s_te), 0));
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

TEST(http_parser, content_length_duplicate)
{
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			  "Content-Length: 0\r\n"
			  "Content-Length: 0\r\n"
			  "\r\n");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 0\r\n"
			  "Content-Length: 0\r\n"
			  "\r\n");
}

#define N 6	// Count of generations
#define MOVE 1	// Mutations per generation

TEST(http_parser, fuzzer)
{
	size_t len = 10 * 1024 * 1024;
	char *str = vmalloc(len);
	int field, i, ret;
	TfwFuzzContext context;

	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_LOG("start field: %d request: %d\n", field, i);
			ret = fuzz_gen(&context, str, str + len, field, MOVE, FUZZ_REQ);
			switch (ret) {
			case FUZZ_VALID:
				chunks = 1;
				TRY_PARSE_EXPECT_PASS(str, FUZZ_REQ);
				break;
			case FUZZ_INVALID:
				chunks = 1;
				TRY_PARSE_EXPECT_BLOCK(str, FUZZ_REQ);
				break;
			case FUZZ_END:
			default:
				goto resp;
			}
		}
	}
resp:
	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_LOG("start field: %d response: %d\n", field, i);
			ret = fuzz_gen(&context, str, str + len, field, MOVE, FUZZ_RESP);
			switch (ret) {
			case FUZZ_VALID:
				chunks = 1;
				TRY_PARSE_EXPECT_PASS(str, FUZZ_RESP);
				break;
			case FUZZ_INVALID:
				chunks = 1;
				TRY_PARSE_EXPECT_BLOCK(str, FUZZ_RESP);
				break;
			case FUZZ_END:
			default:
				goto end;
			}
		}
	}
end:
	vfree(str);
}

TEST(http_parser, folding)
{
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host:    \r\n"
			 "   foo.com\r\n"
			 "Connection: close\r\n"
			 "\r\n");
}

TEST(http_parser, empty_host)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Host:\r\n"
		"Connection: close\r\n"
		"\r\n");
}

TEST_SUITE(http_parser)
{
	TEST_RUN(http_parser, parses_req_method);
	TEST_RUN(http_parser, parses_req_uri);
	TEST_RUN(http_parser, fills_hdr_tbl_for_req);
	TEST_RUN(http_parser, fills_hdr_tbl_for_resp);
	TEST_RUN(http_parser, blocks_suspicious_x_forwarded_for_hdrs);
	TEST_RUN(http_parser, parses_connection_value);
	TEST_RUN(http_parser, content_length_duplicate);
	TEST_RUN(http_parser, fuzzer);
	TEST_RUN(http_parser, folding);
	TEST_RUN(http_parser, empty_host);
}
