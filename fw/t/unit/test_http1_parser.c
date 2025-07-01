/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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

#include "test_http_parser_common.h"
#include "test_http_parser_defs.h"

#define SAMPLE_REQ_STR	"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

#define REQ_SIMPLE_HEAD		"GET / HTTP/1.1\r\n"
#define EMPTY_REQ		REQ_SIMPLE_HEAD "\r\n"
#define RESP_SIMPLE_HEAD	"HTTP/1.0 200 OK\r\n"		\
				"Content-Length: 0\r\n"
#define EMPTY_RESP		RESP_SIMPLE_HEAD "\r\n"

#define FOR_REQ_SIMPLE(headers)					\
	FOR_REQ(REQ_SIMPLE_HEAD headers "\r\n\r\n")
#define FOR_RESP_SIMPLE(headers)				\
	FOR_RESP(RESP_SIMPLE_HEAD headers "\r\n\r\n")

#define FOR_REQ_RESP_SIMPLE(headers, lambda)			\
	FOR_REQ_SIMPLE(headers)					\
	{							\
		TfwHttpMsg *msg = (TfwHttpMsg *)req;		\
		lambda;						\
	}							\
	FOR_RESP_SIMPLE(headers)				\
	{							\
		TfwHttpMsg *msg = (TfwHttpMsg *)resp;		\
		lambda;						\
	}

#define EXPECT_BLOCK_REQ_SIMPLE(headers)			\
	EXPECT_BLOCK_REQ(REQ_SIMPLE_HEAD headers "\r\n\r\n")

#define EXPECT_BLOCK_RESP_SIMPLE(headers)			\
	EXPECT_BLOCK_RESP(RESP_SIMPLE_HEAD headers "\r\n\r\n")

#define EXPECT_BLOCK_REQ_RESP_SIMPLE(headers)			\
	EXPECT_BLOCK_REQ_SIMPLE(headers);			\
	EXPECT_BLOCK_RESP_SIMPLE(headers)


#define FOR_REQ_HDR_EQ(header, id)				\
	FOR_REQ_SIMPLE(header)					\
	{							\
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[id],	header);\
	}

#define FOR_RESP_HDR_EQ(header, id)				\
	FOR_RESP_SIMPLE(header)					\
	{							\
		EXPECT_TFWSTR_EQ(&resp->h_tbl->tbl[id], header);\
	}


TEST(http1_parser, leading_eol)
{
	EXPECT_BLOCK_REQ("\r\n\r\n" EMPTY_REQ);
	EXPECT_BLOCK_REQ("\n\n" EMPTY_REQ);
	EXPECT_BLOCK_REQ("\n\n\n" EMPTY_REQ);
	EXPECT_BLOCK_REQ("\r" EMPTY_REQ);
	EXPECT_BLOCK_REQ("\t" EMPTY_REQ);
	EXPECT_BLOCK_REQ("\x1F" EMPTY_REQ);
	EXPECT_BLOCK_REQ("\xFF" EMPTY_REQ);

	FOR_RESP(EMPTY_RESP);
	FOR_RESP("\n" EMPTY_RESP);
	FOR_RESP("\r\n" EMPTY_RESP);
	FOR_RESP("\n\n\n" EMPTY_RESP);
}

TEST(http1_parser, short_name)
{
	FOR_REQ_SIMPLE("X: test");
	FOR_REQ_SIMPLE("Z: test");
	EXPECT_BLOCK_REQ_SIMPLE(": test");
}

TEST(http1_parser, parses_req_method)
{
#define TEST_REQ_METHOD(METHOD)					\
	FOR_REQ(#METHOD " /filename HTTP/1.1\r\n\r\n")		\
	{							\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);	\
	}

	TEST_REQ_METHOD(COPY);
	TEST_REQ_METHOD(DELETE);
	TEST_REQ_METHOD(GET);
	TEST_REQ_METHOD(HEAD);
	TEST_REQ_METHOD(LOCK);
	TEST_REQ_METHOD(MKCOL);
	TEST_REQ_METHOD(MOVE);
	TEST_REQ_METHOD(OPTIONS);
	TEST_REQ_METHOD(PATCH);
	TEST_REQ_METHOD(POST);
	TEST_REQ_METHOD(PROPFIND);
	TEST_REQ_METHOD(PROPPATCH);
	TEST_REQ_METHOD(PUT);
	TEST_REQ_METHOD(TRACE);
	TEST_REQ_METHOD(UNLOCK);
	/* Supported Non-RFC methods. */
	TEST_REQ_METHOD(PURGE);

#define TEST_REQ_UNKNOWN(METHOD)				\
	FOR_REQ(#METHOD " /filename HTTP/1.1\r\n\r\n")		\
	{							\
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);	\
	}

	/* Some cases when */
	TEST_REQ_UNKNOWN(PURG);
	TEST_REQ_UNKNOWN(DELE);
	TEST_REQ_UNKNOWN(MKCO);
	TEST_REQ_UNKNOWN(OPTI);
	TEST_REQ_UNKNOWN(PATC);
	TEST_REQ_UNKNOWN(PROP);
	TEST_REQ_UNKNOWN(TRAC)
	TEST_REQ_UNKNOWN(UNLO);
	TEST_REQ_UNKNOWN(G);
	TEST_REQ_UNKNOWN(H);
	TEST_REQ_UNKNOWN(P);
	TEST_REQ_UNKNOWN(C);
	TEST_REQ_UNKNOWN(D);
	TEST_REQ_UNKNOWN(L);
	TEST_REQ_UNKNOWN(M);
	TEST_REQ_UNKNOWN(O);
	TEST_REQ_UNKNOWN(T);
	TEST_REQ_UNKNOWN(U);


	/* RFC methods, not supported by TempestaFW. */
	TEST_REQ_UNKNOWN(ACL);
	TEST_REQ_UNKNOWN(BASELINE-CONTROL);
	TEST_REQ_UNKNOWN(BIND);
	TEST_REQ_UNKNOWN(CHECKIN);
	TEST_REQ_UNKNOWN(CHECKOUT);
	TEST_REQ_UNKNOWN(CONNECT);
	TEST_REQ_UNKNOWN(LABEL);
	TEST_REQ_UNKNOWN(LINK);
	TEST_REQ_UNKNOWN(MERGE);
	TEST_REQ_UNKNOWN(MKACTIVITY);
	TEST_REQ_UNKNOWN(MKCALENDAR);
	TEST_REQ_UNKNOWN(MKREDIRECTREF);
	TEST_REQ_UNKNOWN(MKWORKSPACE);
	TEST_REQ_UNKNOWN(ORDERPATCH);
	TEST_REQ_UNKNOWN(PRI);
	TEST_REQ_UNKNOWN(REBIND);
	TEST_REQ_UNKNOWN(REPORT);
	TEST_REQ_UNKNOWN(SEARCH);
	TEST_REQ_UNKNOWN(UNBIND);
	TEST_REQ_UNKNOWN(UNCHECKOUT);
	TEST_REQ_UNKNOWN(UNLINK);
	TEST_REQ_UNKNOWN(UPDATE);
	TEST_REQ_UNKNOWN(UPDATEREDIRECTREF);
	TEST_REQ_UNKNOWN(VERSION-CONTROL);
	/* Unknown methods. */
	TEST_REQ_UNKNOWN(UNKNOWN);

#undef TEST_REQ_UNKNOWN
#undef TEST_REQ_METHOD

	/* Test for empty method */
	EXPECT_BLOCK_REQ(" /filename HTTP/1.1\r\n\r\n");
	/* Malformed methods */
	EXPECT_BLOCK_REQ("\tOST /filename HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("P\tST /filename HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("PO\tT /filename HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("POS\t /filename HTTP/1.1\r\n\r\n");
}

TEST(http1_parser, parses_req_uri)
{
#define TEST_URI_PATH(req_uri_path)					\
	FOR_REQ("GET " req_uri_path " HTTP/1.1\r\n\r\n")		\
	{								\
		EXPECT_TFWSTR_EQ(&req->host, "");			\
		EXPECT_TFWSTR_EQ(&req->uri_path, req_uri_path);		\
	}

	TEST_URI_PATH("/");
	TEST_URI_PATH("/?");
	TEST_URI_PATH("/foo/b_a_r/baz.html");
	TEST_URI_PATH("/a/b/c/dir/");
	TEST_URI_PATH("/a/b/c/dir/?foo=1&bar=2#abcd");

#define TEST_FULL_REQ(req_host, req_uri_path)				\
	FOR_REQ("GET http://" req_host req_uri_path " HTTP/1.1\r\n\r\n")\
	{								\
		EXPECT_TFWSTR_EQ(&req->host, req_host);			\
		if (SLEN(req_uri_path)) {				\
			EXPECT_TFWSTR_EQ(&req->uri_path, req_uri_path);	\
		} else {						\
			/*						\
			 * If request URI is empty Tempesta FW set	\
			 * default req->uri_path "/".			\
			 */						\
			EXPECT_TFWSTR_EQ(&req->uri_path, "/");		\
		}							\
	}

#define TEST_OPTIONS_ASTERISK()						\
	FOR_REQ("OPTIONS * HTTP/1.1\r\n\r\n") {			\
		EXPECT_EQ(req->method, TFW_HTTP_METH_OPTIONS);		\
		EXPECT_TFWSTR_EQ(&req->uri_path, "*");			\
	}

#define TEST_OPTIONS_WITHOUT_PATH(req_host)				\
	FOR_REQ("OPTIONS http://" req_host " HTTP/1.1\r\n\r\n") {	\
		EXPECT_EQ(req->method, TFW_HTTP_METH_OPTIONS);		\
		EXPECT_TFWSTR_EQ(&req->host, req_host);			\
		EXPECT_TFWSTR_EQ(&req->uri_path, "*");			\
	}

	/*
	 * Absolute URI.
	 * NOTE: we combine host and port URI parts into one field 'req->host'.
	 */
	TEST_FULL_REQ("natsys-lab.com", "");
	TEST_FULL_REQ("natsys-lab.com", "/");
	TEST_FULL_REQ("natsys-lab.com:8080", "");
	TEST_FULL_REQ("natsys-lab.com:8080", "/");
	TEST_FULL_REQ("natsys-lab.com", "/foo/");
	TEST_FULL_REQ("natsys-lab.com:8080", "/cgi-bin/show.pl?entry=tempesta");

	TEST_OPTIONS_ASTERISK();

	TEST_OPTIONS_WITHOUT_PATH("example.com");
	TEST_OPTIONS_WITHOUT_PATH("example.com:8080");
	TEST_OPTIONS_WITHOUT_PATH("tempesta-tech.com");

	FOR_REQ("OPTIONS http://tempesta-tech.com/home?name=value HTTP/1.1\r\n\r\n") {
		EXPECT_EQ(req->method, TFW_HTTP_METH_OPTIONS);
		EXPECT_TFWSTR_EQ(&req->host, "tempesta-tech.com");
		EXPECT_FALSE(tfw_str_eq_cstr(&req->uri_path, "*", 1, 0));
	}

	EXPECT_BLOCK_REQ("GET http://userame@natsys-lab.com HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET https://userame@natsys-lab.com HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET ws://userame@natsys-lab.com HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET wss://userame@natsys-lab.com HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://user@tempesta-tech.com/ HTTP/1.1\r\n"
			 "Host: bad.com\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://user@-x/ HTTP/1.1\r\n"
			 "Host: bad.com\r\n\r\n");

	FOR_REQ("GET http://tempesta-tech.com/ HTTP/1.1\r\n"
		"Host: bad.com\r\n\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->host, "tempesta-tech.com");
	}

	EXPECT_BLOCK_REQ("GET http:///path HTTP/1.1\r\nHost: localhost\r\n\r\n");

	FOR_REQ("OPTIONS * HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET sch://userame@natsys-lab.com HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("GET \x7f HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET /\x03uri HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET http://user@/ HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://user@:/url/ HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://user@: HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://tempesta-tech.com: HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://tempesta-tech.com:/ HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://user@/path HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://:443 HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://tempesta-tech.com: HTTP/1.1\r\n"
			 "Host: localhost\r\n\r\n");

	EXPECT_BLOCK_REQ("GET http://example.com?foo=1 HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("GET http://example.com:8080?foo=1 HTTP/1.1\r\n\r\n");

	EXPECT_BLOCK_REQ("OPTIONS *  HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("OPTIONS */asd HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("OPTIONS *HTTP/1.1\r\n\r\n");
	EXPECT_BLOCK_REQ("OPTIONS ** HTTP/1.1\r\n\r\n");

#undef TEST_FULL_REQ
#undef TEST_URI_PATH
#undef TEST_OPTIONS_WITHOUT_PATH
#undef TEST_OPTIONS_ASTERISK
}

TEST(http1_parser, parses_enforce_ext_req)
{
	FOR_REQ("GET / HTTP/1.1\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/index.html");
	}

	FOR_REQ("GET http://natsys-lab.com/ HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ("GET http://natsys-lab.com:8080/cgi-bin/show.pl HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"Cookie: session=42\r\n"
		"Accept: */*\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com:8080");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/cgi-bin/show.pl");
	}
}

/* TODO add HTTP attack examples. */
TEST(http1_parser, mangled_messages)
{
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "POST / HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ_SIMPLE("Host: test\r\n"
				"\x1fX-Foo: test");

	EXPECT_BLOCK_REQ_SIMPLE("Host: test\r\n"
				"Connection: close, \"foo\"");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			 "Content-Type: foo/aa-\x19np\r\n"
			 "\r\n");

	EXPECT_BLOCK_RESP_SIMPLE("X-Foo: t\x7fst");
}

/**
 * Test for allowed characters in different parts of HTTP message.
 */
TEST(http1_parser, alphabets)
{
	FOR_REQ("PUT / HTTP/1.1\r\n"
		"Host: test\r\n"
		/* We don't match open and closing quotes. */
		"Content-Type: Text/HTML;Charset=utf-8\"\t  \n"
		"Pragma: no-cache, fooo \r\n"
		"\r\n");

	/* Trailing SP in request. */
	FOR_REQ("PUT / HTTP/1.1\r\n"
		"Host: localhost\t  \r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\t  \r\n"
		"Accept: */*\t \r\n"
		"Connection: Keep-Alive \t \r\n"
		"X-Custom-Hdr: custom header values \t  \r\n"
		"X-Forwarded-For: 127.0.0.1, example.com    \t \r\n"
		"Forwarded: for=127.0.0.1;host=example.com    \t \r\n"
		"Content-Type: text/html; charset=iso-8859-1  \t \r\n"
		"Cache-Control: "
		"max-age=0, private, min-fresh=42 \t \r\n"
		"Transfer-Encoding: "
		"compress, deflate, gzip, chunked\t  \r\n"
		"Cookie: session=42; theme=dark  \t \r\n"
		"\r\n"
		"3\r\n"
		"123\r\n"
		"0\r\n"
		"\r\n");

	/* Trailing SP in response. */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		"Connection: Keep-Alive \t \r\n"
		"X-header: 6  \t  \t \r\n"
		"Content-Type: text/html; charset=iso-8859-1 \t \r\n"
		"Cache-Control: max-age=0, private, min-fresh=42 \t \r\n"
		"Expires: Tue, 31 Jan 2012 15:02:53 GMT \t \r\n"
		"Keep-Alive: timeout=600, max=65526 \t \r\n"
		"Transfer-Encoding: compress, deflate, gzip, chunked \t \r\n"
		"Server: Apache/2.4.6 (CentOS)  \t  \r\n"
		"\r\n"
		"4\r\n"
		"1234\r\n"
		"0\r\n"
		"\r\n");
}

/**
 * Test for case (in)sensitive matching of letters and special characters.
 */
TEST(http1_parser, casesense)
{
	FOR_REQ("PUT / HTTP/1.1\r\n"
		"hOST: test\r\n"
		"cAchE-CoNtRoL: no-cache\n"
		"x-fORWarDED-For: 1.1.1.1\r\n"
		"conTent-typE: chunked\r\n"
		"\r\n");

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		"aGE: 10\r\n"
		"cAchE-CoNtRoL: no-cache\n"
		"date: Tue, 31 Jan 2012 15:02:53 GMT \t \r\n"
		"eTaG: \"3f80f-1b6-3e1cb03b\"\r\n"
		"eXPIres: tue, 31 jan 2012 15:02:53 GMT \t \r\n"
		"coNTENt-TYPe: text/html; charset=iso-8859-1 \t \r\n"
		"Keep-Alive: timeout=600, max=65526 \t \r\n"
		"Transfer-Encoding: compress, deflate, gzip, chunked \t \r\n"
		"sERVER: Apache/2.4.6 (CentOS)  \t  \r\n"
		"\r\n"
		"4\r\n"
		"1234\r\n"
		"0\r\n"
		"\r\n");

	/*
	 * Check that we don't apply 0x20 mask to special characters.
	 */

	EXPECT_BLOCK_REQ_SIMPLE("Host\x1a test");
	EXPECT_BLOCK_REQ_SIMPLE("Cache-Control\x1a no-cache");
	EXPECT_BLOCK_REQ_SIMPLE("X-Forwarded-For\x1a 1.1.1.1");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded\x1a for=1.1.1.1");
	EXPECT_BLOCK_REQ_SIMPLE("Content-Type\x1a chunked");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Age\x1a\t10\r\n"
			  "\r\n"
			  "4\r\n");
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control\x1a no-cache");
	EXPECT_BLOCK_RESP_SIMPLE("date\x1a Tue, 31 Jan 2012 15:02:53 GMT");
	EXPECT_BLOCK_RESP_SIMPLE("Expires\x1a"
				 " Tue, 31 Jan 2012 15:02:53 GMT \t ");
	EXPECT_BLOCK_RESP_SIMPLE("eTaG\x1a \"3f80f-1b6-3e1cb03b\"");
	EXPECT_BLOCK_RESP_SIMPLE("Content-Type\x1a"
				 " text/html; charset=iso-8859-1");
	EXPECT_BLOCK_RESP_SIMPLE("Server\x1a Apache/2.4.6 (CentOS)");
}

/**
 * Test that we don't treat invalid token prefixes as allowed tokens.
 */
TEST(http1_parser, hdr_token_confusion)
{
	/*
	 * Headers must contain at least single character, otherwise
	 * message must be blocked.
	 */
	EXPECT_BLOCK_REQ_SIMPLE(": methodGET");
	EXPECT_BLOCK_REQ_SIMPLE(":methodGET");
	EXPECT_BLOCK_REQ_SIMPLE(":method GET");

	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  ": methodGET\r\n"
			  "\r\n");
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  ":methodGET\r\n"
			  "\r\n");
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  ":method GET\r\n"
			  "\r\n");
}

TEST(http1_parser, fills_hdr_tbl_for_req)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_accept, *h_xch, *h_dummy4, *h_dummy9, *h_cc, *h_pragma,
	       *h_auth;
	TfwStr h_host, h_connection, h_conttype, h_xff, h_user_agent, h_cookie,
	       h_te, h_fwd;

	/* Expected values for special headers. */
	const char *s_host = "localhost";
	const char *s_connection = "Keep-Alive";
	const char *s_xff = "127.0.0.1, example.com";
	const char *s_fwd = "host=127.0.0.1;proto=http";
	const char *s_ct = "text/html; charset=iso-8859-1";
	const char *s_user_agent = "Wget/1.13.4 (linux-gnu)";
	const char *s_cookie = "session=42; theme=dark";
	/* Expected values for raw headers. */
	const char *s_accept = "Accept: */*";
	const char *s_xch = "X-Custom-Hdr: custom header values";
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc  = "Cache-Control: "
		"max-age=1, dummy, no-store, min-fresh=30";
	const char *s_te  = "compress, gzip, chunked";
	/* Trailing spaces are stored within header strings. */
	const char *s_pragma =  "Pragma: no-cache, fooo ";
	const char *s_auth =  "Authorization: "
			      "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t ";

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
			 "Accept: */*\r\n"
			 "Host: localhost\r\n"
			 "Connection: Keep-Alive\r\n"
			 "X-Custom-Hdr: custom header values\r\n"
			 "Transfer-Encoding: compress, gzip, chunked\r\n"
			 "Cookie: session=42; theme=dark\r\n"
			 "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"
			 "\r\n"
			 "6\r\n"
			 "123456\r\n"
			 "0"
			 "\r\n\r\n")

	EXPECT_BLOCK_REQ("HEAD / HTTP/1.1\r\n"
			 "User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
			 "Accept: */*\r\n"
			 "Host: localhost\r\n"
			 "Connection: Keep-Alive\r\n"
			 "X-Custom-Hdr: custom header values\r\n"
			 "Transfer-Encoding: compress, gzip, chunked\r\n"
			 "Cookie: session=42; theme=dark\r\n"
			 "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"
			 "\r\n"
			 "6\r\n"
			 "123456\r\n"
			 "0"
			 "\r\n\r\n")

	FOR_REQ("POST / HTTP/1.1\r\n"
		"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
		"Accept: */*\r\n"
		"Host: localhost\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Custom-Hdr: custom header values\r\n"
		"X-Forwarded-For: 127.0.0.1, example.com\r\n"
		"Forwarded: host=127.0.0.1;proto=http\r\n"
		"Dummy0: 0\r\n"
		"Dummy1: 1\r\n"
		"Dummy2: 2\r\n"
		"Dummy3: 3\r\n"
		"Dummy4: 4\r\n"
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		/* That is done to check table reallocation. */
		"Dummy8: 8\r\n"
		"Dummy9: 9\r\n"
		"Cache-Control: "
		"max-age=1, dummy, no-store, min-fresh=30\r\n"
		"Pragma: no-cache, fooo \r\n"
		"Transfer-Encoding: compress, gzip, chunked\r\n"
		"Cookie: session=42; theme=dark\r\n"
		"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"
		"\r\n"
		"6\r\n"
		"123456\r\n"
		"0"
		"\r\n\r\n")
	{
		ht = req->h_tbl;

		/* Special headers: */
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_HOST],
					 TFW_HTTP_HDR_HOST, &h_host);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_CONNECTION],
					 TFW_HTTP_HDR_CONNECTION,
					 &h_connection);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
					 TFW_HTTP_HDR_CONTENT_TYPE,
					 &h_conttype);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR],
					 TFW_HTTP_HDR_X_FORWARDED_FOR, &h_xff);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_FORWARDED],
					 TFW_HTTP_HDR_FORWARDED, &h_fwd);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_USER_AGENT],
					 TFW_HTTP_HDR_USER_AGENT,
					 &h_user_agent);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING],
					 TFW_HTTP_HDR_TRANSFER_ENCODING, &h_te);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_COOKIE],
					 TFW_HTTP_HDR_COOKIE, &h_cookie);

		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 15);

		h_accept = &ht->tbl[TFW_HTTP_HDR_RAW + 0];
		h_xch = &ht->tbl[TFW_HTTP_HDR_RAW + 1];
		h_dummy4 = &ht->tbl[TFW_HTTP_HDR_RAW + 6];
		h_dummy9 = &ht->tbl[TFW_HTTP_HDR_RAW + 11];
		h_cc = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_pragma = &ht->tbl[TFW_HTTP_HDR_RAW + 13];
		h_auth = &ht->tbl[TFW_HTTP_HDR_RAW + 14];

		EXPECT_TFWSTR_EQ(&h_host, s_host);
		EXPECT_TFWSTR_EQ(&h_connection, s_connection);
		EXPECT_TFWSTR_EQ(&h_conttype, s_ct);
		EXPECT_TFWSTR_EQ(&h_xff, s_xff);
		EXPECT_TFWSTR_EQ(&h_fwd, s_fwd);
		EXPECT_TFWSTR_EQ(&h_user_agent, s_user_agent);
		EXPECT_TFWSTR_EQ(&h_te, s_te);
		EXPECT_TFWSTR_EQ(&h_cookie, s_cookie);

		EXPECT_TFWSTR_EQ(h_accept, s_accept);
		EXPECT_TFWSTR_EQ(h_xch, s_xch);
		EXPECT_TFWSTR_EQ(h_dummy4, s_dummy4);
		EXPECT_TFWSTR_EQ(h_dummy9, s_dummy9);
		EXPECT_TFWSTR_EQ(h_cc, s_cc);
		EXPECT_TFWSTR_EQ(h_pragma, s_pragma);
		EXPECT_TFWSTR_EQ(h_auth, s_auth);

		EXPECT_TRUE(req->content_length == 0);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_HDR_AUTHORIZATION);
		EXPECT_TRUE(ht->tbl[TFW_HTTP_HDR_HOST].eolen == 2);
	}
}

TEST(http1_parser, fills_hdr_tbl_for_resp)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_dummy4, *h_dummy9, *h_cc, *h_date, *h_exp;
	TfwStr *h_lastmodified, *h_pragma;
	TfwStr h_connection, h_conttype, h_srv, h_te, h_ka, h_etag, h_age;
	TfwStr h_setcookie;

	/* Expected values for special headers. */
	const char *s_connection = "Keep-Alive";
	const char *s_ct = "text/html; charset=iso-8859-1";
	const char *s_srv = "Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"
			    " mod_fcgid/2.3.9";
	const char *s_etag = "W/\"0815\" ";
	const char *s_setcookie = "__Host-id=1; Secure; Path=/; domain=example.com ";
	/* Expected values for raw headers. */
	const char *s_dummy9 = "Dummy9: 9";
	const char *s_dummy4 = "Dummy4: 4";
	const char *s_cc = "Cache-Control: "
		"max-age=5, private, no-cache, no-cache=\"fieldname\", ext=foo";
	const char *s_te = "compress, gzip, chunked";
	const char *s_exp = "Expires: Tue, 31 Jan 2012 15:02:53 GMT";
	const char *s_ka = "timeout=600, max=65526";
	/* Trailing spaces are stored within header strings. */
	const char *s_age = "12  ";
	const char *s_date = "Date: Sun, 09 Sep 2001 01:46:40 GMT\t";
	const char *s_lastmodified =
		"Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT ";
	const char *s_pragma = "Pragma: no-cache ";

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		"Connection: Keep-Alive\r\n"
		"Dummy0: 0\r\n"
		"Dummy1: 1\r\n"
		"Dummy2: 2\r\n"
		"Dummy3: 3\r\n"
		"Dummy4: 4\r\n"
		"Dummy5: 5\r\n"
		"Dummy6: 6\r\n"
		"Content-Type: text/html; charset=iso-8859-1\r\n"
		"Dummy7: 7\r\n"
		"Dummy8: 8\r\n"
		"Cache-Control: "
		"max-age=5, private, no-cache, no-cache=\"fieldname\", ext=foo\r\n"
		"Dummy9: 9\r\n" /* That is done to check table reallocation. */
		"Expires: Tue, 31 Jan 2012 15:02:53 GMT\r\n"
		"Keep-Alive: timeout=600, max=65526\r\n"
		"Transfer-Encoding: compress, gzip, chunked\r\n"
		"Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"
			" mod_fcgid/2.3.9\r\n"
		"Age: 12  \n"
		"Date: Sun, 09 Sep 2001 01:46:40 GMT\t\n"
		"ETag: W/\"0815\" \r\n"
		"Set-Cookie: __Host-id=1; Secure; Path=/; domain=example.com \r\n"
		"Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT \r\n"
		"Pragma: no-cache \r\n"
		"\r\n"
		"3\r\n"
		"012\r\n"
		"0\r\n"
		"\r\n")
	{
		ht = resp->h_tbl;

		EXPECT_TFWSTR_EQ(&ht->tbl[TFW_HTTP_STATUS_LINE],
				 "HTTP/1.1 200 OK");

		/* Special headers: */
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONNECTION],
					TFW_HTTP_HDR_CONNECTION,
					&h_connection);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
					TFW_HTTP_HDR_CONTENT_TYPE,
					&h_conttype);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_SERVER],
					TFW_HTTP_HDR_SERVER, &h_srv);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_TRANSFER_ENCODING],
					TFW_HTTP_HDR_TRANSFER_ENCODING, &h_te);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_KEEP_ALIVE],
					TFW_HTTP_HDR_KEEP_ALIVE, &h_ka);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_ETAG],
					TFW_HTTP_HDR_ETAG,
					&h_etag);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_SET_COOKIE],
					TFW_HTTP_HDR_SET_COOKIE,
					&h_setcookie);
		tfw_http_msg_srvhdr_val(&ht->tbl[TFW_HTTP_HDR_AGE],
					TFW_HTTP_HDR_AGE,
					&h_age);

		/*
		 * Common (raw) headers: 10 dummies, Cache-Control,
		 * Expires, Age, Date.
		 */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 15);

		h_dummy4 = &ht->tbl[TFW_HTTP_HDR_RAW + 4];
		h_cc = &ht->tbl[TFW_HTTP_HDR_RAW + 9];
		h_dummy9 = &ht->tbl[TFW_HTTP_HDR_RAW + 10];
		h_exp = &ht->tbl[TFW_HTTP_HDR_RAW + 11];
		h_date = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_lastmodified = &ht->tbl[TFW_HTTP_HDR_RAW + 13];
		h_pragma = &ht->tbl[TFW_HTTP_HDR_RAW + 14];

		EXPECT_TFWSTR_EQ(&h_connection, s_connection);
		EXPECT_TFWSTR_EQ(&h_conttype, s_ct);
		EXPECT_TFWSTR_EQ(&h_srv, s_srv);
		EXPECT_TFWSTR_EQ(&h_te, s_te);
		EXPECT_TFWSTR_EQ(&h_ka, s_ka);
		EXPECT_TFWSTR_EQ(&h_etag, s_etag);
		EXPECT_TFWSTR_EQ(&h_setcookie, s_setcookie);
		EXPECT_TFWSTR_EQ(&h_age, s_age);

		EXPECT_TFWSTR_EQ(h_dummy4, s_dummy4);
		EXPECT_TFWSTR_EQ(h_cc, s_cc);
		EXPECT_TFWSTR_EQ(h_dummy9, s_dummy9);
		EXPECT_TFWSTR_EQ(h_exp, s_exp);
		EXPECT_TFWSTR_EQ(h_date, s_date);
		EXPECT_TFWSTR_EQ(h_lastmodified, s_lastmodified);
		EXPECT_TFWSTR_EQ(h_pragma, s_pragma);

		EXPECT_TRUE(resp->keep_alive == 600);
		EXPECT_TRUE(h_dummy9->eolen == 2);
	}
}

TEST(http1_parser, cache_control)
{
	TfwStr dummy_header = { .data = "dummy:", .len = SLEN("dummy:") };

	EXPECT_BLOCK_REQ_RESP_SIMPLE("Cache-Control: ");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("Cache-Control: no-cache no-store");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("Cache-Control: dummy0 dummy1");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("Cache-Control: ,,");

	FOR_REQ(EMPTY_REQ)
	{
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_MIN_FRESH);
		EXPECT_FALSE(req->cache_ctl.flags & TFW_HTTP_CC_OIFCACHED);
	}

	FOR_RESP(EMPTY_RESP)
	{
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_MUST_REVAL);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PROXY_REVAL);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PUBLIC);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PRIVATE);
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_S_MAXAGE);
	}

	FOR_REQ_RESP_SIMPLE("Cache-Control: nO-caChE, NO-stOre, "
			    "no-TRansfORm, MAx-age=4", {
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(msg->cache_ctl.max_age == 4);
	});

	/* Cache Control Extensions, not strict compliance with RFC. */
	FOR_REQ_RESP_SIMPLE("Cache-Control: " QETOKEN_ALPHABET ", no-cache, "
			    QETOKEN_ALPHABET ", no-store, "
			    "no-transform, max-age=12, " QETOKEN_ALPHABET, {
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(msg->cache_ctl.max_age == 12);
	});

	FOR_REQ_RESP_SIMPLE(
		"Cache-Control: dummy0, dummy1, dummy1-5, dummy1-6, "
		"dummy2, dummy3, dummy4, no-store, dummy5, no-cache, "
		"dummy6, dummy7, dummy8, dummy9, dummy10, dummy11, "
		"dummy12, dummy13, dummy14, dummy15, dummy16, dummy17, "
		"dummy18, dummy19, dummy20, dummy21, dummy22, dummy23, "
		"dummy24, dummy25, dummy26, dummy27, dummy28, dummy29, "
		"dummy30, dummy31, dummy32, dummy33, dummy34, dummy35, "
		"dummy36, dummy37, dummy38, dummy39, dummy40, dummy41, "
		"dummy42, dummy43, dummy44, dummy45, dummy46, dummy47, "
		"dummy48, dummy49, dummy50, dummy51, dummy52, dummy53, "
		"dummy54, dummy55, dummy56, dummy57, dummy58, dummy59, "
		"dummy60, dummy61, dummy62, dummy63, dummy64, dummy65, "
		"dummy66, dummy67, dummy68, dummy69, dummy70, dummy71, "
		"dummy72, dummy73, dummy74, dummy75, dummy76, dummy77, "
		"dummy78, dummy79, dummy80, dummy81, dummy82, dummy83, "
		"dummy84, dummy85, no-transform, dummy87, dummy88, dummy89, "
		"dummy90, dummy91, dummy92, dummy93, dummy94, dummy95, "
		"dummy96, dummy97, dummy98, max-age=14, dummy100, dummy101, "
		"dummy102, dummy103, dummy104, dummy105, dummy106, dummy107, "
		"dummy108, dummy109, dummy110, dummy111, dummy112, dummy113, "
		"dummy114, dummy115, dummy116, dummy117, dummy118, dummy119, "
		"dummy120, dummy121, dummy122, dummy123, dummy124, dummy125, "
		"dummy126, dummy127, chunked", {
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_TRUE(msg->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(msg->cache_ctl.max_age == 14);
	});

#define TEST_COMMON(directive, flag, MSG_UPPER, MSG_LOWER)		\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive)		\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control: ," directive)		\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control: , " directive)		\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control: " directive ",")	\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:1" directive)		\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive directive)	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:no-store" directive)	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "\"")	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive " = dummy");

#define TEST_HAVING_ARGUMENT(directive, flag, field, MSG_UPPER, MSG_LOWER)	\
	TEST_COMMON(directive, flag, MSG_UPPER, MSG_LOWER);			\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=");	\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=1");	\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=\"")	;\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=\"dummy");\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=dummy");	\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive		\
					  "=\",,\"");				\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive		\
				 "=\"dummy, ,\"");				\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive		\
				 "=\", dummy\"")			\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
		EXPECT_TRUE(MSG_LOWER->field.nchunks != 0);		\
		EXPECT_TRUE(tfw_stricmpspn(&MSG_LOWER->field.chunks[0],	\
					    &dummy_header, ':') == 0);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive		\
				 "=\"dummy,\"")				\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
		EXPECT_TRUE(MSG_LOWER->field.nchunks != 0);		\
		EXPECT_TRUE(tfw_stricmpspn(&MSG_LOWER->field.chunks[0],	\
					    &dummy_header, ':') == 0);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive		\
				 "=\"" TOKEN_ALPHABET "\"")		\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
		EXPECT_TRUE(MSG_LOWER->field.nchunks != 0);		\
	}

#define TEST_NO_ARGUMENT(directive, flag, MSG_UPPER, MSG_LOWER)		\
	TEST_COMMON(directive, flag, MSG_UPPER, MSG_LOWER);		\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=")	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=1")	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=\"")	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=dummy")	\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive		\
				 "=\"dummy\"")				\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
	}

#define TEST_SECONDS(directive, flag, FIELD, MSG_UPPER, MSG_LOWER)	\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=0")	\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.FIELD == 0);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=0000")	\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.FIELD == 0);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=4294967295")\
	{								\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.flags & flag);		\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.FIELD == 4294967295);	\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:" directive directive"=5")\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.FIELD == 0);		\
	}								\
	FOR_##MSG_UPPER##_SIMPLE("Cache-Control:no-store" directive "=5")\
	{								\
		EXPECT_FALSE(MSG_LOWER->cache_ctl.flags & flag);	\
		EXPECT_TRUE(MSG_LOWER->cache_ctl.FIELD == 0);		\
	}								\
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive " = dummy");  \
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive " = 0");      \
	EXPECT_BLOCK_##MSG_UPPER##_SIMPLE("Cache-Control:" directive "=10 10");    \

	/*
	 * RFC 7234 4.2.1:
	 *
	 * When there is more than one value present for a given directive
	 * (e.g., two Expires header fields, multiple Cache-Control: max-age
	 * directives), the directive's value is considered invalid.
	 */
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control: max-age=4\r\n"
				 "Cache-Control: max-age=4");
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control: max-age=4, max-age=4, "
				 "max-age=4");
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control: max-age=4\r\n"
				 "Cache-Control: max-age=4, max-age=4");
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control: s-maxage=4\r\n"
				 "Cache-Control: s-maxage=4");
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control: s-maxage=4, s-maxage=4, "
				 "s-maxage=4");
	EXPECT_BLOCK_RESP_SIMPLE("Cache-Control: s-maxage=4\r\n"
				 "Cache-Control: s-maxage=4, s-maxage=4");

	/*
	 * RFC 7234 5.2.1.2:
	 *
	 * If no value is
	 * assigned to max-stale, then the client is willing to accept a stale
	 * response of any age.
	 */
	FOR_REQ_SIMPLE("Cache-Control: max-stale")
	{
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE);
		EXPECT_TRUE(req->cache_ctl.max_stale == UINT_MAX);
	}

	/* Request directives. */
	TEST_NO_ARGUMENT("no-cache", TFW_HTTP_CC_NO_CACHE, REQ, req);
	TEST_NO_ARGUMENT("no-store", TFW_HTTP_CC_NO_STORE, REQ, req);
	TEST_NO_ARGUMENT("no-transform", TFW_HTTP_CC_NO_TRANSFORM, REQ, req);

	TEST_SECONDS("max-age", TFW_HTTP_CC_MAX_AGE, max_age, REQ, req);
	TEST_SECONDS("max-stale", TFW_HTTP_CC_MAX_STALE, max_stale, REQ, req);
	TEST_SECONDS("min-fresh", TFW_HTTP_CC_MIN_FRESH, min_fresh, REQ, req);
	EXPECT_BLOCK_DIGITS("Cache-Control: max-age=", "",
			    EXPECT_BLOCK_REQ_SIMPLE);
	EXPECT_BLOCK_DIGITS("Cache-Control: max-stale=", "",
			    EXPECT_BLOCK_REQ_SIMPLE);
	EXPECT_BLOCK_DIGITS("Cache-Control: min-fresh=", "",
			    EXPECT_BLOCK_REQ_SIMPLE);

	/* Response directives. */
	TEST_NO_ARGUMENT("only-if-cached", TFW_HTTP_CC_OIFCACHED, REQ, req);
	TEST_HAVING_ARGUMENT("no-cache", TFW_HTTP_CC_NO_CACHE, no_cache_tokens,
			     RESP, resp);
	TEST_NO_ARGUMENT("no-store", TFW_HTTP_CC_NO_STORE, RESP, resp);
	TEST_NO_ARGUMENT("no-transform", TFW_HTTP_CC_NO_TRANSFORM, RESP, resp);
	TEST_NO_ARGUMENT("must-revalidate", TFW_HTTP_CC_MUST_REVAL, RESP, resp);
	TEST_NO_ARGUMENT("proxy-revalidate", TFW_HTTP_CC_PROXY_REVAL, RESP, resp);
	TEST_NO_ARGUMENT("public", TFW_HTTP_CC_PUBLIC, RESP, resp);

	TEST_HAVING_ARGUMENT("private", TFW_HTTP_CC_PRIVATE, private_tokens,
			     RESP, resp);
	TEST_SECONDS("max-age", TFW_HTTP_CC_MAX_AGE, max_age, RESP, resp);
	TEST_SECONDS("s-maxage", TFW_HTTP_CC_S_MAXAGE, s_maxage, RESP, resp);
	EXPECT_BLOCK_DIGITS("Cache-Control: max-age=", "",
			    EXPECT_BLOCK_RESP_SIMPLE);
	EXPECT_BLOCK_DIGITS("Cache-Control: s-maxage=", "",
			    EXPECT_BLOCK_RESP_SIMPLE);

#undef TEST_SECONDS
#undef TEST_NO_ARGUMENT
#undef TEST_HAVING_ARGUMENT
#undef TEST_COMMON
}

TEST(http1_parser, status)
{
#define EXPECT_BLOCK_STATUS(status)				\
	EXPECT_BLOCK_RESP("HTTP/1.0" status "OK\r\n"		\
			  "Content-Length: 0\r\n\r\n")

	FOR_RESP("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	{
		EXPECT_TRUE(resp->status == 200);
	}
	FOR_RESP("HTTP/1.0 65535 OK\r\nContent-Length: 0\r\n\r\n")
	{
		EXPECT_TRUE(resp->status == 65535);
	}

	/* The rest is interpreted as reason-phrase. */
	FOR_RESP("HTTP/1.0 200 200 OK\r\nContent-Length: 0\r\n\r\n")
	{
		EXPECT_TRUE(resp->status == 200);
	}
	FOR_RESP("HTTP/1.0 200, 200 OK\r\nContent-Length: 0\r\n\r\n")
	{
		EXPECT_TRUE(resp->status == 200);
	}

	EXPECT_BLOCK_STATUS("\t200 ");
	EXPECT_BLOCK_STATUS("200 ");
	EXPECT_BLOCK_STATUS(" 200");
	EXPECT_BLOCK_DIGITS("HTTP/1.0 ", " OK\r\nContent-Length: 0\r\n\r\n",
			    EXPECT_BLOCK_RESP);
	EXPECT_BLOCK_SHORT("HTTP/1.0 ", " OK\r\nContent-Length: 0\r\n\r\n",
			   EXPECT_BLOCK_RESP);

#undef EXPECT_BLOCK_STATUS
}

TEST(http1_parser, age)
{
	FOR_RESP_SIMPLE("Age:0")
	{
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_HDR_AGE);
		EXPECT_TRUE(resp->cache_ctl.age == 0);
	}

	FOR_RESP_SIMPLE("Age:0007")
	{
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_HDR_AGE);
		EXPECT_TRUE(resp->cache_ctl.age == 7);
	}

	FOR_RESP_SIMPLE("Age:\t 7\t \t")
	{
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_HDR_AGE);
		EXPECT_TRUE(resp->cache_ctl.age == 7);
	}

	FOR_RESP_SIMPLE("Age: 4294967295")
	{
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_HDR_AGE);
		EXPECT_TRUE(resp->cache_ctl.age == 4294967295);
	}

	EXPECT_BLOCK_DIGITS("Age:", "", EXPECT_BLOCK_RESP_SIMPLE);
}

TEST(http1_parser, pragma)
{
#define ONLY_PRAGMA(header)							\
	FOR_RESP_SIMPLE(header)							\
	{									\
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PRIVATE);	\
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);	\
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);	\
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);\
	}

	ONLY_PRAGMA("Pragma: no-cache");
	ONLY_PRAGMA("Pragma: no-cache, foo");
	ONLY_PRAGMA("Pragma: no-cache foo");
	ONLY_PRAGMA("Pragma: no-cache\r\nDummy: foo");

	FOR_RESP_SIMPLE("Pragma: nocache")
	{
		/* Contents of "Pragma" is not "no-cache" exactly. */
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);
	}


	FOR_RESP_SIMPLE("Pragma: no-cacheX, fooo")
	{
		EXPECT_FALSE(resp->cache_ctl.flags & TFW_HTTP_CC_PRAGMA_NO_CACHE);
	}

#undef ONLY_PRAGMA
}

TEST(http1_parser, suspicious_x_forwarded_for)
{
	FOR_REQ_SIMPLE("X-Forwarded-For:   [::1]:1234,5.6.7.8   ,"
		       "  natsys-lab.com:65535  ")
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		EXPECT_GT(h->len, 0);
	}

	EXPECT_BLOCK_REQ_SIMPLE("X-Forwarded-For: 1.2.3.4, , 5.6.7.8");
	EXPECT_BLOCK_REQ_SIMPLE("X-Forwarded-For: foo!");
	EXPECT_BLOCK_REQ_SIMPLE("X-Forwarded-For: ");
}

TEST(http1_parser, parses_connection_value)
{
	FOR_REQ_SIMPLE("Connection: Keep-Alive")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: keep-alive")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: Close")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: close")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: Dummy")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: Close, Dummy")
	{
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: Keep-Alive, Dummy")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	EXPECT_BLOCK_REQ_SIMPLE("Connection: Close, Keep-Alive");


	FOR_REQ_SIMPLE("Connection: closekeep-alive")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: keep-alive1")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
	}

	FOR_REQ_SIMPLE("Connection: upgrade")
	{
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_CLOSE, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_KA, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CONN_EXTRA, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CONN_UPGRADE, req->flags));
	}
}

TEST(http_parser, upgrade)
{
	FOR_REQ_SIMPLE("Upgrade: websocket")
	{
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_UPGRADE],
				 "Upgrade: websocket");
		EXPECT_TRUE(test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags));
	}

	FOR_REQ_SIMPLE("Upgrade: h2c, quic")
	{
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_UPGRADE],
				 "Upgrade: h2c, quic");
		EXPECT_FALSE(test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET,
				      req->flags));
	}

	FOR_REQ_SIMPLE("Upgrade: websocket, h2c")
	{
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_UPGRADE],
				 "Upgrade: websocket, h2c");
		EXPECT_TRUE(test_bit(TFW_HTTP_B_UPGRADE_WEBSOCKET, req->flags));
	}

	FOR_REQ_SIMPLE("Upgrade: h2c , websocket");
	FOR_REQ_SIMPLE("Upgrade: h2c,  websocket");
	EXPECT_BLOCK_REQ_SIMPLE("Upgrade: /websocket");
	EXPECT_BLOCK_REQ_SIMPLE("Upgrade: , websocket");
	EXPECT_BLOCK_REQ_SIMPLE("Upgrade: websocket/");
	EXPECT_BLOCK_REQ_SIMPLE("Upgrade: websocket/, h2c");

}

#define EXPECT_BLOCK_BODYLESS_REQ(METHOD)					\
	EXPECT_BLOCK_REQ(#METHOD " / HTTP/1.1\r\n"				\
			 "Content-Length: 1\r\n"				\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}									\
	EXPECT_BLOCK_REQ(#METHOD " / HTTP/1.1\r\n"				\
			 "Content-Type: text/html\r\n"				\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE(METHOD)				\
	EXPECT_BLOCK_REQ("PUT / HTTP/1.1\r\n"					\
			 "Content-Length: 1\r\n"				\
			 "X-Method-Override: " #METHOD "\r\n"			\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ("PUT / HTTP/1.1\r\n"					\
			 "Content-Length: 1\r\n"				\
			 "X-HTTP-Method-Override: " #METHOD "\r\n"		\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ("PUT / HTTP/1.1\r\n"					\
			 "Content-Length: 1\r\n"				\
			 "X-HTTP-Method: " #METHOD "\r\n"			\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ("PUT / HTTP/1.1\r\n"					\
			 "Content-Type: text/html\r\n"				\
			 "X-Method-Override: " #METHOD "\r\n"			\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ("PUT / HTTP/1.1\r\n"					\
			 "Content-Type: text/html\r\n"				\
			 "X-HTTP-Method-Override: " #METHOD "\r\n"		\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ("PUT / HTTP/1.1\r\n"					\
			 "Content-Type: text/html\r\n"				\
			 "X-HTTP-Method: " #METHOD "\r\n"			\
			 "\r\n")						\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}

TEST_MPART(http1_parser, content_type_in_bodyless_requests, 0)
{
	EXPECT_BLOCK_BODYLESS_REQ(GET);
	EXPECT_BLOCK_BODYLESS_REQ(HEAD);
}


TEST_MPART(http1_parser, content_type_in_bodyless_requests, 1)
{
	EXPECT_BLOCK_BODYLESS_REQ(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ(TRACE);
}

TEST_MPART(http1_parser, content_type_in_bodyless_requests, 2)
{
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE(GET);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE(HEAD);
}

TEST_MPART(http1_parser, content_type_in_bodyless_requests, 3)
{
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE(TRACE);

	FOR_REQ("OPTIONS / HTTP/1.1\r\n"
		"Content-Type: text/plain\r\n"
		"\r\n")
	{
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain");
	}
}

#undef EXPECT_BLOCK_BODYLESS_REQ
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE

TEST_MPART_DEFINE(http1_parser, content_type_in_bodyless_requests,
		  H1_CT_BODYLESS_TCNT,
		  TEST_MPART_NAME(http1_parser,
				  content_type_in_bodyless_requests, 0),
		  TEST_MPART_NAME(http1_parser,
				  content_type_in_bodyless_requests, 1),
		  TEST_MPART_NAME(http1_parser,
				  content_type_in_bodyless_requests, 2),
		  TEST_MPART_NAME(http1_parser,
				  content_type_in_bodyless_requests, 3));


TEST(http1_parser, content_length)
{
	/* Content-Length is mandatory for responses. */
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n\r\n");

	/* Content-Length greater than zero must not be present in GET requests */
	EXPECT_BLOCK_REQ_SIMPLE("Content-Length: 1");

	/* Content-Length: 0 treats as the absence of a Content-Length. */
	FOR_REQ("GET / HTTP/1.1\r\n"
		"Content-Length: 0\r\n"
		"\r\n")
	{
		EXPECT_TRUE(req->content_length == 0);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"Content-Length: 0\r\n"
		"\r\n")
	{
		EXPECT_TRUE(req->content_length == 0);
	}

	FOR_RESP("HTTP/1.0 200 OK\r\n"
		 "Content-Length: 0\r\n"
		 "\r\n")
	{
		EXPECT_TRUE(resp->content_length == 0);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"Content-Length: 5\r\n"
		"\r\n"
		"dummy")
	{
		EXPECT_TRUE(req->content_length == 5);
	}
	FOR_RESP("HTTP/1.0 200 OK\r\n"
		 "Content-Length: 5\r\n"
		 "\r\n"
		 "dummy")
	{
		EXPECT_TRUE(resp->content_length == 5);
	}

	EXPECT_BLOCK_REQ_SIMPLE("Content-Length: 5");

	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 5\r\n"
			  "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Content-Length: 10\r\n"
			 "\r\n"
			 "dummy");
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 10\r\n"
			  "\r\n"
			  "dummy");

	/*
	 * RFC 7230 3.3.2:
	 *
	 * A server MAY send a Content-Length header field in a response to a
	 * HEAD request (Section 4.3.2 of [RFC7231])
	 */
	set_sample_req("HEAD / HTTP/1.1\r\n\r\n");
	FOR_RESP("HTTP/1.0 200 OK\r\n"
		 "Content-Length: 1000\r\n"
		 "\r\n")
	{
		EXPECT_TRUE(resp->content_length == 1000);
	}
	set_sample_req(SAMPLE_REQ_STR);

	EXPECT_BLOCK_DIGITS("GET / HTTP/1.1\r\nContent-Length: ",
			    "\r\n\r\ndummy", EXPECT_BLOCK_REQ);
	EXPECT_BLOCK_DIGITS("HTTP/1.0 200 OK\r\nContent-Length: ",
			    "\r\n\r\ndummy", EXPECT_BLOCK_RESP);

	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"
			 "Content-Length: 10, 10\r\n"
			 "\r\n"
			 "0123456789");
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 10, 10\r\n"
			  "\r\n"
			  "0123456789");

	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"
			 "Content-Length: 10 10\r\n"
			 "\r\n"
			 "0123456789");
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 10 10\r\n"
			  "\r\n"
			  "0123456789");

	EXPECT_BLOCK_REQ("POST / HTTP/1.1"
				"Content-Length: 0\r\n"
				"Content-Length: 0");
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 0\r\n"
			  "Content-Length: 0\r\n"
			  "\r\n");

	/*
	 * All 1xx (Informational), 204 (No Content), and 304 (Not Modified)
	 * responses do not include a message body
	 */
	EXPECT_BLOCK_RESP("HTTP/1.1 101 Switching Protocols\r\n"
			  "Content-Length: 5\r\n"
			  "\r\n"
			  "dummy");
	EXPECT_BLOCK_RESP("HTTP/1.1 101 Switching Protocols\r\n"
			  "Content-Length: 1\r\n"
			  "\r\n");

	EXPECT_BLOCK_RESP("HTTP/1.1 199 Dummy\r\n"
			  "Content-Length: 5\r\n"
			  "\r\n"
			  "dummy");
	EXPECT_BLOCK_RESP("HTTP/1.1 199 Dummy\r\n"
			  "Content-Length: 1\r\n"
			  "\r\n");

	EXPECT_BLOCK_RESP("HTTP/1.0 204 No Content\r\n"
			  "Content-Length: 5\r\n"
			  "\r\n"
			  "dummy");
	EXPECT_BLOCK_RESP("HTTP/1.0 204 No Content\r\n"
			  "Content-Length: 1\r\n"
			  "\r\n");

	FOR_RESP("HTTP/1.0 205 Reset Content\r\n"
		 "Content-Length: 5\r\n"
		 "\r\n"
		 "dummy");
	FOR_RESP("HTTP/1.0 205 Reset Content\r\n"
		 "Content-Length: 0\r\n"
		 "\r\n");

	/*
	 * A server MAY send a Content-Length header field in a 304
	 * (Not Modified) response to a conditional GET request.
	 */
#define NOT_PARSED "dummy_body"
#define RESP	"HTTP/1.1 304 Not Modified\r\n"		\
		"Content-Length: 5\r\n"			\
		"\r\n"					\
		NOT_PARSED

	/* Hence 304 response can't have a body, the body is not parsed. */
	__FOR_RESP(RESP, sizeof(NOT_PARSED) - 1, CHUNK_ON);

	FOR_RESP("HTTP/1.1 304 Not Modified\r\n"
		 "Content-Length: 5\r\n"
		 "\r\n");

	FOR_RESP("HTTP/1.1 305 Use Proxy\r\n"
		 "Content-Length: 5\r\n"
		 "\r\n"
		 "dummy");

#undef NOT_PARSED
#undef RESP
}

TEST(http1_parser, eol_crlf)
{
	EXPECT_BLOCK_REQ("\rGET / HTTP/1.1\r\n"
			 "Host: d.com\r\n"
			 "\r\n");

	__FOR_REQ("POST / HTTP/1.1\n"
		  "Host: a.com\n"
		  "Content-Length: 5\n"
		  "\n"
		  "a=24\n"
		  "\n",  /* the LF is ignored. */
		  1, CHUNK_ON)
	{
		TfwHttpHdrTbl *ht = req->h_tbl;

		EXPECT_TRUE(req->crlf.len == 1);
		EXPECT_TRUE(req->body.len == 5);
		EXPECT_TRUE(ht->tbl[TFW_HTTP_HDR_HOST].eolen == 1);
		EXPECT_TRUE(ht->tbl[TFW_HTTP_HDR_CONTENT_LENGTH].eolen == 1);
	}

	__FOR_REQ("POST / HTTP/1.1\n"
		  "Host: b.com\n"
		  "Content-Length: 6\n"
		  "\r\n"
		  "b=24\r\n"
		  "\r\n",  /* the CRLF is ignored. */
		  2, CHUNK_ON)
	{
		EXPECT_TRUE(req->crlf.len == 2);
		EXPECT_TRUE(req->body.len == 6);
	}

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\r\n"
			 "Host: c.com\r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET\r/ HTTP/1.1\r\n"
			 "Host: e.com\r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: f.com\r\r\n"
			 "\r\n");
	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host: g.com\r\r\n"
			 "\r\r\n");
}

TEST(http1_parser, ows)
{
	FOR_REQ("GET /a.html HTTP/1.1\r\n"
		"Host: 		 foo.com 	\r\n"
		"Connection:   close   \r\n"
		"Cookie: 	a=5	 \r\n"
		"X-Forwarded-For:   1.2.3.4   \r\n"
		"\n");

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10  	\r\n"
		 "Age:   12   \r\n"
		"\n"
		"0123456789");

	FOR_REQ_SIMPLE("Host:foo.com");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 "Host :foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET	/ HTTP/1.1\r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET /\tHTTP/1.1\r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1 \r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\t\r\n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r \n"
			 "Host: foo.com\r\n"
			 "\r\n");

	EXPECT_BLOCK_REQ("GET / HTTP/1.1\r\n"
			 " Host: foo.com\r\n"
			 "\r\n");
}

TEST(http1_parser, folding)
{
	EXPECT_BLOCK_REQ_SIMPLE("Host:    \r\n"
				"   foo.com\r\n"
				"Connection: close");

	EXPECT_BLOCK_REQ_SIMPLE("Host: 	foo.com\r\n"
				"Connection:\n"
				"	close");
}

TEST(http1_parser, accept)
{
#define __FOR_ACCEPT(accept_val, EXPECT_HTML_MACRO)			\
	FOR_REQ_SIMPLE("Accept:" accept_val)				\
	{								\
		EXPECT_HTML_MACRO(test_bit(TFW_HTTP_B_ACCEPT_HTML,	\
					   req->flags));		\
	}

#define FOR_ACCEPT(accept_val)		__FOR_ACCEPT(accept_val, EXPECT_FALSE)
#define FOR_ACCEPT_HTML(accept_val)	__FOR_ACCEPT(accept_val, EXPECT_TRUE)
#define EXPECT_BLOCK_ACCEPT(header)	EXPECT_BLOCK_REQ_SIMPLE("Accept:"header)

#define TEST_ACCEPT_EXT(HEAD)						\
	FOR_ACCEPT(HEAD ";key=val");					\
	FOR_ACCEPT(HEAD ";" TOKEN_ALPHABET "=" TOKEN_ALPHABET);		\
	FOR_ACCEPT(HEAD ";" TOKEN_ALPHABET "=\"" TOKEN_ALPHABET "\"");	\
	FOR_ACCEPT(HEAD ";key=\"\"");					\
	FOR_ACCEPT(HEAD "  ; \t key=val");				\
	FOR_ACCEPT(HEAD ";key=val;key=val");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";");					\
	EXPECT_BLOCK_ACCEPT(HEAD ";;");					\
	EXPECT_BLOCK_ACCEPT(HEAD ";key=\"");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";key=\"\"\"");			\
	EXPECT_BLOCK_ACCEPT(HEAD ";key=\"val");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";key=val\"");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";key=");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";key==");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";key =val");				\
	EXPECT_BLOCK_ACCEPT(HEAD ";\"key\"=val");			\
	EXPECT_BLOCK_ACCEPT(HEAD ";key= val");				\
	EXPECT_BLOCK_ACCEPT(HEAD " key=val");				\
	EXPECT_BLOCK_ACCEPT(HEAD "key=val");

	/* media-range */
	FOR_ACCEPT("*/*");
	FOR_ACCEPT("dummy/*");
	FOR_ACCEPT("dummy/dummy");
	FOR_ACCEPT(TOKEN_ALPHABET "/" TOKEN_ALPHABET);

	EXPECT_BLOCK_ACCEPT("");
	EXPECT_BLOCK_ACCEPT(" ");
	EXPECT_BLOCK_ACCEPT("dummy");
	EXPECT_BLOCK_ACCEPT("*");
	EXPECT_BLOCK_ACCEPT("*/dummy");
	EXPECT_BLOCK_ACCEPT("dummy/dummy/dummy");
	EXPECT_BLOCK_ACCEPT("dummy/*/*");
	EXPECT_BLOCK_ACCEPT("*/*/*");
	EXPECT_BLOCK_ACCEPT(QETOKEN_ALPHABET "/dummy");
	EXPECT_BLOCK_ACCEPT("/dummy");
	EXPECT_BLOCK_ACCEPT("dummy/");
	EXPECT_BLOCK_ACCEPT("dummy/dummy/");
	/*
	 * '*' is part of the token alphabet, but for Accept header '*' symbol
	 * has special meaning and doesn't included into mime types.
	 */
	EXPECT_BLOCK_ACCEPT("dummy/*dummy");
	EXPECT_BLOCK_ACCEPT("*dummy/dummy");
	EXPECT_BLOCK_ACCEPT("*dummy/*dummy");
	EXPECT_BLOCK_ACCEPT("*/*dummy");

	/* parameter */
	TEST_ACCEPT_EXT("dummy/dummy");
	EXPECT_BLOCK_ACCEPT("*/*;key");

	/* weight */
	FOR_ACCEPT("*/*;q=0");
	/* No prohibition in RFC for that. */
	FOR_ACCEPT("*/*;q=0;q=1");
	FOR_ACCEPT("*/*;q=0.0");
	FOR_ACCEPT("*/*;q=0.5");
	FOR_ACCEPT("*/*;q=0.999");
	FOR_ACCEPT("*/*;q=1");
	FOR_ACCEPT("*/*;q=1.0");
	FOR_ACCEPT("*/*;q=1.000");
	FOR_ACCEPT("*/*\t  ; \tq=0");

	/* Breaks the RFC, just dot+digits alphabet is checked... */
	FOR_ACCEPT("*/*;q=1......");
	FOR_ACCEPT("*/*;q=1.23..45.6..789...");
	FOR_ACCEPT("*/*;q=12345");
	/* ...but first char is checked as in RFC. */
	FOR_ACCEPT("*/*;q=0.000");
	EXPECT_BLOCK_ACCEPT("*/*;q=5.000");
	EXPECT_BLOCK_ACCEPT("*/*;q=.000");

	EXPECT_BLOCK_ACCEPT("*/*;q=dummy");
	EXPECT_BLOCK_ACCEPT("*/*;q==");
	EXPECT_BLOCK_ACCEPT("*/*;q=");
	EXPECT_BLOCK_ACCEPT("*/*;q");
	EXPECT_BLOCK_ACCEPT("*/*;=0.5");
	EXPECT_BLOCK_ACCEPT("*/*;q =0");
	EXPECT_BLOCK_ACCEPT("*/*;q= 0");

	/* accept-ext */
	TEST_ACCEPT_EXT("dummy/dummy;q=0");
	EXPECT_BLOCK_ACCEPT("*/*;q=0;key");

	/* Multiple values */
	FOR_ACCEPT("dummy/dummy\t,dummy/dummy ,\t\tdummy/dummy");
	FOR_ACCEPT("  \t\t */*  ;\t key=val ; key=val\t;\t"
		   "q=0;\t\text=val ; ext=val;\tkey=val \t\t");
	/* Invalid delimiters between parts. */
	EXPECT_BLOCK_ACCEPT("*/* text/plain");
	/* Empty types are not allowed. */
	EXPECT_BLOCK_ACCEPT(",");
	EXPECT_BLOCK_ACCEPT("*/*,,");
	EXPECT_BLOCK_ACCEPT("*/,,");

	/* HTML validations */
	FOR_ACCEPT_HTML("  text/html ");
	FOR_ACCEPT_HTML("  text/html, application/xhtml+xml ");
	FOR_ACCEPT_HTML("  text/html;q=0.8 ");
	FOR_ACCEPT_HTML(" text/html,application/xhtml+xml,application/xml;"
			"q=0.9,image/webp,image/apng,*/*;q=0.8");
	FOR_ACCEPT_HTML("  text/html, */*  ");
	FOR_ACCEPT_HTML("  text/html,  invalid/invalid  ;  key=val;   q=0.5 ");
	FOR_ACCEPT_HTML("  invalid/invalid; param=\"value value\", text/html");
	FOR_ACCEPT("  text/*  ");
	FOR_ACCEPT("  invalid/invalid;  q=0.5;    key=val, */* ");
	FOR_ACCEPT(" textK/html");

#undef TEST_ACCEPT_EXT
#undef EXPECT_BLOCK_ACCEPT
#undef FOR_ACCEPT_HTML
#undef FOR_ACCEPT
#undef __FOR_ACCEPT
}

TEST(http1_parser, host)
{
	FOR_REQ_SIMPLE("Host:\r\n"
		       "Connection: close");

	FOR_REQ_SIMPLE("Host:  ");

	FOR_REQ_SIMPLE("Host:    tempesta-tech.com   ")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "    " , .len = 4,
				  .flags = TFW_STR_OWS },
				{ .data = "tempesta-tech.com" , .len = 17,
				  .flags = TFW_STR_VALUE },
			},
			.len = 26,
			.nchunks = 3
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 0);
	}

	FOR_REQ_SIMPLE("Host:    tempesta-tech.com:443   ")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "    " , .len = 4,
				  .flags = TFW_STR_OWS },
				{ .data = "tempesta-tech.com" , .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":" , .len = 1 },
				{ .data = "443" , .len = 3,
				  .flags = TFW_STR_VALUE },
			},
			.len = 30,
			.nchunks = 5
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 443);
	}

	FOR_REQ_SIMPLE("Host:    [fd42:5ca1:e3a7::1000]   ")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "    " , .len = 4,
				  .flags = TFW_STR_OWS },
				{ .data = "[fd42:5ca1:e3a7::1000]" , .len = 22,
				  .flags = TFW_STR_VALUE },
			},
			.len = 31,
			.nchunks = 3
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 0);
	}

	FOR_REQ_SIMPLE("Host:    [fd42:5ca1:e3a7::1000]:65535   ")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_HOST];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "    " , .len = 4,
				  .flags = TFW_STR_OWS },
				{ .data = "[fd42:5ca1:e3a7::1000]" , .len = 22,
				  .flags = TFW_STR_VALUE },
				{ .data = ":" , .len = 1 },
				{ .data = "65535", .len = 5,
				  .flags = TFW_STR_VALUE },
			},
			.len = 37,
			.nchunks = 5
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 65535);
	}

	/* Invalid port */
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com:0");
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com:");
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com:65536");
	EXPECT_BLOCK_DIGITS("Host: tempesta-tech.com:", "",
			    EXPECT_BLOCK_REQ_SIMPLE);
	EXPECT_BLOCK_SHORT( "Host: tempesta-tech.com:", "",
			    EXPECT_BLOCK_REQ_SIMPLE);
	EXPECT_BLOCK_DIGITS("Host: [fd42:5ca1:e3a7::1000]:", "",
			    EXPECT_BLOCK_REQ_SIMPLE);
	EXPECT_BLOCK_SHORT( "Host: [fd42:5ca1:e3a7::1000]:", "",
			    EXPECT_BLOCK_REQ_SIMPLE);

	/* Port syntax is broken. */
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com:443:1");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000]:443:1");
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com::443");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000]::443");
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com 443");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000] 443");
	EXPECT_BLOCK_REQ_SIMPLE("Host: tempesta-tech.com:443-1");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000]-1");

	/* Invalid brackets around IPv6. */
	EXPECT_BLOCK_REQ_SIMPLE("Host: fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000][");
	EXPECT_BLOCK_REQ_SIMPLE("Host: [fd42:5ca1:e3a7::1000[");
}

TEST(http1_parser, chunked_cut_len)
{
	/* Chunked response */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "8\r\n"
		 "abcdefgh\r\n"
		 "0\r\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 8);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}

	/* Header 'Age' is forbidden in trailers. */
	EXPECT_BLOCK_RESP_SIMPLE("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "8\r\n"
		 "abcdefgh\r\n"
		 "0\r\n"
		 "Age: 1\r\n"
		 "\r\n");

	/* Chunked response with trailer */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "8\r\n"
		 "abcdefgh\r\n"
		 "0\r\n"
		 "X-Token: value\r\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 8);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}

	/* Chunked response with LF insted of CRLF */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "8\n"
		 "abcdefgh\n"
		 "0\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 5);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}

	/* Chunked response with mixed LF and CRLF */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "8\n"
		 "abcdefgh\n"
		 "0\r\n"
		 "X-Token: value\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 6);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}

	/* Chunked response with chunk extension */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "8;qwe=123\r\n"
		 "abcdefgh\r\n"
		 "0\r\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 16);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}

	/* Chunked response */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "0\r\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 3);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}
	/* Chunked response */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\r\n"
		 "000\r\n"
		 "\r\n")
	{
		EXPECT_EQ(resp->cut.len, 5);
		EXPECT_EQ(tfw_str_eolen(&resp->body), 2);
	}
}

TEST(http1_parser, transfer_encoding)
{
#define FOR_CHUNKED(chunks)						\
	FOR_REQ("POST / HTTP/1.1\r\n"					\
		"Transfer-Encoding: chunked\r\n"			\
		"\r\n" chunks "\r\n")					\
	{								\
		EXPECT_TRUE(req->body.len == sizeof(chunks) - 1);	\
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CHUNKED, req->flags));	\
	}								\
	FOR_RESP("HTTP/1.1 200 OK\r\n"					\
		 "Transfer-Encoding: chunked\r\n"			\
		 "\r\n" chunks "\r\n")					\
	{								\
		EXPECT_TRUE(resp->body.len == sizeof(chunks) - 1);	\
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CHUNKED, resp->flags));	\
	}


#define EXPECT_BLOCK_REQ_CHUNKED(chunks)				\
	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"				\
		"Transfer-Encoding: chunked\r\n"			\
		"\r\n" chunks "\r\n")

#define EXPECT_BLOCK_RESP_CHUNKED(chunks)				\
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"				\
		 "Transfer-Encoding: chunked\r\n"			\
		 "\r\n" chunks "\r\n")

#define EXPECT_BLOCK_CHUNKED(chunks)					\
	EXPECT_BLOCK_REQ_CHUNKED(chunks);				\
	EXPECT_BLOCK_RESP_CHUNKED(chunks)

	/*
	 * chunk-ext
	 */
	FOR_CHUNKED("0\r\n");
	FOR_CHUNKED("000\r\n");
	/* Not strict compliance with RFC */
	FOR_CHUNKED("0;==;;" TOKEN_ALPHABET ";=;=\r\n");
	EXPECT_BLOCK_CHUNKED("1\r\n");
	EXPECT_BLOCK_CHUNKED("-1\r\n");
	EXPECT_BLOCK_CHUNKED("invalid\r\n");
	EXPECT_BLOCK_CHUNKED("0\r\n0\r\n"); // only one last-chunk

	/*
	 * chunk
	 */
	FOR_CHUNKED("5;" TOKEN_ALPHABET "\n"
		    "dummy\r\n"
		    "0\r\n");
	EXPECT_BLOCK_CHUNKED("4\r\n"
			     "dummy\r\n"
			     "0000\r\n");
	EXPECT_BLOCK_CHUNKED("5(\r\n"
			     "dummy\r\n"
			     "0\r\n");
	EXPECT_BLOCK_CHUNKED("5;\x09\r\n"
			     "dummy\r\n"
			     "0\r\n");
	FOR_CHUNKED("F\n"
		    "dummydummydummy\r\n"
		    "0\r\n");
	FOR_CHUNKED("f\n"
		    "dummydummydummy\r\n"
		    "0\r\n");
	FOR_CHUNKED("130\r\n"
		    "Well-Prince-so-Genoa-and-Lucca-are-now-just-family-"
		    "estates-of-the-Buonapartes-But-I-warn-you-if-you-dont-"
		    "tell-me-that-this-means-war-if-you-still-try-to-defend-"
		    "the-infamies-and-horrors-perpetrated-by-that-Antichrist-"
		    "I-really-believe-he-is-Antichrist-I-will-have-nothing-"
		    "more-to-do-with-you-and-you-are-no\r\n"
		    "0\r\n");
	/*
	 * chunk is sequence of octets (\x00-\xFF) except NUL because
	 * strings are null terminated
	 */
	EXPECT_BLOCK_CHUNKED("1\r\n"
			     "\x00\r\n"
			     "0\r\n");
	FOR_CHUNKED("1\r\n"
		    "\x01\r\n"
		    "0\r\n");
	FOR_CHUNKED("60\r\n"
		    TOKEN_ALPHABET OTHER_DELIMETERS " \x09\r\n"
		    "0\r\n");
	FOR_CHUNKED("1\r\n"
		    "\x7F\r\n"
		    "0\r\n");
	FOR_CHUNKED("1\r\n"
		    "\x80\r\n"
		    "0\r\n");
	FOR_CHUNKED("1\r\n"
		    "\xFF\r\n"
		    "0\r\n");
	/* Several chunks */
	FOR_CHUNKED("5\r\n"
		"abcde\r\n"
		"a\r\n"
		"fa01234567\r\n"
		"2\n"
		"89\r\n"
		"0\n");

	FOR_REQ_SIMPLE("Host:\r\n"
		       "Transfer-Encoding: chunked\r\n"
		       "\r\n"
		       "0")

	EXPECT_BLOCK_REQ_SIMPLE("Host:\r\n"
				"Transfer-Encoding: chunked\r\n"
				"\r\n"
				"5\r\n"
				"abcde\r\n"
				"0")

	/*
	 * Trailer headers.
	 */
	FOR_REQ_SIMPLE("Host:\r\n"
		       "Transfer-Encoding: chunked\r\n"
		       "\r\n"
		       "0\n"
		       "X-Token: value\r\n"
		       "If-Modified-Since: Wed, 08 Jan 2003 23:11:55 GMT")
	{
		EXPECT_TRUE(req->h_tbl->tbl[TFW_HTTP_HDR_RAW].flags
			    & TFW_STR_TRAILER);
		EXPECT_TRUE(req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 1].flags
			    & TFW_STR_TRAILER);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\n"
		 "0\n"
		 "X-Token: value\r\n"
		 "Pragma: no-cache\r\n"
		 "\r\n")
	{
		EXPECT_TRUE(resp->h_tbl->tbl[TFW_HTTP_HDR_RAW].flags
			    & TFW_STR_TRAILER);
		EXPECT_TRUE(resp->h_tbl->tbl[TFW_HTTP_HDR_RAW + 1].flags
			    & TFW_STR_TRAILER);
	}


	/*
	 * Drop if trailers contain hop-by-hop headers.
	 */
	EXPECT_BLOCK_REQ("Host:\r\n"
			 "Transfer-Encoding: chunked\r\n"
			 "\r\n"
			 "0\n"
			 "Connection: close\r\n"
			 "If-Modified-Since: Wed, 08 Jan 2003 23:11:55 GMT");


	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\n"
			  "0\n"
			  "Connection: keep-alive\r\n"
			  "Pragma: no-cache\r\n"
			  "Age: 2147483647\r\n"
			  "\r\n");

	/*
	 * RFC 7230 4.1.2:
	 *
	 * A sender MUST NOT generate a trailer that contains a field necessary
	 * for message framing (e.g., Transfer-Encoding and Content-Length),
	 * routing (e.g., Host), request modifiers (e.g., controls and
	 * conditionals in Section 5 of [RFC7231]), authentication (e.g., see
	 * [RFC7235] and [RFC6265]), response control data (e.g., see Section
	 * 7.1 of [RFC7231]), or determining how to process the payload (e.g.,
	 * Content-Encoding, Content-Type, Content-Range, and Trailer).
	 *
	 * XXX "e.g." probably means that this header list is incomplete,
	 * please provide more if you find.
	 */
	EXPECT_BLOCK_CHUNKED("0\r\nTransfer-Encoding: chunked\r\n");
	EXPECT_BLOCK_CHUNKED("0\r\nContent-Length: 0\r\n\r\n");

	EXPECT_BLOCK_REQ_CHUNKED("0\r\nHost: example.net\r\n\r\n");

	// TODO #1527
	// EXPECT_BLOCK_CHUNKED("0\r\nCache-Control: no-cache, no-store, "
	// 		     "must-revalidate\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nExpect: 100-continue\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nMax-Forwards: 4\r\n\r\n");
	// EXPECT_BLOCK_CHUNKED("0\r\nPragma: no-cache\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nRange: bytes=0-1023\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nTE: deflate\r\n\r\n");

	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nIf-Match: \"xyzzy\"\r\n\r\n");
	EXPECT_BLOCK_REQ_CHUNKED("0\r\nIf-None-Match: \"xyzzy\"\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nIf-Modified-Since: Sat, 29 Oct 1994 "
	// 			 "19:43:31 GMT\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nIf-Unmodified-Since: Sat, 29 Oct 1994 "
	// 			 "19:43:31 GMT\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nIf-Range: Wed, 21 Oct 2015 07:28:00 GMT"
	// 			 "\r\n\r\n");

	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nWWW-Authenticate: challengeN\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nAuthorization: "
	// 			 "Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n");
	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nProxy-Authenticate: Basic\r\n\r\n");
	// EXPECT_BLOCK_REQ_CHUNKED("0\r\nProxy-Authorization: "
	// 			 "Basic YWxhZGRpbjpvcGVuc2VzYW1l\r\n\r\n");

	EXPECT_BLOCK_RESP_CHUNKED("0\r\nSet-Cookie: "
				  "sessionId=38afes7a8\r\n\r\n");
	EXPECT_BLOCK_REQ_CHUNKED("0\r\nCookie: PHPSESSID=298zf09hf012fh2; "
				 "csrftoken=u32t4o3tb3gg43; _gat=1\r\n\r\n");

	EXPECT_BLOCK_REQ_CHUNKED("0\r\nX-Forwarded-For: 203.0.113.195\r\n\r\n");
	EXPECT_BLOCK_REQ_CHUNKED("0\r\nForwarded: for=203.0.113.195\r\n\r\n");

	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nAge: 1859070\r\n\r\n");
	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nExpires: Wed, 21 Oct 2015 07:28:00 GMT"
	// 			  "\r\n\r\n");
	// EXPECT_BLOCK_CHUNKED("0\r\nDate: Wed, 21 Oct 2015 07:28:00 GMT"
	// 		     "\r\n\r\n");
	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nLocation: /index.html\r\n\r\n");
	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nRetry-After: Wed, 21 Oct 2015 "
	// 			  "07:28:00 GMT\r\n\r\n");
	// EXPECT_BLOCK_RESP_CHUNKED("0\r\nVary: User-Agent\r\n\r\n");
	// EXPECT_BLOCK_CHUNKED("0\r\nWarning: 112 - \"cache down\" "
	// 		     "\"Wed, 21 Oct 2015 07:28:00 GMT\"\r\n\r\n");

	// EXPECT_BLOCK_CHUNKED("0\r\nContent-Encoding: compress\r\n\r\n");
	EXPECT_BLOCK_CHUNKED("0\r\nContent-Type: text/html; charset=utf-8"
			     "\r\n\r\n");
	// EXPECT_BLOCK_CHUNKED("0\r\nContent-Range: bytes 200-1000/67589"
	// 		     "\r\n\r\n");
	// EXPECT_BLOCK_CHUNKED("0\r\nTrailer: Expires\r\n\r\n");

	/* Invalid header name */
	EXPECT_BLOCK_CHUNKED("0\r\nCust@m-Hdr?: custom-data\r\n");

	/*
	 * CRLF
	 */
	EXPECT_BLOCK_CHUNKED("5dummy\r\n"
			     "0\r\n");
	EXPECT_BLOCK_CHUNKED("5\r\n"
			     "dummy"
			     "0\r\n");
	EXPECT_BLOCK_CHUNKED("5\r\n"
			     "dummy\r\n"
			     "0");

	/*
	 * "Content-Length:" and "Transfer-Encoding:" header fields
	 * may not be present together in a request.
	 */
	EXPECT_BLOCK_REQ_SIMPLE("Content-Length: 4\r\n"
				"Transfer-Encoding: chunked\r\n"
				"\r\n"
				"4\r\n"
				"1234\r\n"
				"0");
	/*
	 * "chunked" coding must be present in a request if there's
	 * any other coding (i.e. "Transfer-Encoding" is present).
	 */
	EXPECT_BLOCK_REQ_SIMPLE("Transfer-Encoding: gzip\r\n"
				"\r\n"
				"4\r\n"
				"1234\r\n"
				"0");
	/*
	 * "Content-Length:" and "Transfer-Encoding:" header fields
	 * may not be present together in a response.
	 */
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Content-Length: 7\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");

	/*
	 * RFC 7230 3.3.1:
	 *
	 * If any transfer coding
	 * other than chunked is applied to a REQUEST payload body, the sender
	 * MUST apply chunked as the final transfer coding to ensure that the
	 * message is properly framed.
	 */
	EXPECT_BLOCK_REQ_SIMPLE("Transfer-Encoding: chunked, gzip\r\n"
				"Connection: close\r\n"
				"\r\n"
				"4\r\n"
				"1234\r\n"
				"0");
	/*
	 * RFC 7230 3.3.1:
	 *
	 * If any transfer coding other than
	 * chunked is applied to a RESPONSE payload body, the sender MUST either
	 * apply chunked as the final transfer coding or terminate the message
	 * by closing the connection.
	 *
	 * Closing in response case is performing
	 * in @tfw_http_resp_terminate(), so response is blocked.
	 */
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Transfer-Encoding: chunked, gzip\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");

	/* "chunked" coding may not be applied twice. */
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Transfer-Encoding: gzip, chunked\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");
	EXPECT_BLOCK_RESP("HTTP/1.0 200 OK\r\n"
			  "Transfer-Encoding: chunked, gzip, chunked, gzip\r\n"
			  "\r\n"
			  "7\r\n"
			  "1234567\r\n"
			  "0\r\n"
			  "\r\n");
	/*
	 * If we have Transfer-Encoding, then we must have 'chunked',
	 * so the request must be blocked.
	 */
	EXPECT_BLOCK_REQ_SIMPLE("Transfer-Encoding: chunkedchunked\r\n"
				"\r\n"
				"0");

	EXPECT_BLOCK_RESP("HTTP/1.1 101 Switching Protocols OK\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "0\r\n\r\n");
	EXPECT_BLOCK_RESP("HTTP/1.1 199 Dummy\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "0\r\n\r\n");
	EXPECT_BLOCK_RESP("HTTP/1.1 204 No Content\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "0\r\n\r\n");

	/*
	 * For now the other transfer encodings (gzip, deflate etc.)
	 * are not processed, just passed by the parser.
	 */
	FOR_REQ("POST / HTTP/1.1\r\n"
		"Transfer-Encoding: "
		TOKEN_ALPHABET " ,  dummy \t, chunked\r\n"
		"\r\n"
		"0"
		"\r\n\r\n");
	FOR_RESP("HTTP/1.0 200 OK\r\n"
		 "Transfer-Encoding: " TOKEN_ALPHABET "\t, dummy\t, chunked\r\n"
		 "\r\n"
		 "0\r\n"
		 "\r\n");

	FOR_REQ("POST / HTTP/1.1\r\n"
		"Transfer-Encoding: dummy0, dummy1, dummy2, dummy3, dummy4, "
		"dummy5, dummy6, dummy7, dummy8, dummy9, dummy10, dummy11, "
		"dummy12, dummy13, dummy14, dummy15, dummy16, dummy17, "
		"dummy18, dummy19, dummy20, dummy21, dummy22, dummy23, "
		"dummy24, dummy25, dummy26, dummy27, dummy28, dummy29, "
		"dummy30, dummy31, dummy32, dummy33, dummy34, dummy35, "
		"dummy36, dummy37, dummy38, dummy39, dummy40, dummy41, "
		"dummy42, dummy43, dummy44, dummy45, dummy46, dummy47, "
		"dummy48, dummy49, dummy50, dummy51, dummy52, dummy53, "
		"dummy54, dummy55, dummy56, dummy57, dummy58, dummy59, "
		"dummy60, dummy61, dummy62, dummy63, dummy64, dummy65, "
		"dummy66, dummy67, dummy68, dummy69, dummy70, dummy71, "
		"dummy72, dummy73, dummy74, dummy75, dummy76, dummy77, "
		"dummy78, dummy79, dummy80, dummy81, dummy82, dummy83, "
		"dummy84, dummy85, dummy86, dummy87, dummy88, dummy89, "
		"dummy90, dummy91, dummy92, dummy93, dummy94, dummy95, "
		"dummy96, dummy97, dummy98, dummy99, dummy100, dummy101, "
		"dummy102, dummy103, dummy104, dummy105, dummy106, dummy107, "
		"dummy108, dummy109, dummy110, dummy111, dummy112, dummy113, "
		"dummy114, dummy115, dummy116, dummy117, dummy118, dummy119, "
		"dummy120, dummy121, dummy122, dummy123, dummy124, dummy125, "
		"dummy126, dummy127, chunked\r\n"
		"\r\n"
		"0"
		"\r\n\r\n");
	FOR_RESP("HTTP/1.0 200 OK\r\n"
		 "Transfer-Encoding: dummy0, dummy1, dummy2, dummy3, dummy4, "
		 "dummy5, dummy6, dummy7, dummy8, dummy9, dummy10, dummy11, "
		 "dummy12, dummy13, dummy14, dummy15, dummy16, dummy17, "
		 "dummy18, dummy19, dummy20, dummy21, dummy22, dummy23, "
		 "dummy24, dummy25, dummy26, dummy27, dummy28, dummy29, "
		 "dummy30, dummy31, dummy32, dummy33, dummy34, dummy35, "
		 "dummy36, dummy37, dummy38, dummy39, dummy40, dummy41, "
		 "dummy42, dummy43, dummy44, dummy45, dummy46, dummy47, "
		 "dummy48, dummy49, dummy50, dummy51, dummy52, dummy53, "
		 "dummy54, dummy55, dummy56, dummy57, dummy58, dummy59, "
		 "dummy60, dummy61, dummy62, dummy63, dummy64, dummy65, "
		 "dummy66, dummy67, dummy68, dummy69, dummy70, dummy71, "
		 "dummy72, dummy73, dummy74, dummy75, dummy76, dummy77, "
		 "dummy78, dummy79, dummy80, dummy81, dummy82, dummy83, "
		 "dummy84, dummy85, dummy86, dummy87, dummy88, dummy89, "
		 "dummy90, dummy91, dummy92, dummy93, dummy94, dummy95, "
		 "dummy96, dummy97, dummy98, dummy99, dummy100, dummy101, "
		 "dummy102, dummy103, dummy104, dummy105, dummy106, dummy107, "
		 "dummy108, dummy109, dummy110, dummy111, dummy112, dummy113, "
		 "dummy114, dummy115, dummy116, dummy117, dummy118, dummy119, "
		 "dummy120, dummy121, dummy122, dummy123, dummy124, dummy125, "
		 "dummy126, dummy127, chunked\r\n"
		 "\r\n"
		 "0\r\n"
		 "\r\n");

#undef EXPECT_BLOCK_CHUNKED
#undef EXPECT_BLOCK_RESP_CHUNKED
#undef EXPECT_BLOCK_REQ_CHUNKED
#undef FOR_CHUNKED
}

TEST(http1_parser, content_encoding)
{
#define FOR_CENCODING(cencoding)					\
	FOR_REQ("POST / HTTP/1.1\r\n"					\
		"Content-Encoding:" cencoding "\r\n"			\
		"\r\n");						\
	FOR_RESP("HTTP/1.1 200 OK\r\n"					\
		 "Content-Length: 0\r\n"				\
		 "Content-Encoding:" cencoding "\r\n"			\
		 "\r\n")

#define EXPECT_BLOCK_CENC_REQ_RESP(cencoding)				\
	EXPECT_BLOCK_REQ("POST / HTTP/1.1\r\n"				\
			 "Content-Encoding:" cencoding "\r\n"		\
			 "\r\n");					\
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"				\
			  "Content-Length: 0\r\n"			\
			  "Content-Encoding:" cencoding "\r\n"		\
			  "\r\n")

	FOR_CENCODING(
		"dummy0, dummy1, dummy2, dummy3, dummy4, "
		"dummy5, dummy6, dummy7, dummy8, dummy9, dummy10, dummy11, "
		"dummy12, dummy13, dummy14, dummy15, dummy16, dummy17, "
		"dummy18, dummy19, dummy20, dummy21, dummy22, dummy23, "
		"dummy24, dummy25, dummy26, dummy27, dummy28, dummy29, "
		"dummy30, dummy31, dummy32, dummy33, dummy34, dummy35, "
		"dummy36, dummy37, dummy38, dummy39, dummy40, dummy41, "
		"dummy42, dummy43, dummy44, dummy45, dummy46, dummy47, "
		"dummy48, dummy49, dummy50, dummy51, dummy52, dummy53, "
		"dummy54, dummy55, dummy56, dummy57, dummy58, dummy59, "
		"dummy60, dummy61, dummy62, dummy63, dummy64, dummy65, "
		"dummy66, dummy67, dummy68, dummy69, dummy70, dummy71, "
		"dummy72, dummy73, dummy74, dummy75, dummy76, dummy77, "
		"dummy78, dummy79, dummy80, dummy81, dummy82, dummy83, "
		"dummy84, dummy85, dummy86, dummy87, dummy88, dummy89, "
		"dummy90, dummy91, dummy92, dummy93, dummy94, dummy95, "
		"dummy96, dummy97, dummy98, dummy99, dummy100, dummy101, "
		"dummy102, dummy103, dummy104, dummy105, dummy106, dummy107, "
		"dummy108, dummy109, dummy110, dummy111, dummy112, dummy113, "
		"dummy114, dummy115, dummy116, dummy117, dummy118, dummy119, "
		"dummy120, dummy121, dummy122, dummy123, dummy124, dummy125, "
		"dummy126, dummy127");

	FOR_CENCODING(TOKEN_ALPHABET "," TOKEN_ALPHABET);
	EXPECT_BLOCK_CENC_REQ_RESP(TOKEN_ALPHABET ";");
	EXPECT_BLOCK_CENC_REQ_RESP(TOKEN_ALPHABET ",;" TOKEN_ALPHABET);

	/*
	 * Deny Transfer-Encoding other than chunked and Content-Encoding
	 * in the same response. It's looks suspicious, all common backends
	 * support only Transfer-Encoding chunked.
	 */
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  "Content-Length: 0\r\n"
			  "Content-Encoding: gzip\r\n"
			  "Transfer-Encoding: gzip\r\n"
			  "\r\n");

	FOR_RESP("HTTP/1.1 200 OK\r\n"
			  "Content-Encoding: gzip\r\n"
			  "Transfer-Encoding: chunked\r\n"
			  "\r\n"
			  "0\r\n"
			  "\r\n");

#undef FOR_CENCODING
#undef EXPECT_BLOCK_CENC_REQ_RESP
}

/*
 * This test ensures that there's not retrogression in handling CRLF.
 * The bug was that in case of trailing headers CRLF that was set to
 * point at location after the headers at the beginning of a message
 * was later reset to point at location after the trailing headers.
 */
TEST(http1_parser, crlf_trailer)
{
	unsigned int id;
	DEFINE_TFW_STR(s_custom, "Custom-Hdr:");
	DEFINE_TFW_STR(s_custom2, "Custom-Hdr2:");

	/*
	 * Use a trick with different CRLF length to differentiate
	 * between the correct CRLF and an incorrect CRLF.
	 */
	FOR_REQ("POST / HTTP/1.1\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\n"
		"4\r\n"
		"1234\r\n"
		"0\r\n"
		"Custom-Hdr: custom-data"
		"\r\n\r\n")
	{
		/* 'Custom-Hdr:' is the first raw header in this example. */
		id = tfw_http_msg_hdr_lookup((TfwHttpMsg *)req, &s_custom);

		EXPECT_TRUE(id == TFW_HTTP_HDR_RAW);
		EXPECT_TRUE(req->body.len == 12);
		EXPECT_TRUE(req->crlf.len == 1);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\n"
		 "5\r\n"
		 "abcde\r\n"
		 "0\r\n"
		 "Custom-Hdr: custom-data\r\n"
		 "\r\n")
	{
		/* 'Custom-Hdr:' is the first raw header in this example. */
		id = tfw_http_msg_hdr_lookup((TfwHttpMsg *)resp, &s_custom);

		EXPECT_TRUE(id == TFW_HTTP_HDR_RAW);
		EXPECT_TRUE(resp->body.len == 13);
		EXPECT_TRUE(resp->crlf.len == 1);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Transfer-Encoding: chunked\r\n"
		 "\n"
		 "5\r\n"
		 "abcde\r\n"
		 "0\r\n"
		 "Custom-Hdr: custom-data\r\n"
		 "Custom-Hdr2: other-data\r\n"
		 "\r\n")
	{
		id = tfw_http_msg_hdr_lookup((TfwHttpMsg *)resp, &s_custom);
		EXPECT_TRUE(id == TFW_HTTP_HDR_RAW);

		id = tfw_http_msg_hdr_lookup((TfwHttpMsg *)resp, &s_custom2);
		EXPECT_TRUE(id == TFW_HTTP_HDR_RAW + 1);

		EXPECT_TRUE(resp->body.len == 13);
		EXPECT_TRUE(resp->crlf.len == 1);
	}
}

TEST(http1_parser, cookie)
{
	FOR_REQ_SIMPLE("Host:\r\n"
		       "Cookie: session=42; theme=dark")
	{
		TfwStr *end, *c;
		TfwStr *cookie = &req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
		struct {
			unsigned int flags;
			const char *str;
		} kv[] = {
			{ 0, "Cookie:" },
			{ TFW_STR_OWS, " " },
			{ TFW_STR_NAME, "session=" },
			{ TFW_STR_VALUE, "42" },
			{ 0, "; " },
			{ TFW_STR_NAME, "theme=" },
			{ TFW_STR_VALUE, "dark" },
		};
		size_t kv_count = sizeof(kv) / sizeof(kv[0]);
		int kv_idx;

		/*
		 * Even if the entire cookie field is in a continuous chunk,
		 * the parser splits it into multiple chunks of data, for every
		 * key and value of a cookie parameter to start at the beginning
		 * of a chunk.
		 * Other code expects keys and values to always begin at the
		 * left border of a chunk. Verifying it here.
		 */

		EXPECT_TRUE(cookie->nchunks >= kv_count);

		kv_idx = 0;
		c = cookie->chunks;
		end = c + cookie->nchunks;
		while (c < end) {
			TfwStr *part_end = c;
			TfwStr part = {};
			unsigned int part_flags = c->flags;

			/*
			 * Chunks with keys and values are marked with special
			 * flags.
			 */
			while (part_end < end && part_end->flags == part_flags)
				part_end++;

			if (part_end - c > 1) {
				part.chunks = c;
				part.nchunks = part_end - c;
			} else {
				part = *c;
			}

			c = part_end;

			EXPECT_TRUE(kv_idx < kv_count);
			EXPECT_TFWSTR_EQ(&part, kv[kv_idx].str);
			EXPECT_EQ(part_flags, kv[kv_idx].flags);
			kv_idx++;
		}
	}

	EXPECT_BLOCK_REQ_SIMPLE("Host: g.com\r\n"
				"Cookie: session=42;theme=dark");

	EXPECT_BLOCK_REQ_SIMPLE("Host: g.com\r\n"
				"Cookie: session=42, theme=dark");

	EXPECT_BLOCK_REQ_SIMPLE("Host: g.com\r\n"
				"Cookie: session=42 theme=dark");

	EXPECT_BLOCK_REQ_SIMPLE("Host: g.com\r\n"
				"Cookie: session=42\ttheme=dark");

	/*
	 * This actually should be blocked due to unclosed DQUOTE.
	 * But cookie values are opaque for us, this is job for application
	 * layer to accurately parse cookie values.
	 */
	FOR_REQ_SIMPLE("Host: g.com\r\n"
		       "Cookie: session=\"42; theme=dark");
}

TEST(http1_parser, set_cookie)
{
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		 "Set-Cookie: sessionid=38afes7a8; HttpOnly; Path=/\r\n"
		 "\r\n"
		 "0123456789")
	{
		TfwStr *s_parsed = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];
		TfwStr s_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Set-Cookie:" , .len = 11 },
				{ .data = " " , .len = 1,
				  .flags = TFW_STR_OWS },
				{ .data = "sessionid=" , .len = 10,
				  .flags = TFW_STR_NAME },
				{ .data = "38afes7a8" , .len = 9,
				  .flags = TFW_STR_VALUE  },
				{ .data = "; HttpOnly; Path=/" , .len = 18 }
			},
			.len = 49,
			.nchunks = 5
		};
		test_string_split(&s_expected, s_parsed);
	}

	/* Cookie value inside DQUOTE. */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		 "Set-Cookie: sessionid=\"38afes7a8\"; HttpOnly; Path=/\r\n"
		 "\r\n"
		 "0123456789")
	{
		TfwStr *s_parsed = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];
		TfwStr s_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Set-Cookie:" , .len = 11 },
				{ .data = " " , .len = 1,
				  .flags = TFW_STR_OWS },
				{ .data = "sessionid=" , .len = 10,
				  .flags = TFW_STR_NAME },
				{ .data = "\"38afes7a8\"" , .len = 11,
				  .flags = TFW_STR_VALUE  },
				{ .data = "; HttpOnly; Path=/" , .len = 18 }
			},
			.len = 51,
			.nchunks = 5
		};
		test_string_split(&s_expected, s_parsed);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		 "Set-Cookie: id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; "
		 "Secure; HttpOnly\r\n"
		 "\r\n"
		 "0123456789")
	{
		TfwStr *s_parsed = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];
		TfwStr s_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Set-Cookie:" , .len = 11 },
				{ .data = " " , .len = 1,
				  .flags = TFW_STR_OWS },
				{ .data = "id=" , .len = 3,
				  .flags = TFW_STR_NAME },
				{ .data = "a3fWa" , .len = 5,
				  .flags = TFW_STR_VALUE  },
				{ .data = "; Expires=Wed, 21 Oct 2015 07:28:00 "
				  "GMT; Secure; HttpOnly",
				  .len = 57 }
			},
			.len = 77,
			.nchunks = 5
		};
		test_string_split(&s_expected, s_parsed);
	}

	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		 "Set-Cookie: __Host-id=1; Secure; Path=/; domain=example.com\r\n"
		 "\r\n"
		 "0123456789")
	{
		TfwStr *s_parsed = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];
		TfwStr s_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Set-Cookie:" , .len = 11 },
				{ .data = " " , .len = 1,
				  .flags = TFW_STR_OWS },
				{ .data = "__Host-id=" , .len = 10,
				  .flags = TFW_STR_NAME },
				{ .data = "1" , .len = 1,
				  .flags = TFW_STR_VALUE  },
				{ .data = "; Secure; Path=/; domain=example.com",
				  .len = 36 }
			},
			.len = 59,
			.nchunks = 5
		};
		test_string_split(&s_expected, s_parsed);
	}

	/* Multiple Set-Cookie headers  */
	FOR_RESP("HTTP/1.1 200 OK\r\n"
		 "Content-Length: 10\r\n"
		 "Set-Cookie: sessionid=38afes7a8; HttpOnly; Path=/\r\n"
		 "Set-Cookie: id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; "
		 "Secure; HttpOnly\r\n"
		 "Set-Cookie: __Host-id=1; Secure; Path=/; domain=example.com\r\n"
		 "\r\n"
		 "0123456789")
	{
		const TfwStr *dup, *dup_end;
		TfwStr *s_parsed = &resp->h_tbl->tbl[TFW_HTTP_HDR_SET_COOKIE];
		TfwStr s_expected[] = {
			{
				.chunks = (TfwStr []) {
					{ .data = "Set-Cookie:" , .len = 11 },
					{ .data = " " , .len = 1,
					  .flags = TFW_STR_OWS },
					{ .data = "sessionid=" , .len = 10,
					  .flags = TFW_STR_NAME },
					{ .data = "38afes7a8" , .len = 9,
					  .flags = TFW_STR_VALUE  },
					{ .data = "; HttpOnly; Path=/" , .len = 18 }
				},
				.len = 49,
				.nchunks = 5,
			},
			{
				.chunks = (TfwStr []) {
					{ .data = "Set-Cookie:" , .len = 11 },
					{ .data = " " , .len = 1,
					  .flags = TFW_STR_OWS },
					{ .data = "id=" , .len = 3,
					  .flags = TFW_STR_NAME },
					{ .data = "a3fWa" , .len = 5,
					  .flags = TFW_STR_VALUE  },
					{ .data = "; Expires=Wed, 21 Oct 2015 07:28:00 "
							  "GMT; Secure; HttpOnly",
					  .len = 57 }
				},
				.len = 77,
				.nchunks = 5
			},
			{
				.chunks = (TfwStr []) {
					{ .data = "Set-Cookie:" , .len = 11 },
					{ .data = " " , .len = 1,
					  .flags = TFW_STR_OWS },
					{ .data = "__Host-id=" , .len = 10,
					  .flags = TFW_STR_NAME },
					{ .data = "1" , .len = 1,
					  .flags = TFW_STR_VALUE  },
					{ .data = "; Secure; Path=/; domain=example.com",
					  .len = 36 }
				},
				.len = 59,
				.nchunks = 5
			}
		};
		unsigned long idx = 0;
		TFW_STR_FOR_EACH_DUP(dup, s_parsed, dup_end)
			test_string_split(&s_expected[idx++], dup);
		EXPECT_TRUE(idx == ARRAY_SIZE(s_expected));
	}

	/* No space after semicolon */
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  "Content-Length: 10\r\n"
			  "Set-Cookie: sessionid=38afes7a8;HttpOnly; Path=/\r\n"
			  "\r\n"
			  "0123456789");
	/* No semicolon */
	EXPECT_BLOCK_RESP("HTTP/1.1 200 OK\r\n"
			  "Content-Length: 10\r\n"
			  "Set-Cookie: sessionid=38afes7a8 Path=/\r\n"
			  "\r\n"
			  "0123456789");
}

TEST(http1_parser, etag)
{
#define RESP_ETAG_START						\
	"HTTP/1.1 200 OK\r\n"					\
	"Date: Mon, 23 May 2005 22:38:34 GMT\r\n"		\
	"Content-Type: text/html; charset=UTF-8\r\n"		\
	"Content-Encoding: UTF-8\r\n"				\
	"Content-Length: 10\r\n"				\
	"Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"	\
	"Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"

#define RESP_ETAG_END              \
	"Accept-Ranges: bytes\r\n" \
	"Connection: close\r\n"    \
	"\r\n"                     \
	"0123456789"

#define FOR_ETAG(header, expected)				\
	FOR_RESP(RESP_ETAG_START header "\r\n" RESP_ETAG_END)		\
	{								\
		TfwStr h_etag, s_etag;					\
		DEFINE_TFW_STR(exp_etag, expected);			\
									\
		tfw_http_msg_srvhdr_val(				\
			&resp->h_tbl->tbl[TFW_HTTP_HDR_ETAG],		\
			TFW_HTTP_HDR_ETAG, &h_etag);			\
		s_etag = tfw_str_next_str_val(&h_etag);			\
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);	\
									\
		s_etag = tfw_str_next_str_val(&s_etag);			\
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));			\
	}

#define ETAG_BLOCK(header)						\
	EXPECT_BLOCK_RESP(RESP_ETAG_START header "\r\n" RESP_ETAG_END)

	FOR_ETAG("ETag:   \"dummy\"  ",  "dummy\"");
	FOR_ETAG("ETag:   W/\"dummy\"  ", "dummy\"");
	FOR_ETAG("ETag: \"\" ", "\"");
	FOR_ETAG("ETag: W/\"\"", "\"");
	FOR_ETAG("ETag: \"" ETAG_ALPHABET "\"",  ETAG_ALPHABET "\"");
	FOR_ETAG("ETag: W/\"" ETAG_ALPHABET "\"",  ETAG_ALPHABET "\"");

	/* Same code is used to parse ETag header and If-None-Match header. */
	ETAG_BLOCK("Etag: \"dum my\"");
	ETAG_BLOCK("Etag: \"dummy \"");
	ETAG_BLOCK("Etag:  *\"");
	ETAG_BLOCK("ETag: \"dummy1\", \"dummy2\"");
	COMMON_ETAG_BLOCK("ETag: ", ETAG_BLOCK);
	ETAG_BLOCK("ETag: \"dummy\"\r\n"
		       ": \"dummy\"");

#undef ETAG_BLOCK
#undef FOR_ETAG
#undef RESP_ETAG_END
#undef RESP_ETAG_START
}

TEST(http1_parser, if_none_match)
{
#define ETAG_1	ETAG_ALPHABET
#define ETAG_2	"dummy2"
#define ETAG_3	"dummy3"

	FOR_REQ_SIMPLE("If-None-Match:    \"" ETAG_1 "\"  ")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag, ETAG_1 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_SIMPLE("If-None-Match:    \"\"  ")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag, "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_SIMPLE("If-None-Match:    \"" ETAG_1 "\", \"" ETAG_2 "\"  ")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag_1, ETAG_1 "\"");
		DEFINE_TFW_STR(exp_etag_2, ETAG_2 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_1, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_SIMPLE("If-None-Match:    \"" ETAG_1 "\", W/\"" ETAG_2 "\", \"" ETAG_3 "\"  ")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag_1, ETAG_1 "\"");
		DEFINE_TFW_STR(exp_etag_2, ETAG_2 "\"");
		DEFINE_TFW_STR(exp_etag_3, ETAG_3 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_1, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_3, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_SIMPLE("If-None-Match:   *  ")
	{
		EXPECT_TRUE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	/* Empty header */
	EXPECT_BLOCK_REQ_SIMPLE("If-None-Match: ");
	/* Not quoted value. */
	EXPECT_BLOCK_REQ_SIMPLE("If-None-Match: " ETAG_2);
	/* Incomplete header. */
	EXPECT_BLOCK_REQ_SIMPLE( "If-None-Match: \"" ETAG_2 "\", ");
	/* No delimiter. */
	EXPECT_BLOCK_REQ_SIMPLE("If-None-Match: \"" ETAG_2 "\" \"" ETAG_3 "\" ");
	/* Etag list + Any etag. */
	EXPECT_BLOCK_REQ_SIMPLE("If-None-Match: \"" ETAG_2 "\", * ");
	EXPECT_BLOCK_REQ_SIMPLE("If-None-Match: *, \"" ETAG_2 "\" ");

	COMMON_IF_NON_MATCH_BLOCK("If-None-Match: ", EXPECT_BLOCK_REQ_SIMPLE);
	EXPECT_BLOCK_REQ_SIMPLE("If-None-Match: \"dummy\"\r\n"
					     ": \"dummy\"");

#undef ETAG_1
#undef ETAG_2
#undef ETAG_3
}

TEST(http1_parser, referer)
{
	FOR_REQ_SIMPLE("Referer:    http://tempesta-tech.com:8080"
		       "/cgi-bin/show.pl?entry=tempesta      ");
	FOR_REQ_SIMPLE("Referer:  /cgi-bin/show.pl?entry=tempesta");
	FOR_REQ_SIMPLE("Referer: http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]"
		       ":8080/cgi-bin/show.pl?entry=tempesta");
}

TEST(http1_parser, req_hop_by_hop)
{
	TfwHttpHdrTbl *ht;
	TfwStr *field;
	long id;
#define REQ_HBH_START							\
	"POST /foo HTTP/1.1\r\n"					\
	"User-Agent: Wget/1.13.4 (linux-gnu)\r\n"			\
	"Accept: */*\r\n"						\
	"Host: localhost\r\n"						\
	"X-Custom-Hdr: custom header values\r\n"			\
	"X-Forwarded-For: 127.0.0.1, example.com\r\n"			\
	"Forwarded: for=127.0.0.1;host=example.com\r\n"			\
	"Dummy0: 0\r\n"							\
	"Dummy1: 1\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Dummy2: 2\r\n"							\
	"Dummy3: 3\r\n"							\
	"Keep-Alive: timeout=600, max=65526\r\n"

#define REQ_HBH_END							\
	"Dummy4: 4\r\n"							\
	"Dummy5: 5\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Dummy6: 6\r\n"							\
	"Content-Length: 0\r\n"						\
	"Content-Type: text/html; charset=iso-8859-1\r\n"		\
	"Dummy7: 7\r\n"							\
	"Dummy8: 8\r\n"							\
	"Buzz: is hop-by-hop header\r\n"				\
	"Dummy9: 9\r\n"							\
	"Cache-Control: max-age=1, no-store, min-fresh=30\r\n"		\
	"Pragma: no-cache, fooo \r\n"					\
	"Cookie: session=42; theme=dark\r\n"				\
	"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"	\
	"\r\n"

	/* No Hop-by-hop headers */
	FOR_REQ(REQ_HBH_START
		REQ_HBH_END)
	{
		ht = req->h_tbl;
		/* Common (raw) headers: 17 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			if (id != TFW_HTTP_HDR_KEEP_ALIVE)
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
			else
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive */
	FOR_REQ(REQ_HBH_START
		"Connection: Keep-Alive\r\n"
		REQ_HBH_END)
	{
		ht = req->h_tbl;
		/* Common (raw) headers: 17 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive and user headers */
	FOR_REQ(REQ_HBH_START
		"Connection: Foo, Keep-Alive, Bar, Buzz\r\n"
		REQ_HBH_END)
	{
		ht = req->h_tbl;
		/* Common (raw) headers: 17 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
			case TFW_HTTP_HDR_RAW + 4:
			case TFW_HTTP_HDR_RAW + 12:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Connection header lists end-to-end spec headers */
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Host\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Content-Length\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Content-Type\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Connection\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: X-Forwarded-For\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Forwarded\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Transfer-Encoding\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: User-Agent\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Server\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: Cookie\r\n"
			 REQ_HBH_END);

	/* Connection header lists end-to-end raw headers */
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: authorization\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: cache-control\r\n"
			 REQ_HBH_END);
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: pragma\r\n"
			 REQ_HBH_END);

	/* Too lot of connection tokens */
	EXPECT_BLOCK_REQ(REQ_HBH_START
			 "Connection: t1, t2, t3, t4, t5, t6, t7, t8, t9, t10,"
			 "t11, t12, t13, t14, t15, t16, t17\r\n"
			 REQ_HBH_END);

#undef REQ_HBH_START
#undef REQ_HBH_END
}

TEST(http1_parser, resp_hop_by_hop)
{
	TfwHttpHdrTbl *ht;
	TfwStr *field;
	long id;
#define RESP_HBH_START							\
	"HTTP/1.1 200 OK\r\n"						\
	"Dummy0: 0\r\n"							\
	"Dummy1: 1\r\n"							\
	"Dummy2: 2\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Dummy3: 3\r\n"							\
	"Dummy4: 4\r\n"							\
	"Dummy5: 5\r\n"

#define RESP_HBH_END							\
	"Dummy6: 6\r\n"							\
	"Content-Length: 3\r\n"						\
	"Content-Type: text/html; charset=iso-8859-1\r\n"		\
	"Dummy7: 7\r\n"							\
	"Buzz: is hop-by-hop header\r\n"				\
	"Keep-Alivevv: hello there\r\n"					\
	"Dummy8: 8\r\n"							\
	"Foo: is hop-by-hop header\r\n"					\
	"Cache-Control: max-age=5, private, no-cache, ext=foo\r\n"	\
	"Dummy9: 9\r\n"							\
	"Expires: Tue, 31 Jan 2012 15:02:53 GMT\r\n"			\
	"Keep-Alive: timeout=600, max=65526\r\n"			\
	"Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips"		\
		" mod_fcgid/2.3.9\r\n"					\
	"Bar: is hop-by-hop header\r\n"					\
	"Age: 12  \n"							\
	"Date: Sun, 9 Sep 2001 01:46:40 GMT\t\n"			\
	"\r\n"								\
	"012"

	/* No Hop-by-hop headers */
	FOR_RESP(RESP_HBH_START
		 RESP_HBH_END)
	{
		ht = resp->h_tbl;
		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_SERVER:
			case TFW_HTTP_HDR_KEEP_ALIVE:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive */
	FOR_RESP(RESP_HBH_START
		 "Connection: Keep-Alive\r\n"
		 RESP_HBH_END)
	{
		ht = resp->h_tbl;
		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_SERVER:
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Hop-by-hop headers: Connection, Keep-Alive and user headers */
	FOR_RESP(RESP_HBH_START
		 "Connection: Foo, Keep-Alive, Bar, Buzz, Keep-Alivevv\r\n"
		 RESP_HBH_END)
	{
		ht = resp->h_tbl;
		/* Common (raw) headers: 16 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 17);

		for(id = 0; id < ht->off; ++id) {
			field = &ht->tbl[id];
			switch (id) {
			case TFW_HTTP_HDR_SERVER:
			case TFW_HTTP_HDR_CONNECTION:
			case TFW_HTTP_HDR_KEEP_ALIVE:
			/* Foo: is hop-by-hop header */
			case TFW_HTTP_HDR_RAW + 3:
			/* Buzz: is hop-by-hop header */
			case TFW_HTTP_HDR_RAW + 9:
			/* Keep-Alivevv: hello there */
			case TFW_HTTP_HDR_RAW + 10:
			/* Bar: is hop-by-hop header */
			case TFW_HTTP_HDR_RAW + 15:
				TEST_DBG3("test HBH flag, h_tbl->tbl[%lu]\n", id);
				EXPECT_TRUE(field->flags & TFW_STR_HBH_HDR);
				break;
			default:
				EXPECT_FALSE(field->flags & TFW_STR_HBH_HDR);
				break;
			}
		}
	}

	/* Connection header lists end-to-end spec headers */
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Host\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Content-Length\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Content-Type\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Connection\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: X-Forwarded-For\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_REQ(RESP_HBH_START
			 "Connection: Forwarded\r\n"
			 RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Transfer-Encoding\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: User-Agent\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Server\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: Cookie\r\n"
			  RESP_HBH_END);

	/* Connection header lists end-to-end raw headers */
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: age\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: authorization\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: cache-control\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: date\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: expires\r\n"
			  RESP_HBH_END);
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: pragma\r\n"
			  RESP_HBH_END);

	/* Too lot of connection tokens */
	EXPECT_BLOCK_RESP(RESP_HBH_START
			  "Connection: t1, t2, t3, t4, t5, t6, t7, t8, t9, t10,"
			  "t11, t12, t13, t14, t15, t16, t17\r\n"
			  RESP_HBH_END);

#undef RESP_HBH_START
#undef RESP_HBH_END
}

#define N 6	// Count of generations
#define MOVE 1	// Mutations per generation

TEST(http1_parser, fuzzer)
{
	size_t len = 10 * 1024 * 1024;
	char *str;
	int field, i, ret;
	TfwFuzzContext context;

	kernel_fpu_end();
	str = vmalloc(len);
	kernel_fpu_begin();
	if (!str) {
		pr_err("vmalloc() failure, too small RAM?\n");
		return;
	}

	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_DBG3("start field: %d request: %d\n", field, i);
			ret = fuzz_gen_h1(&context, str, str + len, field, MOVE,
				       FUZZ_REQ);
			test_case_parse_prepare_http(str);
			switch (ret) {
			case FUZZ_VALID:
				TRY_PARSE_EXPECT_PASS(FUZZ_REQ, CHUNK_ON);
				break;
			case FUZZ_INVALID:
				TRY_PARSE_EXPECT_BLOCK(FUZZ_REQ, CHUNK_ON);
				break;
			case FUZZ_END:
			default:
				goto resp;
			}

			/* Fuzzer generates huge debug message flow. */
			__fpu_schedule();
		}
	}
resp:
	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_DBG3("start field: %d response: %d\n", field, i);
			ret = fuzz_gen_h1(&context, str, str + len, field, MOVE,
				       FUZZ_RESP);
			test_case_parse_prepare_http(str);
			switch (ret) {
			case FUZZ_VALID:
				TRY_PARSE_EXPECT_PASS(FUZZ_RESP, CHUNK_ON);
				break;
			case FUZZ_INVALID:
				TRY_PARSE_EXPECT_BLOCK(FUZZ_RESP, CHUNK_ON);
				break;
			case FUZZ_END:
			default:
				goto end;
			}

			/* Fuzzer generates huge debug message flow. */
			__fpu_schedule();
		}
	}
end:
	kernel_fpu_end();
	vfree(str);
	kernel_fpu_begin();
}

#define HEAD "POST / HTTP/1.1\r\nHost: localhost.localdomain\r\nContent-Type: "
#define TAIL "\nContent-Length: 0\r\nKeep-Alive: timeout=98765\r\n\r\n"

#define CT01 "multIPart/forM-data  ;    bouNDary=1234567890 ; otherparam=otherval  "

TEST_MPART(http1_parser, content_type_line_parser, 0)
{
	FOR_REQ(HEAD CT01 TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				     req->flags));
		EXPECT_TFWSTR_EQ(&req->multipart_boundary_raw, "1234567890");
		EXPECT_TFWSTR_EQ(&req->multipart_boundary, "1234567890");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: " CT01);
	}

	FOR_REQ(HEAD "multipart/form-data; boundary=\"1234\\56\\\"7890\"" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				     req->flags));
		EXPECT_TFWSTR_EQ(&req->multipart_boundary_raw,
				 "\"1234\\56\\\"7890\"");
		EXPECT_TFWSTR_EQ(&req->multipart_boundary, "123456\"7890");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data; "
				 "boundary=\"1234\\56\\\"7890\"");
	}

	FOR_REQ(HEAD "multipart/form-data" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data");
	}

	FOR_REQ(HEAD "multipart/form-data " TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data ");
	}

	FOR_REQ(HEAD "multipart/form-data \t" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data \t");
	}

	FOR_REQ(HEAD "multipart/form-data1" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data1");
	}
}

TEST_MPART(http1_parser, content_type_line_parser, 1)
{
	FOR_REQ(HEAD "multipart/form-data1; param=value" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data1; "
				 "param=value");
	}

	FOR_REQ(HEAD "multihello/world" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multihello/world");
	}

	FOR_REQ(HEAD "multihello/world; param=value" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multihello/world; param=value");
	}

	FOR_REQ(HEAD "multipart/form-dat" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-dat");
	}

	FOR_REQ(HEAD "multipart/form-other; param=value" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-other; "
				 "param=value");
	}

	FOR_REQ(HEAD "multipart/form-data; xboundary=1234567890" TAIL) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multipart/form-data; "
				 "xboundary=1234567890");
	}

	FOR_REQ(HEAD "application/octet-stream" TAIL) {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: application/octet-stream");
	}
}

TEST_MPART(http1_parser, content_type_line_parser, 2)
{
	/* Multipart requests with multiple boundaries are clearly malicious. */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary=1; boundary=2"
			 TAIL);

	/* Comma is not a valid separator here. */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data, boundary=123" TAIL);

	/* Unfinished quoted parameter value */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary=\"123" TAIL);

	/* Spaces where they do not belong */
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary =123" TAIL);
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary= 123" TAIL);
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boundary=12 3" TAIL);
	EXPECT_BLOCK_REQ(HEAD "multipart/form-data; boun dary=123" TAIL);

	/*
	 * Other media types are not restricted in terms of boundary parameter
	 * quantities.
	 */
	FOR_REQ(HEAD "text/plain; boundary=1; boundary=2" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; boundary=1; "
				 "boundary=2");
	}
	FOR_REQ(HEAD "text/plain; boundary=1; boundary=2; boundary=3" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; boundary=1; "
				 "boundary=2; boundary=3");
	}
	FOR_REQ(HEAD "textqwe/plain; boundary=1; other=3" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: textqwe/plain; boundary=1; "
				 "other=3");
	}

	/* Parameter should be in format name=value. */
	EXPECT_BLOCK_REQ(HEAD "text/plain; name" TAIL);
	EXPECT_BLOCK_REQ(HEAD "text/plain; name " TAIL);
	EXPECT_BLOCK_REQ(HEAD "text/plain; name\t " TAIL);
}

TEST_MPART(http1_parser, content_type_line_parser, 3)
{

	/* Unfinished quoted parameter value */
	EXPECT_BLOCK_REQ(HEAD "text/plain; name=\"unfinished" TAIL);

	/* Other parameter quoted values. */
	FOR_REQ(HEAD "text/plain; name=\"value\"" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; name=\"value\"");
	}
	FOR_REQ(HEAD "text/plain; name=\"value\" " TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; name=\"value\" ");
	}
	FOR_REQ(HEAD "text/plain; name=\"value\";" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; name=\"value\";");
	}
	FOR_REQ(HEAD "text/plain; name=\"value\"; " TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; name=\"value\"; ");
	}

	FOR_REQ(HEAD "text/plain; name=\"val\\\"ue\"" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; name=\"val\\\"ue\"");
	}
	FOR_REQ(HEAD "text/plain; name=\"val\\\"ue\" " TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: text/plain; name=\"val\\\"ue\" ");
	}

	/* Line ended at '\\'. */
	EXPECT_BLOCK_REQ(HEAD "text/plain; name=\"val\\" TAIL);

	FOR_REQ(HEAD "multitest" TAIL) {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "Content-Type: multitest");
	}

}

#undef HEAD
#undef TAIL

TEST_MPART_DEFINE(http1_parser, content_type_line_parser, H1_CT_LINE_PARSER_TCNT,
		  TEST_MPART_NAME(http1_parser, content_type_line_parser, 0),
		  TEST_MPART_NAME(http1_parser, content_type_line_parser, 1),
		  TEST_MPART_NAME(http1_parser, content_type_line_parser, 2),
		  TEST_MPART_NAME(http1_parser, content_type_line_parser, 3));

TEST(http1_parser, xff)
{
	TfwStr xff, v;

	const char *s_client = "203.0.113.195";
	const char *s_proxy1 = "70.41.3.18";
	const char *s_proxy2 = "150.172.238.178";

	FOR_REQ_SIMPLE("X-Forwarded-For: "
		       "203.0.113.195,70.41.3.18,150.172.238.178")
	{
		xff = req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];

		v = get_next_str_val(&xff);
		EXPECT_TFWSTR_EQ(&v, s_client);

		v = get_next_str_val(&xff);
		EXPECT_TFWSTR_EQ(&v, s_proxy1);

		v = get_next_str_val(&xff);
		EXPECT_TFWSTR_EQ(&v, s_proxy2);
	}
}

#define FOR_EACH_DATE(strdate, expect_seconds)					\
	FOR_RESP_SIMPLE("Last-Modified:" strdate)				\
	{									\
		EXPECT_TRUE(resp->last_modified == expect_seconds);		\
		EXPECT_TRUE(test_bit(TFW_HTTP_B_HDR_LMODIFIED, resp->flags));	\
	}									\
	FOR_RESP_SIMPLE("Date:" strdate)					\
	{									\
		EXPECT_TRUE(resp->date == expect_seconds);			\
		EXPECT_TRUE(test_bit(TFW_HTTP_B_HDR_DATE, resp->flags));	\
	}									\
	FOR_RESP_SIMPLE("Expires:" strdate)					\
	{									\
		EXPECT_TRUE(resp->cache_ctl.expires == expect_seconds);		\
		EXPECT_TRUE(resp->cache_ctl.flags & TFW_HTTP_CC_HDR_EXPIRES);	\
	}									\
	FOR_REQ_SIMPLE("If-Modified-Since:" strdate)				\
	{									\
		EXPECT_TRUE(req->cond.m_date == expect_seconds);		\
		EXPECT_TRUE(req->cond.flags & TFW_HTTP_COND_IF_MSINCE);		\
	}

#define FOR_EACH_DATE_INVALID(strdate)	FOR_EACH_DATE(strdate, 0)

/*
 * Use this macros in cases where exactly
 * 4-digit year tests make sence and 2-digits don't.
 */
#define FOR_EACH_DATE_RFC_822_ISOC(day, month, year, time, expect_seconds)\
	/* Day name is redundant so is skipped on parsing */			\
	FOR_EACH_DATE("Inv, " day " " month " " year " " time " GMT",		\
		      expect_seconds);						\
	/* For ISOC format test only 2 digits in day */				\
	FOR_EACH_DATE("Inv " month " " day " " time " " year, expect_seconds)

#define FOR_EACH_DATE_RFC_822_ISOC_INVALID(day, month, year, time)		\
	FOR_EACH_DATE_RFC_822_ISOC(day, month, year, time, 0)

#define FOR_EACH_DATE_FORMAT(day, month, year, year_2d, time, expect_seconds)	\
	FOR_EACH_DATE_RFC_822_ISOC(day, month, year, time, expect_seconds);	\
	/* ISO850 */								\
	FOR_EACH_DATE("Invalid, " day "-" month "-" year_2d " " time " GMT", 	\
		      expect_seconds)

#define FOR_EACH_DATE_FORMAT_INVALID(day, month, year, year_2d, time)		\
	FOR_EACH_DATE_FORMAT(day, month, year, year_2d, time, 0)

#define IF_MSINCE_INVALID(headers)						\
	FOR_REQ_SIMPLE(headers)							\
	{									\
		EXPECT_TRUE(req->cond.m_date == 0);				\
	}

TEST_MPART(http1_parser, date, 0)
{
	FOR_EACH_DATE_FORMAT("31", "Jan", "2012", "12", "15:02:53",
				   1328022173);
	FOR_EACH_DATE_FORMAT_INVALID("31", "JAN", "2012", "12", "15:02:53");

	FOR_EACH_DATE_FORMAT_INVALID(" 31", "Jan", "2012", "12", "15:02:53");
	FOR_EACH_DATE_FORMAT_INVALID("31", " Jan", "2012", "12", "15:02:53");
	FOR_EACH_DATE_FORMAT_INVALID("31", "Jan", " 2012", " 12", "15:02:53");
	FOR_EACH_DATE_FORMAT_INVALID("31", "Jan", "2012", "12", " 15:02:53");

	/* Header-specific tests. */
	/*
	 * RFC 7232 3.3.
	 *
	 * A recipient MUST ignore If-Modified-Since if the request contains an
	 * If-None-Match header field.
	 */
	IF_MSINCE_INVALID("If-None-Match: \"xyzzy\"\r\n"
			  "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT");
	IF_MSINCE_INVALID("If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n"
			  "If-None-Match: \"xyzzy\"");

	/*
	 * RFC 7232 3.3.
	 *
	 * A recipient MUST ignore the If-Modified-Since header field ...
	 * if the request method is neither GET nor HEAD.
	 */
	FOR_REQ("POST / HTTP/1.1\r\n"
		"If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n"
		"\r\n")
	{
		EXPECT_TRUE(req->cond.m_date == 0);
	}
	FOR_REQ("PUT / HTTP/1.1\r\n"
		"If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n"
		"\r\n")
	{
		EXPECT_TRUE(req->cond.m_date == 0);
	}
}

TEST_MPART(http1_parser, date, 1)
{
	/*
	 * RFC 7230 3.2.2:
	 *
	 * A sender MUST NOT generate multiple header fields with the same field
	 * name in a message unless either the entire field value for that
	 * header field is defined as a comma-separated list [i.e., #(values)]
	 * or the header field is a well-known exception.
	 */
	EXPECT_BLOCK_RESP_SIMPLE("Last-Modified: "
				 "Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				 "Last-Modified: "
				 "Wed, 21 Oct 2015 07:28:00 GMT");
	EXPECT_BLOCK_RESP_SIMPLE("Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				 "Date: Wed, 21 Oct 2015 07:28:00 GMT");
	EXPECT_BLOCK_RESP_SIMPLE("Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				 "Expires: Wed, 21 Oct 2015 07:28:00 GMT");
	EXPECT_BLOCK_REQ_SIMPLE("If-Modified-Since: "
				"Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				"If-Modified-Since: "
				"Wed, 21 Oct 2015 07:28:00 GMT");

	/* If only 1 or 0 dates are valid, it's the multiple headers anyway. */
	EXPECT_BLOCK_RESP_SIMPLE("Last-Modified: "
				 "Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				 "Last-Modified: "
				 "Wed, 41 Oct 2015 07:28:00 GMT");
	EXPECT_BLOCK_RESP_SIMPLE("Date: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				 "Date: Wed, 41 Oct 2015 07:28:00 GMT");
	EXPECT_BLOCK_RESP_SIMPLE("Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				 "Expires: Wed, 41 Oct 2015 07:28:00 GMT");
	EXPECT_BLOCK_REQ_SIMPLE("If-Modified-Since: "
				"Wed, 21 Oct 2015 07:28:00 GMT\r\n"
				"If-Modified-Since: "
				"Wed, 41 Oct 2015 07:28:00 GMT");

	/* Date tests. */

	/* Date ranges. */
	/*
	 * Less then 01 Jan 1970.
	 * Date in RFC 850 can not be less then 01 Jan 1970.
	 */
	/* Treat as 00, 69, 70 (and so on) year CE */
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "0000", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("31", "Dec", "0069", "23:59:59");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "0070", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "0070", "00:00:01");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "0099", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "0100", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "0999", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("31", "Dec", "1969", "23:59:59");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "1970", "00:00:00");
}

TEST_MPART(http1_parser, date, 2)
{
	/* More then 01 Jan 1970. */
	/*
	 * For ISO 850 this implementation violates RFC:
	 *
	 * Recipients of a timestamp value in rfc850-date format, which uses a
	 * two-digit year, MUST interpret a timestamp that appears to be more
	 * than 50 years in the future as representing the most recent year in
	 * the past that had the same last two digits.
	 *
	 * But it's done intensionally, also Nginx implements the same logic.
	 */
	FOR_EACH_DATE_FORMAT("01", "Jan", "1970", "70", "00:00:01", 1);
	/* 2000 */
	FOR_EACH_DATE_FORMAT("01", "Jan", "2000", "00", "00:00:00",
				   946684800);
	FOR_EACH_DATE("Invalid, 01-Jan-00 00:00:00 GMT", 946684800);
	/* 2069 */
	FOR_EACH_DATE_FORMAT("31", "Dec", "2069", "69", "23:59:59",
				   3155759999);
	FOR_EACH_DATE_RFC_822_ISOC("31", "Dec", "9999", "23:59:59",
					 253402300799);
	/*
	 * Incorrect day
	 */
	/*
	 * According to RFC "00" is a valid day, but Tempesta rejects it
	 * because of ambiguity of its interpretation.
	 */
	FOR_EACH_DATE_FORMAT_INVALID("00", "Jan", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("", "Jan", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("0", "Jan", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("1", "Jan", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("32", "Jan", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("-1", "Jan", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("invalid", "Jan", "2000", "00",
				     "00:00:00");
}

TEST_MPART(http1_parser, date, 3)
{
	FOR_EACH_DATE_FORMAT("30", "Apr", "1978", "78", "00:00:00",
				   262742400);
	FOR_EACH_DATE_FORMAT_INVALID("31", "Apr", "1995", "95", "00:00:00");
	FOR_EACH_DATE_FORMAT("31", "Jul", "2003", "03", "00:00:00",
				   1059609600);
	FOR_EACH_DATE_FORMAT("30", "Sep", "2009", "09", "00:00:00",
				   1254268800);
	FOR_EACH_DATE_FORMAT_INVALID("31", "Sep", "2050", "50", "00:00:00");

	/* Leap years */
	FOR_EACH_DATE_FORMAT("29", "Feb", "1996", "96", "00:00:00", 825552000);
	FOR_EACH_DATE_FORMAT_INVALID("29", "Feb", "1999", "99", "00:00:00");

	/* Incorrect month. */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Ja", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Janu", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "January", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jab", "2000", "00", "00:00:00");

	/* Incorrect year. */
	/* Only 4 digits for RFC 822 & ISOC and 2 digits for RFC 850 allowed */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "0", "0", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "1", "1", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "44", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "000", "000","00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "999", "999", "00:00:00");
	FOR_EACH_DATE_RFC_822_ISOC_INVALID("01", "Jan", "10000", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "", "", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "-1", "-1","00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "invalid", "invalid",
				     "00:00:00");
}


TEST_MPART(http1_parser, date, 4)
{
	/* Incorrect hours. */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", ":00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "0:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "000:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "24:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "100:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "-1:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "invalid:00:00");

	/* Incorrect minutes. */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00::00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:0:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:000:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:60:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:100:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:-1:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:invalid:00");

	/*
	 * Incorrect seconds.
	 */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:0");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:000");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:60");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:100");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:-1");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:invalid");
	/* Leap seconds are not implemented (as in Nginx) */
	FOR_EACH_DATE_FORMAT_INVALID("30", "Jun", "1992", "92", "23:59:60");

	/*
	 * Format specific tests.
	 */
	/* Only GMT allowed */
	FOR_EACH_DATE_INVALID("Inv, 01 Jan 2000 00:00:00 EST");
	FOR_EACH_DATE_INVALID("Invalid, 01-Jan-00 00:00:00 EST");

	/* GMT is requred */
	FOR_EACH_DATE_INVALID("Inv, 01 Jan 2000 00:00:00");
	FOR_EACH_DATE_INVALID("Invalid, 01-Jan-00 00:00:00");

	/*
	 * ISOC
	 * Only 2 spaces for 1-digit day and 1 space for 2-digit day
	 */
	FOR_EACH_DATE("Inv Jan  1 00:00:01 1970", 1);
	FOR_EACH_DATE("Inv Jan 01 00:00:01 1970", 1);
	FOR_EACH_DATE_INVALID("Inv Jan   1 00:00:01 1970");
	FOR_EACH_DATE_INVALID("Inv Jan  01 00:00:01 1970");

	FOR_EACH_DATE_INVALID("invalid");
}

#undef IF_MSINCE_INVALID
#undef FOR_EACH_DATE_FORMAT_INVALID
#undef FOR_EACH_DATE_FORMAT
#undef FOR_EACH_DATE_RFC_822_ISOC_INVALID
#undef FOR_EACH_DATE_RFC_822_ISOC
#undef FOR_EACH_DATE_INVALID
#undef FOR_EACH_DATE

TEST_MPART_DEFINE(http1_parser, date, H1_DATE_PARSE_TCNT,
		  TEST_MPART_NAME(http1_parser, date, 0),
		  TEST_MPART_NAME(http1_parser, date, 1),
		  TEST_MPART_NAME(http1_parser, date, 2),
		  TEST_MPART_NAME(http1_parser, date, 3),
		  TEST_MPART_NAME(http1_parser, date, 4));


TEST(http1_parser, method_override)
{
	FOR_REQ("POST / HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, _TFW_HTTP_METH_NONE);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"X-Method-Override: PATCH\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_PATCH);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"X-Method-Override: PUT\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_PUT);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"X-HTTP-Method-Override: PUT\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_PUT);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"X-HTTP-Method: PUT\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_PUT);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"X-Method-Override: PATCHH\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, _TFW_HTTP_METH_UNKNOWN);
	}

	FOR_REQ("POST / HTTP/1.1\r\n"
		"X-Method-Override: PATCH COPY\r\n"
		"Host: example.com\r\n"
		"\r\n")
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, _TFW_HTTP_METH_UNKNOWN);
	}
}
TEST(http1_parser, vchar)
{
/* Tests that header is validated by ctext_vchar alphabet. */
#define TEST_VCHAR_HEADER(header, id, MSG_TYPE)				\
	FOR_##MSG_TYPE##_HDR_EQ(header ":", id);			\
	FOR_##MSG_TYPE##_HDR_EQ(header ":" VCHAR_ALPHABET, id);		\
	EXPECT_BLOCK_##MSG_TYPE##_SIMPLE(header ":\x00");		\
	EXPECT_BLOCK_##MSG_TYPE##_SIMPLE(header ":\x08");		\
	EXPECT_BLOCK_##MSG_TYPE##_SIMPLE(header ":\x0B");		\
	EXPECT_BLOCK_##MSG_TYPE##_SIMPLE(header ":\x14");		\
	EXPECT_BLOCK_##MSG_TYPE##_SIMPLE(header ":\x1F");		\
	EXPECT_BLOCK_##MSG_TYPE##_SIMPLE(header ":\x7F");

#define TEST_RAW_REQ(header) TEST_VCHAR_HEADER(header, TFW_HTTP_HDR_RAW, REQ)
#define TEST_RAW_RESP(header) TEST_VCHAR_HEADER(header, TFW_HTTP_HDR_RAW, RESP)

	/* Special headers */
	TEST_VCHAR_HEADER("Content-Type", TFW_HTTP_HDR_CONTENT_TYPE, RESP);
	TEST_VCHAR_HEADER("Content-Location", TFW_HTTP_HDR_CONTENT_LOCATION, RESP);
	TEST_VCHAR_HEADER("Server", TFW_HTTP_HDR_SERVER, RESP);
	TEST_VCHAR_HEADER("User-Agent", TFW_HTTP_HDR_USER_AGENT, REQ);

	/* Raw headers */
	TEST_RAW_RESP("Access-Control-Allow-Origin");
	TEST_RAW_RESP("Accept-Ranges");
	TEST_RAW_RESP("Authorization");
	TEST_RAW_RESP("Allow");
	TEST_RAW_RESP("Content-Disposition");
	TEST_RAW_RESP("Content-Language");
	TEST_RAW_RESP("Content-Range");
	TEST_RAW_RESP("Link");
	TEST_RAW_RESP("Location");
	TEST_RAW_RESP("Proxy-Authenticate");
	TEST_RAW_RESP("Retry-After");
	TEST_RAW_RESP("Strict-Transport-Security");
	TEST_RAW_RESP("Vary");
	TEST_RAW_RESP("Via");
	TEST_RAW_RESP("WWW-Authenticate");

	/* RGen_HdrOtherN headers */
	TEST_RAW_REQ(TOKEN_ALPHABET ":dummy");
	TEST_RAW_RESP(TOKEN_ALPHABET ":dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\x09:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\":dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE(",:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("/:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("::dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE(";:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("<:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("=:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE(">:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("?:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("@:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("[:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\\:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("]:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("{:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("}:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\x7F:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\x80:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\x90:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\xC8:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\xAE:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\xFE:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\xFF:dummy");
	EXPECT_BLOCK_REQ_RESP_SIMPLE("\xFF:dummy");
	/* Very long header name */
	EXPECT_BLOCK_REQ_RESP_SIMPLE("Well-Prince-so-Genoa-and-Lucca-are-now-"
	"just-family-estates-of-the-Buonapartes-But-I-warn-you-if-you-dont-"
	"tell-me-that-this-means-war-if-you-still-try-to-defend-the-infamies-"
	"and-horrors-perpetrated-by-that-Antichrist-I-really-believe-he-is-"
	"Antichrist-I-will-have-nothing-more-to-do-with-you-and-you-are-no-"
	"longer-my-friend-no-longer-my-faithful-slave-as-you-call-yourself!-"
	"But-how-do-you-do-I-see-I-have-frightened-you-sit-down-and-tell-me-"
	"all-the-news#It-was-in-July-1805-and-the-speaker-was-the-well-known-"
	"Anna-Pavlovna-Scherer-maid-of-honor-and-favorite-of-the-Empress-"
	"Marya-Fedorovna-With-these-words-she-greeted-Prince-Vasili-Kuagin-a-"
	"man-of-high-rank-and-importance-who-was-the-first-to-arrive-at-her-"
	"reception-Anna-Pavlovna-had-had-a-cough-for-some-days-She-was-as-she-"
	"said-suffering-from-la-grippe-grippe-being-then-a-new-word-in-St-"
	"Petersburg-used-only-by-the-elite#All-her-invitations-without-"
	"exception-written-in-French-and-delivered-by-a-scarlet-liveried-"
	"footman-that-morning-ran-as-follows#If-you-have-nothing-better-to-do"
	"-Count-(or-Prince)-and-if-the-prospect-of-spending-an-evening-with-a"
	"-poor-invalid-is-not-too-terrible-I-shall-be-very-charmed-to-see-you"
	"-tonight-between-7-and-10-Annette-Scherer#Heavens!-what-a-virulent-"
	"attack!-replied-the-prince-not-in-the-least-disconcerted-by-this-"
	"reception-He-had-just-entered-wearing-an-embroidered-court-uniform-"
	"knee-breeches-and-shoes-and-had-stars-on-his-breast-and-a-serene-"
	"expression-on-his-flat-face-He-spoke-in-that-refined-French-in-which"
	"-our-grandfathers-not-only-spoke-but-thought-and-with-the-gentle-"
	"patronizing-intonation-natural-to-a-man-of-importance-who-had-grown-"
	"old-in-society-and-at-court-He-went-up-to-Anna-Pavlovna-kissed-her-"
	"hand-presenting-to-her-his-bald-scented-and-shining-head-and-"
	"complacently-seated-himself-on-the-sofa#First-of-all-dear-friend-tell"
	"-me-how-you-are-Set-your-friends-mind-at-rest-said-he-without-"
	"altering-his-tone-beneath-the-politeness-and-affected-sympathy-of-"
	"which-indifference-and-even-irony-could-be-discerned:dummy");

#undef TEST_RAW_REQ
#undef TEST_RAW_RESP
#undef TEST_VCHAR_HEADER
}

TEST(http1_parser, x_tempesta_cache)
{
	FOR_REQ_SIMPLE("X-Tempesta-Cache: get ") {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_PURGE_GET, req->flags));
	}
	FOR_REQ_SIMPLE("X-Tempesta-Cache: get, get") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_PURGE_GET, req->flags));
	}
	FOR_REQ_SIMPLE("X-Tempesta-Cache: ge ") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_PURGE_GET, req->flags));
	}
	FOR_REQ_SIMPLE("X-Tempesta-Cache: head ") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_PURGE_GET, req->flags));
	}
}

TEST_MPART(http1_parser, forwarded, 0)
{
	/* Invalid port. */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
		       "host=tempesta-tech.com:0");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=tempesta-tech.com:65536");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=tempesta-tech.com:");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=tempesta-tech.com:443;");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=tempesta-tech.com:443\"");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=tempesta-tech.com:443 ;");

	/* Space after semicolon */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded:"
		       "host=tempesta-tech.com:443; proto=http");
	/* Space before semicolon */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded:"
		       "host=tempesta-tech.com:443 ;proto=http");
	/* Spaces around semicolon */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded:"
		       "host=tempesta-tech.com:443 ; proto=http");

	/* Invalid non quoted IPv6. */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=[111:222:233]");
	/* IPv6 with invalid chars. */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: "
				"host=[111:p22:t3]");

	/* Quoted host with port. */
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=\"tempesta-tech.com:443\"");
	/* Quoted IPv6 host with port. */
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=\"[11:22:33:44]:443\"");
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443    ");

}

TEST_MPART(http1_parser, forwarded, 1)
{
	/* Common cases. */
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1 },
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE }
			},
			.len = 41,
			.nchunks = 6
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
			},
			.len = 37,
			.nchunks = 4
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443;"
		       "for=8.8.8.8")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1 },
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE },
			},
			.len = 53,
			.nchunks = 9
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443;"
		       "for=8.8.8.8;"
		       "by=8.8.4.4")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE },
			},
			.len = 64,
			.nchunks = 12
		};

		test_string_split(&h_expected, forwarded);
	}
}

TEST_MPART(http1_parser, forwarded, 2)
{
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443;"
		       "for=8.8.8.8;"
		       "by=8.8.4.4;"
		       "proto=https")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1 },
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "proto=", .len = 6,
				  .flags = TFW_STR_NAME },
				{ .data = "https", .len = 5,
				  .flags = TFW_STR_VALUE },
			},
			.len = 76,
			.nchunks = 15
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443;"
		       "for=8.8.8.8,"
		       "for=1.2.3.4:8080;"
		       "by=8.8.4.4;"
		       "proto=https")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1 },
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = ",", .len = 1 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "1.2.3.4:8080", .len = 12,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "proto=", .len = 6,
				  .flags = TFW_STR_NAME },
				{ .data = "https", .len = 5,
				  .flags = TFW_STR_VALUE },
			},
			.len = 93,
			.nchunks = 18
		};

		test_string_split(&h_expected, forwarded);
	}

	/* quoted version */
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=tempesta-tech.com:443;"
		       "for=\"8.8.8.8\";"
		       "by=8.8.4.4")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "\"", .len = 1 },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = "\";", .len = 2 },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE },
			},
			.len = 66,
			.nchunks = 13
		};

		test_string_split(&h_expected, forwarded);
	}

	/* quoted version */
	FOR_REQ_SIMPLE("Forwarded:     "
		       "host=\"tempesta-tech.com:443\";"
		       "for=8.8.8.8;"
		       "by=8.8.4.4")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:", .len = 10 },
				{ .data = "     ", .len = 5,
				  .flags = TFW_STR_OWS },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "\"", .len = 1 },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE },
				{ .data = ":", .len = 1},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE },
				{ .data = "\";", .len = 2 },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE },
				{ .data = ";", .len = 1 },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE },
			},
			.len = 66,
			.nchunks = 13
		};

		test_string_split(&h_expected, forwarded);
	}
}

TEST_MPART(http1_parser, forwarded, 3) {
	/* Cases from RFC 7239. */
	FOR_REQ_SIMPLE("Forwarded: for=\"_gazonk\"");
	FOR_REQ_SIMPLE("Forwarded: For=\"[2001:db8:cafe::17]:4711\"");
	FOR_REQ_SIMPLE("Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43");
	FOR_REQ_SIMPLE("Forwarded: for=192.0.2.43, for=198.51.100.17");

	/* Shuffle params */
	FOR_REQ_SIMPLE("Forwarded: "
		       "for=1.2.3.4;"
		       "host=example.com;"
		       "by=8.8.8.8;"
		       "proto=https");

	FOR_REQ_SIMPLE("Forwarded: "
		       "host=example.com;"
		       "for=1.2.3.4;"
		       "by=8.8.8.8;"
		       "proto=https");

	FOR_REQ_SIMPLE("Forwarded: "
		       "host=example.com;"
		       "by=8.8.8.8;"
		       "for=1.2.3.4;"
		       "proto=https");

	FOR_REQ_SIMPLE("Forwarded: "
		       "host=example.com;"
		       "by=8.8.8.8;"
		       "proto=https;"
		       "for=1.2.3.4");

	FOR_REQ_SIMPLE("Forwarded: "
		       "for=1.2.3.4;"
		       "by=8.8.8.8;"
		       "host=example.com;"
		       "proto=https");

	FOR_REQ_SIMPLE("Forwarded: "
		       "proto=https;"
		       "host=example.com;"
		       "for=1.2.3.4;"
		       "by=8.8.8.8");

	FOR_REQ_SIMPLE("Forwarded: "
		       "by=8.8.8.8;"
		       "host=example.com;"
		       "for=1.2.3.4;"
		       "proto=https");

	FOR_REQ_SIMPLE("Forwarded: "
		       "by=8.8.8.8;"
		       "proto=https;"
		       "for=1.2.3.4;"
		       "host=example.com");

	/* 
	 * Duplicated params name.
	 *
	 * RFC 7239 section 4:
	 * Each parameter MUST NOT occur more than once per field-value.
	 */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: proto=http;for=8.8.8.8;proto=http");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=2.2.2.2;for=8.8.8.8;by=2.2.2.2");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: host=goo.gl;for=8.8.8.8;host="
				"example.com");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.1.1.1;host=goo.gl;for="
				"2.2.2.2");
	/* "for=" represented as separated list is allowed */
	FOR_REQ_SIMPLE("Forwarded: for=1.1.1.1, for=2.2.2.2;host="
				"goo.gl");

	/* Suspicious */
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=\"\"");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: host=");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: host=\"\"");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: host=\"[]\"");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=\"\"");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: proto=");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: proto=\"\"");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4,");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4, ");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4, ,for=5.6.7.8");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4, , 5.6.7.8;");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: foo!");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: ");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4;host=\"goo.gl");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4;proto='https';"
				"host=goo.gl");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4;proto=<xss>;"
				"host=goo.gl");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4;proto=\"><xss>;"
				"host=goo.gl");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4;proto=\"\"><xss>\";"
				"host=goo.gl");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: for=1.2.3.4;proto=\""
				"onclick=alert(1);host=goo.gl");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=1.2.3.4;host=\"><xss>;"
				"proto=http");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=1.2.3.4;host=\" alert(1);"
				"proto=http");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=1.2.3.4;host=' goo.gl;"
				"proto=http");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=1.2.3.4;host=http;proto=http;"
				"for=<xss>");
	EXPECT_BLOCK_REQ_SIMPLE("Forwarded: by=<xss>;host=http;proto=http;"
				"for=1.2.3.4");
}

TEST_MPART_DEFINE(http1_parser, forwarded, H1_FWD_TCNT,
		  TEST_MPART_NAME(http1_parser, forwarded, 0),
		  TEST_MPART_NAME(http1_parser, forwarded, 1),
		  TEST_MPART_NAME(http1_parser, forwarded, 2),
		  TEST_MPART_NAME(http1_parser, forwarded, 3));

TEST(http1_parser, perf)
{
	int i;
	unsigned int parsed;
	volatile unsigned long t0 = jiffies;

#define REQ_PERF(str)							\
do {									\
	test_case_parse_prepare_http(str);				\
	if (req)							\
		test_req_free(req);					\
	req = test_req_alloc(sizeof(str) - 1);				\
	tfw_http_parse_req(req, str, sizeof(str) - 1, &parsed);		\
} while (0)

#define RESP_PERF(str)							\
do {									\
	test_case_parse_prepare_http(str);				\
	if (resp)							\
		test_resp_free(resp);					\
	resp = test_resp_alloc(sizeof(str) - 1, req);			\
	tfw_http_parse_resp(resp, str, sizeof(str) - 1, &parsed);	\
} while (0)

	for (i = 0; i < 1000; ++i) {
		/*
		 * Benchmark several requests to make the headers parsing more
		 * visible in the performance results. Also having L7 DDoS in
		 * mind we need to to care about requests more than responses.
		 */
		REQ_PERF("GET / HTTP/1.1\n"
			 "Host: example.com\n"
			 "\n");
		REQ_PERF("GET /index.html HTTP/1.1\r\n"
			 "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n"
			 "User-Agent: Wget/1.13.4 (linux-gnu)\r\n"
			 "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n"
			 "Keep-Alive: timeout=600, max=65526\r\n"
			 "Host: afaahfaduy3wbfdf.dsfda.12.dsdf.2.df\n"
			 "X-Forwarded-For: 203.0.113.195,70.41.3.18,150.172.238.178\r\n"
			 "Cookie: session=42; theme=dark\r\n"
			 "Referer: http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:"
				  "765d]:8080/cgi-bin/show.pl?entry=tempesta\r\n"
			 "\r\n");

		/* Also test invalid request. */
		REQ_PERF("GET / HTTP/1.1\r\n"
			 "Host :foo.com\r\n"
			 "\r\n");
		REQ_PERF("GET /https://ru.wikipedia.org/wiki/%D0%A8%D0%B0%D0"
			       "%B1%D0%BB%D0%BE%D0%BD:%D0%9B%D0%B5%D0%BE%D0%BD"
			       "%D0%B0%D1%80%D0%B4%D0%BE_%D0%B4%D0%B0_%D0%92%D0"
			       "%B8%D0%BD%D1%87%D0%B8 HTTP/1.1\r\n"
			 "POST / HTTP/1.1\r\n"
			 "Host: test\r\n"
			 "\r\n");

		REQ_PERF("POST /a/b/c/dir/?foo=1&bar=2#abcd HTTP/1.1\r\n"
			 "Host: a.com\r\n"
			 "Cookie: session=42; theme=dark\r\n"
			 "Dummy0: 0\r\n"
			 "Keep-Alive: timeout=600, max=65526\r\n"
			 "Referer:    http://tempesta-tech.com:8080\r\n"
				"/cgi-bin/show.pl?entry=tempesta      \r\n"
			 "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n"
			 "X-Forwarded-For: 203.0.113.195,70.41.3.18,150.172.238.178\r\n"
			 "X-Custom-Hdr: custom header values\r\n"
			 "\r\n");
		REQ_PERF("GET http://natsys-lab.com:8080/cgi-bin/show.pl HTTP/1.1\r\n"
			 "Connection: Keep-Alive\r\n"
			 "Cookie: session=42\r\n"
			 "Accept: */*\r\n"
			 "\r\n");

		/*
		 * We need to benchmark the body processing, but don't make
		 * it too long to mask the headers processing overheads.
		 */
#define __BODY_CHUNK_50	"01234567890123456789012345678901234567890123456789"
#define BODY_CHUNK_1000	"1000\r\n"					\
	__BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50	\
	__BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50	\
	__BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50	\
	__BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50	\
	__BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50 __BODY_CHUNK_50
		RESP_PERF("HTTP/1.1 200 OK\r\n"
			 "Connection: Keep-Alive\r\n"
			 "Dummy0: 0\r\n"
			 "Content-Type: text/html; charset=iso-8859-1\r\n"
			 "X-Forwarded-For: 203.0.113.195,70.41.3.18,150.172.238.178"
			 "Cache-Control: max-age=5, private, no-cache, ext=foo\r\n"
			 "Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
			 "Set-Cookie: sessionid=38afes7a8;HttpOnly; Path=/\r\n"
			 "Expires: Tue, 31 Jan 2012 15:02:53 GMT\r\n"
			 "Keep-Alive: timeout=600, max=65526\r\n"
			 "Transfer-Encoding: compress, gzip, chunked\r\n"
			 "Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.1e-fips mod_fcgid/2.3.9\r\n"
			 "Age: 12  \n"
			 "Date: Sun, 09 Sep 2001 01:46:40 GMT\t\n"
			 "\r\n"
			 BODY_CHUNK_1000
			 BODY_CHUNK_1000
			 BODY_CHUNK_1000
			 BODY_CHUNK_1000
			 "0\r\n"
			 "\r\n");
#undef BODY_CHUNK_1000
#undef __BODY_CHUNK_50
		RESP_PERF("HTTP/1.1 101 Switching Protocols OK\r\n"
			  "Content-Length: 10\r\n"
			  "Set-Cookie: sessionid=38afes7a8 Path=/\r\n"
			  "\r\n"
			  "0123456789");
	}
	pr_info("===> http parser time: %ums\n",
		jiffies_to_msecs(jiffies - t0));
#undef REQ_PERF
#undef RESP_PERF
}

TEST(http1_parser, tfh)
{
	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"\r\n")
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 2);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 0);
	}

	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"a: aa\r\n"
		"aa: aaa\r\n"
		"aaa: aaaa\r\n"
		"aaaa: aaaaa\r\n"
		"aaaaa: aaaaaa\r\n"
		"aaaaaa: aaaaaaa\r\n"
		"aaaaaaa: aaaaaaaa\r\n"
		"aaaaaaaa: aaaaaaaaa\r\n"
		"aaaaaaaaa: aaaaaaaaaa\r\n"
		"aaaaaaaaaa: aaaaaaaaaaa\r\n"
		"aaaaaaaaaaa: aaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaa: aaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaa: aaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaa: aaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"\r\n")
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 34);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 0);
		EXPECT_EQ((unsigned)req->tfh.version, 0);
	}

	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"a: aa\r\n"
		"aa: aaa\r\n"
		"aaa: aaaa\r\n"
		"aaaa: aaaaa\r\n"
		"aaaaa: aaaaaa\r\n"
		"aaaaaa: aaaaaaa\r\n"
		"aaaaaaa: aaaaaaaa\r\n"
		"aaaaaaaa: aaaaaaaaa\r\n"
		"aaaaaaaaa: aaaaaaaaaa\r\n"
		"aaaaaaaaaa: aaaaaaaaaaa\r\n"
		"aaaaaaaaaaa: aaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaa: aaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaa: aaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaa: aaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
		"b: bb\r\n"
		"bb: bbb\r\n"
		"bbb: bbbb\r\n"
		"bbbb: bbbbb\r\n"
		"bbbbb: bbbbbb\r\n"
		"bbbbbb: bbbbbbb\r\n"
		"bbbbbbb: bbbbbbbb\r\n"
		"bbbbbbbb: bbbbbbbbb\r\n"
		"bbbbbbbbb: bbbbbbbbbb\r\n"
		"bbbbbbbbbb: bbbbbbbbbbb\r\n"
		"bbbbbbbbbbb: bbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbb: bbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbb: bbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbb: bbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"
		"bbbbbbbbbbbbbbbbbbbbbbbbbb: bbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n"
		"\r\n")
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 63);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 0);
		EXPECT_EQ((unsigned)req->tfh.version, 0);
	}

	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"Cookie: session=42; theme=dark\r\n"
		"Referer: http://tempesta-tech.com:8080\r\n"
		"\r\n")
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 1);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 4);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 2);
		EXPECT_EQ((unsigned)req->tfh.version, 0);
	}

	FOR_REQ("GET /index.html HTTP/1.1\r\n"
		"Connection: Keep-Alive\r\n"
		"X-Forwarded-For: 127.0.0.1\r\n"
		"Cookie: a=a; aa=a; aaa=a; aaaa=a; aaaaa=a; "
		"aaaaaa=a; aaaaaaa=a; aaaaaaaa=a; aaaaaaaaa=a; aaaaaaaaaa=a; "
		"aaaaaaaaaaa=a; aaaaaaaaaaaa=a; aaaaaaaaaaaaa=a; aaaaaaaaaaaaaa=a; "
		"b=b; bb=b; bbb=b; bbbb=b; bbbbb=b; bbbbbb=b; bbbbbbb=b; "
		"bbbbbbbb=b; bbbbbbbbb=b; bbbbbbbbbb=b; bbbbbbbbbbb=b; "
		"c=c; c=cc; ccc=c; cccc=c; ccccc=c; cccccc=c; ccccccc=c; "
		"d=d; d=dd; d=ddd\r\n"
		"Referer: http://tempesta-tech.com:8080\r\n"
		"\r\n")
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 1);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 4);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 31);
		EXPECT_EQ((unsigned)req->tfh.version, 0);
	}
}

TEST(http1_parser, expect)
{
	FOR_REQ_SIMPLE("Expect: 100-continue")
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_EXPECT];

		EXPECT_GT(h->len, 0);
		EXPECT_TRUE(test_bit(TFW_HTTP_B_EXPECT_CONTINUE, req->flags));
	}

	/* Expect with whitespaces. */
	FOR_REQ_SIMPLE("Expect:     100-continue    ")
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_EXPECT];

		EXPECT_GT(h->len, 0);
		EXPECT_TRUE(test_bit(TFW_HTTP_B_EXPECT_CONTINUE, req->flags));
	}

	EXPECT_BLOCK_REQ_SIMPLE("Expect: 10-continue");
	EXPECT_BLOCK_REQ_SIMPLE("Expect: 100-continue1");
}

TEST_SUITE_MPART(http1_parser, 0)
{
	int r;

	if ((r = set_sample_req(SAMPLE_REQ_STR))) {
		TEST_FAIL("can't parse sample request (code=%d):\n%s",
			  r, SAMPLE_REQ_STR);
		return;
	}

	TEST_RUN(http1_parser, leading_eol);
	TEST_RUN(http1_parser, parses_req_method);
	TEST_RUN(http1_parser, short_name);
	TEST_RUN(http1_parser, parses_req_uri);
	TEST_RUN(http1_parser, mangled_messages);
	TEST_RUN(http1_parser, alphabets);
	TEST_RUN(http1_parser, casesense);
	TEST_RUN(http1_parser, hdr_token_confusion);
	TEST_RUN(http1_parser, fills_hdr_tbl_for_req);
	TEST_RUN(http1_parser, fills_hdr_tbl_for_resp);
	TEST_RUN(http1_parser, cache_control);
	TEST_RUN(http1_parser, status);
	TEST_RUN(http1_parser, age);
	TEST_RUN(http1_parser, pragma);
}

TEST_SUITE_MPART(http1_parser, 1)
{
	TEST_RUN(http1_parser, suspicious_x_forwarded_for);
	TEST_RUN(http1_parser, parses_connection_value);
	TEST_MPART_RUN(http1_parser, content_type_in_bodyless_requests);
	TEST_RUN(http1_parser, content_length);
	TEST_RUN(http1_parser, eol_crlf);
	TEST_RUN(http1_parser, ows);
	TEST_RUN(http1_parser, folding);
	TEST_RUN(http1_parser, accept);
	TEST_RUN(http1_parser, host);
	TEST_RUN(http1_parser, chunked_cut_len);
	TEST_RUN(http1_parser, transfer_encoding);
	TEST_RUN(http1_parser, content_encoding);
	TEST_RUN(http1_parser, crlf_trailer);
	TEST_RUN(http1_parser, cookie);
	TEST_RUN(http1_parser, set_cookie);
	TEST_RUN(http1_parser, etag);
	TEST_RUN(http1_parser, if_none_match);
	TEST_RUN(http1_parser, referer);
	TEST_RUN(http1_parser, req_hop_by_hop);
}

TEST_SUITE_MPART(http1_parser, 2)
{
	TEST_RUN(http1_parser, resp_hop_by_hop);
	TEST_RUN(http1_parser, fuzzer);
	TEST_MPART_RUN(http1_parser, content_type_line_parser);
	TEST_RUN(http1_parser, xff);
	TEST_MPART_RUN(http1_parser, date);
	TEST_RUN(http1_parser, method_override);
	TEST_RUN(http1_parser, x_tempesta_cache);
	TEST_RUN(http1_parser, vchar);
	TEST_MPART_RUN(http1_parser, forwarded);

	/*
	 * Testing for correctness of redirection mark parsing (in
	 * extended enforced mode of 'http_sessions' module).
	 */
	TEST_RUN(http1_parser, parses_enforce_ext_req);

	TEST_RUN(http1_parser, perf);
}

TEST_SUITE_MPART(http1_parser, 3)
{
	TEST_RUN(http1_parser, tfh);
	TEST_RUN(http1_parser, expect);
}

TEST_SUITE_MPART_DEFINE(http1_parser, H1_SUITE_PART_CNT,
	TEST_SUITE_MPART_NAME(http1_parser, 0),
	TEST_SUITE_MPART_NAME(http1_parser, 1),
	TEST_SUITE_MPART_NAME(http1_parser, 2),
	TEST_SUITE_MPART_NAME(http1_parser, 3));

