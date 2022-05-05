/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2022 Tempesta Technologies, Inc.
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

TEST(http2_parser, http2_check_important_fields)
{
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("http")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("Authorization"),
			    VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
		HEADER(WO_IND(NAME("Cache-Control"),
			    VALUE("max-age=1, dummy, no-store, min-fresh=30")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("connection"), VALUE("Keep-Alive")));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser, parses_req_method)
{
#define TEST_REQ_METHOD(METHOD)							\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE(#METHOD)));		\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define TEST_REQ_UNKNOWN(METHOD)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE(#METHOD)));		\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);			\
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
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	);

	/* Malformed methods */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("\tOST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	);
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("P\tST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	);
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("PO\tT")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	);
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POS\t")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser, parses_req_uri)
{
#define TEST_URI_PATH(req_uri_path)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE(req_uri_path)));		\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_TFWSTR_EQ(&req->host, "");				\
		EXPECT_TFWSTR_EQ(&req->uri_path, req_uri_path);			\
	}

#define TEST_FULL_REQ(req_host, req_uri_path)					\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE(req_uri_path)));		\
		HEADER(WO_IND(NAME(":authority"), VALUE(req_host)));		\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_TFWSTR_EQ(&req->host, req_host);				\
		EXPECT_TFWSTR_EQ(&req->uri_path, req_uri_path);			\
	}


	TEST_URI_PATH("/");
	TEST_URI_PATH("/?");
	TEST_URI_PATH("/foo/b_a_r/baz.html");
	TEST_URI_PATH("/a/b/c/dir/");
	TEST_URI_PATH("/a/b/c/dir/?foo=1&bar=2#abcd");

	/*
	 * Absolute URI.
	 * NOTE: we combine host and port URI parts into one field 'req->host'.
	 */
	TEST_FULL_REQ("natsys-lab.com", "/");
	TEST_FULL_REQ("natsys-lab.com:8080", "/");
	TEST_FULL_REQ("natsys-lab.com", "/foo/");
	TEST_FULL_REQ("natsys-lab.com:8080", "/cgi-bin/show.pl?entry=tempesta");


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("OPTIONS")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("*")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("\x7f")));
		HEADER(WO_IND(NAME(":authority"), VALUE("test")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/\x03uri")));
		HEADER(WO_IND(NAME(":authority"), VALUE("test")));
	    HEADERS_FRAME_END();
	);


#undef TEST_FULL_REQ
#undef TEST_URI_PATH
}

TEST(http2_parser, parses_enforce_ext_req)
{
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/index.html")));
		HEADER(WO_IND(NAME("x-forwarded-for"), VALUE("127.0.0.1")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/index.html");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("natsys-lab.com")));
		HEADER(WO_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)")));
		HEADER(WO_IND(NAME("accept"), VALUE("*/*")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/cgi-bin/show.pl")));
		HEADER(WO_IND(NAME(":authority"), VALUE("natsys-lab.com:8080")));
		HEADER(WO_IND(NAME("cookie"), VALUE("session=42")));
		HEADER(WO_IND(NAME("accept"), VALUE("*/*")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com:8080");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/cgi-bin/show.pl");
	}
}

TEST(http2_parser, parses_enforce_ext_req_rmark)
{
/*
 * Redirection attempt number, timestamp and calculated valid
 * HMAC (see 'test_http_sticky.c' file for details about
 * calculation process).
 */
#define RMARK_NAME	"__tfw"
#define ATT_NO		"00000001"
#define TIMESTAMP	"535455565758595a"
#define HMAC		"9cf5585388196965871bf4240ef44a52d0ffb23d"
#define RMARK		"/" RMARK_NAME "=" ATT_NO TIMESTAMP HMAC

#define URI_1		"/"
#define URI_2		"/static/test/index.html"
#define URI_3		"/foo/"
#define URI_4		"/cgi-bin/show.pl?entry=tempesta"

#define HOST		"natsys-lab.com"
#define PORT		"80"


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_1)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_1);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_2)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_2);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_3)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_3);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_4)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_4);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_1)));
		HEADER(WO_IND(NAME(":authority"), VALUE(HOST ":" PORT)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_1);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_3)));
		HEADER(WO_IND(NAME(":authority"), VALUE(HOST ":" PORT)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_3);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK URI_4)));
		HEADER(WO_IND(NAME(":authority"), VALUE(HOST ":" PORT)));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_4);
	}

	/* Partial confusion with redir_mark_eq ("__tfw="), abort with `fin`. */
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/" RMARK_NAME "/"));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/" RMARK_NAME "/");
		EXPECT_TRUE(TFW_STR_EMPTY(&req->mark));
	}

	/* Partial confusion with redir_mark_eq ("__tfw="), abort without `fin`. */
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/" RMARK_NAME "/a"));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/" RMARK_NAME "/a");
		EXPECT_TRUE(TFW_STR_EMPTY(&req->mark));
	}

	/* Wrong RMARK formats. */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(ATT_NO HMAC URI_1)));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/" RMARK_NAME "=" URI_1)));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE(RMARK HMAC URI_1)));
	    HEADERS_FRAME_END();
	);

#undef ATT_NO
#undef TIMESTAMP
#undef HMAC
#undef RMARK

#undef URI_1
#undef URI_2
#undef URI_3
#undef URI_4

#undef HOST
#undef PORT
}

/* TODO add HTTP attack examples. */
TEST(http2_parser, mangled_messages)
{
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("test")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("test")));
		HEADER(WO_IND(NAME("\x1fX-Foo"), VALUE("test")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("test")));
		HEADER(WO_IND(NAME("connection"), VALUE("close, \"foo\"")));
	    HEADERS_FRAME_END();
	);
}

/**
 * Test for allowed characters in different parts of HTTP message.
 */
TEST(http2_parser, alphabets)
{
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("test")));
		/* We don't match open and closing quotes. */
		HEADER(WO_IND(NAME("content-type"), VALUE("Text/HTML;Charset=utf-8\"\t  ")));
		HEADER(WO_IND(NAME("pragma"), VALUE("no-cache, fooo ")));
	    HEADERS_FRAME_END();
	);

	/* Trailing SP in request. */
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("localhost")));
		HEADER(WO_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)\t  ")));
		HEADER(WO_IND(NAME("accept"), VALUE("*/*\t ")));
		HEADER(WO_IND(NAME("x-custom-hdr"), VALUE("custom header values \t  ")));
		HEADER(WO_IND(NAME("x-forwarded-for"),
		       VALUE("127.0.0.1, example.com    \t ")));
		HEADER(WO_IND(NAME("content-type"),
		       VALUE("text/html; charset=iso-8859-1  \t ")));
		HEADER(WO_IND(NAME("cache-control"),
		       VALUE("max-age=0, private, min-fresh=42 \t ")));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser, fills_hdr_tbl_for_req)
{
	TfwHttpHdrTbl *ht;
	TfwStr *h_accept, *h_xch, *h_dummy4, *h_dummy9, *h_cc, *h_pragma,
	       *h_auth;
	TfwStr h_host, h_xff, h_user_agent, h_cookie;

	/* Expected values for special headers. */
	const char *s_host = "localhost";
	const char *s_xff = "127.0.0.1, example.com";
	const char *s_user_agent = "Wget/1.13.4 (linux-gnu)";
	const char *s_cookie = "session=42; theme=dark";
	/* Expected values for raw headers. */
	const char *s_accept = "accept"
			       "*/*";
	const char *s_xch = "x-custom-hdr"
			    "custom header values";
	const char *s_dummy9 = "Dummy9"
			       "9";
	const char *s_dummy4 = "Dummy4"
			       "4";
	const char *s_cc  = "cache-control"
			    "max-age=1, dummy, no-store, min-fresh=30";
	/* Trailing spaces are stored within header strings. */
	const char *s_pragma =  "pragma"
				"no-cache, fooo ";
	const char *s_auth =  "authorization"
			      "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t ";


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("localhost")));
		HEADER(WO_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)")));
		HEADER(WO_IND(NAME("accept"), VALUE("*/*")));
		HEADER(WO_IND(NAME("x-custom-hdr"), VALUE("custom header values")));
		HEADER(WO_IND(NAME("x-forwarded-for"), VALUE("127.0.0.1, example.com")));
		HEADER(WO_IND(NAME("Dummy0"), VALUE("0")));
		HEADER(WO_IND(NAME("Dummy1"), VALUE("1")));
		HEADER(WO_IND(NAME("Dummy2"), VALUE("2")));
		HEADER(WO_IND(NAME("Dummy3"), VALUE("3")));
		HEADER(WO_IND(NAME("Dummy4"), VALUE("4")));
		HEADER(WO_IND(NAME("Dummy5"), VALUE("5")));
		HEADER(WO_IND(NAME("Dummy6"), VALUE("6")));
		/* That is done to check table reallocation. */
		HEADER(WO_IND(NAME("Dummy7"), VALUE("7")));
		HEADER(WO_IND(NAME("Dummy8"), VALUE("8")));
		HEADER(WO_IND(NAME("Dummy9"), VALUE("9")));
		HEADER(WO_IND(NAME("cache-control"),
		       VALUE("max-age=1, dummy, no-store, min-fresh=30")));
		HEADER(WO_IND(NAME("pragma"), VALUE("no-cache, fooo ")));
		HEADER(WO_IND(NAME("cookie"), VALUE("session=42; theme=dark")));
		HEADER(WO_IND(NAME("authorization"),
		       VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t ")));
	    HEADERS_FRAME_END();
	)
	{
		ht = req->h_tbl;

		/* Special headers: */
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_H2_AUTHORITY],
					 TFW_HTTP_HDR_H2_AUTHORITY, &h_host);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR],
					 TFW_HTTP_HDR_X_FORWARDED_FOR, &h_xff);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_USER_AGENT],
					 TFW_HTTP_HDR_USER_AGENT,
					 &h_user_agent);
		tfw_http_msg_clnthdr_val(req,
					 &ht->tbl[TFW_HTTP_HDR_COOKIE],
					 TFW_HTTP_HDR_COOKIE, &h_cookie);

		/* Common (raw) headers: 14 total with 10 dummies. */
		EXPECT_EQ(ht->off, TFW_HTTP_HDR_RAW + 15);

		h_accept = &ht->tbl[TFW_HTTP_HDR_RAW + 0];
		h_xch = &ht->tbl[TFW_HTTP_HDR_RAW + 1];
		h_dummy4 = &ht->tbl[TFW_HTTP_HDR_RAW + 6];
		h_dummy9 = &ht->tbl[TFW_HTTP_HDR_RAW + 11];
		h_cc = &ht->tbl[TFW_HTTP_HDR_RAW + 12];
		h_pragma = &ht->tbl[TFW_HTTP_HDR_RAW + 13];
		h_auth = &ht->tbl[TFW_HTTP_HDR_RAW + 14];

		EXPECT_TFWSTR_EQ(&h_host, s_host);
		EXPECT_TFWSTR_EQ(&h_xff, s_xff);
		EXPECT_TFWSTR_EQ(&h_user_agent, s_user_agent);
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
	}
}

TEST(http2_parser, cache_control)
{
#define EXPECT_BLOCK_REQ_H2_CC(cache_control)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("cache-control"), VALUE(cache_control)));	\
	    HEADERS_FRAME_END();						\
	);

#define FOR_REQ_H2_CC(cache_control)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("cache-control"), VALUE(cache_control)));	\
	    HEADERS_FRAME_END();						\
	)

	EXPECT_BLOCK_REQ_H2_CC("");
	EXPECT_BLOCK_REQ_H2_CC(" ");
	EXPECT_BLOCK_REQ_H2_CC("no-cache no-store");
	EXPECT_BLOCK_REQ_H2_CC("dummy0 dummy1");
	EXPECT_BLOCK_REQ_H2_CC(",,");


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
	    HEADERS_FRAME_END();
	)
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

	FOR_REQ_H2_CC("nO-caChE, NO-stOre, no-TRansfORm, MAx-age=4")
	{
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(req->cache_ctl.max_age == 4);
	}

	/* Cache Control Extensions, not strict compliance with RFC. */
	FOR_REQ_H2_CC(QETOKEN_ALPHABET ", no-cache, "
		      QETOKEN_ALPHABET ", no-store, "
		      "no-transform, max-age=12, " QETOKEN_ALPHABET)
	{
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(req->cache_ctl.max_age == 12);
	}

	FOR_REQ_H2_CC(
		"dummy0, dummy1, dummy1-5, dummy1-6, "
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
		"dummy126, dummy127, chunked")
	{
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_IS_PRESENT);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_CACHE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_STORE);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_NO_TRANSFORM);
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_AGE);
		EXPECT_TRUE(req->cache_ctl.max_age == 14);
	}

	/*
	 * RFC 7234 5.2.1.2:
	 *
	 * If no value is
	 * assigned to max-stale, then the client is willing to accept a stale
	 * response of any age.
	 */
	FOR_REQ_H2_CC("max-stale")
	{
		EXPECT_TRUE(req->cache_ctl.flags & TFW_HTTP_CC_MAX_STALE);
		EXPECT_TRUE(req->cache_ctl.max_stale == UINT_MAX);
	}


#define TEST_COMMON(directive, flag)						\
	FOR_REQ_H2_CC(directive)						\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC("," directive)						\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(", " directive)						\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive ",")						\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC("1" directive)						\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive directive)					\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC("no-store" directive)					\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive "\"")						\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	EXPECT_BLOCK_REQ_H2_CC(directive " = dummy");

#define TEST_NO_ARGUMENT(directive, flag)					\
	TEST_COMMON(directive, flag);						\
	FOR_REQ_H2_CC(directive "=")						\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive "=1")						\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive "=\"")						\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive "=dummy")					\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}									\
	FOR_REQ_H2_CC(directive	"=\"dummy\"")					\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
	}

#define TEST_SECONDS(directive, flag, FIELD)					\
	FOR_REQ_H2_CC(directive "=0")						\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
		EXPECT_TRUE(req->cache_ctl.FIELD == 0);				\
	}									\
	FOR_REQ_H2_CC(directive "=0000")					\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
		EXPECT_TRUE(req->cache_ctl.FIELD == 0);				\
	}									\
	FOR_REQ_H2_CC(directive "=4294967295")					\
	{									\
		EXPECT_TRUE(req->cache_ctl.flags & flag);			\
		EXPECT_TRUE(req->cache_ctl.FIELD == 4294967295);		\
	}									\
	FOR_REQ_H2_CC(directive directive"=5")					\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
		EXPECT_TRUE(req->cache_ctl.FIELD == 0);				\
	}									\
	FOR_REQ_H2_CC("no-store" directive "=5")				\
	{									\
		EXPECT_FALSE(req->cache_ctl.flags & flag);			\
		EXPECT_TRUE(req->cache_ctl.FIELD == 0);				\
	}									\
	EXPECT_BLOCK_REQ_H2_CC(directive " = dummy");				\
	EXPECT_BLOCK_REQ_H2_CC(directive " = 0");				\
	EXPECT_BLOCK_REQ_H2_CC(directive "=10 10");				\


	TEST_NO_ARGUMENT("no-cache", TFW_HTTP_CC_NO_CACHE);
	TEST_NO_ARGUMENT("no-store", TFW_HTTP_CC_NO_STORE);
	TEST_NO_ARGUMENT("no-transform", TFW_HTTP_CC_NO_TRANSFORM);

	TEST_SECONDS("max-age", TFW_HTTP_CC_MAX_AGE, max_age);
	TEST_SECONDS("max-stale", TFW_HTTP_CC_MAX_STALE, max_stale);
	TEST_SECONDS("min-fresh", TFW_HTTP_CC_MIN_FRESH, min_fresh);

	EXPECT_BLOCK_DIGITS("max-age=", "", EXPECT_BLOCK_REQ_H2_CC);
	EXPECT_BLOCK_DIGITS("max-stale=", "", EXPECT_BLOCK_REQ_H2_CC);
	EXPECT_BLOCK_DIGITS("min-fresh=", "", EXPECT_BLOCK_REQ_H2_CC);


#undef TEST_SECONDS
#undef TEST_NO_ARGUMENT
#undef TEST_COMMON

#undef FOR_REQ_H2_CC
#undef EXPECT_BLOCK_REQ_H2_CC
}

TEST(http2_parser, suspicious_x_forwarded_for)
{
#define EXPECT_BLOCK_REQ_H2_XFF(x_forwarded_for)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("x-forwarded-for"), VALUE(x_forwarded_for)));\
	    HEADERS_FRAME_END();						\
	);


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(
		    NAME("x-forwarded-for"),
		    VALUE("   [::1]:1234,5.6.7.8   ,  natsys-lab.com:65535  ")));
	    HEADERS_FRAME_END();
	)
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		EXPECT_GT(h->len, 0);
	}

	EXPECT_BLOCK_REQ_H2_XFF("1.2.3.4, , 5.6.7.8");
	EXPECT_BLOCK_REQ_H2_XFF("foo!");
	EXPECT_BLOCK_REQ_H2_XFF("");
}

TEST(http2_parser, content_type_in_bodyless_requests)
{
#define EXPECT_BLOCK_BODYLESS_REQ_H2(METHOD)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE(#METHOD)));		\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));		\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE(#METHOD)));		\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-type"), VALUE("text/plain")));	\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(METHOD)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));		\
		HEADER(WO_IND(NAME("x-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-type"), VALUE("text/plain")));	\
		HEADER(WO_IND(NAME("x-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));		\
		HEADER(WO_IND(NAME("x-http-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-type"), VALUE("text/plain")));	\
		HEADER(WO_IND(NAME("x-http-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));		\
		HEADER(WO_IND(NAME("x-http-method"), VALUE(#METHOD)));		\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-type"), VALUE("text/plain")));	\
		HEADER(WO_IND(NAME("x-http-method"), VALUE(#METHOD)));		\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}


	EXPECT_BLOCK_BODYLESS_REQ_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_H2(TRACE);

	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(TRACE);

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("OPTIONS")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("content-type"), VALUE("text/plain")));
	    HEADERS_FRAME_END();
	);


#undef EXPECT_BLOCK_BODYLESS_REQ_H2
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2
}

TEST(http2_parser, content_length)
{
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TRUE(req->content_length == 0);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
	    DATA_FRAME_END();
	)
	{
		EXPECT_TRUE(req->content_length == 0);
	}

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("5")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
	    DATA_FRAME_END();
	);

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("5")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
		DATA("dummy");
	    DATA_FRAME_END();
	)
	{
		EXPECT_TRUE(req->content_length == 5);
	}

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("10")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
		DATA("dummy");
	    DATA_FRAME_END();
	);


#define EXPECT_BLOCK_REQ_H2_CL_DUMMY(content_length)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("cache-length"), VALUE(content_length)));	\
	    HEADERS_FRAME_END();						\
	    DATA_FRAME_BEGIN();							\
		DATA("dummy");							\
	    DATA_FRAME_END();							\
	);


	EXPECT_BLOCK_DIGITS("", "", EXPECT_BLOCK_REQ_H2_CL_DUMMY);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("10, 10")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
		DATA("0123456789");
	    DATA_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("10 10")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
		DATA("0123456789");
	    DATA_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));
	    HEADERS_FRAME_END();
	);

#undef EXPECT_BLOCK_REQ_H2_CL_DUMMY
}

TEST(http2_parser, ows)
{
#define EXPECT_BLOCK_REQ_H2_METHOD(name, value)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(name), VALUE(value)));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("foo.com")));		\
	    HEADERS_FRAME_END();						\
	);

#define EXPECT_BLOCK_REQ_H2_SCHEME(name, value)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(name), VALUE(value)));			\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("foo.com")));		\
	    HEADERS_FRAME_END();						\
	);

#define EXPECT_BLOCK_REQ_H2_AUTHORITY(name, value)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(name), VALUE(value)));			\
	    HEADERS_FRAME_END();						\
	);


	EXPECT_BLOCK_REQ_H2_METHOD(":method", "		GET");
	EXPECT_BLOCK_REQ_H2_METHOD(":method", "GET	");
	EXPECT_BLOCK_REQ_H2_METHOD("	:method", "GET");
	EXPECT_BLOCK_REQ_H2_METHOD(":method	", "GET");

	EXPECT_BLOCK_REQ_H2_SCHEME(":scheme", "		https");
	EXPECT_BLOCK_REQ_H2_SCHEME(":scheme", "https	");
	EXPECT_BLOCK_REQ_H2_SCHEME("	:scheme", "https");
	EXPECT_BLOCK_REQ_H2_SCHEME(":scheme	", "https");

	EXPECT_BLOCK_REQ_H2_AUTHORITY(":authority", " foo.com");
	EXPECT_BLOCK_REQ_H2_AUTHORITY(":authority", "foo.com ");
	EXPECT_BLOCK_REQ_H2_AUTHORITY(" :authority", "foo.com");
	EXPECT_BLOCK_REQ_H2_AUTHORITY(":authority ", "foo.com");


#undef EXPECT_BLOCK_REQ_H2_AUTHORITY
#undef EXPECT_BLOCK_REQ_H2_SCHEME
#undef EXPECT_BLOCK_REQ_H2_METHOD
}

TEST(http2_parser, accept)
{
#define __FOR_ACCEPT(accept_val, EXPECT_HTML_MACRO)				\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("accept"), VALUE(accept_val)));		\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_HTML_MACRO(test_bit(TFW_HTTP_B_ACCEPT_HTML,		\
					   req->flags));			\
	}

#define FOR_ACCEPT(accept_val)		__FOR_ACCEPT(accept_val, EXPECT_FALSE)
#define FOR_ACCEPT_HTML(accept_val)	__FOR_ACCEPT(accept_val, EXPECT_TRUE)

#define EXPECT_BLOCK_REQ_H2_ACCEPT(header)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("accept"), VALUE(header)));			\
	    HEADERS_FRAME_END();						\
	);

#define TEST_ACCEPT_EXT(HEAD)							\
	FOR_ACCEPT(HEAD ";key=val");						\
	FOR_ACCEPT(HEAD ";" TOKEN_ALPHABET "=" TOKEN_ALPHABET);			\
	FOR_ACCEPT(HEAD ";" TOKEN_ALPHABET "=\"" TOKEN_ALPHABET "\"");		\
	FOR_ACCEPT(HEAD ";key=\"\"");						\
	FOR_ACCEPT(HEAD "  ; \t key=val");					\
	FOR_ACCEPT(HEAD ";key=val;key=val");					\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";");					\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";;");					\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key=\"");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key=\"\"\"");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key=\"val");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key=val\"");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key=");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key==");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key =val");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";\"key\"=val");			\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD ";key= val");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD " key=val");				\
	EXPECT_BLOCK_REQ_H2_ACCEPT(HEAD "key=val");

	/* media-range */
	FOR_ACCEPT("*/*");
	FOR_ACCEPT("dummy/*");
	FOR_ACCEPT("dummy/dummy");
	FOR_ACCEPT(TOKEN_ALPHABET "/" TOKEN_ALPHABET);

	EXPECT_BLOCK_REQ_H2_ACCEPT("");
	EXPECT_BLOCK_REQ_H2_ACCEPT(" ");
	EXPECT_BLOCK_REQ_H2_ACCEPT("dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("dummy/dummy/dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("dummy/*/*");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*/*");
	EXPECT_BLOCK_REQ_H2_ACCEPT(QETOKEN_ALPHABET "/dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("/dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("dummy/");
	EXPECT_BLOCK_REQ_H2_ACCEPT("dummy/dummy/");
	/*
	 * '*' is part of the token alphabet, but for Accept header '*' symbol
	 * has special meaning and doesn't included into mime types.
	 */
	EXPECT_BLOCK_REQ_H2_ACCEPT("dummy/*dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*dummy/dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*dummy/*dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*dummy");

	/* parameter */
	TEST_ACCEPT_EXT("dummy/dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;key");

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
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q=5.000");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q=.000");

	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q=dummy");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q==");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q=");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;=0.5");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q =0");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q= 0");

	/* accept-ext */
	TEST_ACCEPT_EXT("dummy/dummy;q=0");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*;q=0;key");

	/* Multiple values */
	FOR_ACCEPT("dummy/dummy\t,dummy/dummy ,\t\tdummy/dummy");
	FOR_ACCEPT("  \t\t */*  ;\t key=val ; key=val\t;\t"
		   "q=0;\t\text=val ; ext=val;\tkey=val \t\t");
	/* Invalid delimiters between parts. */
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/* text/plain");
	/* Empty types are not allowed. */
	EXPECT_BLOCK_REQ_H2_ACCEPT(",");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/*,,");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/,,");
	/* Empty subtypes are not allowed. */
	EXPECT_BLOCK_REQ_H2_ACCEPT("text/");
	EXPECT_BLOCK_REQ_H2_ACCEPT("*/");

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
#undef EXPECT_BLOCK_REQ_H2_ACCEPT
#undef FOR_ACCEPT_HTML
#undef FOR_ACCEPT
#undef __FOR_ACCEPT
}

TEST(http2_parser, host)
{
#define FOR_REQ_H2_HOST(host)							\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE(host)));		\
	    HEADERS_FRAME_END();						\
	)

#define EXPECT_BLOCK_REQ_H2_HOST(host)						\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE(host)));		\
	    HEADERS_FRAME_END();						\
	)


	EXPECT_BLOCK_REQ_H2_HOST("");
	EXPECT_BLOCK_REQ_H2_HOST(" ");
	EXPECT_BLOCK_REQ_H2_HOST(" tempesta-tech.com");

	FOR_REQ_H2_HOST("tempesta-tech.com")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY];

		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = ":authority" , .len = 10 },
				{ .data = "tempesta-tech.com" , .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_TRAILER },
			},
			.len = 27,
			.nchunks = 2,
			.flags = TFW_STR_COMPLETE
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 0);
	}

	FOR_REQ_H2_HOST("tempesta-tech.com:443")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY];

		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = ":authority" , .len = 10 },
				{ .data = "tempesta-tech.com" , .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_TRAILER },
				{ .data = ":" , .len = 1,
				  .flags = TFW_STR_TRAILER },
				{ .data = "443" , .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_TRAILER },
			},
			.len = 31,
			.nchunks = 4,
			.flags = TFW_STR_COMPLETE
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 443);
	}

	FOR_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY];

		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = ":authority" , .len = 10 },
				{ .data = "[fd42:5ca1:e3a7::1000]" , .len = 22,
				  .flags = TFW_STR_HDR_VALUE|TFW_STR_VALUE
					   |TFW_STR_TRAILER },
			},
			.len = 32,
			.nchunks = 2,
			.flags = TFW_STR_COMPLETE
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 0);
	}

	FOR_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]:65535")
	{
		TfwStr *host = &req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY];

		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = ":authority" , .len = 10 },
				{ .data = "[fd42:5ca1:e3a7::1000]" , .len = 22,
				  .flags = TFW_STR_HDR_VALUE|TFW_STR_VALUE
					   |TFW_STR_TRAILER },
				{ .data = ":" , .len = 1,
				 .flags = TFW_STR_TRAILER },
				{ .data = "65535", .len = 5,
				  .flags = TFW_STR_HDR_VALUE|TFW_STR_VALUE
					   |TFW_STR_TRAILER },
			},
			.len = 38,
			.nchunks = 4,
			.flags = TFW_STR_COMPLETE
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 65535);
	}

	/* Invalid port */
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com:0");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com:65536");
	EXPECT_BLOCK_DIGITS("tempesta-tech.com:", "",
			    EXPECT_BLOCK_REQ_H2_HOST);
	EXPECT_BLOCK_SHORT( "tempesta-tech.com:", "",
			    EXPECT_BLOCK_REQ_H2_HOST);
	EXPECT_BLOCK_DIGITS("[fd42:5ca1:e3a7::1000]:", "",
			    EXPECT_BLOCK_REQ_H2_HOST);
	EXPECT_BLOCK_SHORT( "[fd42:5ca1:e3a7::1000]:", "",
			    EXPECT_BLOCK_REQ_H2_HOST);

	/* Port syntax is broken. */
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com:443:1");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]:443:1");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com::443");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]::443");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com 443");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000] 443");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com:443-1");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]-1");

	/* Invalid brackets around IPv6. */
	EXPECT_BLOCK_REQ_H2_HOST("fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000][");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000[");


#undef EXPECT_BLOCK_REQ_H2_HOST
#undef FOR_REQ_H2_HOST
}

TEST(http2_parser, cookie)
{
#define FOR_REQ_H2_COOKIE(cookie)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("g.com")));		\
		HEADER(WO_IND(NAME("cookie"), VALUE(cookie)));			\
	    HEADERS_FRAME_END();						\
	)

#define EXPECT_BLOCK_REQ_H2_COOKIE(cookie)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("g.com")));		\
		HEADER(WO_IND(NAME("cookie"), VALUE(cookie)));			\
	    HEADERS_FRAME_END();						\
	)


	FOR_REQ_H2_COOKIE("session=42; theme=dark")
	{
		TfwStr *end, *c;
		TfwStr *cookie = &req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE];
		struct {
			unsigned int flags;
			const char *str;
		} kv[] = {
			{ 0, "cookie" },
			{ TFW_STR_NAME|TFW_STR_TRAILER, "session=" },
			{ TFW_STR_VALUE|TFW_STR_TRAILER, "42" },
			{ TFW_STR_TRAILER, "; " },
			{ TFW_STR_NAME|TFW_STR_TRAILER, "theme=" },
			{ TFW_STR_VALUE|TFW_STR_TRAILER, "dark" },
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

	/*
	 * This actually should be blocked due to unclosed DQUOTE.
	 * But cookie values are opaque for us, this is job for application
	 * layer to accurately parse cookie values.
	 */
	FOR_REQ_H2_COOKIE("session=\"42; theme=dark");

	EXPECT_BLOCK_REQ_H2_COOKIE("session=42;theme=dark");
	EXPECT_BLOCK_REQ_H2_COOKIE("session=42; theme=dark ");
	EXPECT_BLOCK_REQ_H2_COOKIE("session=42; theme=dark\t");
	EXPECT_BLOCK_REQ_H2_COOKIE("session=42, theme=dark");
	EXPECT_BLOCK_REQ_H2_COOKIE("session=42 theme=dark");
	EXPECT_BLOCK_REQ_H2_COOKIE("session=42\ttheme=dark");


#undef EXPECT_BLOCK_REQ_H2_COOKIE
#undef FOR_REQ_H2_COOKIE
}

TEST(http2_parser, if_none_match)
{
#define FOR_REQ_H2_IF_NONE_MATCH(if_none_match)					\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("if-none-match"), VALUE(if_none_match)));	\
	    HEADERS_FRAME_END();						\
	)

#define EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH(if_none_match)			\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("if-none-match"), VALUE(if_none_match)));	\
	    HEADERS_FRAME_END();						\
	)


#define ETAG_1	ETAG_ALPHABET
#define ETAG_2	"dummy2"
#define ETAG_3	"dummy3"


	FOR_REQ_H2_IF_NONE_MATCH("\"" ETAG_1 "\"")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag, ETAG_1 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_H2_IF_NONE_MATCH("\"\"")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag, "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_H2_IF_NONE_MATCH("\"" ETAG_1 "\", \"" ETAG_2 "\"")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag_1, ETAG_1 "\"");
		DEFINE_TFW_STR(exp_etag_2, ETAG_2 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_1, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_H2_IF_NONE_MATCH("\"" ETAG_1 "\", W/\"" ETAG_2 "\", \"" ETAG_3 "\"")
	{
		TfwStr h_inm = req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH];
		TfwStr s_etag;
		DEFINE_TFW_STR(exp_etag_1, ETAG_1 "\"");
		DEFINE_TFW_STR(exp_etag_2, ETAG_2 "\"");
		DEFINE_TFW_STR(exp_etag_3, ETAG_3 "\"");

		s_etag = tfw_str_next_str_val(&h_inm);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_1, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_TRUE((TFW_STR_CHUNK(&s_etag, 0))->flags
				    & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_3, '"'), 0);
		if (!TFW_STR_EMPTY(&s_etag)) {
			EXPECT_FALSE((TFW_STR_CHUNK(&s_etag, 0))->flags
				     & TFW_STR_ETAG_WEAK);
		}

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_TRUE(TFW_STR_EMPTY(&s_etag));

		EXPECT_FALSE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	FOR_REQ_H2_IF_NONE_MATCH("*")
	{
		EXPECT_TRUE(req->cond.flags & TFW_HTTP_COND_ETAG_ANY);
	}

	/* Empty header */
	EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH("");
	/* Not quoted value. */
	EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH("ETAG_2");
	/* Incomplete header. */
	EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH( "\"" ETAG_2 "\", ");
	/* No delimiter. */
	EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH("\"" ETAG_2 "\" \"" ETAG_3 "\" ");
	/* Etag list + Any etag. */
	EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH("\"" ETAG_2 "\", * ");
	EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH("*, \"" ETAG_2 "\" ");

	COMMON_ETAG_BLOCK("", EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH);


#undef ETAG_1
#undef ETAG_2
#undef ETAG_3

#undef EXPECT_BLOCK_REQ_H2_IF_NONE_MATCH
#undef FOR_REQ_H2_IF_NONE_MATCH
}

TEST(http2_parser, referer)
{
#define FOR_REQ_H2_IF_REFERER(referer)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("referer"), VALUE(referer)));		\
	    HEADERS_FRAME_END();						\
	)


	FOR_REQ_H2_IF_REFERER("http://tempesta-tech.com:8080"
		       "/cgi-bin/show.pl?entry=tempesta      ");
	FOR_REQ_H2_IF_REFERER("/cgi-bin/show.pl?entry=tempesta");
	FOR_REQ_H2_IF_REFERER("http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]"
		       ":8080/cgi-bin/show.pl?entry=tempesta");

#undef FOR_REQ_H2_IF_REFERER
}

TEST(http2_parser, content_type_line_parser)
{
#define FOR_REQ_H2_CONTENT_TYPE(content_type)					\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(							\
		    NAME(":authority"), VALUE("localhost.localdomain")));	\
		HEADER(WO_IND(NAME("content-type"), VALUE(content_type)));	\
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));		\
	    HEADERS_FRAME_END();						\
	)

#define EXPECT_BLOCK_REQ_H2_CONTENT_TYPE(content_type)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(							\
		    NAME(":authority"), VALUE("localhost.localdomain")));	\
		HEADER(WO_IND(NAME("content-type"), VALUE(content_type)));	\
		HEADER(WO_IND(NAME("content-length"), VALUE("0")));		\
	    HEADERS_FRAME_END();						\
	)

#define CT01 "multIPart/forM-data  ;    bouNDary=1234567890 ; otherparam=otherval  "

	FOR_REQ_H2_CONTENT_TYPE(CT01) {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				     req->flags));
		EXPECT_TFWSTR_EQ(&req->multipart_boundary_raw, "1234567890");
		EXPECT_TFWSTR_EQ(&req->multipart_boundary, "1234567890");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" CT01);
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data; boundary=\"1234\\56\\\"7890\"") {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				     req->flags));
		EXPECT_TFWSTR_EQ(&req->multipart_boundary_raw,
		                 "\"1234\\56\\\"7890\"");
		EXPECT_TFWSTR_EQ(&req->multipart_boundary, "123456\"7890");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data; "
				 "boundary=\"1234\\56\\\"7890\"");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data") {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data ") {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data ");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data \t") {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data \t");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data1") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data1");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data1; param=value") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data1; "
				 "param=value");
	}

	FOR_REQ_H2_CONTENT_TYPE("multihello/world") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multihello/world");
	}

	FOR_REQ_H2_CONTENT_TYPE("multihello/world; param=value") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multihello/world; param=value");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-dat") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-dat");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-other; param=value") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-other; "
				 "param=value");
	}

	FOR_REQ_H2_CONTENT_TYPE("multipart/form-data; xboundary=1234567890") {
		EXPECT_TRUE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart/form-data; "
				 "xboundary=1234567890");
	}

	FOR_REQ_H2_CONTENT_TYPE("application/octet-stream") {
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART, req->flags));
		EXPECT_FALSE(test_bit(TFW_HTTP_B_CT_MULTIPART_HAS_BOUNDARY,
				      req->flags));
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "application/octet-stream");
	}

	/* Multipart requests with multiple boundaries are clearly malicious. */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data; boundary=1; boundary=2");

	/* Comma is not a valid separator here. */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data, boundary=123");

	/* Unfinished quoted parameter value */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data; boundary=\"123");

	/* Spaces where they do not belong */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data; boundary =123");
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data; boundary= 123");
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data; boundary=12 3");
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/form-data; boun dary=123");

	/*
	 * Other media types are not restricted in terms of boundary parameter
	 * quantities.
	 */
	FOR_REQ_H2_CONTENT_TYPE("text/plain; boundary=1; boundary=2") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; boundary=1; "
				 "boundary=2");
	}
	FOR_REQ_H2_CONTENT_TYPE("text/plain; boundary=1; boundary=2; boundary=3") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; boundary=1; "
				 "boundary=2; boundary=3");
	}
	FOR_REQ_H2_CONTENT_TYPE("textqwe/plain; boundary=1; other=3") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "textqwe/plain; boundary=1; "
				 "other=3");
	}

	/* Parameter should be in format name=value. */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("text/plain; name");
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("text/plain; name ");
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("text/plain; name\t ");

	/* Unfinished quoted parameter value */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("text/plain; name=\"unfinished");

	/* Other parameter quoted values. */
	FOR_REQ_H2_CONTENT_TYPE("text/plain; name=\"value\"") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; name=\"value\"");
	}
	FOR_REQ_H2_CONTENT_TYPE("text/plain; name=\"value\" ") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; name=\"value\" ");
	}
	FOR_REQ_H2_CONTENT_TYPE("text/plain; name=\"value\";") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; name=\"value\";");
	}
	FOR_REQ_H2_CONTENT_TYPE("text/plain; name=\"value\"; ") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; name=\"value\"; ");
	}

	FOR_REQ_H2_CONTENT_TYPE("text/plain; name=\"val\\\"ue\"") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; name=\"val\\\"ue\"");
	}
	FOR_REQ_H2_CONTENT_TYPE("text/plain; name=\"val\\\"ue\" ") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "text/plain; name=\"val\\\"ue\" ");
	}

	/* Line ended at '\\'. */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("text/plain; name=\"val\\");

	/* Other cases */
	EXPECT_BLOCK_REQ_H2_CONTENT_TYPE("multipart/");
	FOR_REQ_H2_CONTENT_TYPE("multipar") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipar");
	}
	FOR_REQ_H2_CONTENT_TYPE("multipart") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multipart");
	}
	FOR_REQ_H2_CONTENT_TYPE("multitest") {
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
				 "content-type" "multitest");
	}

#undef HEAD
#undef TAIL

#undef EXPECT_BLOCK_REQ_H2_CONTENT_TYPE
#undef FOR_REQ_H2_CONTENT_TYPE
}

TEST(http2_parser, xff)
{
	TfwStr xff, v;

	const char *s_client = "203.0.113.195";
	const char *s_proxy1 = "70.41.3.18";
	const char *s_proxy2 = "150.172.238.178";

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("x-forwarded-for"),
		       VALUE("203.0.113.195,70.41.3.18,150.172.238.178")));
	    HEADERS_FRAME_END();
	)
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

TEST(http2_parser, date)
{
#define FOR_EACH_DATE(strdate, expect_seconds)					\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("if-modified-since"), VALUE(strdate)));	\
	    HEADERS_FRAME_END();						\
	)									\
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
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("if-none-match"), VALUE("\"xyzzy\"")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Sat, 29 Oct 1994 19:43:31 GMT")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TRUE(req->cond.m_date == 0);
	}
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Sat, 29 Oct 1994 19:43:31 GMT")));
		HEADER(WO_IND(NAME("if-none-match"), VALUE("\"xyzzy\"")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TRUE(req->cond.m_date == 0);
	}

	/*
	 * RFC 7232 3.3.
	 *
	 * A recipient MUST ignore the If-Modified-Since header field ...
	 * if the request method is neither GET nor HEAD.
	 */
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Sat, 29 Oct 1994 19:43:31 GMT")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TRUE(req->cond.m_date == 0);
	}
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Sat, 29 Oct 1994 19:43:31 GMT")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TRUE(req->cond.m_date == 0);
	}

	/*
	 * RFC 7230 3.2.2:
	 *
	 * A sender MUST NOT generate multiple header fields with the same field
	 * name in a message unless either the entire field value for that
	 * header field is defined as a comma-separated list [i.e., #(values)]
	 * or the header field is a well-known exception.
	 */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
	    HEADERS_FRAME_END();
	);

	/* If only 1 or 0 dates are valid, it's the multiple headers anyway. */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
		HEADER(WO_IND(
		    NAME("if-modified-since"),
		    VALUE("Wed, 41 Oct 2015 07:28:00 GMT")));
	    HEADERS_FRAME_END();
	);

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

#undef IF_MSINCE_INVALID
#undef FOR_EACH_DATE_FORMAT_INVALID
#undef FOR_EACH_DATE_FORMAT
#undef FOR_EACH_DATE_RFC_822_ISOC_INVALID
#undef FOR_EACH_DATE_RFC_822_ISOC
#undef FOR_EACH_DATE_INVALID
#undef FOR_EACH_DATE
}

TEST(http2_parser, method_override)
{
#define EXPECT_FOR_REQ_H2_METHOD_OVERRIDE(METHOD)				\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));	\
		HEADER(WO_IND(NAME("x-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));	\
		HEADER(WO_IND(NAME("x-http-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));	\
		HEADER(WO_IND(NAME("x-http-method"), VALUE(#METHOD)));		\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}

#define EXPECT_FOR_REQ_H2_METHOD_OVERRIDE_UWN(METHOD)				\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));	\
		HEADER(WO_IND(NAME("x-method-override"), VALUE(METHOD)));	\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);			\
		EXPECT_EQ(req->method_override, _TFW_HTTP_METH_UNKNOWN);	\
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("POST")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_EQ(req->method_override, _TFW_HTTP_METH_NONE);
	}

	EXPECT_FOR_REQ_H2_METHOD_OVERRIDE(PATCH);
	EXPECT_FOR_REQ_H2_METHOD_OVERRIDE(PUT);

	EXPECT_FOR_REQ_H2_METHOD_OVERRIDE_UWN("PATCHX");
	EXPECT_FOR_REQ_H2_METHOD_OVERRIDE_UWN("PATCH COPY");

#undef EXPECT_FOR_REQ_H2_METHOD_OVERRIDE_UWN
#undef EXPECT_FOR_REQ_H2_METHOD_OVERRIDE
}

TEST(http2_parser, vchar)
{
#define EXPECT_FOR_REQ_H2_HDR_EQ(name, value, id)				\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(name), VALUE(value)));			\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[id],	name value);		\
	}

#define EXPECT_BLOCK_REQ_H2_HDR(name, value)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(name), VALUE(value)));			\
	    HEADERS_FRAME_END();						\
	)

/* Tests that header is validated by ctext_vchar alphabet. */
#define TEST_VCHAR_HEADER(header, id)						\
	EXPECT_FOR_REQ_H2_HDR_EQ(header, VCHAR_ALPHABET, id);			\
	EXPECT_BLOCK_REQ_H2_HDR(header, "");					\
	EXPECT_BLOCK_REQ_H2_HDR(header, "\x08");				\
	EXPECT_BLOCK_REQ_H2_HDR(header, "\x0B");				\
	EXPECT_BLOCK_REQ_H2_HDR(header, "\x14");				\
	EXPECT_BLOCK_REQ_H2_HDR(header, "\x1F");				\
	EXPECT_BLOCK_REQ_H2_HDR(header, "\x7F");				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME(header), VALUE_RAW("\x00")));		\
	    HEADERS_FRAME_END();						\
	)


	/* Special headers */
	TEST_VCHAR_HEADER("user-agent", TFW_HTTP_HDR_USER_AGENT);

	/* RGen_HdrOtherN headers */
	TEST_VCHAR_HEADER(TOKEN_ALPHABET, TFW_HTTP_HDR_RAW);
	EXPECT_BLOCK_REQ_H2_HDR("\x09", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\"", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR(",", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("/", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR(":", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR(";", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("<", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("=", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR(">", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("?", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("@", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("[", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\\", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("]", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("{", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("}", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\x7F", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\x80", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\x90", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\xC8", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\xAE", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\xFE", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\xFF", "dummy");
	EXPECT_BLOCK_REQ_H2_HDR("\xFF", "dummy");
	/* Very long header name */
	EXPECT_BLOCK_REQ_H2_HDR("Well-Prince-so-Genoa-and-Lucca-are-now-"
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
	"which-indifference-and-even-irony-could-be-discerned", "dummy");

#undef TEST_RAW_REQ
#undef TEST_VCHAR_HEADER
#undef EXPECT_BLOCK_REQ_H2_HDR
#undef EXPECT_FOR_REQ_H2_HDR_EQ
}

TEST(http2_parser, perf)
{
	int i;
	unsigned int parsed;
	volatile unsigned long t0 = jiffies;

	DECLARE_FRAMES_BUF(request_1, 512);
	DECLARE_FRAMES_BUF(request_2, 512);
	DECLARE_FRAMES_BUF(request_3, 512);
	DECLARE_FRAMES_BUF(request_4, 512);
	DECLARE_FRAMES_BUF(request_5, 512);
	DECLARE_FRAMES_BUF(request_6, 512);

	INIT_FRAMES();
	SET_FRAMES_BUF(request_1);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("GET")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(NAME(":path"), VALUE("/")));
	    HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	INIT_FRAMES();
	SET_FRAMES_BUF(request_2);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("GET")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(NAME(":path"), VALUE("/index.html")));
	    HEADER(WO_IND(
		NAME(":authority"),
		VALUE("afaahfaduy3wbfdf.dsfda.12.dsdf.2.df")));
	    HEADER(WO_IND(
		NAME("authorization"),
		VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
	    HEADER(WO_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADER(WO_IND(
		NAME("if-modified-since"),
		VALUE("Sat, 29 Oct 1994 19:43:31 GMT")));
	    HEADER(WO_IND(NAME("x-forwarded-for"),
		   VALUE("203.0.113.195,70.41.3.18,150.172.238.178")));
	    HEADER(WO_IND(NAME("cookie"), VALUE("session=42; theme=dark")));
	    HEADER(WO_IND(NAME("referer"),
		   VALUE("http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]:8080"
		       "/cgi-bin/show.pl?entry=tempesta")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	/* Also test invalid request. */
	INIT_FRAMES();
	SET_FRAMES_BUF(request_3);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("GET")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(NAME(":path"), VALUE("/")));
	    HEADER(WO_IND(NAME("authority"), VALUE("foo.com")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	INIT_FRAMES();
	SET_FRAMES_BUF(request_4);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("GET")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(
		NAME(":path"),
		VALUE("/https://ru.wikipedia.org/wiki/%D0%A8%D0%B0%D0"
		      "%B1%D0%BB%D0%BE%D0%BD:%D0%9B%D0%B5%D0%BE%D0%BD"
		      "%D0%B0%D1%80%D0%B4%D0%BE_%D0%B4%D0%B0_%D0%92%D0"
		      "%B8%D0%BD%D1%87%D0%B8")));
	    HEADER(WO_IND(NAME(":method"), VALUE("POST")));
	    HEADER(WO_IND(NAME(":authority"), VALUE("test")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	INIT_FRAMES();
	SET_FRAMES_BUF(request_5);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("POST")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(NAME(":path"), VALUE("/a/b/c/dir/?foo=1&bar=2#abcd")));
	    HEADER(WO_IND(NAME(":authority"), VALUE("a.com")));
	    HEADER(WO_IND(NAME("cookie"), VALUE("session=42; theme=dark")));
	    HEADER(WO_IND(NAME("Dummy0"), VALUE("0")));
	    HEADER(WO_IND(
		NAME("referer"),
		VALUE("http://tempesta-tech.com:8080\r\n"
		      "/cgi-bin/show.pl?entry=tempesta")));
	    HEADER(WO_IND(
		NAME("if-modified-since"),
		VALUE("Sat, 29 Oct 1994 19:43:31 GMT")));
	    HEADER(WO_IND(NAME("x-forwarded-for"),
		   VALUE("203.0.113.195,70.41.3.18,150.172.238.178")));
	    HEADER(WO_IND(NAME("x-custom-hdr"), VALUE("custom header values")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	INIT_FRAMES();
	SET_FRAMES_BUF(request_6);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("POST")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(
		NAME(":path"),
		VALUE("http://natsys-lab.com:8080/cgi-bin/show.pl")));
	    HEADER(WO_IND(NAME("cookie"), VALUE("session=42")));
	    HEADER(WO_IND(NAME("accept"), VALUE("*/*")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

#define REQ_PERF(frames_buf)							\
do {										\
	test_case_parse_prepare_h2();						\
	if (req)								\
		test_req_free(req);						\
	req = test_req_alloc(frames_buf.size);					\
	req->conn = (TfwConn*)&conn;						\
	req->pit.parsed_hdr = &stream.parser.hdr;				\
	req->stream = &stream;							\
	tfw_http_init_parser_req(req);						\
	stream.msg = (TfwMsg*)req;						\
	__set_bit(TFW_HTTP_B_H2, req->flags);					\
	tfw_h2_parse_req(req, frames_buf.data, frames_buf.size, &parsed);	\
} while (0)

	for (i = 0; i < 1000; ++i) {
		/*
		 * Benchmark several requests to make the headers parsing more
		 * visible in the performance results. Also having L7 DDoS in
		 * mind we need to to care about requests more than responses.
		 */
		REQ_PERF(request_1);
		REQ_PERF(request_2);
		REQ_PERF(request_3);
		REQ_PERF(request_4);
		REQ_PERF(request_5);
		REQ_PERF(request_6);
	}
	pr_info("===> http parser time: %ums\n",
		jiffies_to_msecs(jiffies - t0));

#undef REQ_PERF
#undef H2_BUF
}

TEST(http2_parser, fuzzer)
{
#define N 6	// Count of generations
#define MOVE 1	// Mutations per generation

	size_t len = 10 * 1024 * 1024;
	char *str;
	unsigned int headers_len = 0, body_len = 0;
	int ret;
	int field, i;
	TfwFuzzContext context;

	kernel_fpu_end();
	str = vmalloc(len);
	kernel_fpu_begin();

	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_DBG3("start field: %d request: %d\n", field, i);
			ret = fuzz_gen_h2(&context, str, str + len, field, MOVE,
				       FUZZ_REQ_H2, &headers_len, &body_len);
			INIT_FRAMES();
			ADD_HEADERS_FRAME(str, headers_len);
			ADD_DATA_FRAME(str + headers_len, body_len);
			test_case_parse_prepare_h2();
			switch (ret) {
			case FUZZ_VALID:
				TRY_PARSE_EXPECT_PASS(FUZZ_REQ_H2, CHUNK_ON);
				break;
			case FUZZ_INVALID:
				TRY_PARSE_EXPECT_BLOCK(FUZZ_REQ_H2, CHUNK_ON);
				break;
			case FUZZ_END:
			default:
				goto end;
			}

			/* Fuzzer generates huge debug message flow. */
			test_debug_relax();
		}
	}

end:
	kernel_fpu_end();
	vfree(str);
	kernel_fpu_begin();
}

TEST(http2_parser, hpack_static_table)
{
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	/* TODO: must be fixed in [#1614]
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "http"
		HEADER(INDEX(6));
		// :path = "/"
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	);
	*/

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/index.html" */
		HEADER(INDEX(5));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/index.html");
	}

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/index.html" */
		HEADER(INDEX(5));
		/* content-length = "1" */
		HEADER(WO_IND(INDEX(28), VALUE("1")));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		/* :method = "POST" */
		HEADER(INDEX(3));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_POST);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" */
		HEADER(WO_IND(INDEX(1), VALUE("localhost")));
		/* accept-charset = "utf-8" */
		HEADER(WO_IND(INDEX(15), VALUE("utf-8")));
		/* accept-encoding = "gzip, deflate" */
		HEADER(INDEX(16));
		/* accept-language = "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5" */
		HEADER(WO_IND(
		    INDEX(17),
		    VALUE("fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5")));
		/* accept = "*\/\*" */
		HEADER(WO_IND(INDEX(19), VALUE("*/*")));
		/* age = "13" */
		HEADER(WO_IND(INDEX(21), VALUE("13")));
		/* authorization = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" */
		HEADER(WO_IND(
		    INDEX(23),
		    VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
		/* cache-control = "max-age=1, no-store, min-fresh=30" */
		HEADER(WO_IND(
		    INDEX(24),
		    VALUE("max-age=1, no-store, min-fresh=30")));
		/* cookie = "session=42; theme=dark" */
		HEADER(WO_IND(INDEX(32), VALUE("session=42; theme=dark")));
		/* from = "webmaster@example.org" */
		HEADER(WO_IND(INDEX(37), VALUE("webmaster@example.org")));
		/* host = "developer.mozilla.org:5588" */
		HEADER(WO_IND(INDEX(38), VALUE("developer.mozilla.org:5588")));
		/* if-match = "\"67ab43\", \"54ed21\", \"7892dd\"" */
		HEADER(WO_IND(
		    INDEX(39),
		    VALUE("\"67ab43\", \"54ed21\", \"7892dd\"")));
		/* if-modified-since = "Inv, 31 Jan 2012 15:02:53" */
		HEADER(WO_IND(INDEX(40), VALUE("Inv, 31 Jan 2012 15:02:53 GMT")));
		/* if-range = "Wed, 21 Oct 2015 07:28:00 GMT" */
		HEADER(WO_IND(INDEX(42), VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
		 /* if-unmodified-since = "Inv, 31 Jan 2012 15:02:55" */
		HEADER(WO_IND(INDEX(43), VALUE("Tue, 21 Oct 2015 17:28:00 GMT")));
		/* link = "<https://example.com>; rel=\"preconnect\"" */
		HEADER(WO_IND(
		    INDEX(45),
		    VALUE("<https://example.com>; rel=\"preconnect\"")));
		/* max-forwards = "24" */
		HEADER(WO_IND(INDEX(47), VALUE("24")));
		/* proxy-authorization = "Basic YWxhZGRpbjpvcGVuc2VzYW1l" */
		HEADER(WO_IND(INDEX(49), VALUE("Basic YWxhZGRpbjpvcGVuc2VzYW1l")));
		/* range = "bytes=200-1000, 2000-6576, 19000-" */
		HEADER(WO_IND(
		    INDEX(50),
		    VALUE("bytes=200-1000, 2000-6576, 19000-")));
		/* referer = "https://example.com/page?q=123" */
		HEADER(WO_IND(INDEX(51), VALUE("https://example.com/page?q=123")));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(WO_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
		/* via = "1.0 fred, 1.1 p.example.net" */
		HEADER(WO_IND(INDEX(60), VALUE("1.0 fred, 1.1 p.example.net")));

	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 17);
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
		EXPECT_TFWSTR_EQ(&req->host, "localhost");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW],
				 "accept-charset" "utf-8");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 1],
				 "accept-encoding" "gzip, deflate");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 2],
				 "accept-language"
				 "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 3],
				 "accept" "*/*");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 4],
				 "age" "13");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 5],
				 "authorization"
				 "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 6],
				 "cache-control"
				 "max-age=1, no-store, min-fresh=30");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE],
				 "cookie" "session=42; theme=dark");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 7],
				 "from" "webmaster@example.org");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_HOST],
				 "host" "developer.mozilla.org:5588");
		EXPECT_EQ(req->host_port, 5588);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 8],
				 "if-match"
				 "\"67ab43\", \"54ed21\", \"7892dd\"");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 9],
				 "if-modified-since"
				 "Inv, 31 Jan 2012 15:02:53 GMT");
		EXPECT_TRUE(req->cond.m_date == 1328022173);
		EXPECT_TRUE(req->cond.flags & TFW_HTTP_COND_IF_MSINCE);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 10],
				 "if-range" "Wed, 21 Oct 2015 07:28:00 GMT");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 11],
				 "if-unmodified-since"
				 "Tue, 21 Oct 2015 17:28:00 GMT");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 12],
				 "link"
				 "<https://example.com>; rel=\"preconnect\"");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 13],
				 "max-forwards" "24");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 14],
				 "proxy-authorization"
				 "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 15],
				 "range" "bytes=200-1000, 2000-6576, 19000-");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_REFERER],
				 "referer" "https://example.com/page?q=123");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_USER_AGENT],
				 "user-agent" "Wget/1.13.4 (linux-gnu)");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 16],
				 "via" "1.0 fred, 1.1 p.example.net");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		/* :method = "POST" */
		HEADER(INDEX(3));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* content-length = "7" */
		HEADER(WO_IND(INDEX(28), VALUE("7")));
		/* content-type = "text/plain" */
		HEADER(WO_IND(INDEX(31), VALUE("text/plain")));
		/* expect = "100-continue" */
		HEADER(WO_IND(INDEX(35), VALUE("100-continue")));
		 /* if-none-match = "\"xyzzy\"" */
		HEADER(WO_IND(INDEX(41), VALUE("\"xyzzy\"")));
	    HEADERS_FRAME_END();
	    DATA_FRAME_BEGIN();
		DATA("1234567");
	    DATA_FRAME_END();
	)
	{
	    EXPECT_TRUE(req->content_length == 7);
	    EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_LENGTH],
			     "content-length" "7");
	    EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_TYPE],
			     "content-type" "text/plain");
	    EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW],
			     "expect" "100-continue");
	    EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH],
			     "if-none-match" "\"xyzzy\"");
	}
}

TEST_SUITE(http2_parser)
{
	TEST_RUN(http2_parser, http2_check_important_fields);
	TEST_RUN(http2_parser, parses_req_method);
	TEST_RUN(http2_parser, parses_req_uri);
	TEST_RUN(http2_parser, mangled_messages);
	TEST_RUN(http2_parser, alphabets);
	TEST_RUN(http2_parser, fills_hdr_tbl_for_req);
	TEST_RUN(http2_parser, cache_control);
	TEST_RUN(http2_parser, suspicious_x_forwarded_for);
	TEST_RUN(http2_parser, content_type_in_bodyless_requests);
	TEST_RUN(http2_parser, content_length);
	TEST_RUN(http2_parser, ows);
	TEST_RUN(http2_parser, accept);
	TEST_RUN(http2_parser, host);
	TEST_RUN(http2_parser, cookie);
	TEST_RUN(http2_parser, if_none_match);
	TEST_RUN(http2_parser, referer);
	TEST_RUN(http2_parser, content_type_line_parser);
	TEST_RUN(http2_parser, xff);
	TEST_RUN(http2_parser, date);
	TEST_RUN(http2_parser, method_override);
	TEST_RUN(http2_parser, vchar);
	TEST_RUN(http2_parser, fuzzer);
	TEST_RUN(http2_parser, hpack_static_table);

	/*
	 * Testing for correctness of redirection mark parsing (in
	 * extended enforced mode of 'http_sessions' module).
	 */
	TFW_HTTP_SESS_REDIR_MARK_ENABLE();
	TEST_RUN(http2_parser, parses_enforce_ext_req);
	TEST_RUN(http2_parser, parses_enforce_ext_req_rmark);
	TFW_HTTP_SESS_REDIR_MARK_DISABLE();

	TEST_RUN(http2_parser, perf);
}
