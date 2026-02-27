/**
 *		Tempesta FW
 *
 * Copyright (C) 2022-2025 Tempesta Technologies, Inc.
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

TEST(http2_parser, short_name)
{
	FOR_REQ_H2(
		HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("x"), VALUE("test")));
		HEADERS_FRAME_END();
	);

	FOR_REQ_H2(
		HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("z"), VALUE("test")));
		HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
		HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME(""), VALUE("test")));
		HEADERS_FRAME_END();
	);
}

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
		HEADER(WO_IND(NAME("authorization"),
			    VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
		HEADER(WO_IND(NAME("cache-control"),
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

TEST(http2_parser, header_prefix_confusion)
{
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("upgrade"), VALUE("h2c, quic")));
	    HEADERS_FRAME_END();
	);

	/*
	 * RFC 9113 8.3: "Endpoints MUST treat a request or response that
	 * contains undefined or invalid pseudo-header fields as malformed
	 * (Section 8.1.1).", so we allow :authorityx pseudo-header but
	 * must not confuse it with :authority.
	 */
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME(":authorityx"), VALUE("192.168.1.1:4433")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TRUE(TFW_STR_EMPTY(&req->host));
		EXPECT_ZERO(req->host_port);
	}

	/*
	 * Do not confuse profibited `Proxy-Connection`, `Transfer-Encoding`
	 * headers with headers with the same prefixes and the same or different
	 * lengths.
	 */
#define DO_NOT_CONFUSE_PROHIBITED_HEADER(name)				\
	FOR_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();					\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));		\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));	\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));		\
		HEADER(WO_IND(NAME(name), VALUE("bar")));		\
	    HEADERS_FRAME_END();					\
	)

	DO_NOT_CONFUSE_PROHIBITED_HEADER("upgrade-insecure-requests");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("connection!");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("proxy-connection!");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("proxy-con!ection");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("proxy-connectio");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("tran!fer-encoding");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("transfer-encodin");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("keep-aliv!");
	DO_NOT_CONFUSE_PROHIBITED_HEADER("keep-alivex");
#undef DO_NOT_CONFUSE_PROHIBITED_HEADER
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
	const char *s_dummy9 = "dummy9"
			       "9";
	const char *s_dummy4 = "dummy4"
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
		HEADER(WO_IND(NAME("dummy0"), VALUE("0")));
		HEADER(WO_IND(NAME("dummy1"), VALUE("1")));
		HEADER(WO_IND(NAME("dummy2"), VALUE("2")));
		HEADER(WO_IND(NAME("dummy3"), VALUE("3")));
		HEADER(WO_IND(NAME("dummy4"), VALUE("4")));
		HEADER(WO_IND(NAME("dummy5"), VALUE("5")));
		HEADER(WO_IND(NAME("dummy6"), VALUE("6")));
		/* That is done to check table reallocation. */
		HEADER(WO_IND(NAME("dummy7"), VALUE("7")));
		HEADER(WO_IND(NAME("dummy8"), VALUE("8")));
		HEADER(WO_IND(NAME("dummy9"), VALUE("9")));
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

TEST_MPART(http2_parser, cache_control, 0)
{
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
}

TEST_MPART(http2_parser, cache_control, 1)
{
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
	EXPECT_BLOCK_REQ_H2_CC(directive "=10 10");

TEST_MPART(http2_parser, cache_control, 2)
{
	TEST_NO_ARGUMENT("no-cache", TFW_HTTP_CC_NO_CACHE);
	TEST_NO_ARGUMENT("no-store", TFW_HTTP_CC_NO_STORE);
	TEST_NO_ARGUMENT("no-transform", TFW_HTTP_CC_NO_TRANSFORM);
}

TEST_MPART(http2_parser, cache_control, 3)
{
	TEST_SECONDS("max-age", TFW_HTTP_CC_MAX_AGE, max_age);
	TEST_SECONDS("max-stale", TFW_HTTP_CC_MAX_STALE, max_stale);
	TEST_SECONDS("min-fresh", TFW_HTTP_CC_MIN_FRESH, min_fresh);
}

TEST_MPART(http2_parser, cache_control, 4)
{
	EXPECT_BLOCK_DIGITS("max-age=", "", EXPECT_BLOCK_REQ_H2_CC);
	EXPECT_BLOCK_DIGITS("max-stale=", "", EXPECT_BLOCK_REQ_H2_CC);
	EXPECT_BLOCK_DIGITS("min-fresh=", "", EXPECT_BLOCK_REQ_H2_CC);
}

#undef TEST_SECONDS
#undef TEST_NO_ARGUMENT
#undef TEST_COMMON

#undef FOR_REQ_H2_CC
#undef EXPECT_BLOCK_REQ_H2_CC

TEST_MPART_DEFINE(http2_parser, cache_control, H2_CC_TCNT,
		  TEST_MPART_NAME(http2_parser, cache_control, 0),
		  TEST_MPART_NAME(http2_parser, cache_control, 1),
		  TEST_MPART_NAME(http2_parser, cache_control, 2),
		  TEST_MPART_NAME(http2_parser, cache_control, 3),
		  TEST_MPART_NAME(http2_parser, cache_control, 4));

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

#define EXPECT_BLOCK_BODYLESS_REQ_H2(METHOD)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE(#METHOD)));		\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("1")));		\
	    HEADERS_FRAME_END();						\
	)									\
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
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(METHOD)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("1")));		\
		HEADER(WO_IND(NAME("x-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	)									\
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
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("1")));		\
		HEADER(WO_IND(NAME("x-http-method-override"), VALUE(#METHOD)));	\
	    HEADERS_FRAME_END();						\
	)									\
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
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("PUT")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));		\
		HEADER(WO_IND(NAME("content-length"), VALUE("1")));		\
		HEADER(WO_IND(NAME("x-http-method"), VALUE(#METHOD)));		\
	    HEADERS_FRAME_END();						\
	)									\
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
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}

TEST_MPART(http2_parser, content_type_in_bodyless_requests, 0)
{
	EXPECT_BLOCK_BODYLESS_REQ_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_H2(TRACE);
}

TEST_MPART(http2_parser, content_type_in_bodyless_requests, 1)
{
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(HEAD);
}

TEST_MPART(http2_parser, content_type_in_bodyless_requests, 2)
{
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
}

#undef EXPECT_BLOCK_BODYLESS_REQ_H2
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2

TEST_MPART_DEFINE(http2_parser, content_type_in_bodyless_requests,
		  H2_CT_BODYLESS_TCNT,
		  TEST_MPART_NAME(http2_parser,
				  content_type_in_bodyless_requests, 0),
		  TEST_MPART_NAME(http2_parser,
				  content_type_in_bodyless_requests, 1),
		  TEST_MPART_NAME(http2_parser,
				  content_type_in_bodyless_requests, 2));

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

TEST_MPART(http2_parser, accept, 0)
{
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
}

TEST_MPART(http2_parser, accept, 1)
{
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
}

TEST_MPART(http2_parser, accept, 2)
{
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
}

TEST_MPART(http2_parser, accept, 3)
{

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

}

#undef TEST_ACCEPT_EXT
#undef EXPECT_BLOCK_REQ_H2_ACCEPT
#undef FOR_ACCEPT_HTML
#undef FOR_ACCEPT
#undef __FOR_ACCEPT

TEST_MPART_DEFINE(http2_parser, accept, H2_ACCEPT_TCNT,
		  TEST_MPART_NAME(http2_parser, accept, 0),
		  TEST_MPART_NAME(http2_parser, accept, 1),
		  TEST_MPART_NAME(http2_parser, accept, 2),
		  TEST_MPART_NAME(http2_parser, accept, 3));

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

TEST_MPART(http2_parser, host, 0)
{
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
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
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
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":" , .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "443" , .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
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
				  .flags = TFW_STR_HDR_VALUE|TFW_STR_VALUE },
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
				  .flags = TFW_STR_HDR_VALUE|TFW_STR_VALUE },
				{ .data = ":" , .len = 1,
				 .flags = TFW_STR_HDR_VALUE },
				{ .data = "65535", .len = 5,
				  .flags = TFW_STR_HDR_VALUE|TFW_STR_VALUE },
			},
			.len = 38,
			.nchunks = 4,
			.flags = TFW_STR_COMPLETE
		};
		test_string_split(&h_expected, host);

		EXPECT_EQ(req->host_port, 65535);
	}
}

TEST_MPART(http2_parser, host, 1)
{
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
}

TEST_MPART(http2_parser, host, 2)
{
	/* Port syntax is broken. */
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com:443:1");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]:443:1");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com::443");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]::443");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com 443");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000] 443");
	EXPECT_BLOCK_REQ_H2_HOST("tempesta-tech.com:443-1");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000]-1");
}

TEST_MPART(http2_parser, host, 3)
{
	/* Invalid brackets around IPv6. */
	EXPECT_BLOCK_REQ_H2_HOST("fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000][");
	EXPECT_BLOCK_REQ_H2_HOST("[fd42:5ca1:e3a7::1000[");
}

#undef EXPECT_BLOCK_REQ_H2_HOST
#undef FOR_REQ_H2_HOST
TEST_MPART_DEFINE(http2_parser, host, H2_HOST_TCNT,
		  TEST_MPART_NAME(http2_parser, host, 0),
		  TEST_MPART_NAME(http2_parser, host, 1),
		  TEST_MPART_NAME(http2_parser, host, 2),
		  TEST_MPART_NAME(http2_parser, host, 3));

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
			{ TFW_STR_NAME|TFW_STR_HDR_VALUE, "session=" },
			{ TFW_STR_VALUE|TFW_STR_HDR_VALUE, "42" },
			{ TFW_STR_HDR_VALUE, "; " },
			{ TFW_STR_NAME|TFW_STR_HDR_VALUE, "theme=" },
			{ TFW_STR_VALUE|TFW_STR_HDR_VALUE, "dark" },
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

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);

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

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_2, '"'), 0);

		s_etag = tfw_str_next_str_val(&s_etag);
		EXPECT_EQ(tfw_strcmpspn(&s_etag, &exp_etag_3, '"'), 0);

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

TEST(http2_parser, content_encoding)
{
	static char cenc[] =
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
	        "dummy126, dummy127";

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-encoding"), VALUE(TOKEN_ALPHABET)));
	    HEADERS_FRAME_END();
	)
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_ENCODING];
		EXPECT_GT(h->len, 0);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-encoding"), VALUE("gzip, br")));
	    HEADERS_FRAME_END();
	)
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_ENCODING];
		EXPECT_GT(h->len, 0);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-encoding"), VALUE(cenc)));
	    HEADERS_FRAME_END();
	)
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_CONTENT_ENCODING];
		EXPECT_GT(h->len, 0);
	}

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-encoding"), VALUE(TOKEN_ALPHABET ";"
							      )));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("content-encoding"), VALUE(TOKEN_ALPHABET ",;"
							      )));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser, te)
{
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("te"), VALUE(TOKEN_ALPHABET)));
	    HEADERS_FRAME_END();
	);
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("te"), VALUE("trailers")));
	    HEADERS_FRAME_END();
	)
	{
	}
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

TEST_MPART(http2_parser, date_format, 0)
{
	FOR_EACH_DATE_FORMAT("31", "Jan", "2012", "12", "15:02:53",
				   1328022173);
	FOR_EACH_DATE_FORMAT_INVALID("31", "JAN", "2012", "12", "15:02:53");

	FOR_EACH_DATE_FORMAT_INVALID(" 31", "Jan", "2012", "12", "15:02:53");
	FOR_EACH_DATE_FORMAT_INVALID("31", " Jan", "2012", "12", "15:02:53");
	FOR_EACH_DATE_FORMAT_INVALID("31", "Jan", " 2012", " 12", "15:02:53");
	FOR_EACH_DATE_FORMAT_INVALID("31", "Jan", "2012", "12", " 15:02:53");

	/* More than 01 Jan 1970. */
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
}

TEST_MPART(http2_parser, date_format, 1)
{
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

TEST_MPART_DEFINE(http2_parser, date_format, H2_DATE_FMT_TCNT,
		  TEST_MPART_NAME(http2_parser, date_format, 0),
		  TEST_MPART_NAME(http2_parser, date_format, 1));

TEST(http2_parser, date_ranges)
{
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

TEST_MPART(http2_parser, date_day, 0)
{
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

TEST_MPART(http2_parser, date_day, 1)
{
	FOR_EACH_DATE_FORMAT("30", "Apr", "1978", "78", "00:00:00",
				   262742400);
	FOR_EACH_DATE_FORMAT_INVALID("31", "Apr", "1995", "95", "00:00:00");
	FOR_EACH_DATE_FORMAT("31", "Jul", "2003", "03", "00:00:00",
				   1059609600);
	FOR_EACH_DATE_FORMAT("30", "Sep", "2009", "09", "00:00:00",
				   1254268800);
	FOR_EACH_DATE_FORMAT_INVALID("31", "Sep", "2050", "50", "00:00:00");
}

TEST_MPART_DEFINE(http2_parser, date_day, H2_DATE_FMT_TCNT,
		  TEST_MPART_NAME(http2_parser, date_day, 0),
		  TEST_MPART_NAME(http2_parser, date_day, 1));

TEST(http2_parser, date_year)
{
	/* Leap years */
	FOR_EACH_DATE_FORMAT("29", "Feb", "1996", "96", "00:00:00", 825552000);
	FOR_EACH_DATE_FORMAT_INVALID("29", "Feb", "1999", "99", "00:00:00");

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

TEST(http2_parser, date_month)
{
	/* Incorrect month. */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Ja", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Janu", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "January", "2000", "00", "00:00:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jab", "2000", "00", "00:00:00");
}

TEST(http2_parser, date_hour)
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
}

TEST(http2_parser, date_minute)
{
	/* Incorrect minutes. */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00::00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:0:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:000:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:60:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:100:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:-1:00");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:invalid:00");
}

TEST(http2_parser, date_second)
{
	/* Incorrect seconds. */
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:0");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:000");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:60");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:100");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:-1");
	FOR_EACH_DATE_FORMAT_INVALID("01", "Jan", "2000", "00", "00:00:invalid");
	/* Leap seconds are not implemented (as in Nginx) */
	FOR_EACH_DATE_FORMAT_INVALID("30", "Jun", "1992", "92", "23:59:60");
}
#undef IF_MSINCE_INVALID
#undef FOR_EACH_DATE_FORMAT_INVALID
#undef FOR_EACH_DATE_FORMAT
#undef FOR_EACH_DATE_RFC_822_ISOC_INVALID
#undef FOR_EACH_DATE_RFC_822_ISOC
#undef FOR_EACH_DATE_INVALID
#undef FOR_EACH_DATE

TEST(http2_parser, date)
{
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
	TEST_VCHAR_HEADER(TOKEN_ALPHABET_LC, TFW_HTTP_HDR_RAW);
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
	EXPECT_BLOCK_REQ_H2_HDR("well-prince-so-genoa-and-lucca-are-now-"
	"just-family-estates-of-the-buonapartes-but-i-warn-you-if-you-dont-"
	"tell-me-that-this-means-war-if-you-still-try-to-defend-the-infamies-"
	"and-horrors-perpetrated-by-that-antichrist-i-really-believe-he-is-"
	"antichrist-i-will-have-nothing-more-to-do-with-you-and-you-are-no-"
	"longer-my-friend-no-longer-my-faithful-slave-as-you-call-yourself!-"
	"but-how-do-you-do-i-see-i-have-frightened-you-sit-down-and-tell-me-"
	"all-the-news#it-was-in-july-1805-and-the-speaker-was-the-well-known-"
	"anna-pavlovna-scherer-maid-of-honor-and-favorite-of-the-empress-"
	"marya-fedorovna-with-these-words-she-greeted-prince-vasili-kuagin-a-"
	"man-of-high-rank-and-importance-who-was-the-first-to-arrive-at-her-"
	"reception-anna-pavlovna-had-had-a-cough-for-some-days-she-was-as-she-"
	"said-suffering-from-la-grippe-grippe-being-then-a-new-word-in-st-"
	"petersburg-used-only-by-the-elite#all-her-invitations-without-"
	"exception-written-in-french-and-delivered-by-a-scarlet-liveried-"
	"footman-that-morning-ran-as-follows#if-you-have-nothing-better-to-do"
	"-count-(or-prince)-and-if-the-prospect-of-spending-an-evening-with-a"
	"-poor-invalid-is-not-too-terrible-i-shall-be-very-charmed-to-see-you"
	"-tonight-between-7-and-10-annette-scherer#heavens!-what-a-virulent-"
	"attack!-replied-the-prince-not-in-the-least-disconcerted-by-this-"
	"reception-he-had-just-entered-wearing-an-embroidered-court-uniform-"
	"knee-breeches-and-shoes-and-had-stars-on-his-breast-and-a-serene-"
	"expression-on-his-flat-face-he-spoke-in-that-refined-french-in-which"
	"-our-grandfathers-not-only-spoke-but-thought-and-with-the-gentle-"
	"patronizing-intonation-natural-to-a-man-of-importance-who-had-grown-"
	"old-in-society-and-at-court-he-went-up-to-anna-pavlovna-kissed-her-"
	"hand-presenting-to-her-his-bald-scented-and-shining-head-and-"
	"complacently-seated-himself-on-the-sofa#first-of-all-dear-friend-tell"
	"-me-how-you-are-set-your-friends-mind-at-rest-said-he-without-"
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

	tfw_init_frames();
	SET_FRAMES_BUF(request_1);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("GET")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(NAME(":path"), VALUE("/")));
	    HEADER(WO_IND(NAME(":authority"), VALUE("example.com")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	tfw_init_frames();
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
	tfw_init_frames();
	SET_FRAMES_BUF(request_3);
	HEADERS_FRAME_BEGIN();
	    HEADER(WO_IND(NAME(":method"), VALUE("GET")));
	    HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
	    HEADER(WO_IND(NAME(":path"), VALUE("/")));
	    HEADER(WO_IND(NAME("authority"), VALUE("foo.com")));
	HEADERS_FRAME_END();
	RESET_FRAMES_BUF();

	tfw_init_frames();
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

	tfw_init_frames();
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

	tfw_init_frames();
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
	test_req_resp_cleanup();						\
	tfw_h2_context_clear(conn.h2);						\
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
	if (!str) {
		pr_err("vmalloc() failure, too small RAM?\n");
		return;
	}

	fuzz_init(&context, false);

	for (field = SPACES; field < N_FIELDS; field++) {
		for (i = 0; i < N; i++) {
			TEST_DBG3("start field: %d request: %d\n", field, i);
			ret = fuzz_gen_h2(&context, str, str + len, field, MOVE,
				       FUZZ_REQ_H2, &headers_len, &body_len);
			tfw_init_frames();
			ADD_HEADERS_FRAME(str, headers_len);
			ADD_DATA_FRAME(str + headers_len, body_len);
			test_req_resp_cleanup();
			tfw_h2_context_clear(conn.h2);
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
			__fpu_schedule();
		}
	}

end:
	kernel_fpu_end();
	vfree(str);
	kernel_fpu_begin();
}

/* H2 'forwarded' test request definition */
#define FOR_REQ_H2_FORWARDED(forwarded)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("forwarded"),				\
		       VALUE(forwarded)));					\
	    HEADERS_FRAME_END();						\
	)

#define EXPECT_BLOCK_REQ_H2_FORWARDED(forwarded) 				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));			\
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));		\
		HEADER(WO_IND(NAME(":path"), VALUE("/")));			\
		HEADER(WO_IND(NAME("forwarded"), VALUE(forwarded)));		\
	    HEADERS_FRAME_END();						\
	)

TEST_MPART(http2_parser, forwarded, 0)
{
	/* Invalid port. */
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:0");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:65536");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:443;");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:443\"");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:443 ;");

	/* Space after semicolon */
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:443; proto=http");
	/* Space before semicolon */
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:443 ;proto=http");
	/* Spaces around semicolon */
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=tempesta-tech.com:443"
				      " ; proto=http");

	/* Invalid non quoted IPv6. */
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=[111:222:233]");
	/* IPv6 with invalid chars. */
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=[111:p22:t3]");

	/* Quoted host with port. */
	FOR_REQ_H2_FORWARDED("host=\"tempesta-tech.com:443\"");
	/* Quoted IPv6 host with port. */
	FOR_REQ_H2_FORWARDED("host=\"[11:22:33:44]:443\"");
}

TEST_MPART(http2_parser, forwarded, 1)
{
	/* Common cases. */
	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com:443")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE},
				{ .data = "tempesta-tech.com:443", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
			},
			.len = 35,
			.nchunks = 5
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE},
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
			},
			.len = 31,
			.nchunks = 3
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com:443;"
			     "for=8.8.8.8")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE},
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
			},
			.len = 47,
			.nchunks = 8
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com:443;"
			     "for=8.8.8.8;"
			     "by=8.8.4.4")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
			},
			.len = 58,
			.nchunks = 11
		};

		test_string_split(&h_expected, forwarded);
	}
}

TEST_MPART(http2_parser, forwarded, 2)
{
	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com:443;"
			     "for=8.8.8.8;"
			     "by=8.8.4.4;"
			     "proto=https")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "proto=", .len = 6,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "https", .len = 5,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
			},
			.len = 70,
			.nchunks = 14
		};

		test_string_split(&h_expected, forwarded);
	}

	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com:443;"
			     "for=8.8.8.8,"
		             "for=1.2.3.4:8080;"
		             "by=8.8.4.4;"
		             "proto=https")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded:", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ",", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "1.2.3.4:8080", .len = 12,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "proto=", .len = 6,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "https", .len = 5,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
			},
			.len = 87,
			.nchunks = 17
		};

		test_string_split(&h_expected, forwarded);
	}

	/* quoted version */
	FOR_REQ_H2_FORWARDED("host=tempesta-tech.com:443;"
			     "for=\"8.8.8.8\";"
			     "by=8.8.4.4")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "\"", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = "\";", .len = 2,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
			},
			.len = 60,
			.nchunks = 12
		};

		test_string_split(&h_expected, forwarded);
	}

	/* quoted version */
	FOR_REQ_H2_FORWARDED("host=\"tempesta-tech.com:443\";"
			     "for=8.8.8.8;"
			     "by=8.8.4.4")
	{
		TfwStr *forwarded = &req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED];
		TfwStr h_expected = {
			.chunks = (TfwStr []) {
				{ .data = "forwarded", .len = 9 },
				{ .data = "host=", .len = 5,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "\"", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "tempesta-tech.com", .len = 17,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ":", .len = 1,
				  .flags = TFW_STR_HDR_VALUE},
				{ .data = "443", .len = 3,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE},
				{ .data = "\";", .len = 2,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "for=", .len = 4,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.8.8", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
				{ .data = ";", .len = 1,
				  .flags = TFW_STR_HDR_VALUE },
				{ .data = "by=", .len = 3,
				  .flags = TFW_STR_NAME|TFW_STR_HDR_VALUE },
				{ .data = "8.8.4.4", .len = 7,
				  .flags = TFW_STR_VALUE|TFW_STR_HDR_VALUE },
			},
			.len = 60,
			.nchunks = 12
		};

		test_string_split(&h_expected, forwarded);
	}
}

TEST_MPART(http2_parser, forwarded, 3)
{
	/* Cases from RFC 7239. */
	FOR_REQ_H2_FORWARDED("for=\"_gazonk\"");
	FOR_REQ_H2_FORWARDED("For=\"[2001:db8:cafe::17]:4711\"");
	FOR_REQ_H2_FORWARDED("for=192.0.2.60;proto=http;by=203.0.113.43");
	FOR_REQ_H2_FORWARDED("for=192.0.2.43, for=198.51.100.17");

	/* Shuffle params */
	FOR_REQ_H2_FORWARDED(
		       "for=1.2.3.4;"
		       "host=example.com;"
		       "by=8.8.8.8;"
		       "proto=https");

	FOR_REQ_H2_FORWARDED(
		       "host=example.com;"
		       "for=1.2.3.4;"
		       "by=8.8.8.8;"
		       "proto=https");

	FOR_REQ_H2_FORWARDED(
		       "host=example.com;"
		       "by=8.8.8.8;"
		       "for=1.2.3.4;"
		       "proto=https");

	FOR_REQ_H2_FORWARDED(
		       "host=example.com;"
		       "by=8.8.8.8;"
		       "proto=https;"
		       "for=1.2.3.4");

	FOR_REQ_H2_FORWARDED(
		       "for=1.2.3.4;"
		       "by=8.8.8.8;"
		       "host=example.com;"
		       "proto=https");

	FOR_REQ_H2_FORWARDED(
		       "proto=https;"
		       "host=example.com;"
		       "for=1.2.3.4;"
		       "by=8.8.8.8");

	FOR_REQ_H2_FORWARDED(
		       "by=8.8.8.8;"
		       "host=example.com;"
		       "for=1.2.3.4;"
		       "proto=https");

	FOR_REQ_H2_FORWARDED(
		       "by=8.8.8.8;"
		       "proto=https;"
		       "for=1.2.3.4;"
		       "host=example.com");

	/* Duplicated params name.
	 *
	 * RFC 7239 section 4:
	 * Each parameter MUST NOT occur more than once per field-value.
	 */
	EXPECT_BLOCK_REQ_H2_FORWARDED("proto=http;for=8.8.8.8;proto=http");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=2.2.2.2;for=8.8.8.8;by=2.2.2.2");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=goo.gl;for=8.8.8.8;host="
				"example.com");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.1.1.1;host=goo.gl;for="
				"2.2.2.2");
	/* "for=" represented as separated list is allowed */
	FOR_REQ_H2_FORWARDED("for=1.1.1.1, for=2.2.2.2;host=goo.gl");

	/* Suspicious */
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=\"\"");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=\"\"");
	EXPECT_BLOCK_REQ_H2_FORWARDED("host=\"[]\"");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=\"\"");
	EXPECT_BLOCK_REQ_H2_FORWARDED("proto=");
	EXPECT_BLOCK_REQ_H2_FORWARDED("proto=\"\"");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4,");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4, ");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4, ,for=5.6.7.8");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4, , 5.6.7.8;");
	EXPECT_BLOCK_REQ_H2_FORWARDED("foo!");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4;host=\"goo.gl");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4;proto='https';host=goo.gl");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4;proto=<xss>;host=goo.gl");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4;proto=\"><xss>;host=goo.gl");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4;proto=\"\"><xss>\";"
				      "host=goo.gl");
	EXPECT_BLOCK_REQ_H2_FORWARDED("for=1.2.3.4;proto=\" onclick=alert(1);"
				      "host=goo.gl");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=1.2.3.4;host=\"><xss>;proto=http");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=1.2.3.4;host=\" alert(1);proto=http");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=1.2.3.4;host=' goo.gl;proto=http");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=1.2.3.4;host=http;proto="
				      "http;for=<xss>");
	EXPECT_BLOCK_REQ_H2_FORWARDED("by=<xss>;host=http;proto=http;"
				      "for=1.2.3.4");
}

TEST_MPART_DEFINE(http2_parser, forwarded, H2_FWD_TCNT,
		  TEST_MPART_NAME(http2_parser, forwarded, 0),
		  TEST_MPART_NAME(http2_parser, forwarded, 1),
		  TEST_MPART_NAME(http2_parser, forwarded, 2),
		  TEST_MPART_NAME(http2_parser, forwarded, 3));

#undef EXPECT_BLOCK_REQ_H2_FORWARDED
#undef FOR_REQ_H2_FORWARDED

TEST(http2_parser, tfh)
{
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 3);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 0);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("a"), VALUE("aa")));
		HEADER(WO_IND(NAME("aa"), VALUE("aaa")));
		HEADER(WO_IND(NAME("aaa"), VALUE("aaaa")));
		HEADER(WO_IND(NAME("aaaa"), VALUE("aaaaa")));
		HEADER(WO_IND(NAME("aaaaa"), VALUE("aaaaaa")));
		HEADER(WO_IND(NAME("aaaaaa"), VALUE("aaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaa"), VALUE("aaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaa"), VALUE("aaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaa"), VALUE("aaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaa"), VALUE("aaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaa"), VALUE("aaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("aaaaaaaaaaaaaaaaaaaaaa"), VALUE("aaaaaaaaaaaaaaaaaaaaaaa")));
		HEADER(WO_IND(NAME("b"), VALUE("bb")));
		HEADER(WO_IND(NAME("bb"), VALUE("bbb")));
		HEADER(WO_IND(NAME("bbb"), VALUE("bbbb")));
		HEADER(WO_IND(NAME("bbbb"), VALUE("bbbbb")));
		HEADER(WO_IND(NAME("bbbbb"), VALUE("bbbbbb")));
		HEADER(WO_IND(NAME("bbbbbb"), VALUE("bbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbb"), VALUE("bbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbb"), VALUE("bbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbb"), VALUE("bbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbb"), VALUE("bbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbb"), VALUE("bbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("bbbbbbbbbbbbbbbbbbbbbb"), VALUE("bbbbbbbbbbbbbbbbbbbbbbb")));
		HEADER(WO_IND(NAME("c"), VALUE("cc")));
		HEADER(WO_IND(NAME("cc"), VALUE("ccc")));
		HEADER(WO_IND(NAME("ccc"), VALUE("cccc")));
		HEADER(WO_IND(NAME("cccc"), VALUE("ccccc")));
		HEADER(WO_IND(NAME("ccccc"), VALUE("cccccc")));
		HEADER(WO_IND(NAME("cccccc"), VALUE("ccccccc")));
		HEADER(WO_IND(NAME("ccccccc"), VALUE("cccccccc")));
		HEADER(WO_IND(NAME("cccccccc"), VALUE("ccccccccc")));
		HEADER(WO_IND(NAME("ccccccccc"), VALUE("cccccccccc")));
		HEADER(WO_IND(NAME("cccccccccc"), VALUE("ccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccc"), VALUE("cccccccccccc")));
		HEADER(WO_IND(NAME("cccccccccccc"), VALUE("ccccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccccc"), VALUE("cccccccccccccc")));
		HEADER(WO_IND(NAME("cccccccccccccc"), VALUE("ccccccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccccccc"), VALUE("cccccccccccccccc")));
		HEADER(WO_IND(NAME("cccccccccccccccc"), VALUE("ccccccccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccccccccc"), VALUE("cccccccccccccccccc")));
		HEADER(WO_IND(NAME("cccccccccccccccccc"), VALUE("ccccccccccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccccccccccc"), VALUE("cccccccccccccccccccc")));
		HEADER(WO_IND(NAME("cccccccccccccccccccc"), VALUE("ccccccccccccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccccccccccccc"), VALUE("cccccccccccccccccccccc")));
		HEADER(WO_IND(NAME("cccccccccccccccccccccc"), VALUE("ccccccccccccccccccccccc")));
		HEADER(WO_IND(NAME("ccccccccccccccccccccccc"), VALUE("cccccccccccccccccccccccc")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 63);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 0);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("referer"), VALUE("http://tempesta-tech.com:8080")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 1);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 4);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 0);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("cookie"), VALUE("a=b")));
		HEADER(WO_IND(NAME("cookie"), VALUE("c=d")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 5);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 2);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("cookie"), VALUE("a=b; c=d")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 4);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 2);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("cookie"), VALUE("a=b; c=d")));
		HEADER(WO_IND(NAME("cookie"), VALUE("a=aa; q=qq")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 5);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 4);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/filename")));
		HEADER(WO_IND(NAME("cookie"), VALUE("a=b; c=d; d=e; e=k; k=q")));
		HEADER(WO_IND(NAME("cookie"), VALUE("a=aa; q=qq; r=rr; l=ll")));
		HEADER(WO_IND(NAME("cookie"), VALUE("aa=a; qq=q; rr=r; ll=l")));
		HEADER(WO_IND(NAME("cookie"), VALUE("zz=z; yy=y; uu=u; oo=o")));
		HEADER(WO_IND(NAME("cookie"), VALUE("z=zz; y=yy; u=uu; o=oo")));
		HEADER(WO_IND(NAME("cookie"), VALUE("t=tt; i=ii; p=pp; x=xx")));
		HEADER(WO_IND(NAME("cookie"), VALUE("tt=t; ii=i; pp=p; xx=x")));
		HEADER(WO_IND(NAME("cookie"), VALUE("ttt=t; iii=i; ppp=p; xxx=x")));
		HEADER(WO_IND(NAME("cookie"), VALUE("tttt=t; iiii=i; pppp=p; xxxx=x")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ((unsigned)req->tfh.has_referer, 0);
		EXPECT_EQ((unsigned)req->tfh.headers_num, 12);
		EXPECT_EQ((unsigned)req->tfh.cookie_num, 31);
	}
}

TEST(http2_parser, expect)
{
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("expect"), VALUE("100-continue")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(WO_IND(NAME(":method"), VALUE("GET")));
		HEADER(WO_IND(NAME(":scheme"), VALUE("https")));
		HEADER(WO_IND(NAME(":path"), VALUE("/")));
		HEADER(WO_IND(NAME("expect"), VALUE("invalid")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* Expect = "invalid" */
		HEADER(INC_IND(INDEX(35), VALUE("invalid")));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* Expect = "100-continue" */
		HEADER(INC_IND(INDEX(35), VALUE("100-continue")));
	    HEADERS_FRAME_END();
	);
}

TEST_SUITE_MPART(http2_parser, 0)
{
	TEST_RUN(http2_parser, short_name);
	TEST_RUN(http2_parser, http2_check_important_fields);
	TEST_RUN(http2_parser, parses_req_method);
	TEST_RUN(http2_parser, parses_req_uri);
}

TEST_SUITE_MPART(http2_parser, 1)
{
	TEST_RUN(http2_parser, mangled_messages);
	TEST_RUN(http2_parser, header_prefix_confusion);
	TEST_RUN(http2_parser, alphabets);
	TEST_RUN(http2_parser, fills_hdr_tbl_for_req);
	TEST_MPART_RUN(http2_parser, cache_control);
}

TEST_SUITE_MPART(http2_parser, 2)
{
	TEST_RUN(http2_parser, suspicious_x_forwarded_for);
	TEST_MPART_RUN(http2_parser, content_type_in_bodyless_requests);
	TEST_RUN(http2_parser, content_length);
}

TEST_SUITE_MPART(http2_parser, 3)
{
	TEST_RUN(http2_parser, ows);
	TEST_MPART_RUN(http2_parser, accept);
}

TEST_SUITE_MPART(http2_parser, 4)
{
	TEST_MPART_RUN(http2_parser, host);
	TEST_RUN(http2_parser, cookie);
	TEST_RUN(http2_parser, if_none_match);
	TEST_RUN(http2_parser, referer);
	TEST_RUN(http2_parser, content_encoding);
	TEST_RUN(http2_parser, content_type_line_parser);
	TEST_RUN(http2_parser, xff);
	TEST_RUN(http2_parser, te);
}

TEST_SUITE_MPART(http2_parser, 5)
{
	TEST_MPART_RUN(http2_parser, date_format);
	TEST_RUN(http2_parser, date_ranges);
	TEST_MPART_RUN(http2_parser, date_day);
	TEST_RUN(http2_parser, date_year);
}

TEST_SUITE_MPART(http2_parser, 6)
{
	TEST_RUN(http2_parser, date_month);
	TEST_RUN(http2_parser, date_hour);
	TEST_RUN(http2_parser, date_minute);
	TEST_RUN(http2_parser, date_second);
	TEST_RUN(http2_parser, date);
}

TEST_SUITE_MPART(http2_parser, 7)
{
	TEST_RUN(http2_parser, method_override);
	TEST_RUN(http2_parser, vchar);
	TEST_RUN(http2_parser, fuzzer);
	TEST_MPART_RUN(http2_parser, forwarded);

	/*
	 * Testing for correctness of redirection mark parsing (in
	 * extended enforced mode of 'http_sessions' module).
	 */
	TEST_RUN(http2_parser, parses_enforce_ext_req);

	TEST_RUN(http2_parser, perf);
}

TEST_SUITE_MPART(http2_parser, 8)
{
	TEST_RUN(http2_parser, tfh);
	TEST_RUN(http2_parser, expect);
}

TEST_SUITE_MPART_DEFINE(http2_parser, H2_SUITE_PART_CNT,
	TEST_SUITE_MPART_NAME(http2_parser, 0),
	TEST_SUITE_MPART_NAME(http2_parser, 1),
	TEST_SUITE_MPART_NAME(http2_parser, 2),
	TEST_SUITE_MPART_NAME(http2_parser, 3),
	TEST_SUITE_MPART_NAME(http2_parser, 4),
	TEST_SUITE_MPART_NAME(http2_parser, 5),
	TEST_SUITE_MPART_NAME(http2_parser, 6),
	TEST_SUITE_MPART_NAME(http2_parser, 7),
	TEST_SUITE_MPART_NAME(http2_parser, 8));

