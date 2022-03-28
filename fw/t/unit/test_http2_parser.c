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
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("http"));
		HEADER(STR(":path"), STR("/filename"));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
		HEADER(STR("Authorization"),
			    STR("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
		HEADER(STR("Cache-Control"),
			    STR("max-age=1, dummy, no-store, min-fresh=30"));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
		HEADER(STR("connection"), STR("Keep-Alive"));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser, parses_req_method)
{
#define TEST_REQ_METHOD(METHOD)							\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR(#METHOD));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define TEST_REQ_UNKNOWN(METHOD)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR(#METHOD));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
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
		HEADER(STR(":method"), STR(""));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
	    HEADERS_FRAME_END();
	);

	/* Malformed methods */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("\tOST"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
	    HEADERS_FRAME_END();
	);
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("P\tST"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
	    HEADERS_FRAME_END();
	);
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("PO\tT"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
	    HEADERS_FRAME_END();
	);
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("POS\t"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser, parses_req_uri)
{
#define TEST_URI_PATH(req_uri_path)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("GET"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR(req_uri_path));			\
	    HEADERS_FRAME_END();						\
	)									\
	{									\
		EXPECT_TFWSTR_EQ(&req->host, "");				\
		EXPECT_TFWSTR_EQ(&req->uri_path, req_uri_path);			\
	}

#define TEST_FULL_REQ(req_host, req_uri_path)					\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("GET"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR(req_uri_path));			\
		HEADER(STR(":authority"), STR(req_host));			\
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
		HEADER(STR(":method"), STR("OPTIONS"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("*"));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("\x7f"));
		HEADER(STR(":authority"), STR("test"));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/\x03uri"));
		HEADER(STR(":authority"), STR("test"));
	    HEADERS_FRAME_END();
	);


#undef TEST_FULL_REQ
#undef TEST_URI_PATH
}

TEST(http2_parser, parses_enforce_ext_req)
{
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/index.html"));
		HEADER(STR("x-forwarded-for"), STR("127.0.0.1"));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->uri_path, "/index.html");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("natsys-lab.com"));
		HEADER(STR("user-agent"), STR("Wget/1.13.4 (linux-gnu)"));
		HEADER(STR("accept"), STR("*/*"));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, "natsys-lab.com");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/cgi-bin/show.pl"));
		HEADER(STR(":authority"), STR("natsys-lab.com:8080"));
		HEADER(STR("cookie"), STR("session=42"));
		HEADER(STR("accept"), STR("*/*"));
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
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_1));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_1);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_2));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_2);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_3));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_3);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_4));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_4);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_1));
		HEADER(STR(":authority"), STR(HOST ":" PORT));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_1);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_3));
		HEADER(STR(":authority"), STR(HOST ":" PORT));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_3);
	}

	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK URI_4));
		HEADER(STR(":authority"), STR(HOST ":" PORT));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ(&req->host, HOST ":" PORT);
		EXPECT_TFWSTR_EQ(&req->mark, RMARK);
		EXPECT_TFWSTR_EQ(&req->uri_path, URI_4);
	}

	/* Wrong RMARK formats. */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(ATT_NO HMAC URI_1));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/" RMARK_NAME "=" URI_1));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR(RMARK HMAC URI_1));
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
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":method"), STR("POST"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("test"));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("test"));
		HEADER(STR("\x1fX-Foo"), STR("test"));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("test"));
		HEADER(STR("connection"), STR("close, \"foo\""));
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
		HEADER(STR(":method"), STR("PUT"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("test"));
		/* We don't match open and closing quotes. */
		HEADER(STR("content-type"), STR("Text/HTML;Charset=utf-8\"\t  "));
		HEADER(STR("pragma"), STR("no-cache, fooo "));
	    HEADERS_FRAME_END();
	);

	/* Trailing SP in request. */
	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("PUT"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("localhost"));
		HEADER(STR("user-agent"), STR("Wget/1.13.4 (linux-gnu)\t  "));
		HEADER(STR("accept"), STR("*/*\t "));
		HEADER(STR("x-custom-hdr"), STR("custom header values \t  "));
		HEADER(STR("x-forwarded-for"), STR("127.0.0.1, example.com    \t "));
		HEADER(STR("content-type"), STR("text/html; charset=iso-8859-1  \t "));
		HEADER(STR("cache-control"), STR("max-age=0, private, min-fresh=42 \t "));
//		HEADER(STR("cookie"), STR("session=42; theme=dark  \t "));	// TODO
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
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(STR(":authority"), STR("localhost"));
		HEADER(STR("user-agent"), STR("Wget/1.13.4 (linux-gnu)"));
		HEADER(STR("accept"), STR("*/*"));
		HEADER(STR("x-custom-hdr"), STR("custom header values"));
		HEADER(STR("x-forwarded-for"), STR("127.0.0.1, example.com"));
		HEADER(STR("Dummy0"), STR("0"));
		HEADER(STR("Dummy1"), STR("1"));
		HEADER(STR("Dummy2"), STR("2"));
		HEADER(STR("Dummy3"), STR("3"));
		HEADER(STR("Dummy4"), STR("4"));
		HEADER(STR("Dummy5"), STR("5"));
		HEADER(STR("Dummy6"), STR("6"));
		/* That is done to check table reallocation. */
		HEADER(STR("Dummy7"), STR("7"));
		HEADER(STR("Dummy8"), STR("8"));
		HEADER(STR("Dummy9"), STR("9"));
		HEADER(STR("cache-control"), STR("max-age=1, dummy, no-store, min-fresh=30"));
		HEADER(STR("pragma"), STR("no-cache, fooo "));
		HEADER(STR("cookie"), STR("session=42; theme=dark"));
		HEADER(STR("authorization"), STR("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t "));
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
		HEADER(STR(":method"), STR("GET"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/"));					\
		HEADER(STR("cache-control"), STR(cache_control));		\
	    HEADERS_FRAME_END();						\
	);

#define FOR_REQ_H2_CC(cache_control)						\
	FOR_REQ_H2(								\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("GET"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/"));					\
		HEADER(STR("cache-control"), STR(cache_control));		\
	    HEADERS_FRAME_END();						\
	)

//	EXPECT_BLOCK_REQ_H2_CC("");	// TODO
	EXPECT_BLOCK_REQ_H2_CC(" ");
	EXPECT_BLOCK_REQ_H2_CC("no-cache no-store");
	EXPECT_BLOCK_REQ_H2_CC("dummy0 dummy1");
	EXPECT_BLOCK_REQ_H2_CC(",,");


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
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
		HEADER(STR(":method"), STR("GET"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/"));					\
		HEADER(STR("x-forwarded-for"), STR(x_forwarded_for));		\
	    HEADERS_FRAME_END();						\
	);


	FOR_REQ_H2(
	    HEADERS_FRAME_BEGIN();
		HEADER(STR(":method"), STR("GET"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/"));
		HEADER(
		    STR("x-forwarded-for"),
		    STR("   [::1]:1234,5.6.7.8   ,  natsys-lab.com:65535  "));
	    HEADERS_FRAME_END();
	)
	{
		const TfwStr *h = &req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR];
		EXPECT_GT(h->len, 0);
	}

	EXPECT_BLOCK_REQ_H2_XFF("1.2.3.4, , 5.6.7.8");
	EXPECT_BLOCK_REQ_H2_XFF("foo!");
//	EXPECT_BLOCK_REQ_H2_XFF(""); // TODO
}

TEST(http2_parser, content_type_in_bodyless_requests)
{
#define EXPECT_BLOCK_BODYLESS_REQ_H2(METHOD)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR(#METHOD));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-length"), STR("0"));			\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR(#METHOD));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-type"), STR("text/plain"));			\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(METHOD)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("PUT"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-length"), STR("0"));			\
		HEADER(STR("x-method-override"), STR(#METHOD));			\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("PUT"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-type"), STR("text/plain"));			\
		HEADER(STR("x-method-override"), STR(#METHOD));			\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("PUT"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-length"), STR("0"));			\
		HEADER(STR("x-http-method-override"), STR(#METHOD));		\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("PUT"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-type"), STR("text/plain"));			\
		HEADER(STR("x-http-method-override"), STR(#METHOD));		\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("PUT"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-length"), STR("0"));			\
		HEADER(STR("x-http-method"), STR(#METHOD));			\
	    HEADERS_FRAME_END();						\
	);									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME_BEGIN();						\
		HEADER(STR(":method"), STR("PUT"));				\
		HEADER(STR(":scheme"), STR("https"));				\
		HEADER(STR(":path"), STR("/filename"));				\
		HEADER(STR("content-type"), STR("text/plain"));			\
		HEADER(STR("x-http-method"), STR(#METHOD));			\
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
		HEADER(STR(":method"), STR("OPTIONS"));
		HEADER(STR(":scheme"), STR("https"));
		HEADER(STR(":path"), STR("/filename"));
		HEADER(STR("content-type"), STR("text/plain"));
	    HEADERS_FRAME_END();
	);


#undef EXPECT_BLOCK_BODYLESS_REQ_H2
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2
}

TEST_SUITE(http2_parser)
{
//	TEST_RUN(http2_parser, http2_check_important_fields);
//	TEST_RUN(http2_parser, parses_req_method);
//	TEST_RUN(http2_parser, parses_req_uri);
//	TEST_RUN(http2_parser, mangled_messages);
//	TEST_RUN(http2_parser, alphabets);
//	TEST_RUN(http2_parser, fills_hdr_tbl_for_req);
//	TEST_RUN(http2_parser, cache_control);
//	TEST_RUN(http2_parser, suspicious_x_forwarded_for);
//	TEST_RUN(http2_parser, content_type_in_bodyless_requests);

	/*
	 * Testing for correctness of redirection mark parsing (in
	 * extended enforced mode of 'http_sessions' module).
	 */
	tfw_http_sess_redir_mark_enable();

//	TEST_RUN(http2_parser, parses_enforce_ext_req);
//	TEST_RUN(http2_parser, parses_enforce_ext_req_rmark);

	tfw_http_sess_redir_mark_disable();
}
