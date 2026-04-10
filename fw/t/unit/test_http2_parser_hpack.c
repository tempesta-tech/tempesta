/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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

#define STATIC_TBL_LAST_INDEX 61
#define DYN_TBL_FIRST_INDEX 62

#define DYN_TBL_INDEX(index)							\
({										\
	BUG_ON((index) < 1);							\
	INDEX(STATIC_TBL_LAST_INDEX + (index));					\
})

#define EXPECT_H_TBL_TFW_STR_EMPTY(h_tbl_index) \
	EXPECT_TRUE(TFW_STR_EMPTY(&req->h_tbl->tbl[h_tbl_index]))

#define EXPECT_H_TBL_TFWSTR_EQ(h_tbl_index, expected) \
	EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[h_tbl_index], expected)

#define EXPECT_H_TBL_TFWSTR_DUP_EQ(h_tbl_index, dup_no, expected)		\
do {										\
	const TfwStr *str = &req->h_tbl->tbl[h_tbl_index];			\
	BUG_ON(!TFW_STR_DUP(str));						\
	EXPECT_TFWSTR_EQ(TFW_STR_CHUNK(str, dup_no), expected);			\
} while (0)

#define HPACK_ENTRY_OVERHEAD		32

#define DYN_TBL_ENTRY_SZ(data) \
	(strlen(data) + HPACK_ENTRY_OVERHEAD)

TEST(http2_parser_hpack, literal_header_field_with_incremental_indexing)
{
	const char *s_dummy = "dummy" "super123";

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INC_IND(INDEX(DYN_TBL_FIRST_INDEX), VALUE("FooBoo")));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(INC_IND(NAME("dummy"), VALUE("super123")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(INC_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 0);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT,
				       "user-agent" "Wget/1.13.4 (linux-gnu)");
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 0);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT,
				       "user-agent" "Wget/1.13.4 (linux-gnu)");
	}
}

TEST(http2_parser_hpack, literal_header_field_without_indexing)
{
	const char *s_dummy = "dummy" "super123";

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(WO_IND(INDEX(DYN_TBL_FIRST_INDEX), VALUE("FooBoo")));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(WO_IND(NAME("dummy"), VALUE("super123")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(WO_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 0);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT,
				       "user-agent" "Wget/1.13.4 (linux-gnu)");
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser_hpack, literal_header_field_never_indexed)
{
	const char *s_dummy = "dummy" "super123";

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(NEV_IND(INDEX(DYN_TBL_FIRST_INDEX), VALUE("FooBoo")));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(NEV_IND(NAME("dummy"), VALUE("super123")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(NEV_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 0);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT,
				       "user-agent" "Wget/1.13.4 (linux-gnu)");
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser_hpack, not_existed_indexes)
{
	const char *s_dummy = "dummy" "super123";

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(INC_IND(NAME("dummy"), VALUE("super123")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
		EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* not existed index */
		HEADER(INDEX(DYN_TBL_FIRST_INDEX + 1));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser_hpack, static_table_all_indexes_for_request)
{
	FOR_REQ_H2_HPACK(
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

	FOR_REQ_H2_HPACK(
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

	EXPECT_BLOCK_REQ_H2_HPACK(
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

	FOR_REQ_H2_HPACK(
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

	FOR_REQ_H2_HPACK(
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

	FOR_REQ_H2_HPACK(
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
		/* refresh = "5; url=https://example.com" */
		HEADER(WO_IND(INDEX(52), VALUE("5; url=https://example.com")));
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
			     "refresh" "5; url=https://example.com");
	    EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_IF_NONE_MATCH],
			     "if-none-match" "\"xyzzy\"");
	}
}

TEST(http2_parser_hpack, increment_all_static_indexes_for_request)
{
	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INC_IND(INDEX(7), VALUE("https")));
		/* :path = "/" */
		HEADER(INC_IND(INDEX(4), VALUE("/")));
		/* :authority = "localhost" */
		HEADER(INC_IND(INDEX(1), VALUE("localhost")));
		/* accept-charset = "utf-8" */
		HEADER(INC_IND(INDEX(15), VALUE("utf-8")));
		/* accept-encoding = "gzip, deflate" */
		HEADER(INC_IND(INDEX(16), VALUE("gzip, deflate")));
		/* accept-language = "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5" */
		HEADER(INC_IND(
		    INDEX(17),
		    VALUE("fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5")));
		/* accept = "*\/\*" */
		HEADER(INC_IND(INDEX(19), VALUE("*/*")));
		/* age = "13" */
		HEADER(INC_IND(INDEX(21), VALUE("13")));
		/* authorization = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" */
		HEADER(INC_IND(
		    INDEX(23),
		    VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
		/* cache-control = "max-age=1, no-store, min-fresh=30" */
		HEADER(INC_IND(
		    INDEX(24),
		    VALUE("max-age=1, no-store, min-fresh=30")));
		/* cookie = "session=42; theme=dark" */
		HEADER(INC_IND(INDEX(32), VALUE("session=42; theme=dark")));
		/* from = "webmaster@example.org" */
		HEADER(INC_IND(INDEX(37), VALUE("webmaster@example.org")));
		/* host = "developer.mozilla.org:5588" */
		HEADER(INC_IND(INDEX(38), VALUE("developer.mozilla.org:5588")));
		/* if-match = "\"67ab43\", \"54ed21\", \"7892dd\"" */
		HEADER(INC_IND(
		    INDEX(39),
		    VALUE("\"67ab43\", \"54ed21\", \"7892dd\"")));
		/* if-modified-since = "Inv, 31 Jan 2012 15:02:53" */
		HEADER(INC_IND(INDEX(40), VALUE("Inv, 31 Jan 2012 15:02:53 GMT")));
		/* if-range = "Wed, 21 Oct 2015 07:28:00 GMT" */
		HEADER(INC_IND(INDEX(42), VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
		/* if-unmodified-since = "Inv, 31 Jan 2012 15:02:55" */
		HEADER(INC_IND(INDEX(43), VALUE("Tue, 21 Oct 2015 17:28:00 GMT")));
		/* link = "<https://example.com>; rel=\"preconnect\"" */
		HEADER(INC_IND(
		    INDEX(45),
		    VALUE("<https://example.com>; rel=\"preconnect\"")));
		/* max-forwards = "24" */
		HEADER(INC_IND(INDEX(47), VALUE("24")));
		/* proxy-authorization = "Basic YWxhZGRpbjpvcGVuc2VzYW1l" */
		HEADER(INC_IND(INDEX(49), VALUE("Basic YWxhZGRpbjpvcGVuc2VzYW1l")));
		/* range = "bytes=200-1000, 2000-6576, 19000-" */
		HEADER(INC_IND(
		    INDEX(50),
		    VALUE("bytes=200-1000, 2000-6576, 19000-")));
		/* referer = "https://example.com/page?q=123" */
		HEADER(INC_IND(INDEX(51), VALUE("https://example.com/page?q=123")));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(INC_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
		/* via = "1.0 fred, 1.1 p.example.net" */
		HEADER(INC_IND(INDEX(60), VALUE("1.0 fred, 1.1 p.example.net")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 17);
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_PATH],
				 ":path" "/");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY],
				 ":authority" "localhost");
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

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(DYN_TBL_INDEX(24));
		/* :path = "/" */
		HEADER(DYN_TBL_INDEX(23));
		/* :authority = "localhost" */
		HEADER(DYN_TBL_INDEX(22));
		/* accept-charset = "utf-8" */
		HEADER(DYN_TBL_INDEX(21));
		/* accept-encoding = "gzip, deflate" */
		HEADER(DYN_TBL_INDEX(20));
		/* accept-language = "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5" */
		HEADER(DYN_TBL_INDEX(19));
		/* accept = "*\/\*" */
		HEADER(DYN_TBL_INDEX(18));
		/* age = "13" */
		HEADER(DYN_TBL_INDEX(17));
		/* authorization = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" */
		HEADER(DYN_TBL_INDEX(16));
		/* cache-control = "max-age=1, no-store, min-fresh=30" */
		HEADER(DYN_TBL_INDEX(15));
		/* cookie = "session=42; theme=dark" */
		HEADER(DYN_TBL_INDEX(14));
		/* from = "webmaster@example.org" */
		HEADER(DYN_TBL_INDEX(13));
		/* host = "developer.mozilla.org:5588" */
		HEADER(DYN_TBL_INDEX(12));
		/* if-match = "\"67ab43\", \"54ed21\", \"7892dd\"" */
		HEADER(DYN_TBL_INDEX(11));
		/* if-modified-since = "Inv, 31 Jan 2012 15:02:53" */
		HEADER(DYN_TBL_INDEX(10));
		/* if-range = "Wed, 21 Oct 2015 07:28:00 GMT" */
		HEADER(DYN_TBL_INDEX(9));
		/* if-unmodified-since = "Inv, 31 Jan 2012 15:02:55" */
		HEADER(DYN_TBL_INDEX(8));
		/* link = "<https://example.com>; rel=\"preconnect\"" */
		HEADER(DYN_TBL_INDEX(7));
		/* max-forwards = "24" */
		HEADER(DYN_TBL_INDEX(6));
		/* proxy-authorization = "Basic YWxhZGRpbjpvcGVuc2VzYW1l" */
		HEADER(DYN_TBL_INDEX(5));
		/* range = "bytes=200-1000, 2000-6576, 19000-" */
		HEADER(DYN_TBL_INDEX(4));
		/* referer = "https://example.com/page?q=123" */
		HEADER(DYN_TBL_INDEX(3));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(DYN_TBL_INDEX(2));
		/* via = "1.0 fred, 1.1 p.example.net" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 17);
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_PATH],
				 ":path" "/");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY],
				 ":authority" "localhost");
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
}

TEST(http2_parser_hpack, erase_all_indexes)
{
	const char *s_authority = ":authority" "localhost";
	const char *s_dummy = "dummy" "super123";
	const char *s_user_agent = "user-agent" "Wget/1.13.4 (linux-gnu)";

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" */
		HEADER(INC_IND(NAME(":authority"), VALUE("localhost")));
		/* dummy = "super123" */
		HEADER(INC_IND(NAME("dummy"), VALUE("super123")));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(INC_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_H2_AUTHORITY, s_authority);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy = "super123" */
		HEADER(DYN_TBL_INDEX(2));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_H2_AUTHORITY, s_authority);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* erase all entries from dynamic table */
		HEADER(SZ_UPD(0));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
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
		/* :authority = "localhost" - already not exists */
		HEADER(DYN_TBL_INDEX(3));
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
		/* dummy = "super123" - already not exists */
		HEADER(DYN_TBL_INDEX(2));
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
		/* user-agent = "Wget/1.13.4 (linux-gnu)" - already not exists */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser_hpack, erase_indexes_one_by_one)
{
	const char *s_authority = ":authority" "localhost";
	const char *s_dummy = "dummy" "super123";
	const char *s_user_agent = "user-agent" "Wget/1.13.4 (linux-gnu)";

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" */
		HEADER(INC_IND(NAME(":authority"), VALUE("localhost")));
		/* dummy = "super123" */
		HEADER(INC_IND(NAME("dummy"), VALUE("super123")));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(INC_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_H2_AUTHORITY, s_authority);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy = "super123" */
		HEADER(DYN_TBL_INDEX(2));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_H2_AUTHORITY, s_authority);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* dynamic table fits to indexes size */
		HEADER(SZ_UPD(DYN_TBL_ENTRY_SZ(s_authority)
			    + DYN_TBL_ENTRY_SZ(s_dummy)
			    + DYN_TBL_ENTRY_SZ(s_user_agent)));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy = "super123" */
		HEADER(DYN_TBL_INDEX(2));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_H2_AUTHORITY, s_authority);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* erase one index from the end of dynamic table */
		HEADER(SZ_UPD(DYN_TBL_ENTRY_SZ(s_dummy)
			    + DYN_TBL_ENTRY_SZ(s_user_agent)));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" */
		HEADER(DYN_TBL_INDEX(2));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFW_STR_EMPTY(TFW_HTTP_HDR_H2_AUTHORITY);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW, s_dummy);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* :authority = "localhost" - not existed index */
		HEADER(DYN_TBL_INDEX(3));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* erase one index from the end of dynamic table */
		HEADER(SZ_UPD(DYN_TBL_ENTRY_SZ(s_user_agent)));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* user-agent = "Wget/1.13.4 (linux-gnu)" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 0);
	    EXPECT_H_TBL_TFW_STR_EMPTY(TFW_HTTP_HDR_H2_AUTHORITY);
	    EXPECT_H_TBL_TFW_STR_EMPTY(TFW_HTTP_HDR_RAW);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_USER_AGENT, s_user_agent);
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy = "super123" -  not existed index */
		HEADER(DYN_TBL_INDEX(2));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* erase all indexes */
		HEADER(SZ_UPD(0));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
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
		/* user-agent = "Wget/1.13.4 (linux-gnu)" - not existed index */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser_hpack, eviction_of_indexes)
{
	const char *s_dummy1 = "dummy1" "Luper1";
	const char *s_dummy2 = "dummy2" "pUper2";
	const char *s_dummy3 = "dummy3" "zuPer3";
	const char *s_dummy4 = "dummy4" "fupEr4";
	const char *s_dummy5 = "dummy5" "supeR5";

	BUG_ON(strlen(s_dummy1) != strlen(s_dummy2));
	BUG_ON(strlen(s_dummy1) != strlen(s_dummy3));
	BUG_ON(strlen(s_dummy1) != strlen(s_dummy4));
	BUG_ON(strlen(s_dummy1) != strlen(s_dummy5));

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(INC_IND(NAME("dummy1"), VALUE("Luper1")));
		/* dummy2 = "pUper2" */
		HEADER(INC_IND(NAME("dummy2"), VALUE("pUper2")));
		/* dummy3 = "zuPer3" */
		HEADER(INC_IND(NAME("dummy3"), VALUE("zuPer3")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* dynamic table fits to indexes size */
		HEADER(SZ_UPD(DYN_TBL_ENTRY_SZ(s_dummy1)
			    + DYN_TBL_ENTRY_SZ(s_dummy2)
			    + DYN_TBL_ENTRY_SZ(s_dummy3)));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(1));
		/*
		 * dummy4 = "fupEr4" */
		HEADER(INC_IND(NAME("dummy4"), VALUE("fupEr4")));
		/* [dummy1 = "Luper1"] was pushed out
		 * from below by [dummy4 = "fupEr4"]
		*/
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy4 = "fupEr4" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 4);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 0, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 2, 0, s_dummy3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 2, 1, s_dummy3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 3, 0, s_dummy4);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 3, 1, s_dummy4);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy4 = "fupEr4" */
		HEADER(DYN_TBL_INDEX(1));
		/*
		 * dummy5 = "supeR5" */
		HEADER(INC_IND(NAME("dummy5"), VALUE("supeR5")));
		/* [dummy2 = "pUper1"] was pushed out
		 * from below by [dummy5 = "supeR5"]
		*/
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy4 = "fupEr4" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy5 = "supeR5" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 4);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 0, s_dummy3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 1, s_dummy3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 2, 0, s_dummy4);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 2, 1, s_dummy4);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 3, 0, s_dummy5);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 3, 1, s_dummy5);
	}
}

TEST(http2_parser_hpack, dup_with_equal_values_in_indexes)
{
	const char *s_dummy1 = "dummy1" "Luper1";
	const char *s_dummy2 = "dummy2" "pUper2";
	const char *s_dummy3 = "dummy3" "zuPer3";

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(INC_IND(NAME("dummy1"), VALUE("Luper1")));
		/* dummy2 = "pUper2" */
		HEADER(INC_IND(NAME("dummy2"), VALUE("pUper2")));
		/* dummy3 = "zuPer3" */
		HEADER(INC_IND(NAME("dummy3"), VALUE("zuPer3")));
		/* dummy1 = "Luper1" - add duplicate with the same frame */
		HEADER(INC_IND(NAME("dummy1"), VALUE("Luper1")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 1, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy2 = "pUper2" - add duplicate with the other frame */
		HEADER(INC_IND(NAME("dummy2"), VALUE("pUper2")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy2);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(5));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(4));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 1, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 0, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(5));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(4));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(3));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy2);
	}
}

TEST(http2_parser_hpack, dup_with_diff_values_in_indexes)
{
	const char *s_dummy1_luper1 = "dummy1" "Luper1";
	const char *s_dummy1_luper2 = "dummy1" "Luper2";
	const char *s_dummy2_puper1 = "dummy2" "pUper1";
	const char *s_dummy2_puper2 = "dummy2" "pUper2";
	const char *s_dummy3 = "dummy3" "zuPer1";

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(INC_IND(NAME("dummy1"), VALUE("Luper1")));
		/* dummy2 = "pUper1" */
		HEADER(INC_IND(NAME("dummy2"), VALUE("pUper1")));
		/* dummy3 = "zuPer1" */
		HEADER(INC_IND(NAME("dummy3"), VALUE("zuPer1")));
		/* dummy1 = "Luper2" - add duplicate with the same frame */
		HEADER(INC_IND(NAME("dummy1"), VALUE("Luper2")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 0, s_dummy1_luper1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 1, s_dummy1_luper2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2_puper1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy2 = "pUper2" - add duplicate with the other frame */
		HEADER(INC_IND(NAME("dummy2"), VALUE("pUper2")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy2_puper2);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(5));
		/* dummy2 = "pUper1" */
		HEADER(DYN_TBL_INDEX(4));
		/* dummy3 = "zuPer1" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy1 = "Luper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 0, s_dummy1_luper1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 0, 1, s_dummy1_luper2);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 0, s_dummy2_puper1);
	    EXPECT_H_TBL_TFWSTR_DUP_EQ(TFW_HTTP_HDR_RAW + 1, 1, s_dummy2_puper2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(5));
		/* dummy2 = "pUper1" */
		HEADER(DYN_TBL_INDEX(4));
		/* dummy3 = "zuPer1" */
		HEADER(DYN_TBL_INDEX(3));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy1_luper1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2_puper1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy3 = "zuPer1" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy1 = "Luper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy1_luper2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy2_puper2);
	}
}

TEST(http2_parser_hpack, erased_indexes_not_come_back)
{
	const char *s_dummy1 = "dummy1" "Luper1";
	const char *s_dummy2 = "dummy2" "pUper2";
	const char *s_dummy3 = "dummy3" "zuPer3";

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(INC_IND(NAME("dummy1"), VALUE("Luper1")));
		/* dummy2 = "pUper2" */
		HEADER(INC_IND(NAME("dummy2"), VALUE("pUper2")));
		/* dummy3 = "zuPer3" */
		HEADER(INC_IND(NAME("dummy3"), VALUE("zuPer3")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy1 = "Luper1" */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 3);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy1);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 2, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* set dynamic table size little smaller than need */
		HEADER(SZ_UPD(DYN_TBL_ENTRY_SZ(s_dummy1)
			    + DYN_TBL_ENTRY_SZ(s_dummy2)
			    + DYN_TBL_ENTRY_SZ(s_dummy3) - 1));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
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
		/* dummy1 = "Luper1" - already not exists */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy3);
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* set dynamic table size to fit indexes size */
		HEADER(SZ_UPD(DYN_TBL_ENTRY_SZ(s_dummy1)
			    + DYN_TBL_ENTRY_SZ(s_dummy2)
			    + DYN_TBL_ENTRY_SZ(s_dummy3)));
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
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
		/* dummy1 = "Luper1" - still not exists */
		HEADER(DYN_TBL_INDEX(3));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		/* :method = "GET" */
		HEADER(INDEX(2));
		/* :scheme = "https" */
		HEADER(INDEX(7));
		/* :path = "/" */
		HEADER(INDEX(4));
		/* dummy2 = "pUper2" */
		HEADER(DYN_TBL_INDEX(2));
		/* dummy3 = "zuPer3" */
		HEADER(DYN_TBL_INDEX(1));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_EQ(req->h_tbl->off, TFW_HTTP_HDR_RAW + 2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 0, s_dummy2);
	    EXPECT_H_TBL_TFWSTR_EQ(TFW_HTTP_HDR_RAW + 1, s_dummy3);
	}
}

TEST_SUITE(http2_parser_hpack)
{
	TEST_SETUP(test_http2_parser_setup_fn);
	TEST_TEARDOWN(test_http2_parser_teardown_fn);

	TEST_RUN(http2_parser_hpack, literal_header_field_with_incremental_indexing);
	TEST_RUN(http2_parser_hpack, literal_header_field_without_indexing);
	TEST_RUN(http2_parser_hpack, literal_header_field_never_indexed);
	TEST_RUN(http2_parser_hpack, not_existed_indexes);
	TEST_RUN(http2_parser_hpack, static_table_all_indexes_for_request);
	TEST_RUN(http2_parser_hpack, increment_all_static_indexes_for_request);
	TEST_RUN(http2_parser_hpack, erase_all_indexes);
	TEST_RUN(http2_parser_hpack, erase_indexes_one_by_one);
	TEST_RUN(http2_parser_hpack, eviction_of_indexes);
	TEST_RUN(http2_parser_hpack, dup_with_equal_values_in_indexes);
	TEST_RUN(http2_parser_hpack, dup_with_diff_values_in_indexes);
	TEST_RUN(http2_parser_hpack, erased_indexes_not_come_back);
}
