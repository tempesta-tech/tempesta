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


#define DYN_TBL_START_INDEX 62

static unsigned int dyn_tbl_total_cnt_inc_indexes = 0;

#define GET_INC_IND_TOTAL_CNT() \
	({dyn_tbl_total_cnt_inc_indexes;})

#define SET_INC_IND_TOTAL_CNT(value) \
	({dyn_tbl_total_cnt_inc_indexes = value;})

#define DYN_IND(entry_seq_no) \
	INDEX(DYN_TBL_START_INDEX + dyn_tbl_total_cnt_inc_indexes - entry_seq_no)

#define EXPECT_TFWSTR_EQ_H_TBL(index, name, value) \
	EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[index], name value)

TEST(http2_parser_hpack, static_table_all_indexes_for_req)
{
	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_EQ(req->method, TFW_HTTP_METH_GET);
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_H2_SCHEME],
				 ":scheme" "https");
		EXPECT_TFWSTR_EQ(&req->uri_path, "/");
	}

//	EXPECT_BLOCK_REQ_H2_HPACK(	// TODO: must be fixed in [#1614]
//	    HEADERS_FRAME_BEGIN();
//		// :method = "GET"
//		HEADER(INDEX(2));
//		// :scheme = "http"
//		HEADER(INDEX(6));
//		// :path = "/"
//		HEADER(INDEX(4));
//	    HEADERS_FRAME_END();
//	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/index.html"
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
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/index.html"
		HEADER(INDEX(5));
		// content-length = "1"
		HEADER(WO_IND(INDEX(28), VALUE("1")));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "POST"
		HEADER(INDEX(3));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
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
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// :authority = "localhost"
		HEADER(WO_IND(INDEX(1), VALUE("localhost")));
		// accept-charset = "utf-8"
		HEADER(WO_IND(INDEX(15), VALUE("utf-8")));
		// accept-encoding = "gzip, deflate"
		HEADER(INDEX(16));
		// accept-language = "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5"
		HEADER(WO_IND(
		    INDEX(17),
		    VALUE("fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5")));
		// accept = "*/*"
		HEADER(WO_IND(INDEX(19), VALUE("*/*")));
		// age = "13"
		HEADER(WO_IND(INDEX(21), VALUE("13")));
		// authorization = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		HEADER(WO_IND(
		    INDEX(23),
		    VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
		// cache-control = "max-age=1, no-store, min-fresh=30"
		HEADER(WO_IND(
		    INDEX(24),
		    VALUE("max-age=1, no-store, min-fresh=30")));
		// cookie = "session=42; theme=dark"
		HEADER(WO_IND(INDEX(32), VALUE("session=42; theme=dark")));
		// from = "webmaster@example.org"
		HEADER(WO_IND(INDEX(37), VALUE("webmaster@example.org")));
		// host = "developer.mozilla.org:5588"
		HEADER(WO_IND(INDEX(38), VALUE("developer.mozilla.org:5588")));
		// if-match = "\"67ab43\", \"54ed21\", \"7892dd\""
		HEADER(WO_IND(
		    INDEX(39),
		    VALUE("\"67ab43\", \"54ed21\", \"7892dd\"")));
		// if-modified-since = "Inv, 31 Jan 2012 15:02:53"
		HEADER(WO_IND(INDEX(40), VALUE("Inv, 31 Jan 2012 15:02:53 GMT")));
		// if-range = "Wed, 21 Oct 2015 07:28:00 GMT"
		HEADER(WO_IND(INDEX(42), VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
		 // if-unmodified-since = "Inv, 31 Jan 2012 15:02:55"
		HEADER(WO_IND(INDEX(43), VALUE("Tue, 21 Oct 2015 17:28:00 GMT")));
		// link = "<https://example.com>; rel=\"preconnect\""
		HEADER(WO_IND(
		    INDEX(45),
		    VALUE("<https://example.com>; rel=\"preconnect\"")));
		// max-forwards = "24"
		HEADER(WO_IND(INDEX(47), VALUE("24")));
		// proxy-authorization = "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
		HEADER(WO_IND(INDEX(49), VALUE("Basic YWxhZGRpbjpvcGVuc2VzYW1l")));
		// range = "bytes=200-1000, 2000-6576, 19000-"
		HEADER(WO_IND(
		    INDEX(50),
		    VALUE("bytes=200-1000, 2000-6576, 19000-")));
		// referer = "https://example.com/page?q=123"
		HEADER(WO_IND(INDEX(51), VALUE("https://example.com/page?q=123")));
		// user-agent = "Wget/1.13.4 (linux-gnu)"
		HEADER(WO_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
		// via = "1.0 fred, 1.1 p.example.net"
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
		// :method = "POST"
		HEADER(INDEX(3));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// content-length = "7"
		HEADER(WO_IND(INDEX(28), VALUE("7")));
		// content-type = "text/plain"
		HEADER(WO_IND(INDEX(31), VALUE("text/plain")));
		// expect = "100-continue"
		HEADER(WO_IND(INDEX(35), VALUE("100-continue")));
		 // if-none-match = "\"xyzzy\""
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

TEST(http2_parser_hpack, increment_all_static_indexes_for_req)
{
	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INC_IND(INDEX(7), VALUE("https")));
		// :path = "/"
		HEADER(INC_IND(INDEX(4), VALUE("/")));
		// :authority = "localhost"
		HEADER(INC_IND(INDEX(1), VALUE("localhost")));
		// accept-charset = "utf-8"
		HEADER(INC_IND(INDEX(15), VALUE("utf-8")));
		// accept-encoding = "gzip, deflate"
		HEADER(INC_IND(INDEX(16), VALUE("gzip, deflate")));
		// accept-language = "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5"
		HEADER(INC_IND(
		    INDEX(17),
		    VALUE("fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5")));
		// accept = "*/*"
		HEADER(INC_IND(INDEX(19), VALUE("*/*")));
		// age = "13"
		HEADER(INC_IND(INDEX(21), VALUE("13")));
		// authorization = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		HEADER(INC_IND(
		    INDEX(23),
		    VALUE("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")));
		// cache-control = "max-age=1, no-store, min-fresh=30"
		HEADER(INC_IND(
		    INDEX(24),
		    VALUE("max-age=1, no-store, min-fresh=30")));
		// cookie = "session=42; theme=dark"
		HEADER(INC_IND(INDEX(32), VALUE("session=42; theme=dark")));
		// from = "webmaster@example.org"
		HEADER(INC_IND(INDEX(37), VALUE("webmaster@example.org")));
		// host = "developer.mozilla.org:5588"
		HEADER(INC_IND(INDEX(38), VALUE("developer.mozilla.org:5588")));
		// if-match = "\"67ab43\", \"54ed21\", \"7892dd\""
		HEADER(INC_IND(
		    INDEX(39),
		    VALUE("\"67ab43\", \"54ed21\", \"7892dd\"")));
		// if-modified-since = "Inv, 31 Jan 2012 15:02:53"
		HEADER(INC_IND(INDEX(40), VALUE("Inv, 31 Jan 2012 15:02:53 GMT")));
		// if-range = "Wed, 21 Oct 2015 07:28:00 GMT"
		HEADER(INC_IND(INDEX(42), VALUE("Wed, 21 Oct 2015 07:28:00 GMT")));
		 // if-unmodified-since = "Inv, 31 Jan 2012 15:02:55"
		HEADER(INC_IND(INDEX(43), VALUE("Tue, 21 Oct 2015 17:28:00 GMT")));
		// link = "<https://example.com>; rel=\"preconnect\""
		HEADER(INC_IND(
		    INDEX(45),
		    VALUE("<https://example.com>; rel=\"preconnect\"")));
		// max-forwards = "24"
		HEADER(INC_IND(INDEX(47), VALUE("24")));
		// proxy-authorization = "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
		HEADER(INC_IND(INDEX(49), VALUE("Basic YWxhZGRpbjpvcGVuc2VzYW1l")));
		// range = "bytes=200-1000, 2000-6576, 19000-"
		HEADER(INC_IND(
		    INDEX(50),
		    VALUE("bytes=200-1000, 2000-6576, 19000-")));
		// referer = "https://example.com/page?q=123"
		HEADER(INC_IND(INDEX(51), VALUE("https://example.com/page?q=123")));
		// user-agent = "Wget/1.13.4 (linux-gnu)"
		HEADER(INC_IND(INDEX(58), VALUE("Wget/1.13.4 (linux-gnu)")));
		// via = "1.0 fred, 1.1 p.example.net"
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

	SET_INC_IND_TOTAL_CNT(24);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(DYN_IND(1));
		// :path = "/"
		HEADER(DYN_IND(2));
		// :authority = "localhost"
		HEADER(DYN_IND(3));
		// accept-charset = "utf-8"
		HEADER(DYN_IND(4));
		// accept-encoding = "gzip, deflate"
		HEADER(DYN_IND(5));
		// accept-language = "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5"
		HEADER(DYN_IND(6));
		// accept = "*/*"
		HEADER(DYN_IND(7));
		// age = "13"
		HEADER(DYN_IND(8));
		// authorization = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
		HEADER(DYN_IND(9));
		// cache-control = "max-age=1, no-store, min-fresh=30"
		HEADER(DYN_IND(10));
		// cookie = "session=42; theme=dark"
		HEADER(DYN_IND(11));
		// from = "webmaster@example.org"
		HEADER(DYN_IND(12));
		// host = "developer.mozilla.org:5588"
		HEADER(DYN_IND(13));
		// if-match = "\"67ab43\", \"54ed21\", \"7892dd\""
		HEADER(DYN_IND(14));
		// if-modified-since = "Inv, 31 Jan 2012 15:02:53"
		HEADER(DYN_IND(15));
		// if-range = "Wed, 21 Oct 2015 07:28:00 GMT"
		HEADER(DYN_IND(16));
		 // if-unmodified-since = "Inv, 31 Jan 2012 15:02:55"
		HEADER(DYN_IND(17));
		// link = "<https://example.com>; rel=\"preconnect\""
		HEADER(DYN_IND(18));
		// max-forwards = "24"
		HEADER(DYN_IND(19));
		// proxy-authorization = "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
		HEADER(DYN_IND(20));
		// range = "bytes=200-1000, 2000-6576, 19000-"
		HEADER(DYN_IND(21));
		// referer = "https://example.com/page?q=123"
		HEADER(DYN_IND(22));
		// user-agent = "Wget/1.13.4 (linux-gnu)"
		HEADER(DYN_IND(23));
		// via = "1.0 fred, 1.1 p.example.net"
		HEADER(DYN_IND(24));
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
//		EXPECT_EQ(req->host_port, 5588);			// TODO: must be fixed in [#1617]
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 8],
				 "if-match"
				 "\"67ab43\", \"54ed21\", \"7892dd\"");
		EXPECT_TFWSTR_EQ(&req->h_tbl->tbl[TFW_HTTP_HDR_RAW + 9],
				 "if-modified-since"
				 "Inv, 31 Jan 2012 15:02:53 GMT");
//		EXPECT_TRUE(req->cond.m_date == 1328022173);		// TODO: must be fixed in [#1617]
//		EXPECT_TRUE(req->cond.flags & TFW_HTTP_COND_IF_MSINCE);	// TODO: must be fixed in [#1617]
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

TEST(http2_parser_hpack, not_existed_indexes)
{
	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// not existed index
		HEADER(INDEX(DYN_TBL_START_INDEX));
	    HEADERS_FRAME_END();
	);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// dummy = "super123"
		HEADER(INC_IND(NAME("dummy"), VALUE("super123")));
	    HEADERS_FRAME_END();
	)
	{
		EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_RAW, "dummy", "super123");
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// dummy = "super123"
		HEADER(INDEX(DYN_TBL_START_INDEX));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_RAW, "dummy", "super123");
	}

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// not existed index
		HEADER(INDEX(DYN_TBL_START_INDEX + 1));
	    HEADERS_FRAME_END();
	);
}

TEST(http2_parser_hpack, erase_all_indexes)
{
	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// :authority = "localhost"
		HEADER(INC_IND(NAME(":authority"), VALUE("localhost")));
		// dummy = "super123"
		HEADER(INC_IND(NAME("dummy"), VALUE("super123")));
		// user-agent = "Wget/1.13.4 (linux-gnu)"
		HEADER(INC_IND(NAME("user-agent"), VALUE("Wget/1.13.4 (linux-gnu)")));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_H2_AUTHORITY, ":authority", "localhost");
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_RAW, "dummy", "super123");
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_USER_AGENT, "user-agent", "Wget/1.13.4 (linux-gnu)");
	}

	SET_INC_IND_TOTAL_CNT(3);

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// :authority = "localhost"
		HEADER(DYN_IND(1));
		// dummy = "super123"
		HEADER(DYN_IND(2));
		// user-agent = "Wget/1.13.4 (linux-gnu)"
		HEADER(DYN_IND(3));
	    HEADERS_FRAME_END();
	)
	{
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_H2_AUTHORITY, ":authority", "localhost");
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_RAW, "dummy", "super123");
	    EXPECT_TFWSTR_EQ_H_TBL(TFW_HTTP_HDR_USER_AGENT, "user-agent", "Wget/1.13.4 (linux-gnu)");
	}

	FOR_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// erase all entries from dynamic table
		HEADER(SZ_UPD(0));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// :authority = "localhost" - already not exists
		HEADER(DYN_IND(1));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// dummy = "super123" - already not exists
		HEADER(DYN_IND(2));
	    HEADERS_FRAME_END();
	);

	EXPECT_BLOCK_REQ_H2_HPACK(
	    HEADERS_FRAME_BEGIN();
		// :method = "GET"
		HEADER(INDEX(2));
		// :scheme = "https"
		HEADER(INDEX(7));
		// :path = "/"
		HEADER(INDEX(4));
		// user-agent = "Wget/1.13.4 (linux-gnu)" - already not exists
		HEADER(DYN_IND(3));
	    HEADERS_FRAME_END();
	);
}

TEST_SUITE(http2_parser_hpack)
{
	TEST_SETUP(test_case_parse_prepare_h2);

	TEST_RUN(http2_parser_hpack, static_table_all_indexes_for_req);
	TEST_RUN(http2_parser_hpack, increment_all_static_indexes_for_req);
	TEST_RUN(http2_parser_hpack, not_existed_indexes);
	TEST_RUN(http2_parser_hpack, erase_all_indexes);
}
