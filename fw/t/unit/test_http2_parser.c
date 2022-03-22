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
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("GET")),
		HEADER(STR(":scheme"), STR("http")),
		HEADER(STR(":path"), STR("/filename"))
	));

	FOR_REQ_H2(
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("GET")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename")),
		HEADER(STR("Authorization"),
			    STR("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")),
		HEADER(STR("Cache-Control"),
			    STR("max-age=1, dummy, no-store, min-fresh=30"))
	));

	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("GET")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename")),
		HEADER(STR("connection"), STR("Keep-Alive"))
	));
}

TEST(http2_parser, parses_req_method)
{
#define TEST_REQ_METHOD(METHOD)						\
	FOR_REQ_H2(							\
	    HEADERS_FRAME(						\
		HEADER(STR(":method"), STR(#METHOD)),			\
		HEADER(STR(":scheme"), STR("https")),			\
		HEADER(STR(":path"), STR("/filename"))			\
	));								\
	{								\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);		\
	}

#define TEST_REQ_UNKNOWN(METHOD)					\
	FOR_REQ_H2(							\
	    HEADERS_FRAME(						\
		HEADER(STR(":method"), STR(#METHOD)),			\
		HEADER(STR(":scheme"), STR("https")),			\
		HEADER(STR(":path"), STR("/filename"))			\
	));								\
	{								\
		EXPECT_EQ(req->method, _TFW_HTTP_METH_UNKNOWN);		\
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
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename"))
	));

	/* Malformed methods */
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("\tOST")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename"))
	));
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("P\tST")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename"))
	));
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("PO\tT")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename"))
	));
	EXPECT_BLOCK_REQ_H2(
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("POS\t")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename"))
	));
}

TEST(http2_parser, content_type_in_bodyless_requests)
{
#define EXPECT_BLOCK_BODYLESS_REQ_H2(METHOD)					\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR(#METHOD)),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-length"), STR("0"))				\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR(#METHOD)),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-type"), STR("text/plain"))			\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_##METHOD);			\
	}

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(METHOD)				\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR("PUT")),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-length"), STR("0")),			\
		HEADER(STR("x-method-override"), STR(#METHOD))			\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR("PUT")),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-type"), STR("text/plain")),			\
		HEADER(STR("x-method-override"), STR(#METHOD))			\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR("PUT")),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-length"), STR("0")),			\
		HEADER(STR("x-http-method-override"), STR(#METHOD))		\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR("PUT")),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-type"), STR("text/plain")),			\
		HEADER(STR("x-http-method-override"), STR(#METHOD))		\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR("PUT")),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-length"), STR("0")),			\
		HEADER(STR("x-http-method"), STR(#METHOD))			\
	));									\
	{									\
		EXPECT_EQ(req->method, TFW_HTTP_METH_PUT);			\
		EXPECT_EQ(req->method_override, TFW_HTTP_METH_##METHOD);	\
	}									\
	EXPECT_BLOCK_REQ_H2(							\
	    HEADERS_FRAME(							\
		HEADER(STR(":method"), STR("PUT")),				\
		HEADER(STR(":scheme"), STR("https")),				\
		HEADER(STR(":path"), STR("/filename")),				\
		HEADER(STR("content-type"), STR("text/plain")),			\
		HEADER(STR("x-http-method"), STR(#METHOD))			\
	));									\
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
	    HEADERS_FRAME(
		HEADER(STR(":method"), STR("OPTIONS")),
		HEADER(STR(":scheme"), STR("https")),
		HEADER(STR(":path"), STR("/filename")),
		HEADER(STR("content-type"), STR("text/plain"))
	));


#undef EXPECT_BLOCK_BODYLESS_REQ_H2
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2
}

TEST_SUITE(http2_parser)
{
	TEST_RUN(http2_parser, http2_check_important_fields);
	TEST_RUN(http2_parser, parses_req_method);
	TEST_RUN(http2_parser, content_type_in_bodyless_requests);
}
