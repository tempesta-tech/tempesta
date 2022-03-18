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

TEST(http2_parser, content_type_in_bodyless_requests)
{
#define EXPECT_BLOCK_BODYLESS_REQ_H2(METHOD)				\
	EXPECT_BLOCK_REQ_H2(":method: "#METHOD"\n"			\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0");			\
	EXPECT_BLOCK_REQ_H2(":method: "#METHOD"\n"			\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain");

#define EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(METHOD)			\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0\n"			\
			    "x-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0\n"			\
			    "x-http-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-length: 0\n"			\
			    "x-http-method: "#METHOD);			\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain\n"		\
			    "x-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain\n"		\
			    "x-http-method-override: "#METHOD);		\
	EXPECT_BLOCK_REQ_H2(":method: PUT\n"				\
			    ":scheme: https\n"				\
			    ":path: /\n"				\
			    "content-type: text/plain\n"		\
			    "x-http-method: "#METHOD);


	EXPECT_BLOCK_BODYLESS_REQ_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_H2(TRACE);

	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(GET);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(HEAD);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(DELETE);
	EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2(TRACE);

	FOR_REQ_H2(":method: OPTIONS\n"
		   ":scheme: https\n"
		   ":path: /\n"
		   "content-type: text/plain");


#undef EXPECT_BLOCK_BODYLESS_REQ_H2
#undef EXPECT_BLOCK_BODYLESS_REQ_OVERRIDE_H2
}

TEST(http2_parser, http2_check_important_fields)
{
	EXPECT_BLOCK_REQ_H2(":method: GET\n"
			    ":scheme: http\n"
			    ":path: /");

	FOR_REQ_H2(":method: GET\n"
		   ":scheme: https\n"
		   ":path: /\n"
		   "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n"
		   "Cache-Control: max-age=1, dummy, no-store, min-fresh=30");

	EXPECT_BLOCK_REQ_H2(":method: GET\n"
			    ":scheme: https\n"
			    ":path: /\n"
			    "connection: Keep-Alive");
}

TEST_SUITE(http2_parser)
{
	TEST_RUN(http2_parser, content_type_in_bodyless_requests);
	TEST_RUN(http2_parser, http2_check_important_fields);
}
