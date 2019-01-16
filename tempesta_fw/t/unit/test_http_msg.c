/**
 *		Tempesta FW
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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


#include "test.h"
#include "http_msg.h"

TEST(http_msg, hdr_in_array)
{
	size_t i;
#define TfwStr_string(v)	{ .data = (v), NULL, sizeof(v) - 1, 0 }
	static const TfwStr hdrs[] = {
		TfwStr_string("age:"),
		TfwStr_string("authorization:"),
		TfwStr_string("cache-control:"),
		TfwStr_string("connection:"),
		TfwStr_string("content-length:"),
		TfwStr_string("content-type:"),
		TfwStr_string("cookie:"),
		TfwStr_string("date:"),
		TfwStr_string("etag:"),
		TfwStr_string("expires:"),
		TfwStr_string("from:"),
		TfwStr_string("host:"),
		TfwStr_string("if-unmodified-since:"),
		TfwStr_string("last-modified:"),
		TfwStr_string("location:"),
		TfwStr_string("pragma:"),
		TfwStr_string("proxy-authorization:"),
		TfwStr_string("referer:"),
		TfwStr_string("server:"),
		TfwStr_string("transfer-encoding:"),
		TfwStr_string("user-agent:"),
		TfwStr_string("vary:"),
		TfwStr_string("x-forwarded-for:"),
	};
	static const TfwStr o_hdrs[] = {
		TfwStr_string("keep-alive:"),
		TfwStr_string("max-forwards:"),
		TfwStr_string("content-location:"),
	};
#define S_PART_01	"cache-control: no-cache"
#define S_PART_02	"cache-control: no-store"
	TfwStr dup_hdr = {
		.chunks = (TfwStr []){
			TfwStr_string(S_PART_01),
			TfwStr_string(S_PART_01),
		},
		.len = SLEN(S_PART_01 S_PART_02),
		.nchunks = 2,
		.flags = TFW_STR_DUPLICATE,
	};
#undef TfwStr_string
#undef S_PART_01
#undef S_PART_02

	for (i = 0; i < ARRAY_SIZE(hdrs); ++i) {
		const TfwStr *h = &hdrs[i];

		EXPECT_NOT_NULL(tfw_http_msg_find_hdr(h, hdrs));
	};
	for (i = 0; i < ARRAY_SIZE(o_hdrs); ++i) {
		const TfwStr *h = &o_hdrs[i];

		EXPECT_NULL(tfw_http_msg_find_hdr(h, hdrs));
	};

	/* Duplicated string */
	EXPECT_NOT_NULL(tfw_http_msg_find_hdr(&dup_hdr, hdrs));
}

TEST_SUITE(http_msg)
{
	TEST_RUN(http_msg, hdr_in_array);
}
