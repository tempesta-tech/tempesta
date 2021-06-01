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
	static const TfwStr hdrs[] = {
		TFW_STR_STRING("age:"),
		TFW_STR_STRING("authorization:"),
		TFW_STR_STRING("cache-control:"),
		TFW_STR_STRING("connection:"),
		TFW_STR_STRING("content-length:"),
		TFW_STR_STRING("content-type:"),
		TFW_STR_STRING("cookie:"),
		TFW_STR_STRING("date:"),
		TFW_STR_STRING("etag:"),
		TFW_STR_STRING("expires:"),
		TFW_STR_STRING("from:"),
		TFW_STR_STRING("host:"),
		TFW_STR_STRING("if-unmodified-since:"),
		TFW_STR_STRING("last-modified:"),
		TFW_STR_STRING("location:"),
		TFW_STR_STRING("pragma:"),
		TFW_STR_STRING("proxy-authorization:"),
		TFW_STR_STRING("referer:"),
		TFW_STR_STRING("server:"),
		TFW_STR_STRING("transfer-encoding:"),
		TFW_STR_STRING("user-agent:"),
		TFW_STR_STRING("vary:"),
		TFW_STR_STRING("x-forwarded-for:"),
	};
	static const TfwStr o_hdrs[] = {
		TFW_STR_STRING("keep-alive:"),
		TFW_STR_STRING("max-forwards:"),
		TFW_STR_STRING("content-location:"),
	};
#define S_PART_01	"cache-control: no-cache"
#define S_PART_02	"cache-control: no-store"
	TfwStr dup_hdr = {
		.chunks = (TfwStr []){
			TFW_STR_STRING(S_PART_01),
			TFW_STR_STRING(S_PART_01),
		},
		.len = SLEN(S_PART_01 S_PART_02),
		.nchunks = 2,
		.flags = TFW_STR_DUPLICATE,
	};
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
