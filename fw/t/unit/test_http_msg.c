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

/* Test replacing PURGE with GET method in HTTP/1 request */
TEST(http_msg, test_tfw_http_subst_purge_with_get)
{
	TfwHttpMsg *hm;
	struct sk_buff *skb = NULL;
	unsigned char *skb_data;
	size_t i,j;
	size_t len;
	int r;

	#define S_PURGE_FULL	"PURGE /index.html HTTP/1.1"

	#define S_PURGE_FRAG_01_01 "PURGE"
	#define S_PURGE_FRAG_01_02 " /index.html HTTP/1.1"

	#define S_PURGE_FRAG_02_01 "PUR"
	#define S_PURGE_FRAG_02_02 "GE /index.html HTTP/1.1"

	#define S_PURGE_FRAG_03_01 "PUR"
	#define S_PURGE_FRAG_03_02 "GE"
	#define S_PURGE_FRAG_03_03 " /index.html HTTP/1.1"

	#define S_PURGE_FRAG_04_01 "PU"
	#define S_PURGE_FRAG_04_02 "RGE"
	#define S_PURGE_FRAG_04_03 " /index.html HTTP/1.1"

	#define S_PURGE_FRAG_05_01 "PU"
	#define S_PURGE_FRAG_05_02 "RG"
	#define S_PURGE_FRAG_05_03 "E "
	#define S_PURGE_FRAG_05_04 "/index.html HTTP/1.1"

	const char *data[6][4] = {
		{S_PURGE_FULL, "", "", ""},
		{S_PURGE_FRAG_01_01, S_PURGE_FRAG_01_02, "", ""},
		{S_PURGE_FRAG_02_01, S_PURGE_FRAG_02_02, "", ""},
		{S_PURGE_FRAG_03_01, S_PURGE_FRAG_03_02, S_PURGE_FRAG_03_03, ""},
		{S_PURGE_FRAG_04_01, S_PURGE_FRAG_04_02, S_PURGE_FRAG_04_03, ""},
		{S_PURGE_FRAG_05_01, S_PURGE_FRAG_05_02, S_PURGE_FRAG_05_03,
			S_PURGE_FRAG_05_04}
	 };


	hm = kmalloc(sizeof(TfwHttpMsg), GFP_ATOMIC);
	EXPECT_NOT_NULL(hm);
	memset(hm, 0, sizeof(TfwHttpMsg));
	for (i=0; i<6; i++) {

		for(j=0; j<4; j++) {
			skb = alloc_skb(128, GFP_ATOMIC);
			EXPECT_NOT_NULL(skb);
			skb_reserve(skb, 64);

			len = strlen(data[i][j]);
			if (len > 0) {
				skb_data = skb_put(skb, len);
				EXPECT_NOT_NULL(skb_data);
				memcpy(skb_data, data[i][j], len);
			}
			ss_skb_queue_tail(&hm->msg.skb_head, skb);
		}

		T_WARN("Test: tfw_http_subst_purge_with_get [%lu]\n", i);
		r = tfw_http_subst_purge_with_get(hm);
		EXPECT_ZERO(r);

		/* purge skb */
		while ((skb = ss_skb_dequeue(&hm->msg.skb_head)) != NULL)
			kfree_skb(skb);
	}

	/* cleanup */
	kfree(hm);
}

TEST_SUITE(http_msg)
{
	TEST_RUN(http_msg, hdr_in_array);
	TEST_RUN(http_msg, test_tfw_http_subst_purge_with_get);
}
