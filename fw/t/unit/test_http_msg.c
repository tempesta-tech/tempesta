/**
 *		Tempesta FW
 *
 * Copyright (C) 2023 Tempesta Technologies, Inc.
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

static TfwHttpResp *
__test_resp_alloc(TfwStr *head_data, TfwStr *paged_data,
		  unsigned short nr_frags)
{
	TfwMsgIter *it;
	TfwHttpResp *hmresp;
	struct sk_buff *skb;
	struct page *page;
	char *addr;
	int i;

	hmresp = (TfwHttpResp *)__tfw_http_msg_alloc(Conn_HttpSrv, true);
	BUG_ON(!hmresp);

	skb = ss_skb_alloc(head_data->len);
	if (!skb)
		return NULL;

	skb->next = skb->prev = skb;
	it = &hmresp->mit.iter;
	it->skb = it->skb_head = skb;
	it->frag = -1;

	skb_put_data(skb, head_data->data, head_data->len);

	if (nr_frags == 0)
		return hmresp;

	page = alloc_page(GFP_ATOMIC);
	if (!page) {
		kfree_skb(skb);
		return NULL;
	}

	addr = page_address(page);
	memcpy(addr, paged_data->data, paged_data->len);

	for (i = 0; i < nr_frags; ++i) {
		skb_fill_page_desc(skb, i, page, 0, paged_data->len);
		ss_skb_adjust_data_len(skb, paged_data->len);
	}

	return hmresp;
}

/*
 * Tests to chdeck that skb has no linear data after
 * call `tfw_h2_msg_cutoff_headers`
 */
TEST(http_msg, cutoff_linear_headers_paged_body)
{
	static TfwStr frags[] = {
		TFW_STR_STRING("headers"),
		TFW_STR_STRING("paged_body")
	};
	static TfwStr expected_frags[] = {
		TFW_STR_STRING("paged_body")
	};
	TfwStr *head = &frags[0], *pgd = &frags[1];
	TfwHttpResp *resp = __test_resp_alloc(head, pgd, 1);
	TfwHttpRespCleanup cleanup = {};
	TfwMsgIter *it;
	int i;

	EXPECT_NOT_NULL(resp);
	if (!resp)
		return;

	it = &resp->mit.iter;
	resp->body.data = skb_frag_address(&skb_shinfo(it->skb)->frags[0]);

	EXPECT_EQ(tfw_h2_msg_cutoff_headers(resp, &cleanup), 0);

	/* Linear part MUST be moved to paged fragments */
	EXPECT_TRUE(!skb_headlen(it->skb));
	EXPECT_NULL(cleanup.skb_head);

	for (i = 0; i < ARRAY_SIZE(expected_frags); i++) {
		skb_frag_t *frag = &skb_shinfo(it->skb)->frags[i];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, expected_frags[i].data, fragsz));
	}

	tfw_http_msg_free((TfwHttpMsg *)resp);
}

TEST(http_msg, cutoff_linear_headers_and_linear_body)
{
	static TfwStr frags[] = {
		TFW_STR_STRING("headerspaged_body1"),
		TFW_STR_STRING("paged_body2")
	};
	static TfwStr expected_frags[] = {
		TFW_STR_STRING("paged_body1"),
		TFW_STR_STRING("paged_body2")
	};
	TfwStr *head = &frags[0], *pgd = &frags[1];
	TfwHttpResp *resp = __test_resp_alloc(head, pgd, 1);
	TfwHttpRespCleanup cleanup = {};
	TfwMsgIter *it;
	int i;

	EXPECT_NOT_NULL(resp);
	if (!resp)
		return;

	it = &resp->mit.iter;
	resp->body.data = it->skb->data + SLEN("headers");

	EXPECT_EQ(tfw_h2_msg_cutoff_headers(resp, &cleanup), 0);

	/* Linear part MUST be moved to paged fragments */
	EXPECT_TRUE(!skb_headlen(it->skb));
	EXPECT_NULL(cleanup.skb_head);

	for (i = 0; i < ARRAY_SIZE(expected_frags); i++) {
		skb_frag_t *frag = &skb_shinfo(it->skb)->frags[i];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, expected_frags[i].data, fragsz));
	}

	tfw_http_msg_free((TfwHttpMsg *)resp);
}

TEST_SUITE(http_msg)
{
	TEST_RUN(http_msg, hdr_in_array);
	TEST_RUN(http_msg, cutoff_linear_headers_paged_body);
	TEST_RUN(http_msg, cutoff_linear_headers_and_linear_body);
}
