/**
 *		Tempesta FW
 *
 * Copyright (C) 2023-2025 Tempesta Technologies, Inc.
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
#include "helpers.h"
#include "http_msg.h"
#include "helpers.h"

static TfwHttpResp *resp;
static TfwHttpReq *req;

static void
http_msg_suite_setup(void)
{
	req = test_req_alloc(0);
	BUG_ON(!req);
	resp = test_resp_alloc_no_data(req);
	BUG_ON(!resp);
}

static void
http_msg_suite_teardown(void)
{
	test_resp_free(resp);
	test_req_free(req);
}

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

static bool
__test_resp_data_alloc(TfwStr *head_data, TfwStr *paged_data,
		       unsigned short nr_frags)
{
	TfwMsgIter *it;
	struct sk_buff *skb;
	struct page *page;
	char *addr;
	int i;

	skb = ss_skb_alloc(head_data->len);
	if (!skb)
		return false;

	ss_skb_set_owner(skb, tfw_http_msg_client((TfwHttpMsg*)resp));
	skb->next = skb->prev = skb;
	it = &resp->iter;
	resp->msg.skb_head = it->skb = it->skb_head = skb;
	it->frag = -1;

	skb_put_data(skb, head_data->data, head_data->len);

	if (nr_frags == 0)
		return true;

	page = alloc_page(GFP_ATOMIC);
	if (!page)
		return false;

	addr = page_address(page);
	memcpy(addr, paged_data->data, paged_data->len);

	for (i = 0; i < nr_frags; ++i) {
		skb_fill_page_desc(skb, i, page, 0, paged_data->len);
		get_page(page);
		ss_skb_adjust_data_len(skb, paged_data->len);
	}

	put_page(page);

	return true;
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
	TfwHttpMsgCleanup cleanup = {};
	TfwMsgIter *it;
	int i;

	EXPECT_TRUE(__test_resp_data_alloc(head, pgd, 1));

	it = &resp->iter;
	resp->body.data = skb_frag_address(&skb_shinfo(it->skb)->frags[0]);

	EXPECT_EQ(tfw_http_msg_cutoff_headers((TfwHttpMsg* )resp, &cleanup), 0);

	/* Linear part MUST be moved to paged fragments */
	EXPECT_TRUE(!skb_headlen(it->skb));
	EXPECT_NULL(cleanup.skb_head);

	for (i = 0; i < ARRAY_SIZE(expected_frags); i++) {
		skb_frag_t *frag = &skb_shinfo(it->skb)->frags[i];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, expected_frags[i].data, fragsz));
	}
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
	TfwHttpMsgCleanup cleanup = {};
	TfwMsgIter *it;
	int i;

	EXPECT_TRUE(__test_resp_data_alloc(head, pgd, 1));

	it = &resp->iter;
	resp->body.data = it->skb->data + SLEN("headers");

	EXPECT_EQ(tfw_http_msg_cutoff_headers((TfwHttpMsg* )resp, &cleanup), 0);

	/* Linear part MUST be moved to paged fragments */
	EXPECT_TRUE(!skb_headlen(it->skb));
	EXPECT_NULL(cleanup.skb_head);

	for (i = 0; i < ARRAY_SIZE(expected_frags); i++) {
		skb_frag_t *frag = &skb_shinfo(it->skb)->frags[i];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, expected_frags[i].data, fragsz));
	}
}

TEST(http_msg, expand_from_pool_for_headers)
{
	static TfwStr frags[] = {
		TFW_STR_STRING("headers"),
		TFW_STR_STRING("paged_body")
	};
	TfwStr *hdr = &frags[0], *head = &frags[0], *pgd = &frags[1];
	TfwHttpMsg *msg = (TfwHttpMsg *)resp;
	TfwHttpMsgCleanup cleanup = {};
	TfwMsgIter *it;
	int i;

	EXPECT_TRUE(__test_resp_data_alloc(head, pgd, MAX_SKB_FRAGS - 1));

	it = &resp->iter;
	set_bit(TFW_HTTP_B_CHUNKED, resp->flags);
	resp->body.data = skb_frag_address(&skb_shinfo(it->skb)->frags[0]);
	resp->body_start_data = skb_frag_address(&skb_shinfo(it->skb)->frags[0]);
	resp->body_start_skb = it->skb;
	resp->body.len = (MAX_SKB_FRAGS - 1) * SLEN("paged_body");

	tfw_http_msg_setup_transform_pool(&resp->mit, msg, resp->pool);

	EXPECT_EQ(tfw_http_msg_cutoff_headers(msg, &cleanup), 0);

	/* Linear part MUST be moved to paged fragments */
	EXPECT_TRUE(!skb_headlen(it->skb));
	EXPECT_NULL(cleanup.skb_head);

	EXPECT_EQ(tfw_http_msg_expand_from_pool(msg, hdr), 0);
	EXPECT_EQ(tfw_http_msg_expand_from_pool(msg, hdr), 0);
	EXPECT_EQ(tfw_http_msg_expand_from_pool(msg, hdr), 0);
	EXPECT_EQ(tfw_http_msg_expand_from_pool(msg, hdr), 0);

	EXPECT_TRUE(resp->msg.skb_head != resp->msg.skb_head->next);
	EXPECT_TRUE(resp->msg.skb_head->next->next == resp->msg.skb_head);

	{
		skb_frag_t *frag = &skb_shinfo(resp->msg.skb_head)->frags[0];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, "headersheadersheadersheaders", fragsz));
	}

	for (i = 0; i < MAX_SKB_FRAGS - 1; i++) {
		skb_frag_t *frag = &skb_shinfo(resp->msg.skb_head->next)->frags[i];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, pgd->data, fragsz));
	}
}

TEST(http_msg, expand_from_pool_for_trailers)
{
	static TfwStr frags[] = {
		TFW_STR_STRING("trailers"),
		TFW_STR_STRING("headers"),
		TFW_STR_STRING("paged_body")
	};
	TfwStr *trailer = &frags[0], *head = &frags[1], *pgd = &frags[2];
	TfwHttpMsg *msg = (TfwHttpMsg *)resp;
	TfwHttpMsgCleanup cleanup = {};
	TfwMsgIter *it;
	int i;

	EXPECT_TRUE(__test_resp_data_alloc(head, pgd, MAX_SKB_FRAGS - 1));

	it = &resp->iter;
	set_bit(TFW_HTTP_B_CHUNKED, resp->flags);
	resp->body.data = skb_frag_address(&skb_shinfo(it->skb)->frags[0]);
	resp->body_start_data = skb_frag_address(&skb_shinfo(it->skb)->frags[0]);
	resp->body_start_skb = it->skb;
	resp->body.len = (MAX_SKB_FRAGS - 1) * SLEN("paged_body");

	EXPECT_EQ(tfw_http_msg_cutoff_headers(msg, &cleanup), 0);

	/* Linear part MUST be moved to paged fragments */
	EXPECT_TRUE(!skb_headlen(it->skb));
	EXPECT_NULL(cleanup.skb_head);

	it->frag = skb_shinfo(it->skb)->nr_frags - 1;
	tfw_http_msg_setup_transform_pool(&resp->mit, msg, resp->pool);

	__set_bit(TFW_HTTP_B_RESP_ENCODE_TRAILERS, resp->flags);

	EXPECT_EQ(tfw_http_msg_expand_from_pool(msg, trailer), 0);
	EXPECT_EQ(tfw_http_msg_expand_from_pool(msg, trailer), 0);

	clear_bit(TFW_HTTP_B_RESP_ENCODE_TRAILERS, resp->flags);

	for (i = 0; i < MAX_SKB_FRAGS - 1; i++) {
		skb_frag_t *frag = &skb_shinfo(resp->msg.skb_head)->frags[i];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, pgd->data, fragsz));
	}

	EXPECT_TRUE(resp->msg.skb_head != resp->msg.skb_head->next);
	EXPECT_TRUE(resp->msg.skb_head->next->next == resp->msg.skb_head);
	EXPECT_EQ(skb_shinfo(resp->msg.skb_head->next)->nr_frags, 1);

	{
		skb_frag_t *frag = &skb_shinfo(resp->msg.skb_head->next)->frags[0];
		char* addr = skb_frag_address(frag);
		unsigned int fragsz = skb_frag_size(frag);

		EXPECT_ZERO(memcmp(addr, "trailerstrailers", fragsz));
	}
}

TEST_SUITE(http_msg)
{
	TEST_SETUP(http_msg_suite_setup);
	TEST_TEARDOWN(http_msg_suite_teardown);

	TEST_RUN(http_msg, hdr_in_array);
	TEST_RUN(http_msg, cutoff_linear_headers_paged_body);
	TEST_RUN(http_msg, cutoff_linear_headers_and_linear_body);
	TEST_RUN(http_msg, expand_from_pool_for_headers);
	TEST_RUN(http_msg, expand_from_pool_for_trailers);
}
