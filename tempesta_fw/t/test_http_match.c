/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#include "http_match.h"
#include "http_msg.h"

TfwMatchTbl *test_match_tbl;
TfwHttpReq *test_http_req;

static void
http_match_suite_setup(void)
{
	test_match_tbl = tfw_match_tbl_alloc();
	BUG_ON(!test_match_tbl);

	test_http_req = (TfwHttpReq *)tfw_http_msg_alloc(Conn_Clnt);
	BUG_ON(!test_http_req);
}

static void
http_match_suite_teardown(void)
{
	tfw_http_msg_free((TfwHttpMsg *)test_http_req);
	test_http_req = NULL;

	tfw_match_tbl_free(test_match_tbl);
	test_match_tbl = NULL;
}

TEST(tfw_match_tbl_rise, adds_rule_to_tbl)
{
	TfwMatchRule *rule;
	const TfwMatchRule r = {
		TFW_MATCH_SUBJ_METHOD, TFW_MATCH_OP_EQ,
		{ .method = TFW_HTTP_METH_GET }
	};

	EXPECT_EQ(0, test_match_tbl->rules_n);
	EXPECT_NULL(tfw_match_http_req(test_http_req, test_match_tbl));

	tfw_match_tbl_rise(&test_match_tbl, &rule, 0);
	*rule = r;
	test_http_req->method = TFW_HTTP_METH_GET;

	EXPECT_EQ(1, test_match_tbl->rules_n);
	EXPECT_NOT_NULL(tfw_match_http_req(test_http_req, test_match_tbl));
}

TEST(tfw_match_tbl_rise, expands_tbl_without_corruption)
{
	u8 pattern;
	int i, data_len, old_max, ret;
	TfwMatchRule *rule;

	/* Assume that initially rules_max > 1, so the loop below may do
	 * at least two iterations. */
	EXPECT_GT(test_match_tbl->rules_max, 1);

	/* Over-fill the table, so it should grow automatically. */
	old_max = test_match_tbl->rules_max;
	for (i = 0; i < (test_match_tbl->rules_max + 1); ++i) {
		pattern = i;
		data_len = i % 8;

		ret = tfw_match_tbl_rise(&test_match_tbl, &rule, data_len);
		EXPECT_EQ(0, ret);

		memset(rule, pattern, sizeof(*rule));
		memset(rule->arg.str.data, pattern, data_len);
	}
	EXPECT_EQ(old_max + 1, test_match_tbl->rules_n);
	EXPECT_LE(old_max, test_match_tbl->rules_max);

	/* Check that rules are still filled with their patterns, and thus:
	 *  - Allocated memory regions don't overlap.
	 *  - Data is preserved when the table is re-allocated (when it grows).
	 */
	for (i = 0; i < test_match_tbl->rules_n; ++i) {
		rule = test_match_tbl->rules[i];
		pattern = i;
		data_len = i % 8;

		EXPECT_NULL(memchr_inv(rule, pattern, sizeof(*rule)));
		EXPECT_NULL(memchr_inv(rule->arg.str.data, pattern, data_len));
	}
}

TEST(tfw_match_http_req, returns_first_matching_rule)
{
	const TfwMatchRule *match;
	TfwMatchRule *r1, *r2, *r3;

	tfw_match_tbl_rise(&test_match_tbl, &r1, 0);
	tfw_match_tbl_rise(&test_match_tbl, &r2, 0);
	tfw_match_tbl_rise(&test_match_tbl, &r3, 0);

	r1->subj = r2->subj = r3->subj = TFW_MATCH_SUBJ_METHOD;
	r1->op = r2->op = r3->op = TFW_MATCH_OP_EQ;

	r1->arg.method = TFW_HTTP_METH_POST;
	r2->arg.method = TFW_HTTP_METH_GET;
	r3->arg.method = TFW_HTTP_METH_GET;

	match = tfw_match_http_req(test_http_req, test_match_tbl);

	EXPECT_EQ(r2, match);
}

static void
add_str_rule(TfwMatchTbl **tbl, TfwMatchRule **rule,
             tfw_match_subj_t subj, tfw_match_op_t op, const char *str_arg)
{
	size_t len = strlen(str_arg);

	tfw_match_tbl_rise(tbl, rule, len);
	(*rule)->subj = subj;
	(*rule)->op = op;
	(*rule)->arg.str.len = len;
	memcpy((*rule)->arg.str.data, str_arg, len);
}

static void
set_tfw_str(TfwStr *str, const char *cstr)
{
	str->ptr = (void *)cstr;
	str->len = strlen(cstr);
}

TEST(http_match, uri_prefix)
{
	const TfwMatchRule *match;
	TfwMatchRule *r1, *r2, *r3;

	add_str_rule(&test_match_tbl, &r1,
	             TFW_MATCH_SUBJ_URI, TFW_MATCH_OP_PREFIX, "/foo/bar/baz");
	add_str_rule(&test_match_tbl, &r2,
	             TFW_MATCH_SUBJ_URI, TFW_MATCH_OP_PREFIX, "/foo/ba");
	add_str_rule(&test_match_tbl, &r3,
	             TFW_MATCH_SUBJ_URI, TFW_MATCH_OP_PREFIX, "/");

	set_tfw_str(&test_http_req->uri, "/foo/bar/baz.html");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_EQ(r1, match);

	set_tfw_str(&test_http_req->uri, "/FOO/BAR/");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_EQ(r2, match);

	set_tfw_str(&test_http_req->uri, "/baz");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_EQ(r3, match);

	set_tfw_str(&test_http_req->uri, "../foo");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_NULL(match);
}

TEST(http_match, host_eq)
{
	const TfwMatchRule *match;
	TfwMatchRule *r1, *r2, *r3;

	add_str_rule(&test_match_tbl, &r1,
	             TFW_MATCH_SUBJ_HOST, TFW_MATCH_OP_EQ, "www.natsys-lab.com");
	add_str_rule(&test_match_tbl, &r2,
	             TFW_MATCH_SUBJ_HOST, TFW_MATCH_OP_EQ, "natsys-lab");
	add_str_rule(&test_match_tbl, &r3,
	             TFW_MATCH_SUBJ_HOST, TFW_MATCH_OP_EQ, "NATSYS-LAB.COM");

	set_tfw_str(&test_http_req->host, "natsys-lab.com");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_EQ(r3, match);
}

TEST(http_match, headers_eq)
{
	const TfwMatchRule *match;
	TfwMatchRule *r1, *r2, *r3;

	add_str_rule(&test_match_tbl, &r1, TFW_MATCH_SUBJ_HEADERS,
	             TFW_MATCH_OP_EQ, "User-Agent: U880D/4.0 (CP/M; 8-bit)");
	add_str_rule(&test_match_tbl, &r2, TFW_MATCH_SUBJ_HEADERS,
	             TFW_MATCH_OP_EQ, "Connection: close");
	add_str_rule(&test_match_tbl, &r3, TFW_MATCH_SUBJ_HEADERS,
	             TFW_MATCH_OP_EQ, "Connection: Keep-Alive");

	set_tfw_str(&test_http_req->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION].field,
	            "Connection: Keep-Alive");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_EQ(r3, match);

	set_tfw_str(&test_http_req->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION].field,
	            "Connection: cLoSe");
	match = tfw_match_http_req(test_http_req, test_match_tbl);
	EXPECT_EQ(r2, match);
}

TEST_SUITE(http_match)
{
	TEST_SETUP(http_match_suite_setup);
	TEST_TEARDOWN(http_match_suite_teardown);

	TEST_RUN(tfw_match_tbl_rise, adds_rule_to_tbl);
	TEST_RUN(tfw_match_tbl_rise, expands_tbl_without_corruption);
	TEST_RUN(tfw_match_http_req, returns_first_matching_rule);

	TEST_RUN(http_match, uri_prefix);
	TEST_RUN(http_match, host_eq);
	TEST_RUN(http_match, headers_eq);
}
