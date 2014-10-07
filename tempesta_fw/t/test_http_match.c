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

static TfwMatchRule rule_host_eq_examplecom = {
	.subj = TFW_MATCH_SUBJ_HOST,
	.op = TFW_MATCH_OP_EQ,
	.arg = {
		.str = { 11, "example.com" }
	}
};

static TfwMatchRule rule_headers_eq_useragent = {
	.subj = TFW_MATCH_SUBJ_HEADERS,
	.op = TFW_MATCH_OP_PREFIX,
	.arg = {
		.str = { 23, "U880D/4.0 (CP/M; 8-bit)" }
	}
};

static TfwMatchRule rule_uri_prefix_foobar = {
	.subj = TFW_MATCH_SUBJ_URI,
	.op = TFW_MATCH_OP_PREFIX,
	.arg = {
		.str = { 8, "/foo/bar" }
	}
};

static TfwMatchRule rule_uri_prefix_root = {
	.subj = TFW_MATCH_SUBJ_URI,
	.op = TFW_MATCH_OP_PREFIX,
	.arg = {
		.str = { 1, "/" }
	}
};

/*
static TfwMatchTbl test_match_tbl = {
	.rules_max = 4,
	.rules_n = 4,
	.pool = NULL,
	.rules = {
		&rule_host_eq_examplecom,
		&rule_headers_eq_useragent,
		&rule_uri_prefix_foobar,
		&rule_uri_prefix_root
	}
};
*/


TfwMatchTbl *test_match_tbl;
TfwHttpReq *test_http_req;

static void
http_match_suite_setup(void)
{
	test_match_tbl = tfw_match_tbl_alloc();
	BUG_ON(!test_match_tbl);

	test_http_req = tfw_http_msg_alloc(Conn_Clnt);
	BUG_ON(!test_http_req);
}

static void
http_match_suite_teardown(void)
{
	tfw_http_msg_free(test_http_req);
	test_http_req = NULL;

	tfw_match_tbl_free(test_match_tbl);
	test_match_tbl = NULL;
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

TEST(tfw_match_tbl_rise, adds_rule_to_tbl)
{
}

TEST_SUITE(http_match)
{
	TEST_SETUP(http_match_suite_setup);
	TEST_TEARDOWN(http_match_suite_teardown);

	TEST_RUN(tfw_match_tbl_rise, expands_tbl_without_corruption);
	TEST_RUN(tfw_match_tbl_rise, adds_rule_to_tbl);
	//TEST_RUN(tfw_match_http_req, returns_first_matching_rule);
}

