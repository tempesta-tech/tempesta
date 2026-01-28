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
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/ctype.h>

#include "http_match.h"
#include "http_msg.h"

#include "test.h"
#include "helpers.h"
#include "tfw_str_helper.h"
#include "test_http_parser_common.h"

#include "http_match.c"

typedef struct {
	int test_id;
	TfwHttpMatchRule rule;
} MatchEntry;

TfwHttpTable *test_table;
TfwHttpChain *test_chain;
TfwHttpReq *test_req;

/**
 * Size of a container of the TfwHttpMatchRule.
 *
 * @arg_len is variable size of the @arg member.
 * Because of this, the rule must be the last member in the container.
 */
#define TFW_HTTP_MATCH_CONT_SIZE(container_struct_name, arg_len)  \
	(sizeof(container_struct_name) - sizeof(TfwHttpMatchRule) \
	 + TFW_HTTP_MATCH_RULE_SIZE(arg_len))

/**
 * Allocate a container (with embedded rule) and add it to appropriate
 * chain list (for numerical mark comparing or string matching).
 */
#define test_rule_container_new(chain, container, member, type, arg_len)\
({ 									\
	size_t _s = (type == TFW_HTTP_MATCH_A_STR)			\
		  ? TFW_HTTP_MATCH_CONT_SIZE(container, arg_len)	\
		  : sizeof(container);					\
	container *_c = tfw_pool_alloc((chain)->pool, _s);		\
	if (!_c) {							\
		T_ERR("Can't allocate memory from pool\n");		\
	} else { 							\
		struct list_head *head = (type == TFW_HTTP_MATCH_A_NUM)	\
				       ? &(chain)->mark_list		\
				       : &(chain)->match_list;		\
		memset(_c, 0, _s);					\
		INIT_LIST_HEAD(&_c->member.list);			\
		list_add_tail(&_c->member.list, head);			\
	}								\
	_c;								\
})

/**
 * Match a HTTP request against list of rules in chain, but return
 * a container structure instead of TfwHttpMatchRule.
 */
#define test_rule_container_match_req(req, mlst, container, member)	\
({ 									\
	container *_c = NULL;						\
	TfwHttpMatchRule *_r = tfw_http_match_req((req), (mlst)); 	\
	if (_r)								\
		_c = container_of(_r, container, member);		\
	_c;								\
})

static int
http_match_suite_rule_release(TfwHttpMatchRule *rule)
{
	if (rule->val.type == TFW_HTTP_MATCH_V_COOKIE)
		kfree(rule->val.ptn.str);
	return 0;
}

static void
http_match_suite_setup(void)
{
	test_req = test_req_alloc(1);

	test_table = tfw_pool_new(TfwHttpTable,
				  tfw_http_msg_client((TfwHttpMsg *)test_req),
				  TFW_POOL_ZERO);
	BUG_ON(!test_table);
	INIT_LIST_HEAD(&test_table->head);

	test_chain = tfw_http_chain_add(NULL, test_table);
	BUG_ON(!test_chain);
}

static void
http_match_suite_teardown(void)
{
	test_req_free(test_req);
	test_req = NULL;

	tfw_http_chain_rules_for_each(test_chain, http_match_suite_rule_release);

	tfw_http_table_free(test_table);
	test_table = NULL;
}

static void
test_chain_add_rule_str(int test_id, tfw_http_match_fld_t field,
			const char *in_val, const char *in_arg)
{
	MatchEntry *e;
	unsigned int hid = TFW_HTTP_HDR_RAW;
	tfw_http_match_op_t op = TFW_HTTP_MATCH_O_WILDCARD,
			    op_val = TFW_HTTP_MATCH_O_WILDCARD;
	tfw_http_match_arg_t type = TFW_HTTP_MATCH_A_WILDCARD;
	tfw_http_match_val_t val_type = TFW_HTTP_MATCH_V_HID;
	size_t arg_size = 0;
	unsigned int val_len = 0;
	const char *arg = NULL, *val = NULL;

	BUG_ON(in_arg && field == TFW_HTTP_MATCH_F_WILDCARD);
	BUG_ON(!in_arg && field != TFW_HTTP_MATCH_F_WILDCARD);

	if (field != TFW_HTTP_MATCH_F_COOKIE) {
		tfw_http_verify_hdr_field(field, &in_val, &hid);
	}
	val = tfw_http_val_adjust(in_val, field, &val_len, &val_type, &op_val);
	arg = tfw_http_arg_adjust(in_arg, field, in_val, &arg_size, &type, &op);
	EXPECT_NOT_NULL(arg);
	if (!arg)
		return;
	e = test_rule_container_new(test_chain, MatchEntry, rule,
				    type, arg_size);
	EXPECT_NOT_NULL(e);
	if (!e)
		goto err;
	e->rule.field = field;
	e->rule.val.type = val_type;
	if (val_type == TFW_HTTP_MATCH_V_COOKIE) {
		e->rule.val.ptn.op = op_val;
		e->rule.val.ptn.str = val;
		e->rule.val.ptn.len = val_len;
	} else {
		e->rule.val.hid = hid;
	}
	e->rule.op = op;
	e->rule.arg.type = type;
	tfw_http_rule_arg_init(&e->rule, arg, arg_size - 1);
	/* Just dummy action type to avoid BUG_ON in 'do_eval()'. */
	e->rule.act.type = TFW_HTTP_MATCH_ACT_CHAIN;
	e->test_id = test_id;

	kfree(arg);
	return;
err:
	kfree(arg);
	kfree(val);
}

static int
test_chain_match(void)
{
	MatchEntry *e;

	e = test_rule_container_match_req(test_req, &test_chain->match_list,
					  MatchEntry, rule);
	if (e)
		return e->test_id;

	return -1;
}

static void
set_tfw_str(TfwStr *str, const char *cstr)
{
	memset(str, 0, sizeof(TfwStr));
	str->data = (void *)cstr;
	str->len = strlen(cstr);
}

static void
set_raw_hdr(const char *cstr)
{
	unsigned int hid = test_req->h_tbl->off;

	if (hid == test_req->h_tbl->size &&
	    tfw_http_msg_grow_hdr_tbl((TfwHttpMsg *)test_req))
		return;

	++test_req->h_tbl->off;

	set_tfw_str(&test_req->h_tbl->tbl[hid], cstr);
}

TEST(tfw_http_match_req, returns_first_matching_rule)
{
	const TfwHttpMatchRule *match;
	TfwHttpMatchRule *r1, *r2, *r3;

	r1 = tfw_http_rule_new(test_chain, TFW_HTTP_MATCH_A_METHOD, 0);
	r2 = tfw_http_rule_new(test_chain, TFW_HTTP_MATCH_A_METHOD, 0);
	r3 = tfw_http_rule_new(test_chain, TFW_HTTP_MATCH_A_METHOD, 0);

	r1->act.type = r2->act.type = r3->act.type = TFW_HTTP_MATCH_ACT_CHAIN;
	r1->field = r2->field = r3->field = TFW_HTTP_MATCH_F_METHOD;
	r1->op = r2->op = r3->op = TFW_HTTP_MATCH_O_EQ;
	r1->arg.type = r2->arg.type = r3->arg.type = TFW_HTTP_MATCH_A_METHOD;
	r1->arg.method = TFW_HTTP_METH_POST;
	r2->arg.method = TFW_HTTP_METH_GET;
	r3->arg.method = TFW_HTTP_METH_GET;

	test_req->method = TFW_HTTP_METH_GET;

	match = tfw_http_match_req(test_req, &test_chain->match_list);

	EXPECT_EQ(r2, match);
}

TEST(http_match, uri_prefix)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_URI, NULL, "/foo/bar/baz*");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_URI, NULL, "/foo/ba*");
	test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_URI, NULL, "/*");

	set_tfw_str(&test_req->uri_path, "/foo/bar/baz.html");
	match_id = test_chain_match();
	EXPECT_EQ(1, match_id);

	set_tfw_str(&test_req->uri_path, "/foo/bar/");
	match_id = test_chain_match();
	EXPECT_EQ(2, match_id);

	set_tfw_str(&test_req->uri_path, "/baz");
	match_id = test_chain_match();
	EXPECT_EQ(3, match_id);

	set_tfw_str(&test_req->uri_path, "../foo");
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);
}

TEST(http_match, uri_suffix)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_URI, NULL, "*.jpg");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_URI, NULL, "*/people.html");
	test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_URI, NULL,
				"*/bar/folks.html");

	set_tfw_str(&test_req->uri_path, "/foo/bar/picture.jpg");
	match_id = test_chain_match();
	EXPECT_EQ(1, match_id);

	set_tfw_str(&test_req->uri_path, "/foo/bar/people.html");
	match_id = test_chain_match();
	EXPECT_EQ(2, match_id);

	set_tfw_str(&test_req->uri_path, "/foo/bar/folks.html");
	match_id = test_chain_match();
	EXPECT_EQ(3, match_id);

	set_tfw_str(&test_req->uri_path, "../foo");
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);

	set_tfw_str(&test_req->uri_path, "/foo/bar/picture.png");
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);
}

TEST(http_match, uri_wc_escaped)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_URI, NULL,
				"\\*/foo/bar");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_URI, NULL,
				"/foo/\\*people*");
	test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_URI, NULL,
				"*/foo\\*/bar\\*/index.html\\*");

	set_tfw_str(&test_req->uri_path, "*/foo/bar");
	match_id = test_chain_match();
	EXPECT_EQ(1, match_id);

	set_tfw_str(&test_req->uri_path, "/foo/*people.html");
	match_id = test_chain_match();
	EXPECT_EQ(2, match_id);

	set_tfw_str(&test_req->uri_path, "/root/foo*/bar*/index.html*");
	match_id = test_chain_match();
	EXPECT_EQ(3, match_id);
}

TEST(http_match, host_eq)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HOST, NULL,
				"www.natsys-lab.com");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HOST, NULL,
				"natsys-lab");
	test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_HOST, NULL,
				"NATSYS-LAB.COM");
	set_tfw_str(&test_req->host, "natsys-lab.com");
	match_id = test_chain_match();
	EXPECT_EQ(3, match_id);
}

TEST(http_match, headers_eq)
{
	create_str_pool();

	{
		int match_id;

		/* Special headers must be compound */
		TFW_STR2(hdr1, "Connection: ", "Keep-Alive");
		TFW_STR2(hdr2, "Connection: ", "cLoSe");

		test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
					"User-Agent", "U880D/4.0 (CP/M; 8-bit)");
		test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HDR,
					"Connection", "close");
		test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_HDR,
					"Connection", "Keep-Alive");

		test_req->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION] = *hdr1;
		match_id = test_chain_match();
		EXPECT_EQ(3, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_CONNECTION] = *hdr2;
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);
	}

	free_all_str();
}

TEST(http_match, headers_duplicated_eq)
{
	create_str_pool();

	{
		int match_id;
		TfwStr *hdr1, *hdr2, *hdr3, *dup1, *dup2, *dup3;

		hdr1 =  make_compound_str2("X-Forwarded-For: ", "2.2.2.2");
		dup1 = tfw_str_add_duplicate(str_pool, hdr1);
		*dup1 = *make_compound_str2("X-Forwarded-For: ", "1.1.1.1");

		hdr2 =  make_compound_str2("X-Forwarded-For: ", "4.4.4.4");
		dup2 = tfw_str_add_duplicate(str_pool, hdr2);
		*dup2 = *make_compound_str2("X-Forwarded-For: ", "5.5.5.5");

		hdr3 =  make_compound_str2("X-Forwarded-For: ", "1.1.1.1");
		dup3 = tfw_str_add_duplicate(str_pool, hdr3);
		*dup3 = *make_compound_str2("X-Forwarded-For: ", "2.2.2.2");

		test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
					"X-Forwarded-For: ", "3.3.3.3");
		test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HDR,
					"X-Forwarded-For: ", "1.1.1.1");

		test_req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR] = *hdr2;
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR] = *hdr1;
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_X_FORWARDED_FOR] = *hdr3;
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);
	}

	free_all_str();
}

TEST(http_match, hdr_host_prefix)
{
	create_str_pool();

	{
		int match_id;

		/* Special headers must be compound */
		TFW_STR2(hdr1, "Host: ", "example.com");
		TFW_STR2(hdr2, "Host: ", "Host: eXample.COM");
		TFW_STR2(hdr3, "Host: ", "www");
		TFW_STR2(hdr4, "Host: ", "WWW.EXAMPLE.COM:8081");

		test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
					"Connection", "    Keep-Alive");
		test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HDR,
					"Host", "ex*");
		test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_HDR,
					"Host",	"www.example.com*");

		set_tfw_str(&test_req->host, "example.com");
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr1;
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr2;
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id); /* Host header contains the header name. */

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr3;
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr4;
		match_id = test_chain_match();
		EXPECT_EQ(3, match_id);
	}

	free_all_str();
}

TEST(http_match, hdr_host_suffix)
{
	create_str_pool();

	{
		int match_id;

		/* Special headers must be compound */
		TFW_STR2(hdr1, "Host: ", "example.biz");
		TFW_STR2(hdr2, "Host: ", "example.com");
		TFW_STR2(hdr3, "Host: ", "example.ru");
		TFW_STR2(hdr4, "Host: ", "eXample.COM");
		TFW_STR2(hdr5, "Host: ", "www");
		TFW_STR2(hdr6, "Host: ", "TEST.FOLKS.COM");

		test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
					"Connection", "  Keep-Alive");
		test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HDR,
					"Host", "*.ru");
		test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_HDR,
					"Host", "*.biz");
		test_chain_add_rule_str(4, TFW_HTTP_MATCH_F_HDR,
					"Host", "*.folks.com");
		test_chain_add_rule_str(5, TFW_HTTP_MATCH_F_HDR,
					"Host", "*.com");

		set_tfw_str(&test_req->host, "example.com");
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr1;
		match_id = test_chain_match();
		EXPECT_EQ(3, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr2;
		match_id = test_chain_match();
		EXPECT_EQ(5, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr3;
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr4;
		match_id = test_chain_match();
		EXPECT_EQ(5, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr5;
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);

		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = *hdr6;
		match_id = test_chain_match();
		EXPECT_EQ(4, match_id);
	}

	free_all_str();
}

TEST(http_match, raw_header_eq)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
				"User-Agent", "U880D/4.0 (CP/M; 8-bit)");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HDR,
				"Via", "test_proxy 1.0");

	set_raw_hdr("Via: test_proxy 1.0");
	match_id = test_chain_match();
	EXPECT_EQ(2, match_id);
}

TEST(http_match, raw_header_eq_ws)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
				"User-Agent", "U880D/4.0 (CP/M; 8-bit)");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HDR,
				"Connection", "close");
	test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_HDR,
				"Connection", "Keep-Alive");
	test_chain_add_rule_str(4, TFW_HTTP_MATCH_F_HDR,
				"Warning", "        123 miscellaneous warning");

	set_raw_hdr("Warning: 123 miscellaneous warning");
	match_id = test_chain_match();
	EXPECT_EQ(4, match_id);
}

TEST(http_match, method_eq)
{
	int match_id;
	MatchEntry *e1, *e2;

	e1 = test_rule_container_new(test_chain, MatchEntry, rule,
				     TFW_HTTP_MATCH_A_METHOD, 0);
	EXPECT_NOT_NULL(e1);
	if (!e1)
		return;
	e1->test_id = 42,
	e1->rule.field = TFW_HTTP_MATCH_F_METHOD;
	e1->rule.op = TFW_HTTP_MATCH_O_EQ;
	e1->rule.arg.type = TFW_HTTP_MATCH_A_METHOD;
	e1->rule.arg.method = TFW_HTTP_METH_POST;
	e1->rule.act.type = TFW_HTTP_MATCH_ACT_CHAIN;

	e2 = test_rule_container_new(test_chain, MatchEntry, rule,
				     TFW_HTTP_MATCH_A_METHOD, 0);
	EXPECT_NOT_NULL(e2);
	if (!e2)
		return;
	e2->test_id = 43,
	e2->rule.field = TFW_HTTP_MATCH_F_METHOD;
	e2->rule.op = TFW_HTTP_MATCH_O_EQ;
	e2->rule.arg.type = TFW_HTTP_MATCH_A_METHOD;
	e2->rule.arg.method = TFW_HTTP_METH_GET;
	e2->rule.act.type = TFW_HTTP_MATCH_ACT_CHAIN;

	test_req->method = TFW_HTTP_METH_HEAD;
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);

	test_req->method = TFW_HTTP_METH_GET;
	match_id = test_chain_match();
	EXPECT_EQ(43, match_id);

	test_req->method = TFW_HTTP_METH_POST;
	match_id = test_chain_match();
	EXPECT_EQ(42, match_id);
}

#define TFW_TEST_MAX_COOKIE_NCHUNKS 20
TfwStr test_cookie_chunks[TFW_TEST_MAX_COOKIE_NCHUNKS] = { 0 };
TfwStr test_cookie = { .chunks = test_cookie_chunks };

static
void tfw_test_cookie(char* header, ...)
{
	char *field;

	va_list args;
	va_start(args, header);

	test_cookie_chunks[0] = TFW_STR_FROM_CSTR(header);
	test_cookie.nchunks = 1;

	do {
		char *eq_p;
		field = va_arg(args, char *);
		if (!field)
			break;

		eq_p = strchr(field, '=');
		BUG_ON(!eq_p);

		if (test_cookie.nchunks != 1)
			test_cookie.chunks[test_cookie.nchunks++]
				= TFW_STR_STRING("; ");

		test_cookie.chunks[test_cookie.nchunks++] = (TfwStr) {
			.data = field, eq_p - field + 1, NULL, 0, TFW_STR_NAME, 0
		};
		test_cookie.chunks[test_cookie.nchunks++] = (TfwStr) {
			.data = eq_p + 1, strlen(field) - (eq_p - field + 1),
			NULL, 0, TFW_STR_VALUE, 0
		};
	} while (true);

	va_end(args);

	{
		unsigned int n;

		test_cookie.len = 0;
		for (n = 0; n < test_cookie.nchunks; ++n) {
			test_cookie.len += test_cookie.chunks[n].len;
		}
	}

	test_req->h_tbl->tbl[TFW_HTTP_HDR_COOKIE] = test_cookie;
}

TEST(http_match, cookie)
{
	int match_id;

	test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HDR,
				"User-Agent", "U880D/4.0 (CP/M; 8-bit)");
	test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_COOKIE,
				"name", "*");
	test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_COOKIE,
				"coo_*", "*");
	test_chain_add_rule_str(4, TFW_HTTP_MATCH_F_COOKIE,
				"J_-*", "Val_");
	test_chain_add_rule_str(5, TFW_HTTP_MATCH_F_COOKIE,
				"J_-*", "Val__*");
	test_chain_add_rule_str(6, TFW_HTTP_MATCH_F_COOKIE,
				"name", "Val_");
	test_chain_add_rule_str(7, TFW_HTTP_MATCH_F_COOKIE,
				"_09", "_088_*");
	test_chain_add_rule_str(8, TFW_HTTP_MATCH_F_COOKIE,
				"_09*", "_088_*");
	test_chain_add_rule_str(9, TFW_HTTP_MATCH_F_COOKIE,
				"some", "some_\\*_");
	test_chain_add_rule_str(10, TFW_HTTP_MATCH_F_COOKIE,
				"*zxcv", "*dd");

	tfw_test_cookie("Cookie: ",
			"name1=value1",
			"NaMe=Val_",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);

	tfw_test_cookie("Cookie: ",
			"name=",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(2, match_id);

	tfw_test_cookie("Cookie: ",
			"name1=value1",
			"name=Val_",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(2, match_id);

	tfw_test_cookie("Cookie: ",
			"coo_=value1",
			"5678=Val_",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(3, match_id);

	tfw_test_cookie("Cookie: ",
			"coo_-DDD=value1",
			"5678=Val_",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(3, match_id);

	tfw_test_cookie("Cookie: ",
			"name1=value1",
			"J_-=Val_",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(4, match_id);

	tfw_test_cookie("Cookie: ",
			"name1=value1",
			"J_-=Val",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);

	tfw_test_cookie("Cookie: ",
			"name1=value1",
			"J_----=Val__",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(5, match_id);

	tfw_test_cookie("Cookie: ",
			"name1=value1",
			"J_----=Val__--",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(5, match_id);

	tfw_test_cookie("Cookie: ",
			"_09=_088_*",
			"some=some_*",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(7, match_id);

	tfw_test_cookie("Cookie: ",
			"_0*9=_088_",
			"some=some_*_",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(9, match_id);

	tfw_test_cookie("Cookie: ",
			"ggggggg=fffff",
			"zxcv=dd",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(10, match_id);

	tfw_test_cookie("Cookie: ",
			"ggggggg=fffff",
			"zzzzzzzxcv=dd",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(10, match_id);

	tfw_test_cookie("Cookie: ",
			"ggggggg=fffff",
			"zxcv=d",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);

	tfw_test_cookie("Cookie: ",
			"ggggggg=fffff",
			"xcv=dddd",
			NULL);
	match_id = test_chain_match();
	EXPECT_EQ(-1, match_id);
}

/*
 * Match host by priority.
 *
 * For http1 when URI host not empty, Host
 * header and Forwarded will be ignored.
 * otherwise headers will be matched
 * in such order: Host, Forwarded.
 *
 * For http2 all three headers will be matched
 * in such order: URI(:authority), Host, Forwarded.
 */
TEST(http_match, choose_host)
{
	create_str_pool();

	{
		int match_id;

		/* Special headers must be compound */
		TfwStr hdr1	= {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "example.eu", .len = 10,
				  .flags = TFW_STR_HDR_VALUE | TFW_STR_VALUE },
			},
			.len = 15,
			.nchunks = 2
		};

		TfwStr hdr2	= {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "example.de", .len = 10,
				  .flags = TFW_STR_HDR_VALUE | TFW_STR_VALUE },
			},
			.len = 15,
			.nchunks = 2
		};

		TfwStr hdr3	= {
			.chunks = (TfwStr []) {
				{ .data = "Host:" , .len = 5 },
				{ .data = "example.net", .len = 11,
				  .flags = TFW_STR_HDR_VALUE | TFW_STR_VALUE },
			},
			.len = 16,
			.nchunks = 2
		};

		TfwStr hdr4     = {
			.chunks = (TfwStr []) {
				{ .data = "Forwarded:" , .len = 10 },
				{ .data = " " , .len = 1,
				  .flags = TFW_STR_OWS },
				{ .data = "host=" , .len = 5,
				  .flags = TFW_STR_NAME },
				{ .data = "example.ru" , .len = 10,
				  .flags = TFW_STR_VALUE },
			},
			.len = 25,
			.nchunks = 4
		};

		TfwStr hdr5     = {
			.chunks = (TfwStr []) {
				{ .data = ":authority" , .len = 10 },
				{ .data = "example.eu" , .len = 10,
				  .flags = TFW_STR_HDR_VALUE | TFW_STR_VALUE },
			},
			.len = 20,
			.nchunks = 2
		};

		test_chain_add_rule_str(1, TFW_HTTP_MATCH_F_HOST,
					NULL, "example.com");

		test_chain_add_rule_str(2, TFW_HTTP_MATCH_F_HOST,
					NULL, "example.eu");

		test_chain_add_rule_str(3, TFW_HTTP_MATCH_F_HOST,
					NULL, "example.ru");

		/* Host not specified. */
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);
		/* Host specified by URI. */
		set_tfw_str(&test_req->host, "example.com");
		match_id = test_chain_match();
		EXPECT_EQ(1, match_id);

		/*
		 * Host specified by URI and Host header
		 * host from uri must be matched.
		 */
		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = hdr1;
		tfw_http_extract_request_authority(test_req);
		match_id = test_chain_match();
		EXPECT_EQ(1, match_id);

		/* Host specified by Host header */
		set_tfw_str(&test_req->host, "");
		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = hdr1;
		tfw_http_extract_request_authority(test_req);
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);

		/*
		 * Host specified by Host, Forwarded headers
		 * and URI. Host from uri must be matched.
		 */
		set_tfw_str(&test_req->host, "example.com");
		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = hdr1;
		test_req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED] = hdr4;
		tfw_http_extract_request_authority(test_req);
		match_id = test_chain_match();
		EXPECT_EQ(1, match_id);

		/*
		 * Host specified by Host and Forwarded headers.
		 * Host from Forwarded header must NOT be matched.
		 */
		set_tfw_str(&test_req->host, "");
		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = hdr2;
		test_req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED] = hdr4;
		tfw_http_extract_request_authority(test_req);
		match_id = test_chain_match();
		EXPECT_EQ(-1, match_id);

		/*
		 * HTTP2!
		 * Host specified by Host, Forwarded headers
		 * and :authority. Host from :authority must be matched.
		 */
		__set_bit(TFW_HTTP_B_H2, test_req->flags);
		set_tfw_str(&test_req->host, "");
		test_req->h_tbl->tbl[TFW_HTTP_HDR_H2_AUTHORITY] = hdr5;
		test_req->h_tbl->tbl[TFW_HTTP_HDR_HOST] = hdr3;
		test_req->h_tbl->tbl[TFW_HTTP_HDR_FORWARDED] = hdr4;
		tfw_http_extract_request_authority(test_req);
		match_id = test_chain_match();
		EXPECT_EQ(2, match_id);
	}

	free_all_str();
}

TEST_SUITE(http_match)
{
	TEST_SETUP(http_match_suite_setup);
	TEST_TEARDOWN(http_match_suite_teardown);

	TEST_RUN(tfw_http_match_req, returns_first_matching_rule);
	TEST_RUN(http_match, uri_prefix);
	TEST_RUN(http_match, uri_suffix);
	TEST_RUN(http_match, uri_wc_escaped);
	TEST_RUN(http_match, host_eq);
	TEST_RUN(http_match, headers_eq);
	TEST_RUN(http_match, headers_duplicated_eq);
	TEST_RUN(http_match, hdr_host_prefix);
	TEST_RUN(http_match, hdr_host_suffix);
	TEST_RUN(http_match, raw_header_eq);
	TEST_RUN(http_match, raw_header_eq_ws);
	TEST_RUN(http_match, method_eq);
	TEST_RUN(http_match, cookie);
	TEST_RUN(http_match, choose_host);
}
