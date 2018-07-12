/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include <asm/fpu/api.h>

#undef tfw_sock_srv_init
#define tfw_sock_srv_init test_http_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_http_sock_srv_exit
#undef tfw_srv_conn_release
#define tfw_srv_conn_release test_http_srv_conn_release
#undef tfw_sock_srv_mod
#define tfw_sock_srv_mod test_http_sock_srv_mod

#include "sock_srv.c"
#include "vhost.c"
#include "http_tbl.c"

#include "cfg.h"
#include "http_msg.h"
#include "helpers.h"
#include "sched_helper.h"
#include "test.h"

static int
parse_cfg(const char *cfg_text)
{
	struct list_head mod_list;
	TfwMod vhost_mod, tbl_mod;
	int r;

	kernel_fpu_end();

	INIT_LIST_HEAD(&mod_list);

	vhost_mod = *tfw_mod_find("vhost");
	INIT_LIST_HEAD(&vhost_mod.list);
	list_add(&vhost_mod.list, &mod_list);

	tbl_mod = *tfw_mod_find("http_tbl");
	INIT_LIST_HEAD(&tbl_mod.list);
	list_add(&tbl_mod.list, &mod_list);

	/*
	 * Configure and start HTTP scheduler directly. 'cfgend()'
	 * callback of 'sched_mod' is not used since implicit
	 * default match rule is undesirable in the tests.
	 * Also 'vhost_mod' is used for proper configuration
	 * of http scheduler.
	 */
	r = tfw_vhost_cfgstart();
	r |= tfw_http_tbl_cfgstart();
	r |= tfw_cfg_parse_mods(cfg_text, &mod_list);
	r |= tfw_vhost_cfgend();
	r |= tfw_vhost_start();
	r |= tfw_http_tbl_start();

	kernel_fpu_begin();

	return r;
}

static void
cleanup_cfg(void)
{
	TfwMod tbl_mod, vhost_mod;

	kernel_fpu_end();

	tbl_mod = *tfw_mod_find("http_tbl");
	test_spec_cleanup(tbl_mod.specs);
	vhost_mod = *tfw_mod_find("vhost");
	test_spec_cleanup(vhost_mod.specs);

	kernel_fpu_begin();
}

static void
test_req(char *req_str, TfwSrvConn *expect_conn)
{
	bool block = false;
	TfwSrvConn *srv_conn = NULL;
	TfwHttpReq *req = test_req_alloc(req_str? strlen(req_str): 1);

	if (req_str) {
		static char req_str_copy[PAGE_SIZE];
		const size_t req_str_len = strlen(req_str);

		BUG_ON(req_str_len + 1 > sizeof(req_str_copy));
		strcpy(req_str_copy, req_str);
		tfw_http_parse_req(req, req_str_copy, req_str_len);
	}

	req->vhost = tfw_http_tbl_vhost((TfwMsg *)req, &block);
	if (req->vhost) {
		EXPECT_FALSE(block);
		srv_conn = tfw_vhost_get_srv_conn((TfwMsg *)req);
	}
	EXPECT_EQ(srv_conn, expect_conn);

	test_req_free(req);
	tfw_srv_conn_put(srv_conn);
}

TEST(http_tbl, one_wildcard_rule)
{
	TfwSrvGroup *sg;
	TfwServer *srv;
	TfwSrvConn *expect_conn;

	sg = test_create_sg("default");
	srv = test_create_srv("127.0.0.1", sg);
	expect_conn = test_create_srv_conn(srv);
	test_start_sg(sg, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	if (parse_cfg("vhost default {\nproxy_pass default;\n}\n\
		       http_chain {\n -> default;\n}\n")) {
		TEST_FAIL("can't parse rules\n");
	}

	test_req(NULL, expect_conn);

	cleanup_cfg();
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(http_tbl, some_rules)
{
	TfwServer *srv;
	TfwSrvGroup *sg1, *sg2, *sg3, *sg4, *sg5, *sg6, *sg7, *sg8,
		    *sg9, *sg10;
	TfwSrvConn *expect_conn1, *expect_conn2, *expect_conn3, *expect_conn4,
		   *expect_conn5, *expect_conn6, *expect_conn7, *expect_conn8,
		   *expect_conn9, *expect_conn10;

	sg1 = test_create_sg("sg1");
	srv = test_create_srv("127.0.0.1", sg1);
	expect_conn1 = test_create_srv_conn(srv);
	test_start_sg(sg1, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg2 = test_create_sg("sg2");
	srv = test_create_srv("127.0.0.1", sg2);
	expect_conn2 = test_create_srv_conn(srv);
	test_start_sg(sg2, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg3 = test_create_sg("sg3");
	srv = test_create_srv("127.0.0.1", sg3);
	expect_conn3 = test_create_srv_conn(srv);
	test_start_sg(sg3, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg4 = test_create_sg("sg4");
	srv = test_create_srv("127.0.0.1", sg4);
	expect_conn4 = test_create_srv_conn(srv);
	test_start_sg(sg4, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg5 = test_create_sg("sg5");
	srv = test_create_srv("127.0.0.1", sg5);
	expect_conn5 = test_create_srv_conn(srv);
	test_start_sg(sg5, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg6 = test_create_sg("sg6");
	srv = test_create_srv("127.0.0.1", sg6);
	expect_conn6 = test_create_srv_conn(srv);
	test_start_sg(sg6, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg7 = test_create_sg("sg7");
	srv = test_create_srv("127.0.0.1", sg7);
	expect_conn7 = test_create_srv_conn(srv);
	test_start_sg(sg7, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg8 = test_create_sg("sg8");
	srv = test_create_srv("127.0.0.1", sg8);
	expect_conn8 = test_create_srv_conn(srv);
	test_start_sg(sg8, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg9 = test_create_sg("sg9");
	srv = test_create_srv("127.0.0.1", sg9);
	expect_conn9 = test_create_srv_conn(srv);
	test_start_sg(sg9, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	sg10 = test_create_sg("sg10");
	srv = test_create_srv("127.0.0.1", sg10);
	expect_conn10 = test_create_srv_conn(srv);
	test_start_sg(sg10, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

	if (parse_cfg("vhost vh1 {\nproxy_pass sg1;\n}\n\
	               vhost vh2 {\nproxy_pass sg2;\n}\n\
	               vhost vh3 {\nproxy_pass sg3;\n}\n\
	               vhost vh4 {\nproxy_pass sg4;\n}\n\
	               vhost vh5 {\nproxy_pass sg5;\n}\n\
	               vhost vh6 {\nproxy_pass sg6;\n}\n\
	               vhost vh7 {\nproxy_pass sg7;\n}\n\
	               vhost vh8 {\nproxy_pass sg8;\n}\n\
	               vhost vh9 {\nproxy_pass sg9;\n}\n\
	               vhost vh10 {\nproxy_pass sg10;\n}\n\
	               http_chain {\nuri == /foo -> vh1;\n\
                                     uri == /foo/bar* -> vh2;\n\
                                     host == natsys-lab.com -> vh3;\n\
	                             host == natsys-lab* -> vh4;\n\
	                             hdr Host == google.com -> vh5;\n\
	                             hdr Host == google* -> vh6;\n\
	                             hdr Connection == close -> vh7;\n\
	                             hdr Connection == Keep* -> vh8;\n\
	                             hdr X-Forwarded-For == * -> vh9;\n\
	                             hdr User-Agent == Bot -> vh10;\n}\n")) {
		TEST_FAIL("can't parse rules\n");
	}

	test_req("GET http://natsys-lab.com/foo HTTP/1.1\r\n\r\n", expect_conn1);
	test_req("GET http://natsys-lab.com/foo/bar/ HTTP/1.1\r\n\r\n", expect_conn2);
	test_req("GET http://natsys-lab.com/foo/baz/ HTTP/1.1\r\n\r\n", expect_conn3);
	test_req("GET http://natsys-lab2.com/foo/baz/ HTTP/1.1\r\n\r\n", expect_conn4);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nHost: google.com\r\n\r\n", expect_conn5);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nHost: google2.com\r\n\r\n", expect_conn6);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nConnection: close\r\n\r\n", expect_conn7);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n", expect_conn8);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n", expect_conn9);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nUser-Agent:Bot\r\n\r\n", expect_conn10);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\n\r\n", NULL);

	cleanup_cfg();
	test_conn_release_all(sg1);
	test_conn_release_all(sg2);
	test_conn_release_all(sg3);
	test_conn_release_all(sg4);
	test_conn_release_all(sg5);
	test_conn_release_all(sg6);
	test_conn_release_all(sg7);
	test_conn_release_all(sg8);
	test_conn_release_all(sg9);
	test_conn_release_all(sg10);
	test_sg_release_all();
}

typedef struct {
	char *rule_str;
	char *good_req_str;
	char *bad_req_str;
} TestCase;

TestCase test_cases[] = {
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nuri == /foo -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo2 HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nuri == /foo* -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo2 HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/bar HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhost == natsys-lab.com -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab2.com/foo HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhost == natsys-lab* -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab2.com/foo HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://google.com/foo HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr Host == natsys-lab.com -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: natsys-lab.com\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: natsys-lab2.com\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr Host == natsys-lab* -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: natsys-lab2.com\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: google.com\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr Connection == Keep-Alive -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: close\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr Connection == Keep* -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: close\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr User-Agent == Bot -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nUser-Agent:Bot\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nUser-Agent:Tot\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr User-Agent == * -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nUser-Agent: Bot\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: close\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr Via == Sever* -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nVia: SeverExample\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nVia: Proxy\r\n\r\n",
	},
	{
		.rule_str = "vhost default {\nproxy_pass default;\n}\n\
			     http_chain {\nhdr Via == * -> default;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nVia: Proxy\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: Proxy\r\n\r\n",
	},
};

size_t test_cases_size = ARRAY_SIZE(test_cases);

TEST(http_tbl, one_rule)
{
	int i;

	for (i = 0; i < test_cases_size; ++i)
	{
		TfwSrvGroup *sg;
		TfwServer *srv;
		TfwSrvConn *expect_conn;

		sg = test_create_sg("default");
		srv = test_create_srv("127.0.0.1", sg);
		expect_conn = test_create_srv_conn(srv);
		test_start_sg(sg, "ratio", TFW_SG_F_SCHED_RATIO_STATIC);

		if (parse_cfg(test_cases[i].rule_str)) {
			TEST_FAIL("can't parse rules\n");
		}

		test_req(test_cases[i].good_req_str, expect_conn);
		test_req(test_cases[i].bad_req_str, NULL);

		cleanup_cfg();
		test_conn_release_all(sg);
		test_sg_release_all();
	}
}

TEST_SUITE(http_tbl)
{
	TfwScheduler *s;

	kernel_fpu_end();

	s = tfw_sched_lookup("ratio");
	if (!s)
		tfw_sched_ratio_init();
	tfw_vhost_init();
	tfw_http_tbl_init();
	tfw_server_init();

	kernel_fpu_begin();

	TEST_RUN(http_tbl, one_wildcard_rule);
	TEST_RUN(http_tbl, some_rules);
	TEST_RUN(http_tbl, one_rule);
}
