/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#undef tfw_sock_srv_cfg_mod
#define tfw_sock_srv_cfg_mod test_http_sock_srv_cfg_mod

#include "sock_srv.c"

#ifdef module_init
#undef module_init
#undef module_exit
#define module_init(func)
#define module_exit(func)
#endif

#include "../../sched/tfw_sched_http.c"

#include "cfg.h"
#include "http_msg.h"
#include "helpers.h"
#include "sched_helper.h"
#include "test.h"

static int
parse_cfg(const char *cfg_text)
{
	struct list_head mod_list;
	TfwCfgMod cfg_mod;
	int r;

	kernel_fpu_end();

	cfg_mod = *tfw_cfg_mod_find("tfw_sched_http");
	
	INIT_LIST_HEAD(&cfg_mod.list);
	INIT_LIST_HEAD(&mod_list);
	list_add(&cfg_mod.list, &mod_list);

	r = tfw_cfg_parse_mods_cfg(cfg_text, &mod_list);

	kernel_fpu_begin();

	return r;
}

static void
cleanup_cfg(void)
{
	TfwCfgMod cfg_mod;


	cfg_mod = *tfw_cfg_mod_find("tfw_sched_http");
	test_spec_cleanup(cfg_mod.specs);
}

static void
test_req(char *req_str, TfwSrvConnection *expect_conn)
{
	TfwScheduler *sched;
	TfwConnection *conn;
	TfwHttpReq *req = test_req_alloc(req_str? strlen(req_str): 1);

	if (req_str) {
		static char req_str_copy[PAGE_SIZE];
		const size_t req_str_len = strlen(req_str);

		BUG_ON(req_str_len + 1 > sizeof(req_str_copy));
		strcpy(req_str_copy, req_str);
		tfw_http_parse_req(req, req_str_copy, req_str_len);
	}

	sched = tfw_sched_lookup("http");
	conn = sched->sched_grp((TfwMsg *)req);
	EXPECT_EQ(conn, &expect_conn->conn);

	test_req_free(req);
	tfw_connection_put(conn);
}

TEST(tfw_sched_http, zero_rules_and_zero_conns)
{
	TfwScheduler *sched = tfw_sched_lookup("http");

	EXPECT_TRUE(sched->sched_grp(NULL) == NULL);
}

TEST(tfw_sched_http, one_rule_and_zero_conns)
{
	test_create_sg("default", "round-robin");

	if (parse_cfg("sched_http_rules {\nmatch default * * *;\n}\n")) {
		TEST_FAIL("can't parse rules\n");
	}

	test_req(NULL, NULL);

	cleanup_cfg();
	test_sg_release_all();
}

TEST(tfw_sched_http, one_wildcard_rule)
{
	TfwSrvGroup *sg;
	TfwServer *srv;
	TfwSrvConnection *expect_conn;

	sg = test_create_sg("default", "round-robin");
	srv = test_create_srv("127.0.0.1", sg);
	expect_conn = test_create_conn((TfwPeer *)srv);
	sg->sched->add_conn(sg, srv, &expect_conn->conn);

	if (parse_cfg("sched_http_rules {\nmatch default * * *;\n}\n")) {
		TEST_FAIL("can't parse rules\n");
	}

	test_req(NULL, expect_conn);

	cleanup_cfg();
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_http, some_rules)
{
	TfwServer *srv;
	TfwSrvGroup *sg1, *sg2, *sg3, *sg4, *sg5, *sg6, *sg7, *sg8,
		    *sg9, *sg10;
	TfwSrvConnection *expect_conn1, *expect_conn2, *expect_conn3,
			 *expect_conn4, *expect_conn5, *expect_conn6,
			 *expect_conn7, *expect_conn8, *expect_conn9,
			 *expect_conn10;

	sg1 = test_create_sg("sg1", "round-robin");
	srv = test_create_srv("127.0.0.1", sg1);
	expect_conn1 = test_create_conn((TfwPeer *)srv);
	sg1->sched->add_conn(sg1, srv, &expect_conn1->conn);

	sg2 = test_create_sg("sg2", "round-robin");
	srv = test_create_srv("127.0.0.1", sg2);
	expect_conn2 = test_create_conn((TfwPeer *)srv);
	sg2->sched->add_conn(sg2, srv, &expect_conn2->conn);

	sg3 = test_create_sg("sg3", "round-robin");
	srv = test_create_srv("127.0.0.1", sg3);
	expect_conn3 = test_create_conn((TfwPeer *)srv);
	sg3->sched->add_conn(sg3, srv, &expect_conn3->conn);

	sg4 = test_create_sg("sg4", "round-robin");
	srv = test_create_srv("127.0.0.1", sg4);
	expect_conn4 = test_create_conn((TfwPeer *)srv);
	sg4->sched->add_conn(sg4, srv, &expect_conn4->conn);

	sg5 = test_create_sg("sg5", "round-robin");
	srv = test_create_srv("127.0.0.1", sg5);
	expect_conn5 = test_create_conn((TfwPeer *)srv);
	sg5->sched->add_conn(sg5, srv, &expect_conn5->conn);

	sg6 = test_create_sg("sg6", "round-robin");
	srv = test_create_srv("127.0.0.1", sg6);
	expect_conn6 = test_create_conn((TfwPeer *)srv);
	sg6->sched->add_conn(sg6, srv, &expect_conn6->conn);

	sg7 = test_create_sg("sg7", "round-robin");
	srv = test_create_srv("127.0.0.1", sg7);
	expect_conn7 = test_create_conn((TfwPeer *)srv);
	sg7->sched->add_conn(sg7, srv, &expect_conn7->conn);

	sg8 = test_create_sg("sg8", "round-robin");
	srv = test_create_srv("127.0.0.1", sg8);
	expect_conn8 = test_create_conn((TfwPeer *)srv);
	sg8->sched->add_conn(sg8, srv, &expect_conn8->conn);

	sg9 = test_create_sg("sg9", "round-robin");
	srv = test_create_srv("127.0.0.1", sg9);
	expect_conn9 = test_create_conn((TfwPeer *)srv);
	sg9->sched->add_conn(sg9, srv, &expect_conn9->conn);

	sg10 = test_create_sg("sg10", "round-robin");
	srv = test_create_srv("127.0.0.1", sg10);
	expect_conn10 = test_create_conn((TfwPeer *)srv);
	sg10->sched->add_conn(sg10, srv, &expect_conn10->conn);

	if (parse_cfg("sched_http_rules {\nmatch sg1 uri eq /foo;\n\
	                                   match sg2 uri prefix /foo/bar;\n\
	                                   match sg3 host eq natsys-lab.com;\n\
	                                   match sg4 host prefix natsys-lab;\n\
	                                   match sg5 hdr_host eq google.com;\n\
	                                   match sg6 hdr_host prefix google;\n\
	                                   match sg7 hdr_conn eq close;\n\
	                                   match sg8 hdr_conn prefix Keep;\n\
	                                   match sg9 hdr_raw eq User-Agent:Bot;\n\
	                                   match sg10 hdr_raw prefix X-Forwarded-For;\n}\n")) {
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
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nUser-Agent:Bot\r\n\r\n", expect_conn9);
	test_req("GET http://google.com/foo/baz/ HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n", expect_conn10);
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
		.rule_str = "sched_http_rules {\nmatch default uri eq /foo;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo2 HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default uri prefix /foo;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo2 HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/bar HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default host eq natsys-lab.com;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab2.com/foo HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default host prefix natsys-lab;\n}\n",
		.good_req_str = "GET http://natsys-lab2.com/foo HTTP/1.1\r\n\r\n",
		.bad_req_str = "GET http://google.com/foo HTTP/1.1\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default hdr_host eq natsys-lab.com;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: natsys-lab.com\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: natsys-lab2.com\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default hdr_host prefix natsys-lab;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: natsys-lab2.com\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nHost: google.com\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default hdr_conn eq Keep-Alive;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: close\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default hdr_conn prefix Keep;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: close\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default hdr_raw eq User-Agent:Bot;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nUser-Agent:Bot\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nUser-Agent:Tot\r\n\r\n",
	},
	{
		.rule_str = "sched_http_rules {\nmatch default hdr_raw prefix User-Agent;\n}\n",
		.good_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nUser-Agent: Bot\r\n\r\n",
		.bad_req_str = "GET http://natsys-lab.com/foo HTTP/1.1\r\nConnection: close\r\n\r\n",
	},
};

size_t test_cases_size = sizeof(test_cases) / sizeof(test_cases[0]);

TEST(tfw_sched_http, one_rule)
{
	int i;

	for (i = 0; i < test_cases_size; ++i)
	{
		TfwSrvGroup *sg;
		TfwServer *srv;
		TfwSrvConnection *expect_conn;

		sg = test_create_sg("default", "round-robin");
		srv = test_create_srv("127.0.0.1", sg);
		expect_conn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, &expect_conn->conn);

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

TEST_SUITE(sched_http)
{
	TfwScheduler *s;

	kernel_fpu_end();

	s = tfw_sched_lookup("round-robin");
	if (!s)
		tfw_sched_rr_init();
	tfw_sched_http_init();
	tfw_server_init();

	kernel_fpu_begin();

	TEST_RUN(tfw_sched_http, zero_rules_and_zero_conns);
	TEST_RUN(tfw_sched_http, one_rule_and_zero_conns);
	TEST_RUN(tfw_sched_http, one_wildcard_rule);
	TEST_RUN(tfw_sched_http, some_rules);
	TEST_RUN(tfw_sched_http, one_rule);
}
