/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#undef tfw_sock_srv_init
#define tfw_sock_srv_init test_rr_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_rr_sock_srv_exit
#undef tfw_sock_srv_drop
#define tfw_sock_srv_drop test_rr_sock_srv_drop
#undef tfw_srv_conn_release
#define tfw_srv_conn_release test_rr_srv_conn_release
#undef tfw_sock_srv_cfg_mod
#define tfw_sock_srv_cfg_mod test_rr_srv_cfg_mod

#include "sock_srv.c"

#ifdef module_init
#undef module_init
#undef module_exit
#define module_init(func)
#define module_exit(func)
#endif

#include "../../sched/tfw_sched_rr.c"

#include "sched_helper.h"
#include "server.h"
#include "test.h"

TEST(tfw_sched_rr, sg_empty)
{
	int i;

	TfwSrvGroup *sg = test_create_sg("test", "round-robin");

	for (i = 0; i < 3; ++i) {
		TfwConnection *conn = sg->sched->sched_srv(NULL, sg);
		EXPECT_TRUE(conn == NULL);
	}

	test_sg_release_all();
}

TEST(tfw_sched_rr, one_srv_in_sg_and_zero_conn)
{
	int i;

	TfwSrvGroup *sg = test_create_sg("test", "round-robin");
	test_create_srv("127.0.0.1", sg);

	for (i = 0; i < 3; ++i) {
		TfwConnection *conn = sg->sched->sched_srv(NULL, sg);
		EXPECT_TRUE(conn == NULL);
	}

	test_sg_release_all();
}

TEST(tfw_sched_rr, one_srv_in_sg_and_max_conn)
{
	int i;
	long long s = 0;

	TfwSrvGroup *sg = test_create_sg("test", "round-robin");
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_SRV_MAX_CONN; ++i) {
		TfwSrvConnection *sconn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, &sconn->conn);
		s ^= (long long)sconn;
	}

	for (i = 0; i < 3 * TFW_SRV_MAX_CONN; ++i) {
		TfwConnection *conn = sg->sched->sched_srv(NULL, sg);
		s ^= (long long)conn;
		tfw_connection_put(conn);
	}

	EXPECT_TRUE(s == 0);

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_rr, max_srv_in_sg_and_zero_conn)
{
	int i;

	TfwSrvGroup *sg = test_create_sg("test", "round-robin");

	for (i = 0; i < TFW_SG_MAX_SRV; ++i)
		test_create_srv("127.0.0.1", sg);

	for (i = 0; i < 2 * TFW_SG_MAX_SRV; ++i) {
		TfwConnection *conn = sg->sched->sched_srv(NULL, sg);
		EXPECT_TRUE(conn == NULL);
	}

	test_sg_release_all();
}

TEST(tfw_sched_rr, max_srv_in_sg_and_max_conn)
{
	int i, j;
	long long s = 0;
	TfwSrvConnection *sconn;

	TfwSrvGroup *sg = test_create_sg("test", "round-robin");

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);
		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			sconn = test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, &sconn->conn);
			s ^= (long long)sconn;
		}
	}

	for (j = 0; j < 3 * TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN; ++j) {
		TfwConnection *conn = sg->sched->sched_srv(NULL, sg);
		s ^= (long long)conn;
		tfw_connection_put(conn);
	}

	EXPECT_TRUE(s == 0);

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST_SUITE(sched_rr)
{
	tfw_server_init();
	tfw_sched_rr_init();

	TEST_RUN(tfw_sched_rr, sg_empty);
	TEST_RUN(tfw_sched_rr, one_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_rr, one_srv_in_sg_and_max_conn);
	TEST_RUN(tfw_sched_rr, max_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_rr, max_srv_in_sg_and_max_conn);
}
