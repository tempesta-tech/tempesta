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
#include <asm/fpu/api.h>

#undef tfw_sock_srv_init
#define tfw_sock_srv_init test_rr_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_rr_sock_srv_exit
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

static TfwMsg *
sched_rr_get_arg(size_t conn_type __attribute__((unused)))
{
	return NULL;
}

static void
sched_rr_free_arg(TfwMsg *msg __attribute__((unused)))
{
}

static struct TestSchedHelper sched_helper_rr = {
	.sched = "round-robin",
	.conn_types = 1,
	.get_sched_arg = &sched_rr_get_arg,
	.free_sched_arg = &sched_rr_free_arg,
};

TEST(tfw_sched_rr, sg_empty)
{
	test_sched_generic_empty_sg(&sched_helper_rr);
}

TEST(tfw_sched_rr, one_srv_in_sg_and_zero_conn)
{
	test_sched_generic_one_srv_zero_conn(&sched_helper_rr);
}

/*
 * This unit test is implementation aware and checks more than just interface.
 * Note, that it is very similar to other tests (one_srv_in_sg_and_max_conn and
 * max_srv_in_sg_and_max_conn) for round-robin and hash schedullers. So if test
 * structure is changed, other mentioned in above tests should be also be
 * updated
 */
TEST(tfw_sched_rr, one_srv_in_sg_and_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_rr.sched);
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_SRV_MAX_CONN; ++i) {
		TfwSrvConnection *sconn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, &sconn->conn);
		conn_acc ^= (long long)&sconn->conn;
	}

	/*
	 * Check that connections is scheduled in the fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_rr.conn_types; ++i) {
		conn_acc_check = 0;

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_rr.get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_srv(msg, sg);
			EXPECT_NOT_NULL(conn);

			conn_acc_check ^= (long long)conn;
			tfw_connection_put(conn);
			sched_helper_rr.free_sched_arg(msg);
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_rr, max_srv_in_sg_and_zero_conn)
{
	test_sched_generic_max_srv_zero_conn(&sched_helper_rr);
}

/*
 * This unit test is implementation aware and checks more than just interface.
 * Note, that it is very similar to other tests (one_srv_in_sg_and_max_conn and
 * max_srv_in_sg_and_max_conn) for round-robin and hash schedullers. So if test
 * structure is changed, other mentioned in above tests should be also be
 * updated
 */
TEST(tfw_sched_rr, max_srv_in_sg_and_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_rr.sched);

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwSrvConnection *sconn =
					test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, &sconn->conn);
			conn_acc ^= (long long)&(sconn->conn);
		}
	}

	/*
	 * Check that connections is scheduled in the fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_rr.conn_types; ++i) {
		conn_acc_check = 0;

		for (j = 0; j < TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_rr.get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_srv(msg, sg);
			EXPECT_NOT_NULL(conn);

			conn_acc_check ^= (long long)conn;
			tfw_connection_put(conn);
			sched_helper_rr.free_sched_arg(msg);
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST_SUITE(sched_rr)
{
	kernel_fpu_end();

	tfw_server_init();
	tfw_sched_rr_init();

	kernel_fpu_begin();

	TEST_RUN(tfw_sched_rr, sg_empty);
	TEST_RUN(tfw_sched_rr, one_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_rr, one_srv_in_sg_and_max_conn);
	TEST_RUN(tfw_sched_rr, max_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_rr, max_srv_in_sg_and_max_conn);
}
