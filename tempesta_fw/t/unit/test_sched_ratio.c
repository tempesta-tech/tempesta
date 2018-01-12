/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#define tfw_sock_srv_init test_ratio_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_ratio_sock_srv_exit
#undef tfw_srv_conn_release
#define tfw_srv_conn_release test_ratio_srv_conn_release
#undef tfw_sock_srv_mod
#define tfw_sock_srv_mod test_ratio_sock_srv_mod

#include "sock_srv.c"

#ifdef module_init
#undef module_init
#undef module_exit
#define module_init(func)
#define module_exit(func)
#endif

#include "../../sched/tfw_sched_ratio.c"

#include "sched_helper.h"
#include "server.h"
#include "test.h"

static TfwMsg *
sched_ratio_get_arg(size_t conn_type __attribute__((unused)))
{
	return NULL;
}

static void
sched_ratio_free_arg(TfwMsg *msg __attribute__((unused)))
{
}

static struct TestSchedHelper sched_helper_ratio = {
	.sched = "ratio",
	.flags = TFW_SG_F_SCHED_RATIO_STATIC,
	.conn_types = 1,
	.get_sched_arg = &sched_ratio_get_arg,
	.free_sched_arg = &sched_ratio_free_arg,
};

TEST(tfw_sched_ratio, sched_sg_one_srv_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test");
	TfwServer *srv = test_create_srv("127.0.0.1", sg);
	TfwSrvConn *srv_conn;

	for (i = 0; i < TFW_TEST_SRV_MAX_CONN_N; ++i) {
		srv_conn = test_create_srv_conn(srv);
		conn_acc ^= (long long)srv_conn;
	}
	test_start_sg(sg, sched_helper_ratio.sched, sched_helper_ratio.flags);

	/*
	 * Check that connections are scheduled in fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_ratio.conn_types; ++i) {
		TfwMsg *msg = sched_helper_ratio.get_sched_arg(i);
		conn_acc_check = 0;

		for (j = 0; j < srv->conn_n; ++j) {
			srv_conn = sg->sched->sched_sg_conn(msg, sg);
			EXPECT_NOT_NULL(srv_conn);
			if (!srv_conn)
				goto err;

			conn_acc_check ^= (long long)srv_conn;
			tfw_srv_conn_put(srv_conn);
			/*
			 * Don't let the kernel watchdog decide
			 * that we are stuck in locked context.
			 */
			kernel_fpu_end();
			schedule();
			kernel_fpu_begin();
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
		sched_helper_ratio.free_sched_arg(msg);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_ratio, sched_sg_max_srv_max_conn)
{
	unsigned long i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test");
	TfwServer *srv;
	TfwSrvConn *srv_conn;

	for (i = 0; i < TFW_TEST_SG_MAX_SRV_N; ++i) {
		srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_TEST_SRV_MAX_CONN_N; ++j) {
			srv_conn = test_create_srv_conn(srv);
			conn_acc ^= (long long)srv_conn;
		}
	}
	test_start_sg(sg, sched_helper_ratio.sched, sched_helper_ratio.flags);

	/*
	 * Check that connections are scheduled in fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_ratio.conn_types; ++i) {
		TfwMsg *msg = sched_helper_ratio.get_sched_arg(i);
		conn_acc_check = 0;

		for (j = 0; j < TFW_TEST_SG_MAX_CONN_N; ++j) {
			srv_conn = sg->sched->sched_sg_conn(msg, sg);
			EXPECT_NOT_NULL(srv_conn);
			if (!srv_conn)
				goto err;

			conn_acc_check ^= (long long)srv_conn;
			tfw_srv_conn_put(srv_conn);
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
		sched_helper_ratio.free_sched_arg(msg);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_ratio, sched_srv_one_srv_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test");
	TfwServer *srv = test_create_srv("127.0.0.1", sg);
	TfwSrvConn *srv_conn;

	for (i = 0; i < TFW_TEST_SRV_MAX_CONN_N; ++i) {
		srv_conn = test_create_srv_conn(srv);
		conn_acc ^= (long long)srv_conn;
	}
	test_start_sg(sg, sched_helper_ratio.sched, sched_helper_ratio.flags);

	/*
	 * Check that connections are scheduled in fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_ratio.conn_types; ++i) {
		TfwMsg *msg = sched_helper_ratio.get_sched_arg(i);
		conn_acc_check = 0;

		for (j = 0; j < srv->conn_n; ++j) {
			srv_conn = sg->sched->sched_srv_conn(msg, srv, false);
			EXPECT_NOT_NULL(srv_conn);
			if (!srv_conn)
				goto err;
			EXPECT_EQ((TfwServer *)srv_conn->peer, srv);

			conn_acc_check ^= (long long)srv_conn;
			tfw_srv_conn_put(srv_conn);

			/*
			 * Don't let the kernel watchdog decide
			 * that we are stuck in locked context.
			 */
			kernel_fpu_end();
			schedule();
			kernel_fpu_begin();
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
		sched_helper_ratio.free_sched_arg(msg);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_ratio, sched_srv_max_srv_max_conn)
{
	size_t i, j;
	long long conn_acc_check = 0;
	struct {
		TfwServer *srv;
		long long conn_acc;
	} srv_acc[TFW_TEST_SG_MAX_SRV_N] = {{ 0 }};
	TfwServer *srv;
	TfwSrvConn *srv_conn;

	TfwSrvGroup *sg = test_create_sg("test");

	for (i = 0; i < TFW_TEST_SG_MAX_SRV_N; ++i) {
		srv = test_create_srv("127.0.0.1", sg);
		srv_acc[i].srv = srv;

		for (j = 0; j < TFW_TEST_SRV_MAX_CONN_N; ++j) {
			srv_conn = test_create_srv_conn(srv);
			srv_acc[i].conn_acc ^= (long long)srv_conn;
		}
	}
	test_start_sg(sg, sched_helper_ratio.sched, sched_helper_ratio.flags);

	/*
	 * Check that connections are scheduled in fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_ratio.conn_types; ++i) {
		TfwMsg *msg = sched_helper_ratio.get_sched_arg(i);

		list_for_each_entry(srv, &sg->srv_list, list) {
			size_t k = 0;
			conn_acc_check = 0;

			for (j = 0; j < srv->conn_n; ++j) {
				srv_conn = sg->sched->sched_srv_conn(msg, srv, false);
				EXPECT_NOT_NULL(srv_conn);
				if (!srv_conn)
					goto err;
				EXPECT_EQ((TfwServer *)srv_conn->peer, srv);

				conn_acc_check ^= (long long)srv_conn;
				tfw_srv_conn_put(srv_conn);

				/*
				 * Don't let the kernel watchdog decide
				 * that we are stuck in locked context.
				 */
				kernel_fpu_end();
				schedule();
				kernel_fpu_begin();
			}

			for (k = 0; k < srv->conn_n; ++k) {
				if (srv_acc[k].srv == srv)
					EXPECT_EQ(srv_acc[k].conn_acc,
						  conn_acc_check);
			}
		}
		sched_helper_ratio.free_sched_arg(msg);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_ratio, sched_srv_offline_srv)
{
	test_sched_srv_offline_srv(&sched_helper_ratio);
}

TEST_SUITE(sched_ratio)
{
	kernel_fpu_end();

	tfw_server_init();
	tfw_sched_ratio_init();

	kernel_fpu_begin();

	/*
	 * Static ratios, each server has default weight TFW_CFG_SRV_WEIGHT_DEF.
	 */
	TEST_RUN(tfw_sched_ratio, sched_sg_one_srv_max_conn);
	TEST_RUN(tfw_sched_ratio, sched_sg_max_srv_max_conn);

	TEST_RUN(tfw_sched_ratio, sched_srv_one_srv_max_conn);
	TEST_RUN(tfw_sched_ratio, sched_srv_max_srv_max_conn);
	TEST_RUN(tfw_sched_ratio, sched_srv_offline_srv);
}
