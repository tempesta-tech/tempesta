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
	test_sched_sg_empty_sg(&sched_helper_rr);
}

TEST(tfw_sched_rr, sched_sg_one_srv_zero_conn)
{
	test_sched_sg_one_srv_zero_conn(&sched_helper_rr);
}

TEST(tfw_sched_rr, sched_sg_one_srv_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_rr.sched);
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_TEST_SRV_CONN_N; ++i) {
		TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, srv_conn);
		conn_acc ^= (long long)srv_conn;
	}

	/*
	 * Check that connections is scheduled in the fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_rr.conn_types; ++i) {
		conn_acc_check = 0;

		for (j = 0; j < TFW_TEST_SRV_CONN_N; ++j) {
			TfwMsg *msg = sched_helper_rr.get_sched_arg(i);
			TfwSrvConn *srv_conn =
					sg->sched->sched_sg_conn(msg, sg);
			EXPECT_NOT_NULL(srv_conn);
			if (!srv_conn)
				goto err;

			conn_acc_check ^= (long long)srv_conn;
			tfw_srv_conn_put(srv_conn);
			sched_helper_rr.free_sched_arg(msg);
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_rr, sched_sg_max_srv_zero_conn)
{
	test_sched_sg_max_srv_zero_conn(&sched_helper_rr);
}

TEST(tfw_sched_rr, sched_sg_max_srv_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_rr.sched);

	for (i = 0; i < TFW_TEST_SG_SRV_N; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_TEST_SRV_CONN_N; ++j) {
			TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, srv_conn);
			conn_acc ^= (long long)srv_conn;
		}
	}

	/*
	 * Check that connections is scheduled in the fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_rr.conn_types; ++i) {
		conn_acc_check = 0;

		for (j = 0; j < TFW_TEST_SG_CONN_N; ++j) {
			TfwMsg *msg = sched_helper_rr.get_sched_arg(i);
			TfwSrvConn *srv_conn =
					sg->sched->sched_sg_conn(msg, sg);
			EXPECT_NOT_NULL(srv_conn);
			if (!srv_conn)
				goto err;

			conn_acc_check ^= (long long)srv_conn;
			tfw_srv_conn_put(srv_conn);
			sched_helper_rr.free_sched_arg(msg);
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_rr, sched_srv_one_srv_zero_conn)
{
	test_sched_srv_one_srv_zero_conn(&sched_helper_rr);
}

TEST(tfw_sched_rr, sched_srv_one_srv_max_conn)
{
	size_t i, j;
	long long conn_acc = 0, conn_acc_check = 0;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_rr.sched);
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_TEST_SRV_CONN_N; ++i) {
		TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, srv_conn);
		conn_acc ^= (long long)srv_conn;
	}

	/*
	 * Check that connections is scheduled in the fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_rr.conn_types; ++i) {
		conn_acc_check = 0;

		for (j = 0; j < TFW_TEST_SRV_CONN_N; ++j) {
			TfwMsg *msg = sched_helper_rr.get_sched_arg(i);
			TfwSrvConn *srv_conn =
					sg->sched->sched_srv_conn(msg, srv);
			EXPECT_NOT_NULL(srv_conn);
			if (!srv_conn)
				goto err;
			EXPECT_EQ((TfwServer *)srv_conn->peer, srv);

			conn_acc_check ^= (long long)srv_conn;
			tfw_srv_conn_put(srv_conn);
			sched_helper_rr.free_sched_arg(msg);
		}

		EXPECT_EQ(conn_acc, conn_acc_check);
	}
err:
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_rr, sched_srv_max_srv_zero_conn)
{
	test_sched_srv_max_srv_zero_conn(&sched_helper_rr);
}

TEST(tfw_sched_rr, sched_srv_max_srv_max_conn)
{
	size_t i, j;
	long long conn_acc_check = 0;
	TfwSrvGroup *sg;
	struct ConnChecker {
		TfwServer *srv;
		long long conn_acc;
	} *srv_acc;

	srv_acc = kcalloc(sizeof(struct ConnChecker), TFW_TEST_SG_SRV_N,
			  GFP_KERNEL);
	BUG_ON(!srv_acc);

	sg = test_create_sg("test", sched_helper_rr.sched);

	for (i = 0; i < TFW_TEST_SG_SRV_N; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);
		srv_acc[i].srv = srv;

		for (j = 0; j < TFW_TEST_SRV_CONN_N; ++j) {
			TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, srv_conn);
			srv_acc[i].conn_acc ^= (long long)srv_conn;
		}
	}

	/*
	 * Check that connections is scheduled in the fair way:
	 * every connection will be scheduled only once
	 */
	for (i = 0; i < sched_helper_rr.conn_types; ++i) {
		TfwServer *srv;

		list_for_each_entry(srv, &sg->srv_list, list) {
			size_t k = 0;
			conn_acc_check = 0;

			for (j = 0; j < TFW_TEST_SRV_CONN_N; ++j) {
				TfwMsg *msg = sched_helper_rr.get_sched_arg(i);
				TfwSrvConn *srv_conn =
					sg->sched->sched_srv_conn(msg, srv);
				EXPECT_NOT_NULL(srv_conn);
				if (!srv_conn)
					goto err;
				EXPECT_EQ((TfwServer *)srv_conn->peer, srv);

				conn_acc_check ^= (long long)srv_conn;
				tfw_srv_conn_put(srv_conn);
				sched_helper_rr.free_sched_arg(msg);
			}

			for (k = 0; k < TFW_TEST_SG_SRV_N; ++k) {
				if (srv_acc[k].srv == srv)
					EXPECT_EQ(srv_acc[k].conn_acc,
						  conn_acc_check);
			}
		}
	}
err:
	if (srv_acc)
		kfree(srv_acc);
	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_rr, sched_srv_offline_srv)
{
	test_sched_srv_offline_srv(&sched_helper_rr);
}

TEST_SUITE(sched_rr)
{
	kernel_fpu_end();

	tfw_server_init();
	tfw_sched_rr_init();

	kernel_fpu_begin();

	/*
	 * Schedulers have the same interface so some test cases can use generic
	 * implementations. Some test cases still have to know how scheduler
	 * work at low level. Please, keep same structure for implementation
	 * aware test cases across all schedulers.
	 *
	 * Implementation aware cases:
	 * sched_sg_one_srv_max_conn
	 * sched_sg_max_srv_max_conn
	 * sched_srv_one_srv_max_conn
	 * sched_srv_max_srv_max_conn
	 */

	TEST_RUN(tfw_sched_rr, sg_empty);

	TEST_RUN(tfw_sched_rr, sched_sg_one_srv_zero_conn);
	TEST_RUN(tfw_sched_rr, sched_sg_one_srv_max_conn);
	TEST_RUN(tfw_sched_rr, sched_sg_max_srv_zero_conn);
	TEST_RUN(tfw_sched_rr, sched_sg_max_srv_max_conn);

	TEST_RUN(tfw_sched_rr, sched_srv_one_srv_zero_conn);
	TEST_RUN(tfw_sched_rr, sched_srv_one_srv_max_conn);
	TEST_RUN(tfw_sched_rr, sched_srv_max_srv_zero_conn);
	TEST_RUN(tfw_sched_rr, sched_srv_max_srv_max_conn);
	TEST_RUN(tfw_sched_rr, sched_srv_offline_srv);
}
