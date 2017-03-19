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
#define tfw_sock_srv_init test_hash_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_hash_sock_srv_exit
#undef tfw_srv_conn_release
#define tfw_srv_conn_release test_hash_srv_conn_release
#undef tfw_sock_srv_cfg_mod
#define tfw_sock_srv_cfg_mod test_hash_sock_srv_cfg_mod

#include "sock_srv.c"

#ifdef module_init
#undef module_init
#undef module_exit
#define module_init(func)
#define module_exit(func)
#endif

#include "../../sched/tfw_sched_hash.c"

#include "helpers.h"
#include "http_msg.h"
#include "sched_helper.h"
#include "test.h"

static char *req_strs[] = {
	"GET / HTTP/1.1\r\nhost:host1\r\n\r\n",
	"GET / HTTP/1.1\r\nhost:host2\r\n\r\n",
	"GET / HTTP/1.1\r\nhost:host3\r\n\r\n",
	"GET / HTTP/1.1\r\nhost:host4\r\n\r\n",
};

static TfwMsg *sched_hash_get_arg(size_t conn_type);

static void
sched_hash_free_arg(TfwMsg *msg)
{
	test_req_free((TfwHttpReq *)msg);
}

static struct TestSchedHelper sched_helper_hash = {
	.sched = "hash",
	.conn_types = ARRAY_SIZE(req_strs),
	.get_sched_arg = &sched_hash_get_arg,
	.free_sched_arg = &sched_hash_free_arg,
};

static TfwMsg *
sched_hash_get_arg(size_t conn_type)
{
	TfwHttpReq *req = NULL;

	BUG_ON(conn_type >= sched_helper_hash.conn_types);

	req = test_req_alloc(strlen(req_strs[conn_type]));
	tfw_http_parse_req(req,
			   (unsigned char *) req_strs[conn_type],
			   strlen(req_strs[conn_type]));

	return (TfwMsg *) req;
}

TEST(tfw_sched_hash, sg_empty)
{
	test_sched_sg_empty_sg(&sched_helper_hash);
}

TEST(tfw_sched_hash, sched_sg_one_srv_zero_conn)
{
	test_sched_sg_one_srv_zero_conn(&sched_helper_hash);
}

TEST(tfw_sched_hash, sched_sg_one_srv_max_conn)
{
	size_t i, j;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_hash.sched);
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_SRV_MAX_CONN; ++i) {
		TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, srv_conn);
	}

	/* Check that every request is scheduled to the same connection. */
	for (i = 0; i < sched_helper_hash.conn_types; ++i) {
		TfwSrvConn *exp_conn = NULL;

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_hash.get_sched_arg(i);
			TfwSrvConn *srv_conn = sg->sched->sched_sg(msg, sg);
			EXPECT_NOT_NULL(srv_conn);

			if (!exp_conn)
				exp_conn = srv_conn;
			else
				EXPECT_EQ(srv_conn, exp_conn);

			tfw_srv_conn_put(srv_conn);
			sched_helper_hash.free_sched_arg(msg);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_hash, sched_sg_max_srv_zero_conn)
{
	test_sched_sg_max_srv_zero_conn(&sched_helper_hash);
}

TEST(tfw_sched_hash, sched_sg_max_srv_max_conn)
{
	size_t i, j;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_hash.sched);

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, srv_conn);
		}
	}

	/* Check that every request is scheduled to the same connection. */
	for (i = 0; i < sched_helper_hash.conn_types; ++i) {
		TfwSrvConn *exp_conn = NULL;

		for (j = 0; j < TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_hash.get_sched_arg(i);
			TfwSrvConn *srv_conn = sg->sched->sched_sg(msg, sg);
			EXPECT_NOT_NULL(srv_conn);

			if (!exp_conn)
				exp_conn = srv_conn;
			else
				EXPECT_EQ(srv_conn, exp_conn);

			tfw_srv_conn_put(srv_conn);
			sched_helper_hash.free_sched_arg(msg);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_hash, sched_srv_one_srv_zero_conn)
{
	test_sched_srv_one_srv_zero_conn(&sched_helper_hash);
}

TEST(tfw_sched_hash, sched_srv_one_srv_max_conn)
{
	size_t i, j;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_hash.sched);
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_SRV_MAX_CONN; ++i) {
		TfwSrvConn *srv_conn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, srv_conn);
	}

	/* Check that every request is scheduled to the same connection. */
	for (i = 0; i < sched_helper_hash.conn_types; ++i) {
		TfwSrvConn *exp_conn = NULL;

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_hash.get_sched_arg(i);
			TfwSrvConn *srv_conn = sg->sched->sched_srv(msg, srv);

			EXPECT_NOT_NULL(srv_conn);
			EXPECT_EQ((TfwServer *)srv_conn->peer, srv);

			if (!exp_conn)
				exp_conn = srv_conn;
			else
				EXPECT_EQ(srv_conn, exp_conn);

			tfw_srv_conn_put(srv_conn);
			sched_helper_hash.free_sched_arg(msg);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_hash, sched_srv_max_srv_zero_conn)
{
	test_sched_srv_max_srv_zero_conn(&sched_helper_hash);
}

TEST(tfw_sched_hash, sched_srv_max_srv_max_conn)
{
	size_t i, j;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_hash.sched);

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwSrvConn *srv_conn =
					test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, srv_conn);
		}
	}

	/* Check that every request is scheduled to the same connection. */
	for (i = 0; i < sched_helper_hash.conn_types; ++i) {
		TfwServer *srv;

		list_for_each_entry(srv, &sg->srv_list, list) {
			TfwSrvConn *exp_conn = NULL;

			for (j = 0; j < TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN; ++j) {
				TfwMsg *msg = sched_helper_hash.get_sched_arg(i);
				TfwSrvConn *srv_conn =
					sg->sched->sched_srv(msg, srv);

				EXPECT_NOT_NULL(srv_conn);
				EXPECT_EQ((TfwServer *)srv_conn->peer, srv);

				if (!exp_conn)
					exp_conn = srv_conn;
				else
					EXPECT_EQ(srv_conn, exp_conn);

				tfw_srv_conn_put(srv_conn);
				sched_helper_hash.free_sched_arg(msg);
			}
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_hash, sched_srv_offline_srv)
{
	test_sched_srv_offline_srv(&sched_helper_hash);
}

TEST_SUITE(sched_hash)
{
	kernel_fpu_end();

	tfw_sched_hash_init();
	tfw_server_init();

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

	TEST_RUN(tfw_sched_hash, sg_empty);

	TEST_RUN(tfw_sched_hash, sched_sg_one_srv_zero_conn);
	TEST_RUN(tfw_sched_hash, sched_sg_one_srv_max_conn);
	TEST_RUN(tfw_sched_hash, sched_sg_max_srv_zero_conn);
	TEST_RUN(tfw_sched_hash, sched_sg_max_srv_max_conn);

	TEST_RUN(tfw_sched_hash, sched_srv_one_srv_zero_conn);
	TEST_RUN(tfw_sched_hash, sched_srv_one_srv_max_conn);
	TEST_RUN(tfw_sched_hash, sched_srv_max_srv_zero_conn);
	TEST_RUN(tfw_sched_hash, sched_srv_max_srv_max_conn);
	TEST_RUN(tfw_sched_hash, sched_srv_offline_srv);
}
