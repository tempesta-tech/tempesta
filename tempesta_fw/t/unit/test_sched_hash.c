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
	test_sched_generic_empty_sg(&sched_helper_hash);
}

TEST(tfw_sched_hash, one_srv_in_sg_and_zero_conn)
{
	test_sched_generic_one_srv_zero_conn(&sched_helper_hash);
}

/*
 * This unit test is implementation aware and checks more than just interface.
 * Note, that it is very similar to other tests (one_srv_in_sg_and_max_conn and
 * max_srv_in_sg_and_max_conn) for round-robin and hash schedullers. So if test
 * structure is changed, other mentioned in above tests should be also be
 * updated
 */
TEST(tfw_sched_hash, one_srv_in_sg_and_max_conn)
{
	size_t i, j;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_hash.sched);
	TfwServer *srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < TFW_SRV_MAX_CONN; ++i) {
		TfwSrvConnection *sconn = test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, &sconn->conn);
	}

	/* Check that every request is scheduled to the same connection. */
	for (i = 0; i < sched_helper_hash.conn_types; ++i) {
		TfwConnection *exp_conn = NULL;

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_hash.get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_srv(msg, sg);
			EXPECT_NOT_NULL(conn);

			if (!exp_conn)
				exp_conn = conn;
			else
				EXPECT_EQ(conn, exp_conn);

			tfw_connection_put(conn);
			sched_helper_hash.free_sched_arg(msg);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST(tfw_sched_hash, max_srv_in_sg_and_zero_conn)
{
	test_sched_generic_max_srv_zero_conn(&sched_helper_hash);
}

/*
 * This unit test is implementation aware and checks more than just interface.
 * Note, that it is very similar to other tests (one_srv_in_sg_and_max_conn and
 * max_srv_in_sg_and_max_conn) for round-robin and hash schedullers. So if test
 * structure is changed, other mentioned in above tests should be also be
 * updated
 */
TEST(tfw_sched_hash, max_srv_in_sg_and_max_conn)
{
	size_t i, j;

	TfwSrvGroup *sg = test_create_sg("test", sched_helper_hash.sched);

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);

		for (j = 0; j < TFW_SRV_MAX_CONN; ++j) {
			TfwSrvConnection *sconn =
					test_create_conn((TfwPeer *)srv);
			sg->sched->add_conn(sg, srv, &sconn->conn);
		}
	}

	/* Check that every request is scheduled to the same connection. */
	for (i = 0; i < sched_helper_hash.conn_types; ++i) {
		TfwConnection *exp_conn = NULL;

		for (j = 0; j < TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN; ++j) {
			TfwMsg *msg = sched_helper_hash.get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_srv(msg, sg);
			EXPECT_NOT_NULL(conn);

			if (!exp_conn)
				exp_conn = conn;
			else
				EXPECT_EQ(conn, exp_conn);

			tfw_connection_put(conn);
			sched_helper_hash.free_sched_arg(msg);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}

TEST_SUITE(sched_hash)
{
	kernel_fpu_end();

	tfw_sched_hash_init();
	tfw_server_init();

	kernel_fpu_begin();

	TEST_RUN(tfw_sched_hash, sg_empty);
	TEST_RUN(tfw_sched_hash, one_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_hash, one_srv_in_sg_and_max_conn);
	TEST_RUN(tfw_sched_hash, max_srv_in_sg_and_zero_conn);
	TEST_RUN(tfw_sched_hash, max_srv_in_sg_and_max_conn);
}
