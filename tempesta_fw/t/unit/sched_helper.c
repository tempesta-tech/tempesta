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
#include <asm/i387.h>

#undef tfw_sock_srv_init
#define tfw_sock_srv_init test_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_sock_srv_exit
#undef tfw_srv_conn_release
#define tfw_srv_conn_release test_srv_conn_release
#undef tfw_sock_srv_cfg_mod
#define tfw_sock_srv_cfg_mod test_sock_srv_cfg_mod
#include "sock_srv.c"

#include "server.h"
#include "sched_helper.h"
#include "test.h"

void
test_spec_cleanup(TfwCfgSpec specs[])
{
	TfwCfgSpec *spec;

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (spec->call_counter && spec->cleanup) {
			TFW_DBG2("spec cleanup: '%s'\n", spec->name);
			spec->cleanup(spec);
		}
		spec->call_counter = 0;

		/**
		 * When spec processing function is tfw_cfg_handle_children(),
		 * a user-defined .cleanup function for that spec is not
		 * allowed. Instead, an special .cleanup function is assigned
		 * to that spec, thus overwriting the (zero) value there.
		 * When the whole cleanup process completes, revert that spec
		 * entry to original (zero) value. That will allow reuse of
		 * the spec.
		 */
		if (spec->handler == &tfw_cfg_handle_children) {
			spec->cleanup = NULL;
		}
	}
}

TfwSrvGroup *
test_create_sg(const char *name, const char *sched_name)
{
	TfwSrvGroup *sg;

	kernel_fpu_end();

	sg = tfw_sg_new(name, GFP_ATOMIC);
	BUG_ON(!sg);

	{
		int r = tfw_sg_set_sched(sg, sched_name);
		BUG_ON(r);
	}

	kernel_fpu_begin();

	return sg;
}

void
test_sg_release_all(void)
{
	kernel_fpu_end();

	tfw_sg_release_all();

	kernel_fpu_begin();
}

TfwServer *
test_create_srv(const char *in_addr, TfwSrvGroup *sg)
{
	TfwAddr addr;
	TfwServer *srv;

	{
		int r = tfw_addr_pton(&TFW_STR_FROM(in_addr), &addr);
		BUG_ON(r);
	}

	srv = tfw_server_create(&addr);
	BUG_ON(!srv);

	tfw_sg_add(sg, srv);

	return srv;
}

TfwSrvConnection *
test_create_conn(TfwPeer *peer)
{
	static struct sock __test_sock = {
		.sk_state = TCP_ESTABLISHED,
	};
	TfwSrvConnection *srv_conn;

	kernel_fpu_end();

	if (!tfw_srv_conn_cache)
		tfw_sock_srv_init();
	srv_conn = tfw_srv_conn_alloc();

	BUG_ON(!srv_conn);
	tfw_connection_link_peer(&srv_conn->conn, peer);
	srv_conn->conn.sk = &__test_sock;
	/* A connection is skipped by schedulers if (refcnt <= 0). */
	tfw_connection_revive(&srv_conn->conn);

	kernel_fpu_begin();

	return srv_conn;
}

void
test_conn_release_all(TfwSrvGroup *sg)
{
	TfwConnection *conn, *conn_tmp;
	TfwServer *srv, *srv_tmp;

	list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list) {
		list_for_each_entry_safe(conn, conn_tmp, &srv->conn_list, list) {
			conn->sk = NULL;
			tfw_connection_unlink_from_peer(conn);
			while (tfw_connection_nfo(conn)) {
				tfw_connection_put(conn);
			}
			tfw_srv_conn_free((TfwSrvConnection *)conn);
		}
	}
}

/**
 * Unit test. Message cannot be scheduled to empty server group.
 */
void
test_sched_sg_conn_empty_sg(struct TestSchedHelper *sched_helper)
{
	size_t i;
	TfwSrvGroup *sg;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);

	sg = test_create_sg("test", sched_helper->sched);

	for (i = 0; i < sched_helper->conn_types; ++i) {
		TfwMsg *msg = sched_helper->get_sched_arg(i);
		TfwConnection *conn = sg->sched->sched_sg_conn(msg, sg);

		EXPECT_NULL(conn);
		sched_helper->free_sched_arg(msg);
	}

	test_sg_release_all();
}

/**
 * Unit test. Message cannot be scheduled to server group if server in that
 * group have no live connections.
 */
void
test_sched_sg_conn_one_srv_zero_conn(struct TestSchedHelper *sched_helper)
{
	size_t i;
	TfwSrvGroup *sg;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);

	sg = test_create_sg("test", sched_helper->sched);

	test_create_srv("127.0.0.1", sg);

	for (i = 0; i < sched_helper->conn_types; ++i) {
		TfwMsg *msg = sched_helper->get_sched_arg(i);
		TfwConnection *conn = sg->sched->sched_sg_conn(msg, sg);

		EXPECT_NULL(conn);
		sched_helper->free_sched_arg(msg);
	}

	test_sg_release_all();
}

/**
 * Unit test. Message cannot be scheduled to server group if servers in that
 * group have no live connections. Server group contain as much servers as
 * possible.
 */
void
test_sched_sg_conn_max_srv_zero_conn(struct TestSchedHelper *sched_helper)
{
	size_t i, j;
	TfwSrvGroup *sg;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);

	sg = test_create_sg("test", sched_helper->sched);

	for (j = 0; j < TFW_SG_MAX_SRV; ++j)
		test_create_srv("127.0.0.1", sg);

	for (i = 0; i < sched_helper->conn_types; ++i) {
		for (j = 0; j < TFW_SG_MAX_SRV; ++j) {
			TfwMsg *msg = sched_helper->get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_sg_conn(msg, sg);

			EXPECT_NULL(conn);
			sched_helper->free_sched_arg(msg);
		}
	}

	test_sg_release_all();
}

/**
 * Unit test. Message cannot be scheduled to server if it has no live
 * connections.
 */
void
test_sched_srv_conn_one_srv_zero_conn(struct TestSchedHelper *sched_helper)
{
	size_t i;
	TfwSrvGroup *sg;
	TfwServer *srv;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);

	sg = test_create_sg("test", sched_helper->sched);

	srv = test_create_srv("127.0.0.1", sg);

	for (i = 0; i < sched_helper->conn_types; ++i) {
		TfwMsg *msg = sched_helper->get_sched_arg(i);
		TfwConnection *conn = sg->sched->sched_srv_conn(msg, srv);

		EXPECT_NULL(conn);
		sched_helper->free_sched_arg(msg);
	}

	test_sg_release_all();
}

/**
 * Unit test. Message cannot be scheduled to any server of server group if
 * there is no no live connections across all server.
 */
void
test_sched_srv_conn_max_srv_zero_conn(struct TestSchedHelper *sched_helper)
{
	size_t i, j;
	TfwSrvGroup *sg;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);

	sg = test_create_sg("test", sched_helper->sched);

	for (j = 0; j < TFW_SG_MAX_SRV; ++j)
		test_create_srv("127.0.0.1", sg);

	for (i = 0; i < sched_helper->conn_types; ++i) {
		TfwServer *srv;

		list_for_each_entry(srv, &sg->srv_list, list) {
			TfwMsg *msg = sched_helper->get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_srv_conn(msg, srv);

			EXPECT_NULL(conn);
			sched_helper->free_sched_arg(msg);
		}
	}

	test_sg_release_all();
}

/**
 * Unit test. Message cannot be scheduled to server if it is in failovering
 * process.
 */
void
test_sched_srv_conn_offline_srv(struct TestSchedHelper *sched_helper)
{
	size_t i;
	size_t offline_num = 3;
	TfwServer *offline_srv = NULL;
	TfwSrvGroup *sg;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);
	BUG_ON(offline_num >= TFW_SG_MAX_SRV);

	sg = test_create_sg("test", sched_helper->sched);

	for (i = 0; i < TFW_SG_MAX_SRV; ++i) {
		TfwServer *srv = test_create_srv("127.0.0.1", sg);
		TfwSrvConnection *sconn =
				test_create_conn((TfwPeer *)srv);
		sg->sched->add_conn(sg, srv, &sconn->conn);

		if (i == offline_num) {
			offline_srv = srv;
			atomic_set(&sconn->conn.refcnt, 0);
		}
	}

	for (i = 0; i < sched_helper->conn_types; ++i) {
		TfwServer *srv;
		list_for_each_entry(srv, &sg->srv_list, list) {
			TfwMsg *msg = sched_helper->get_sched_arg(i);
			TfwConnection *conn = sg->sched->sched_srv_conn(msg, srv);

			if (srv == offline_srv)
				EXPECT_NULL(conn);
			else
				EXPECT_NOT_NULL(conn);
			sched_helper->free_sched_arg(msg);
		}
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}
