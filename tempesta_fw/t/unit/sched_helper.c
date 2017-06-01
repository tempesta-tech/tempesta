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
	}
}

TfwSrvGroup *
test_create_sg(const char *name)
{
	TfwSrvGroup *sg;

	kernel_fpu_end();

	sg = tfw_sg_new(name, GFP_ATOMIC);
	BUG_ON(!sg);

	sg->max_qsize = 100;

	kernel_fpu_begin();

	return sg;
}

void
test_start_sg(TfwSrvGroup *sg, const char *sched_name, unsigned int flags)
{
	int r;

	kernel_fpu_end();

	sg->flags = flags;
	/* Adjust servers weights for static ratio scheduler. */
	if (!strcmp(sched_name, "ratio")
	    && (sg->flags & TFW_SG_F_SCHED_RATIO_STATIC))
	{
		tfw_cfg_sg_ratio_adjust(&sg->srv_list);
	}
	r = tfw_sg_set_sched(sg, sched_name);
	BUG_ON(r);

	kernel_fpu_begin();
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

TfwSrvConn *
test_create_srv_conn(TfwServer *srv)
{
	static struct sock __test_sock = {
		.sk_state = TCP_ESTABLISHED,
	};
	TfwSrvConn *srv_conn;

	kernel_fpu_end();

	if (!tfw_srv_conn_cache)
		tfw_sock_srv_init();
	srv_conn = tfw_srv_conn_alloc();
	BUG_ON(!srv_conn);

	tfw_connection_link_peer((TfwConn *)srv_conn, (TfwPeer *)srv);
	srv_conn->sk = &__test_sock;
	/* A connection is skipped by schedulers if (refcnt <= 0). */
	tfw_connection_revive((TfwConn *)srv_conn);

	srv->conn_n++;

	kernel_fpu_begin();

	return srv_conn;
}

void
test_conn_release_all(TfwSrvGroup *sg)
{
	TfwServer *srv;
	TfwConn *conn, *tmp;

	list_for_each_entry(srv, &sg->srv_list, list) {
		list_for_each_entry_safe(conn, tmp, &srv->conn_list, list) {
			conn->sk = NULL;
			tfw_connection_unlink_from_peer(conn);
			while (tfw_connection_live(conn))
				tfw_connection_put(conn);
			tfw_srv_conn_free((TfwSrvConn *)conn);
		}
	}
}

/**
 * Unit test. Message cannot be scheduled to server if it is in failovering
 * process.
 */
void
test_sched_srv_offline_srv(struct TestSchedHelper *sched_helper)
{
	size_t i;
	size_t offline_num = 3;
	TfwServer *offline_srv = NULL;
	TfwSrvGroup *sg;
	TfwServer *srv;
	TfwSrvConn *srv_conn;

	BUG_ON(!sched_helper);
	BUG_ON(!sched_helper->sched);
	BUG_ON(!sched_helper->conn_types);
	BUG_ON(!sched_helper->get_sched_arg);
	BUG_ON(!sched_helper->free_sched_arg);
	BUG_ON(offline_num >= TFW_TEST_SG_MAX_SRV_N);

	sg = test_create_sg("test");

	for (i = 0; i < TFW_TEST_SG_MAX_SRV_N; ++i) {
		srv = test_create_srv("127.0.0.1", sg);
		srv_conn = test_create_srv_conn(srv);

		if (i == offline_num)
			offline_srv = srv;
	}
	list_for_each_entry(srv, &sg->srv_list, list) {
		if (srv == offline_srv) {
			list_for_each_entry(srv_conn, &srv->conn_list, list)
				atomic_set(&srv_conn->refcnt, 0);
			break;
		}
	}
	test_start_sg(sg, sched_helper->sched, sched_helper->flags);

	for (i = 0; i < sched_helper->conn_types; ++i) {
		TfwMsg *msg = sched_helper->get_sched_arg(i);

		list_for_each_entry(srv, &sg->srv_list, list) {
			srv_conn = sg->sched->sched_srv_conn(msg, srv);

			if (srv == offline_srv)
				EXPECT_NULL(srv_conn);
			else
				EXPECT_NOT_NULL(srv_conn);
			/*
			 * Don't let the kernel watchdog decide
			 * that we're stuck in a locked context.
			 */
			kernel_fpu_end();
			schedule();
			kernel_fpu_begin();
		}
		sched_helper->free_sched_arg(msg);
	}

	test_conn_release_all(sg);
	test_sg_release_all();
}
