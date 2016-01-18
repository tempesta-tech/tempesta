/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#undef tfw_sock_srv_init
#define tfw_sock_srv_init test_sock_srv_conn_init
#undef tfw_sock_srv_exit
#define tfw_sock_srv_exit test_sock_srv_exit
#undef tfw_sock_srv_drop
#define tfw_sock_srv_drop test_sock_srv_drop
#undef tfw_srv_conn_release
#define tfw_srv_conn_release test_srv_conn_release
#undef tfw_sock_srv_cfg_mod
#define tfw_sock_srv_cfg_mod test_sock_srv_cfg_mod
#include "sock_srv.c"

#include "server.h"
#include "sched_helper.h"

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

	sg = tfw_sg_new(name, GFP_KERNEL);
	BUG_ON(!sg);

	{
		int r = tfw_sg_set_sched(sg, sched_name);
		BUG_ON(r);
	}

	return sg;
}

void
test_sg_release_all(void)
{
	tfw_sg_release_all();
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

	srv = tfw_create_server(&addr);
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
	if(!tfw_srv_conn_cache)
		tfw_sock_srv_init();
	srv_conn = tfw_srv_conn_alloc();

	BUG_ON(!srv_conn);
	tfw_connection_link_peer(&srv_conn->conn, peer);
	srv_conn->conn.sk = &__test_sock;

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
			tfw_srv_conn_free((TfwSrvConnection *)conn);
		}
	}
}
