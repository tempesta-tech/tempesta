/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
 
#include "sched_helper.h"
#include "kallsyms_helper.h"

TfwSrvConnection *tfw_srv_conn_alloc(void);
void tfw_srv_conn_free(TfwConnection *conn);

/* Export syms*/
static TfwSrvGroup *(*tfw_sg_new_ptr)(const char *name, gfp_t flags);
static int (*tfw_sg_set_sched_ptr)(TfwSrvGroup *sg, const char *sched);
static TfwServer *(*tfw_create_server_ptr)(const TfwAddr *addr);
static void (*tfw_sg_release_all_ptr)(void);
static TfwSrvConnection *(*tfw_srv_conn_alloc_ptr)(void);
static void (*tfw_srv_conn_free_ptr)(TfwSrvConnection *srv_conn);

void
sched_helper_init(void)
{
	tfw_sg_new_ptr = get_sym_ptr("tfw_sg_new");
	tfw_sg_set_sched_ptr = get_sym_ptr("tfw_sg_set_sched");
	tfw_create_server_ptr = get_sym_ptr("tfw_create_server");
	tfw_sg_release_all_ptr = get_sym_ptr("tfw_sg_release_all");
	tfw_srv_conn_alloc_ptr = get_sym_ptr("tfw_srv_conn_alloc");
	tfw_srv_conn_free_ptr = get_sym_ptr("tfw_srv_conn_free");

	BUG_ON(tfw_sg_new_ptr == NULL);
	BUG_ON(tfw_sg_set_sched_ptr == NULL);
	BUG_ON(tfw_create_server_ptr == NULL);
	BUG_ON(tfw_sg_release_all_ptr == NULL);
	BUG_ON(tfw_srv_conn_alloc_ptr == NULL);
	BUG_ON(tfw_srv_conn_free_ptr == NULL);
}

TfwSrvGroup *
test_create_sg(const char *name, const char *sched_name)
{
	TfwSrvGroup *sg;

	BUG_ON(tfw_sg_new_ptr == NULL);
	sg = tfw_sg_new_ptr(name, GFP_KERNEL);
	BUG_ON(!sg);

	BUG_ON(tfw_sg_set_sched_ptr == NULL);
	{
		int r = tfw_sg_set_sched_ptr(sg, sched_name);
		BUG_ON(r);
	}

	return sg;
}

void
test_sg_release_all(void)
{
	BUG_ON(tfw_sg_release_all_ptr == NULL);
	tfw_sg_release_all_ptr();
}

TfwServer *
test_create_srv(const char *in_addr, TfwSrvGroup *sg)
{
	TfwAddr addr;
	TfwServer *srv;

	{
		int r = tfw_addr_pton(in_addr, &addr);
		BUG_ON(r);
	}

	BUG_ON(tfw_create_server_ptr == NULL);
	srv = tfw_create_server_ptr(&addr);
	BUG_ON(!srv);

	tfw_sg_add(sg, srv);

	return srv;
}
TfwSrvConnection *
test_create_conn(TfwPeer *peer)
{
	void (*tfw_connection_link_peer)(TfwConnection *conn,TfwPeer *peer);

	static struct sock __test_sock = {
		.sk_state = TCP_ESTABLISHED,
	};
	TfwSrvConnection *srv_conn;


	tfw_connection_link_peer = get_sym_ptr("tfw_connection_link_peer");
	

	if(!tfw_connection_link_peer)
		TFW_DBG("sched_help: link_peer ptr null\n");

	BUG_ON(tfw_srv_conn_alloc_ptr == NULL);
	srv_conn = tfw_srv_conn_alloc_ptr();
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
			BUG_ON(tfw_srv_conn_free_ptr == NULL);
			tfw_srv_conn_free_ptr((TfwSrvConnection *)conn);
		}
	}
}
