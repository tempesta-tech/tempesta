#include "sched_helper.h"

TfwSrvConnection *tfw_srv_conn_alloc(void);
void tfw_srv_conn_free(TfwSrvConnection *srv_conn);

TfwSrvGroup *
test_create_sg(const char *name, const char *sched_name)
{
	TfwSrvGroup *sg = tfw_sg_new(name, GFP_KERNEL);
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
		int r = tfw_addr_pton(in_addr, &addr);
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
	TfwSrvConnection *srv_conn = tfw_srv_conn_alloc();
	BUG_ON(!srv_conn);

	tfw_connection_link_peer(&srv_conn->conn, peer);
	srv_conn->conn.sk = (struct sock *)1;

	return srv_conn;
}

void
test_conn_release_all(TfwSrvGroup *sg)
{
	TfwSrvConnection *conn, *conn_tmp;
	TfwServer *srv, *srv_tmp;

	list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list) {
		list_for_each_entry_safe(conn, conn_tmp, &srv->conn_list, conn.list) {
			conn->conn.sk = NULL;
			tfw_connection_unlink_peer(&conn->conn);
			tfw_srv_conn_free(conn);
		}
	}
}
