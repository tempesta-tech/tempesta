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

#include "connection.h"
#include "sched_helper.h"
#include "server.h"
#define TFW_SOCK_SRV_RETRY_TIMER_MIN	10
#define TFW_SOCK_SRV_RETRY_TIMER_MAX	(1000 * 300)

static struct kmem_cache *test_conn_cache;

void
test_spec_cleanup(TfwCfgSpec specs[])
{
	TfwCfgSpec *spec;

	TFW_CFG_FOR_EACH_SPEC(spec, specs) {
		if (spec->call_counter && spec->cleanup) {
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

static int
test_connect_try(TestConnection *srv_conn)
{
	int r;
	TfwAddr *addr;
	struct sock *sk;
	TfwConnection *conn = &srv_conn->conn;

	addr = &conn->peer->addr;

	r = ss_sock_create(addr->family, SOCK_STREAM, IPPROTO_TCP, &sk);
	if (r) {
		TFW_ERR("Unable to create server socket\n");
		return r;
	}

	/*
	 * Setup connection handlers before ss_connect() call. We can get
	 * an established connection right when we're in the call in case
	 * of a local peer connection, so all handlers must be installed
	 * before the call.
	 */
	sock_set_flag(sk, SOCK_DBG);
	tfw_connection_link_from_sk(conn, sk);
	ss_set_callbacks(sk);

	/*
	 * There are two possible use patterns of this function:
	 *
	 * 1. tfw_sock_srv_connect_srv() called in system initialization
	 *    phase before initialization of client listening interfaces,
	 *    so there is no activity in the socket;
	 *
	 * 2. tfw_sock_srv_do_failover() upcalled from SS layer and with
	 *    inactive conn->sk, so nobody can send through the socket.
	 *    Also since the function is called by connection_error or
	 *    connection_drop hook from SoftIRQ, there can't be another
	 *    socket state change upcall from SS layer due to RSS.
	 *
	 * Thus we don't need syncronization for ss_connect().
	 */
	r = ss_connect(sk, &addr->sa, tfw_addr_sa_len(addr), 0);
	if (r) {
		TFW_ERR("Unable to initiate a connect to server: %d\n", r);
		tfw_connection_unlink_from_sk(sk);
		ss_close(sk);
		return r;
	}

	return 0;
}

static inline void
test_connect_try_later(TestConnection *srv_conn)
{
	/*
	 * Timeout between connect attempts is increased with each
	 * unsuccessful attempt. Length of the timeout is decided
	 * with a variant of exponential backoff delay algorithm.
	 */
	if (srv_conn->timeout < TFW_SOCK_SRV_RETRY_TIMER_MAX) {
		srv_conn->timeout = min(TFW_SOCK_SRV_RETRY_TIMER_MAX,
					TFW_SOCK_SRV_RETRY_TIMER_MIN
					* (1 << srv_conn->attempts));
		srv_conn->attempts++;
	}
	mod_timer(&srv_conn->retry_timer,
		  jiffies + msecs_to_jiffies(srv_conn->timeout));
}

static void
test_connect_retry_timer_cb(unsigned long data)
{
	TestConnection *srv_conn = (TestConnection *)data;

	/* A new socket is created for each connect attempt. */
	if (test_connect_try(srv_conn))
		test_connect_try_later(srv_conn);
}

static inline void
test_reset_retry_timer(TestConnection *srv_conn)
{
	srv_conn->timeout = 0;
	srv_conn->attempts = 0;
}

static inline void
test_setup_retry_timer(TestConnection *srv_conn)
{
	test_reset_retry_timer(srv_conn);
	setup_timer(&srv_conn->retry_timer,
		    test_connect_retry_timer_cb,
		    (unsigned long)srv_conn);
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
		if (r != 0)
			sg = NULL;		
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

TestConnection *
test_create_conn(TfwPeer *peer)
{
	static struct sock __test_sock = {
		.sk_state = TCP_ESTABLISHED,
	};
	TestConnection *srv_conn;

	if(!test_conn_cache)
		test_conn_cache = kmem_cache_create("test_conn_cache", \
						    sizeof(TestConnection), 0, 0, NULL);

	srv_conn = (TestConnection *)kmem_cache_alloc(test_conn_cache, 
						      GFP_ATOMIC);
	tfw_connection_init(&srv_conn->conn);
	test_setup_retry_timer((TestConnection*)srv_conn);
	BUG_ON(!srv_conn);
	tfw_connection_link_peer(&srv_conn->conn, peer);
	srv_conn->conn.sk = &__test_sock;

	return srv_conn;
}

static void
test_conn_free(TestConnection *srv_conn)
{
	timer_pending(&srv_conn->retry_timer);
	tfw_connection_validate_cleanup(&srv_conn->conn);
	kmem_cache_free(test_conn_cache,srv_conn);
}

void
test_conn_release_all(TfwSrvGroup *sg)
{
	TfwConnection *conn, *conn_tmp;
	TfwServer *srv, *srv_tmp;

	list_for_each_entry_safe(srv, srv_tmp, &sg->srv_list, list) {
		list_for_each_entry_safe(conn, conn_tmp, &srv->conn_list, list) {
			((TestConnection *)conn)->conn.sk = NULL;
			tfw_connection_unlink_from_peer(
					   &((TestConnection *)conn)->conn);
			test_conn_free((TestConnection *)conn);
		}
	}
}
