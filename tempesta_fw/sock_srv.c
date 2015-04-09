/**
 *		Tempesta FW
 *
 * Handling server connections.
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

/**
 * TODO
 * -- [connection pool, reverse proxy only] establish N connections with each server
 *    for better parallelization on the server side.
 * -- limit number of persistent connections to be able to work as forward
 *    (transparent) proxy (probably we need to switch on/off functionality for
 *    connections pool)
 * -- FIXME synchronize with socket operations.
 */
/*
 * TODO In case of forward proxy manage connections to servers
 * we can have too many servers, so we need to prune low-active
 * connections from the connection pool.
 */
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/freezer.h>
#include <net/inet_sock.h>

#include "tempesta_fw.h"
#include "connection.h"
#include "addr.h"
#include "log.h"
#include "server.h"

/**
 * Create a single connection to the @addr.
 */
static TfwConnection *
tfw_sock_srv_connect(TfwAddr *addr)
{
	static struct {
		SsProto	_placeholder;
		int	type;
	} dummy_proto = {
		.type = TFW_FSM_HTTP,
	};

	int r;
	struct sock *sk;
	struct socket *sock;
	TfwConnection *conn;

	r = sock_create_kern(addr->family, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (r) {
		TFW_ERR("can't create a socket: err=%d\n", r);
		return NULL;
	}

	r = kernel_connect(sock, &addr->sa, tfw_addr_sa_len(addr), 0);
	if (r) {
		sock_release(sock);
		return NULL;
	}

	sk = sock->sk;
	ss_set_callbacks(sk);

	sk->sk_user_data = &dummy_proto;
	conn = tfw_connection_new(sk, Conn_HttpSrv, NULL);
	if (!conn) {
		TFW_ERR("can't create a connection object\n");
		sock_release(sock);
	}

	return conn;
}

/**
 * Delete @srv object with all nested sockets.
 */
static void
tfw_sock_srv_destroy(TfwServer *srv)
{
	TfwConnection *conn, *tmp;

	list_for_each_entry_safe(conn, tmp, &srv->conn_list, list) {
		tfw_peer_del_conn((TfwPeer *)srv, &conn->list);
		sock_release(conn->socket);
	}

	tfw_destroy_server(srv);
}

/**
 * Create a TfwServer object with nested sockets.
 */
static TfwServer *
tfw_sock_srv_create(TfwAddr *addr, int conns_n)
{
	int i;
	TfwServer *srv;
	TfwConnection *conn;

	srv = tfw_create_server(addr);
	if (!srv) {
		TFW_ERR("can't create a server object\n");
	}

	for (i = 0; i < conns_n; ++i) {
		conn = tfw_sock_srv_connect(addr);
		if (!conn) {
			TFW_ERR_ADDR("can't connect to", addr);
			tfw_sock_srv_destroy(srv);
			return NULL;
		}
	}

	TFW_DBG_ADDR("connected", addr);
	return srv;
}

/*
 * ------------------------------------------------------------------------
 *	Configuration handling
 * ------------------------------------------------------------------------
 */

#define TFW_SRV_CFG_DEF_CONNS_N		"4"

/**
 * A "srv_group" which is currently being parsed.
 * All "server" entries are added to this group.
 */
static TfwSrvGroup *tfw_srv_cfg_curr_group;

/**
 * Handle "server" within an "srv_group", e.g.:
 *   srv_group foo {
 *       server 10.0.0.1;
 *       server 10.0.0.2;
 *       server 10.0.0.3 conns_n=1;
 *   }
 *
 * Every server is simply added to the tfw_srv_cfg_curr_group.
 */
static int
tfw_srv_cfg_handle_server(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwAddr addr;
	TfwServer *srv;
	int r, conns_n;
	const char *in_addr, *in_conns_n;

	BUG_ON(!tfw_srv_cfg_curr_group);

	r  = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return -EINVAL;

	in_addr = ce->vals[0];
	in_conns_n = tfw_cfg_get_attr(ce, "conns_n", TFW_SRV_CFG_DEF_CONNS_N);

	r =  tfw_addr_pton(in_addr, &addr);
	if (r)
		return r;
	r = tfw_cfg_parse_int(in_conns_n, &conns_n);
	if (r)
		return r;

	srv = tfw_sock_srv_create(&addr, conns_n);
	if (!srv) {
		TFW_ERR("can't create a server socket\n");
		return -EPERM;
	}

	tfw_sg_add(tfw_srv_cfg_curr_group, srv);
	return 0;
}

/**
 * Handle a top-level "server" entry that doesn't belong to any group.
 *
 * All such top-level entries are simply added to the "default" group.
 * So this configuration example:
 *    server 10.0.0.1;
 *    server 10.0.0.2;
 *    srv_group local {
 *        server 127.0.0.1:8000;
 *    }
 * is implicitly transformed to this:
 *    srv_group default {
 *        server 10.0.0.1;
 *        server 10.0.0.2;
 *    }
 *    srv_group local {
 *        server 127.0.0.1:8000;
 *    }
 */
static int
tfw_srv_cfg_handle_server_outside_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	tfw_srv_cfg_curr_group = tfw_sg_lookup("default");

	/* The "default" group is created implicitly. */
	if (!tfw_srv_cfg_curr_group) {
		tfw_srv_cfg_curr_group = tfw_sg_new("default", GFP_KERNEL);
		BUG_ON(!tfw_srv_cfg_curr_group);
	}

	return tfw_srv_cfg_handle_server(cs, ce);
}

/**
 * Handle defaults for the "server" spec.
 *
 * The separate function is only needed to check that there are no "server"
 * entries already defined (either top-level or within an "srv_group").
 * If there is at least one, we don't need to use defaults.
 */
static int
tfw_srv_cfg_handle_server_defaults(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_sg_count()) {
		TFW_DBG("at least one server is defined, ignore defaults\n");
		return 0;
	}

	TFW_DBG("no servers defined, apply defaults\n");
	return tfw_srv_cfg_handle_server_outside_group(cs, ce);
}

/**
 * The callback is invoked on entering an "srv_group", e.g:
 *
 *   srv_group foo sched=hash {  <--- The position at the moment of call.
 *       server ...;
 *       server ...;
 *       ...
 *   }
 *
 * Basically it parses the group name and the "sched" attribute, creates a
 * new TfwSrvGroup object and sets the context for parsing nested "server"s.
 */
static int
fw_srv_cfg_begin_srv_group(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;
	TfwSrvGroup *sg;
	const char *name, *sched_str;

	r = tfw_cfg_check_val_n(ce, 1);
	if (r)
		return r;
	name = ce->vals[0];
	sched_str = tfw_cfg_get_attr(ce, "sched", NULL);

	TFW_DBG("begin srv_group: %s\n", name);

	sg = tfw_sg_new(name, GFP_KERNEL);
	if (!sg) {
		TFW_ERR("can't add srv_group: %s\n", name);
		return -EINVAL;
	}

	r = tfw_sg_set_sched(sg, sched_str);
	if (r) {
		TFW_ERR("can't set scheduler for srv_group: %s\n", name);
		return r;
	}

	/* Set the current group. All nested "server"s are added to it. */
	tfw_srv_cfg_curr_group = sg;
	return 0;
}

/**
 * The callback is invoked upon exit from a "srv_group" when all nested
 * "server"s are parsed, e.g.:
 *
 *   srv_group foo sched=hash {
 *       server ...;
 *       server ...;
 *       ...
 *   }  <--- The position at the moment of call.
 */
static int
tfw_srv_cfg_finish_srv_group(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_srv_cfg_curr_group);
	BUG_ON(list_empty(&tfw_srv_cfg_curr_group->srv_list));
	TFW_DBG("finish srv_group: %s\n", tfw_srv_cfg_curr_group->name);
	tfw_srv_cfg_curr_group = NULL;
	return 0;
}

/**
 * Clean the state that is changed during parsing "server" and "srv_group".
 */
static void
tfw_srv_cfg_clean_srv_groups(TfwCfgSpec *cs)
{
	tfw_sg_release_all();
	tfw_srv_cfg_curr_group = NULL;
}

static TfwCfgSpec tfw_sock_srv_cfg_srv_group_specs[] = {
	{
		"server", NULL,
		tfw_srv_cfg_handle_server,
		.allow_repeat = true,
		.cleanup = tfw_srv_cfg_clean_srv_groups
	},
	{}
};

TfwCfgMod tfw_sock_srv_cfg_mod = {
	.name = "sock_srv",
	.specs = (TfwCfgSpec[]){
		{
			"server", NULL,
			tfw_srv_cfg_handle_server_outside_group,
			.allow_none = true,
			.allow_repeat = true,
			.cleanup = tfw_srv_cfg_clean_srv_groups,
		},
		{
			"server_default_dummy", "127.0.0.1:8080 conns_n=4",
			tfw_srv_cfg_handle_server_defaults
		},
		{
			"srv_group", NULL,
			tfw_cfg_handle_children,
			tfw_sock_srv_cfg_srv_group_specs,
			&(TfwCfgSpecChild) {
				.begin_hook = fw_srv_cfg_begin_srv_group,
				.finish_hook = tfw_srv_cfg_finish_srv_group
			},
			.allow_none = true,
			.allow_repeat = true,
		},
		{}
	}
};
