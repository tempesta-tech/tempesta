/**
 *		Tempesta FW
 *
 * The dummy load balancer suitable for testing and debugging.
 *
 * It supports only one connection to a single backend server.
 * It sends all messages to this single connection without actually balancing
 * anything. The connection is established only once upon start, and not
 * restored automatically in case it is closed (you have to restart Tempesta FW
 * to re-connect to the backend server).
 *
 * Also the module provides primitive configuration: only one "backend" entry is
 * allowed in the configuration file (e.g. "backend 127.0.0.1:8080"). Multiple
 * backends are not allowed.
 *
 * Copyright (C) 2015 Tempesta Technologies.
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

#include <net/tcp_states.h>

#include "addr.h"
#include "lb_mod.h"
#include "log.h"
#include "connection.h"
#include "tempesta.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta FW dummy load balancer");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

static struct socket *tfw_lb_dummy_be_sock;
static TfwAddr tfw_lb_dummy_be_addr;

static int
tfw_lb_dummy_send_msg(TfwMsg *msg)
{
	struct sock *sk;

	BUG_ON(!tfw_lb_dummy_be_sock);
	sk = tfw_lb_dummy_be_sock->sk;

	if (sk->sk_state != TCP_ESTABLISHED) {
		TFW_ERR_ADDR("not connected to backend", &tfw_lb_dummy_be_addr);
		return -EPERM;
	}

	TFW_DBG_ADDR("send msg to backend", &tfw_lb_dummy_be_addr);
	ss_send(sk, &msg->skb_list);
	return 0;
}

static void
tfw_lb_dummy_close_cb(struct sock *sk)
{
	TFW_ERR_ADDR("backend connection is closed", &tfw_lb_dummy_be_addr);
}

static int
tfw_lb_dummy_start(void)
{
	static TfwServer dummy_srv;
	static struct {
		SsProto	_placeholder;
		int	type;
	} dummy_proto = {
		.type = TFW_FSM_HTTP,
	};

	int r;
	size_t sza;
	sa_family_t family;
	struct sock *sk;
	struct socket *sock;
	struct sockaddr *sa;

	BUG_ON(tfw_lb_dummy_be_sock);
	TFW_DBG_ADDR("connect to backend", &tfw_lb_dummy_be_addr);

	sa = &tfw_lb_dummy_be_addr.sa;
	sza = tfw_addr_sa_len(&tfw_lb_dummy_be_addr);
	family = sa->sa_family;


	r = sock_create_kern(family, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (r) {
		TFW_ERR("can't create backend socket: err=%d\n", r);
		return r;
	}

	r = kernel_connect(sock, sa, sza, 0);
	if (r) {
		TFW_ERR_ADDR("can't conenct to", &tfw_lb_dummy_be_addr);
		sock_release(sock);
		return r;
	}

	sk = sock->sk;
	ss_set_callbacks(sk);

	sk->sk_user_data = &dummy_proto;
	r = tfw_connection_new(sk, Conn_Srv, &dummy_srv, tfw_lb_dummy_close_cb);
	if (r) {
		TFW_ERR("can't create connection object: err=%d\n", r);
		sock_release(sock);
		return r;
	}

	TFW_DBG_ADDR("connection established", &tfw_lb_dummy_be_addr);
	TFW_DBG("backend socket: sock=%p, sk=%p\n", sock, sk);
	tfw_lb_dummy_be_sock = sock;
	return 0;
}

static void
tfw_lb_dummy_stop(void)
{
	BUG_ON(!tfw_lb_dummy_be_sock);
	TFW_DBG_ADDR("disconnect from backend", &tfw_lb_dummy_be_addr);
	TFW_DBG("close backend socket: sock=%p, sk=%p\n",
		tfw_lb_dummy_be_sock, tfw_lb_dummy_be_sock->sk);

	sock_release(tfw_lb_dummy_be_sock);
	tfw_lb_dummy_be_sock = NULL;
}

static int
tfw_lb_dummy_cfg_handle_backend(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r;

	r = tfw_cfg_check_single_val(ce);
	if (r)
		return -EINVAL;

	r = tfw_addr_pton(ce->vals[0], &tfw_lb_dummy_be_addr);
	if (r)
		return -EINVAL;

	TFW_DBG_ADDR("parsed backend address", &tfw_lb_dummy_be_addr);
	return 0;
}

static TfwCfgMod twf_lb_dummy_cfg_mod = {
	.name = "tfw_lb_dummy",
	.start = tfw_lb_dummy_start,
	.stop = tfw_lb_dummy_stop,
	.specs = (TfwCfgSpec[]) {
		{
			"backend", "127.0.0.1:8080",
			tfw_lb_dummy_cfg_handle_backend,
		},
		{}
	}
};

static const TfwLbMod tfw_lb_dummy_mod = {
	.name = "tfw_lb_dummy",
	.send_msg = tfw_lb_dummy_send_msg
};

int
tfw_lb_dummy_init(void)
{
	int r;

	r = tfw_lb_mod_register(&tfw_lb_dummy_mod);
	if (r) {
		TFW_ERR("can't register as a load balancer\n");
		return r;
	}

	r = tfw_cfg_mod_register(&twf_lb_dummy_cfg_mod);
	if (r) {
		TFW_ERR("can't register as a configuration module\n");
		tfw_lb_mod_unregister();
		return r;
	}

	return 0;
}
module_init(tfw_lb_dummy_init);

void
tfw_lb_dummy_exit(void)
{
	tfw_cfg_mod_unregister(&twf_lb_dummy_cfg_mod);
	tfw_lb_mod_unregister();
}
module_exit(tfw_lb_dummy_exit);
