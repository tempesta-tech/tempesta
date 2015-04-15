/**
 *		Tempesta FW
 *
 * Servers handling.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/slab.h>

#include "addr.h"
#include "log.h"
#include "sched.h"
#include "server.h"

static struct kmem_cache *srv_cache;

void
tfw_destroy_server(struct sock *s)
{
	TfwConnection *conn = s->sk_user_data;
	TfwServer *srv;

	BUG_ON(!conn);
	srv = (TfwServer *)conn->peer;

	/* The call back can be called twise bou our and Linux code. */
	if (unlikely(!srv))
		return;

	TFW_DBG("Destroy server socket %p\n", s);

	if (tfw_sched_del_srv(srv))
		TFW_WARN("Try to delete orphaned server from"
			 " requests scheduler");

	conn->peer = NULL;

	kmem_cache_free(srv_cache, srv);

	conn->sk_destruct(s);
}

TfwServer *
tfw_create_server(struct sock *sk, TfwConnection *conn)
{
	TfwServer *srv = kmem_cache_alloc(srv_cache, GFP_ATOMIC);
	if (!srv)
		return NULL;

	/*
	 * Bind connectin with the server.
	 * Must be done before we publish the server to scheduler.
	 */
	srv->sock = sk;
	conn->peer = (TfwPeer *)srv;

	if (tfw_sched_add_srv(srv)) {
		TFW_ERR("Can't add a server to requests scheduler\n");
		kmem_cache_free(srv_cache, srv);
		return NULL;
	}

	return srv;
}

int
tfw_server_get_addr(const TfwServer *srv, TfwAddr *addr)
{
	int ret = 0;
	int len = sizeof(*addr);

	memset(addr, 0, len);
	ret = ss_getpeername(srv->sock, &addr->sa, &len);

	return ret;
}
EXPORT_SYMBOL(tfw_server_get_addr);

int
tfw_server_snprint(const TfwServer *srv, char *buf, size_t buf_size)
{
	TfwAddr addr;
	char addr_str_buf[TFW_ADDR_STR_BUF_SIZE];

	BUG_ON(!srv || !buf || !buf_size);

	tfw_server_get_addr(srv, &addr);
	tfw_addr_ntop(&addr, addr_str_buf, sizeof(addr_str_buf));

	return snprintf(buf, buf_size, "srv %p: %s", srv, addr_str_buf);
}
EXPORT_SYMBOL(tfw_server_snprint);

int __init
tfw_server_init(void)
{
	srv_cache = kmem_cache_create("tfw_srv_cache", sizeof(TfwServer),
				       0, 0, NULL);
	if (!srv_cache)
		return -ENOMEM;
	return 0;
}

void
tfw_server_exit(void)
{
	kmem_cache_destroy(srv_cache);
}
