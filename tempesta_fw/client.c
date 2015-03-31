/**
 *		Tempesta FW
 *
 * Clients handling.
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

#include "client.h"
#include "connection.h"
#include "log.h"

static struct kmem_cache *cli_cache;

/**
 * Used as socket destructor callback.
 */
void
tfw_client_put(struct sock *s)
{
	TfwConnection *conn = s->sk_user_data;
	TfwClient *clnt;

	BUG_ON(!conn);
	clnt =(TfwClient *)conn->peer;

	list_del(&conn->list);

	if (atomic_dec_and_test(&clnt->conn_users)) {
		BUG_ON(!list_empty(&clnt->conn_list));
		kmem_cache_free(cli_cache, clnt);
	}

	if (conn->sk_destruct)
		conn->sk_destruct(s);
}

TfwClient *
tfw_create_client(TfwConnection *conn, const TfwAddr *addr)
{
	TfwClient *clnt = kmem_cache_alloc(cli_cache, GFP_ATOMIC);
	if (!clnt)
		return NULL;

	tfw_peer_init((TfwPeer *)clnt, addr);

	tfw_peer_add_conn((TfwPeer *)clnt, &conn->list);
	conn->peer = (TfwPeer *)clnt;

	atomic_set(&clnt->conn_users, 1);

	return clnt;
}

int __init
tfw_client_init(void)
{
	cli_cache = kmem_cache_create("tfw_cli_cache", sizeof(TfwClient),
				       0, 0, NULL);
	if (!cli_cache)
		return -ENOMEM;
	return 0;
}

void
tfw_client_exit(void)
{
	kmem_cache_destroy(cli_cache);
}
