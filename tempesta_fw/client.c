/**
 *		Tempesta FW
 *
 * Clients handling.
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
#include <linux/slab.h>

#include "client.h"
#include "connection.h"
#include "log.h"

static struct kmem_cache *cli_cache;

/**
 * Called when a client socket is closed.
 */
void
tfw_client_put(TfwClient *clnt)
{
	if (atomic_dec_and_test(&clnt->conn_users)) {
		BUG_ON(!list_empty(&clnt->conn_list));
		kmem_cache_free(cli_cache, clnt);
	}
}

/**
 * Find a client corresponding to the @sk.
 *
 * The returned TfwClient reference must be released via tfw_client_put()
 * when the @sk is closed.
 */
TfwClient *
tfw_client_obtain(struct sock *sk)
{
	int daddr_len;
	TfwAddr daddr;

	/* Derive client's IP address from @sk. */
	if (ss_getpeername(sk, &daddr.sa, &daddr_len))
		return NULL;

	/*
	 * TODO: currently there is one to one socket-client
	 * mapping, which isn't appropriate since a client can
	 * have more than one socket with the server.
	 *
	 * We need to look up a client by the socket and create
	 * a new one only if it's really new.
	 */
	TfwClient *cli = kmem_cache_alloc(cli_cache, GFP_ATOMIC);
	if (!cli)
		return NULL;

	tfw_peer_init((TfwPeer *)cli, &daddr);
	atomic_set(&cli->conn_users, 1);

	TFW_DBG("new client: cli=%p\n", cli);

	return cli;
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
