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

void
tfw_destroy_client(struct sock *s)
{
	TfwConnection *conn = s->sk_user_data;
	TfwClient *cli;

	BUG_ON(!conn);
	cli = conn->hndl;

	/* The call back can be called twise bou our and Linux code. */
	if (unlikely(!cli))
		return;

	TFW_DBG("Destroy client socket %p\n", s);

	conn->hndl = NULL;

	kmem_cache_free(cli_cache, cli);
}

TfwClient *
tfw_create_client(struct sock *s)
{
	TfwClient *c = kmem_cache_alloc(cli_cache, GFP_ATOMIC);
	if (!c)
		return NULL;
	c->sock = s;

	return c;
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
