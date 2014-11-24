/**
 *		Tempesta FW
 *
 * Handling client and server sessions (at OSI level 5 and higher).
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#include <linux/list.h>

#include "log.h"
#include "sched.h"
#include "session.h"

static struct kmem_cache *sess_cache;

int
tfw_session_sched_msg(TfwSession *s, TfwMsg *msg)
{
	TfwServer *srv = tfw_sched_get_srv(msg);
	if (!srv) {
		TFW_ERR("Can't get an appropriate server for a session");
		return -ENOENT;
	}

	s->srv = srv;

	return 0;
}

TfwSession *
tfw_session_create(TfwClient *cli)
{
	TfwSession *s = kmem_cache_alloc(sess_cache, GFP_ATOMIC);
	if (!s)
		return NULL;

	s->cli = cli;
	s->srv = NULL;
	INIT_LIST_HEAD(&s->req_list);

	return s;
}

void
tfw_session_free(TfwSession *s)
{
	TfwMsg *msg, *tmp;

	TFW_DBG("Free session: %p\n", s);

	/* Release all pipelined HTTP requests. */
	list_for_each_entry_safe(msg, tmp, &s->req_list, pl_list) {
		list_del(&msg->pl_list);
		tfw_msg_destruct(msg);
	}

	kmem_cache_free(sess_cache, s);
}

static int
tfw_session_init(void)
{
	sess_cache = kmem_cache_create("tfw_sess_cache", sizeof(TfwSession),
				       0, 0, NULL);
	if (!sess_cache)
		return -ENOMEM;
	return 0;
}

static void
tfw_session_exit(void)
{
	kmem_cache_destroy(sess_cache);
}


TfwCfgMod tfw_mod_session = {
	.name = "session",
	.init = tfw_session_init,
	.exit = tfw_session_exit
};
