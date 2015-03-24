/**
 *		Tempesta FW
 *
 * Requst schedulers interface.
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

#include "log.h"
#include "sched.h"
#include "tempesta_fw.h"

static TfwScheduler *tfw_sched = NULL;

TfwConnection *
tfw_sched_get_srv_conn(TfwMsg *msg)
{
	TfwServer *srv;

	BUG_ON(!msg);
	BUG_ON(!tfw_sched);

	srv = tfw_sched->get_srv(msg);
	if (!srv)
		return NULL;

	/*
	 * TODO: determine whether we need to establish a new connection
	 * (e.g. if current backend connection is busy (not HTTP case))
	 * and ask backend layer to establish a new connection.
	 *
	 * Also here we need to ask for other connection from the pool
	 * if current connection is failed (probably to mirrored backend).
	 * XXX Or should we do this on connection fail event instead?
	 */

	return srv->sock->sk_user_data;
}

int
tfw_sched_add_srv(TfwServer *srv)
{
	int ret;
	
	BUG_ON(!srv);
	BUG_ON(!tfw_sched);

	ret = tfw_sched->add_srv(srv);
	if (ret)
		TFW_ERR("Can't add a server to the scheduler (%d)\n", ret);

	return ret;
}

int
tfw_sched_del_srv(TfwServer *srv)
{
	int ret;
	
	BUG_ON(!srv);
	BUG_ON(!tfw_sched);

	ret = tfw_sched->del_srv(srv);
	if (ret)
		TFW_ERR("Can't remove a server from the scheduler (%d)\n", ret);

	return ret;
}

int
tfw_sched_register(TfwScheduler *mod)
{
	BUG_ON(!mod);
	BUG_ON(!mod->name || !mod->get_srv || !mod->add_srv || !mod->del_srv);

	TFW_LOG("Registering new scheduler: %s\n", mod->name);

	if (!tfw_sched) {
		tfw_sched = mod;
		return 0;
	}

	TFW_ERR("Can't register a scheduler - the '%s' is already registered\n",
		tfw_sched->name);
	return -EEXIST;
}
EXPORT_SYMBOL(tfw_sched_register);

void
tfw_sched_unregister(void)
{
	BUG_ON(!tfw_sched);

	TFW_LOG("Un-registering scheduler: %s\n", tfw_sched->name);
	tfw_sched = NULL;
}
EXPORT_SYMBOL(tfw_sched_unregister);
