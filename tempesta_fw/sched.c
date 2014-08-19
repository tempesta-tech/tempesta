/**
 *		Tempesta FW
 *
 * Requst schedulers interface.
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

#include "tempesta.h"
#include "log.h"
#include "sched.h"

static TfwScheduler *sched = NULL;
static rwlock_t	tfw_sched_lock = __RW_LOCK_UNLOCKED(tfw_sched_lock);

/* TODO the TfwServer structures must be handled by scheduler modules. */
static TfwServer *dummy_srv = NULL;

int
tfw_sched_add_srv(TfwServer *srv)
{
	dummy_srv = srv;
	TFW_DBG("Added new server %p\n", dummy_srv);
	return 0;
}

int
tfw_sched_del_srv(TfwServer *srv)
{
	BUG_ON(srv != dummy_srv);
	dummy_srv = NULL;

	return 0;
}

TfwServer *
tfw_sched_get_srv(void)
{
	return dummy_srv;
}

int
tfw_sched_register(TfwScheduler *mod)
{
	write_lock(&tfw_sched_lock);
	if (sched) {
		write_unlock(&tfw_sched_lock);
		TFW_ERR("Can't register a scheduler - there is already one"
		        " registered\n");
		return -1;
	}
	sched = mod;
	write_unlock(&tfw_sched_lock);

	return 0;
}
EXPORT_SYMBOL(tfw_sched_register);

void
tfw_sched_unregister(void)
{
	write_lock(&tfw_sched_lock);
	sched = NULL;
	write_unlock(&tfw_sched_lock);
}
EXPORT_SYMBOL(tfw_sched_unregister);
