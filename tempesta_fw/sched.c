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

static LIST_HEAD(sched_list);
static DEFINE_RWLOCK(sched_lock);

TfwConnection *
tfw_sched_get_srv_conn(TfwMsg *msg)
{
	TfwConnection *conn;
	TfwScheduler *sched;

	read_lock(&sched_lock);

	list_for_each_entry(sched, &sched_list, list) {
		if (!sched->sched_grp)
			break;

		/* Try all able schedulers until some of them gets a result. */
		conn = sched->sched_grp(msg);
		if (conn) {
			read_unlock(&sched_lock);
			return conn;
		}
	}

	read_unlock(&sched_lock);

	TFW_ERR("No server group scheduler\n");

	return NULL;
}

/**
 * Lookup a scheduler by name.
 * Useful only for configuration routines.
 */
TfwScheduler *
tfw_sched_lookup(const char *name)
{
	TfwScheduler *sched;

	read_lock(&sched_lock);

	list_for_each_entry(sched, &sched_list, list) {
		if (!strcmp(name, sched->name)) {
			read_unlock(&sched_lock);
			return sched;
		}
	}

	read_unlock(&sched_lock);

	return NULL;
}

int
tfw_sched_register(TfwScheduler *sched)
{
	TFW_LOG("Registering new scheduler: %s\n", sched->name);

	write_lock(&sched_lock);

	/* Add groups scheduling schedulers to head of the list. */
	if (sched->sched_grp)
		list_add(&sched->list, &sched_list);
	else
		list_add_tail(&sched->list, &sched_list);

	write_unlock(&sched_lock);

	return 0;
}
EXPORT_SYMBOL(tfw_sched_register);

void
tfw_sched_unregister(TfwScheduler *sched)
{
	TFW_LOG("Un-registering scheduler: %s\n", sched->name);

	write_lock(&sched_lock);

	list_del(&sched->list);

	write_unlock(&sched_lock);

}
EXPORT_SYMBOL(tfw_sched_unregister);
