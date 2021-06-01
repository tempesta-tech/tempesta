/**
 *		Tempesta FW
 *
 * Request schedulers interface.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "tempesta_fw.h"
#include "log.h"
#include "server.h"
#include "http_sess.h"

/*
 * Schedulers register and deregister themselves successively via
 * register()/unregister() functions during initialisation of
 * 'tempesta_fw' module. Registered schedulers are placed on the
 * list which can be used from user context during (re)configuration
 * procedures only.
 */
static LIST_HEAD(sched_list);

/*
 * Lookup a scheduler by name.
 *
 * If @name is NULL, then the first available scheduler is returned.
 * Called only in user context, and used in configuration routines.
 */
TfwScheduler *
tfw_sched_lookup(const char *name)
{
	TfwScheduler *sched;

	list_for_each_entry(sched, &sched_list, list) {
		if (!name || !strcasecmp(name, sched->name))
			return sched;
	}

	return NULL;
}

/*
 * Register a new scheduler.
 * Called only in user context.
 */
int
tfw_sched_register(TfwScheduler *sched)
{
	T_DBG("Registering new scheduler: %s\n", sched->name);
	BUG_ON(!list_empty(&sched->list));
	list_add_tail(&sched->list, &sched_list);

	return 0;
}

/*
 * Deregister a new scheduler.
 * Called only in user context.
 */
void
tfw_sched_unregister(TfwScheduler *sched)
{
	T_DBG("Un-registering scheduler: %s\n", sched->name);
	BUG_ON(list_empty(&sched->list));
	list_del_init(&sched->list);
}

