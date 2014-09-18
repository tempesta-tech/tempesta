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

#define TFW_MAX_SCHED_COUNT 16

/* The list of all scheduler modules registered with tfw_sched_register(). */
static TfwScheduler *tfw_scheds[TFW_MAX_SCHED_COUNT];
static size_t tfw_scheds_n = 0;

/* Currently active scheduler from the list of all registered schedulers. */
static TfwScheduler *tfw_active_sched = NULL;

/* The lock should be acquired when any variable above is accessed. */
DEFINE_RWLOCK(tfw_sched_lock);


static TfwScheduler *
get_active_sched(void)
{
	TfwScheduler *sched;
	unsigned long flags;
	
	read_lock_irqsave(&tfw_sched_lock, flags);
	sched = tfw_active_sched;
	read_unlock_irqrestore(&tfw_sched_lock, flags);

	return sched;
}

TfwServer *
tfw_sched_get_srv(TfwMsg *msg)
{
	return get_active_sched()->get_srv(msg);
}

int
tfw_sched_add_srv(TfwServer *srv)
{
	return get_active_sched()->add_srv(srv);
}

int
tfw_sched_del_srv(TfwServer *srv)
{
	return get_active_sched()->del_srv(srv);
}

int
tfw_sched_register(TfwScheduler *mod)
{
	unsigned long flags;

	BUG_ON(!mod);
	BUG_ON(!mod->name);
	BUG_ON(!mod->get_srv || !mod->add_srv || !mod->del_srv);
	BUG_ON(tfw_scheds_n >= TFW_MAX_SCHED_COUNT);

	write_lock_irqsave(&tfw_sched_lock, flags);
	tfw_scheds[tfw_scheds_n] = mod;
	tfw_active_sched = tfw_scheds[tfw_scheds_n];
	++tfw_scheds_n;
	write_unlock_irqrestore(&tfw_sched_lock, flags);

	TFW_LOG("Registered new scheduler: %s\n", mod->name);

	return 0;
}
EXPORT_SYMBOL(tfw_sched_register);


void
tfw_sched_unregister(TfwScheduler *mod)
{
	int idx, rem;
	unsigned long flags;

	BUG_ON(!mod);
	BUG_ON(!tfw_scheds_n);

	TFW_LOG("Un-registering scheduler: %s\n", mod->name);

	write_lock_irqsave(&tfw_sched_lock, flags);

	/* Find a requested scheduler. */
	for (idx = 0; idx < ARRAY_SIZE(tfw_scheds); ++idx) {
		if (mod == tfw_scheds[idx])
			break;
	}
	BUG_ON(idx >= tfw_scheds_n);

	/* Fall back to previously registered scheduler module. */
	if (idx > 0)
		tfw_active_sched = tfw_scheds[idx - 1];
	else
		tfw_active_sched = NULL;

	/* Remove gap in the array of schedulers. */
	tfw_scheds[idx] = NULL;
	rem = tfw_scheds_n - idx - 1;
	memmove(&tfw_scheds[idx], &tfw_scheds[idx + 1], rem);
	--tfw_scheds_n;
	tfw_scheds[tfw_scheds_n] = NULL;

	write_unlock_irqrestore(&tfw_sched_lock, flags);
}
EXPORT_SYMBOL(tfw_sched_unregister);
