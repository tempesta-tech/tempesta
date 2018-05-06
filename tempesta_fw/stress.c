/**
 *		Tempesta FW
 *
 * Interface to stress (local system or back-end server overloading)
 * handling modules.
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
#include "tempesta_fw.h"
#include "http_limits.h"
#include "stress.h"

/* TODO replace by RCU list. */
static LIST_HEAD(stress_handlers);
static DEFINE_RWLOCK(tfw_stress_lock);

void
tfw_stress_account_srv(/* we need here a packet and connection */)
{
	TfwStress *s;

	read_lock(&tfw_stress_lock);
	list_for_each_entry(s, &stress_handlers, st_list) {
		if (s->type & TfwStress_Srv)
			if (s->account_srv())
				tfw_classify_shrink();
	}
	read_unlock(&tfw_stress_lock);
}

void
tfw_stress_account_sys(void)
{
	TfwStress *s;

	read_lock(&tfw_stress_lock);
	list_for_each_entry(s, &stress_handlers, st_list) {
		if (s->type & TfwStress_Sys)
			if (s->account_sys())
				tfw_classify_shrink();
	}
	read_unlock(&tfw_stress_lock);
}

int
tfw_stress_register(TfwStress *mod)
{
	write_lock(&tfw_stress_lock);
	list_add(&mod->st_list, &stress_handlers);
	write_unlock(&tfw_stress_lock);

	return 0;
}

void
tfw_stress_unregister(TfwStress *mod)
{
	TfwStress *s, *tmp;

	write_lock(&tfw_stress_lock);
	list_for_each_entry_safe(s, tmp, &stress_handlers, st_list) {
		if (s == mod) {
			list_del(&s->st_list);
			break;
		}
	}
	write_unlock(&tfw_stress_lock);
}
