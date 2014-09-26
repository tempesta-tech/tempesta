/**
 *		Tempesta FW
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
#include <linux/module.h>

#include "../log.h"
#include "../sched.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta dummy scheduler");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");

/* The only single server is supported by the dummy scheduler. */
static TfwServer *dummy_srv = NULL;

TfwServer *
tfw_sched_dummy_get_srv(TfwMsg *msg)
{
	return dummy_srv;
}

int
tfw_sched_dummy_add_srv(TfwServer *srv)
{
	if (srv && dummy_srv)
		TFW_WARN("Can't add multiple servers to the dummy scheduler,"
			 "so only the most recently added server is used\n");

	dummy_srv = srv;

	return 0;
}

int
tfw_sched_dummy_del_srv(TfwServer *srv)
{
	if (srv != dummy_srv) {
		TFW_WARN("Can't remove the server from the dummy scheduler\n");
		return -ENOENT;
	} else {
		dummy_srv = NULL;
		return 0;
	}
}

int
tfw_sched_dummy_init(void)
{
	static TfwScheduler tfw_sched_dummy_mod = {
		.name = "dummy",
		.get_srv = tfw_sched_dummy_get_srv,
		.add_srv = tfw_sched_dummy_add_srv,
		.del_srv = tfw_sched_dummy_del_srv
	};

	return tfw_sched_register(&tfw_sched_dummy_mod);
}
module_init(tfw_sched_dummy_init);

void
tfw_sched_dummy_exit(void)
{
	dummy_srv = NULL;

	tfw_sched_unregister();
}
module_exit(tfw_sched_dummy_exit);
