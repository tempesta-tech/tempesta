/**
 *		Tempesta FW
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
#include <linux/module.h>

#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta dummy scheduler");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");

/**
 * Just return first connection to the first server in the group.
 */
static TfwConnection *
tfw_sched_dummy_schedule(TfwMsg *msg, TfwSrvGroup *sg)
{
	TfwServer *srv;
	TfwConnection *conn = NULL;

	write_lock(&sg->lock);

	if (unlikely(list_empty(&sg->srv_list)))
		goto out;

	srv = list_first_entry(&sg->srv_list, TfwServer, list);

	if (unlikely(list_empty(&srv->conn_list)))
		goto out;

	conn = list_first_entry(&srv->conn_list, TfwConnection, list);
out:
	read_unlock(&sg->lock);

	return conn;
}

static TfwScheduler tfw_sched_dummy = {
	.name		= "dummy",
	.list		= LIST_HEAD_INIT(tfw_sched_dummy.list),
	.sched_srv	= tfw_sched_dummy_schedule
};

int
tfw_sched_dummy_init(void)
{
	return tfw_sched_register(&tfw_sched_dummy);
}
module_init(tfw_sched_dummy_init);

void
tfw_sched_dummy_exit(void)
{
	tfw_sched_unregister(&tfw_sched_dummy);
}
module_exit(tfw_sched_dummy_exit);
