/**
 *		Tempesta FW
 *
 * Interface for requests scheduling and connections management to
 * back-end servers.
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
#ifndef __TFW_SCHED_H__
#define __TFW_SCHED_H__

#include "tempesta_fw.h"
#include "connection.h"

/*
 * The scheduler must know about server groups which it schedules as well as
 * server group should know about scheduler which is binded to it.
 */
struct tfw_srv_group_t;

/**
 * Requests scheduling algorithm handler.
 *
 * @name	- name of the algorithm;
 * @list	- list of registered schedulers;
 * @add_grp	- add server group to the scheduler;
 * @del_grp	- delete server group from the scheduler;
 * @update_grp	- update server group referencing the scheduler;
 * @sched_grp	- server scheduling virtual method;
 * @sched_srv	- requests scheduling virtual method;
 *
 * All schedulers must be able to scheduler messages among servers of one
 * server group, i.e. @sched_srv must be defined.
 * However, not all the schedulers are able to designate target server group.
 * If a scheduler determines server group, then it should register @sched_grp
 * callback. The callback determines the target server group which references
 * a scheduler responsible to distribute messages in the group.
 * For the avoidance of unnecessary calls, any @sched_grp callback must call
 * @sched_srv callback of the target scheduler.
 */
typedef struct {
	const char		*name;
	struct list_head	list;
	void			(*add_grp)(struct tfw_srv_group_t *sg);
	void			(*del_grp)(struct tfw_srv_group_t *sg);
	void			(*update_grp)(struct tfw_srv_group_t *sg);
	TfwConnection		*(*sched_grp)(TfwMsg *msg);
	TfwConnection		*(*sched_srv)(TfwMsg *msg,
					      struct tfw_srv_group_t *sg);
} TfwScheduler;

TfwConnection *tfw_sched_get_srv_conn(TfwMsg *msg);
TfwScheduler *tfw_sched_lookup(const char *name);
int tfw_sched_register(TfwScheduler *sched);
void tfw_sched_unregister(TfwScheduler *sched);

#endif /* __TFW_SCHED_H__ */
