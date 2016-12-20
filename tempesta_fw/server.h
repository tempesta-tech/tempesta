/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#ifndef __SERVER_H__
#define __SERVER_H__

#include "addr.h"
#include "connection.h"
#include "peer.h"

#define TFW_SRV_MAX_CONN	32	/* TfwConnection per TfwServer */
#define TFW_SG_MAX_SRV		32	/* TfwServer per TfwSrvGroup */
#define TFW_SG_MAX_CONN		(TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN)

typedef enum {
	TFW_SG_SRV_ADD,
	TFW_SG_SRV_DEL,
} TfwSgSrvUpdate;

typedef struct tfw_srv_group_t TfwSrvGroup;
typedef struct tfw_scheduler_t TfwScheduler;

/**
 * Server descriptor, a TfwPeer successor.
 *
 * @list	- member pointer in the list of servers of a server group;
 * @sg		- back-reference to the server group;
 * @apm		- opaque handle for APM stats;
 * @weight	- static server weight for load balancers;
 */
typedef struct {
	TFW_PEER_COMMON;
	struct list_head	list;
	TfwSrvGroup		*sg;
	void			*apm;
	unsigned int		flags;
	int			stress;
	unsigned char		weight;
} TfwServer;

/**
 * The servers group with the same load balancing, failovering and eviction
 * policies.
 *
 * Reverse proxy must define load balancing policy. Forward proxy must define
 * eviction policy. While both of them should define failovering policy.
 *
 * @list		- member pointer in the list of server groups;
 * @srv_list		- list of servers belonging to the group;
 * @lock		- synchronizes the group readers with updaters;
 * @flags		- various flags;
 * @sched		- requests scheduling handler;
 * @sched_data		- private scheduler data for the server group;
 * @name		- name of the group specified in the configuration;
 */
struct tfw_srv_group_t {
	struct list_head	list;
	struct list_head	srv_list;
	rwlock_t		lock;
	unsigned int		flags;
	TfwScheduler		*sched;
	void			*sched_data;
	char			name[0];
};

/*
 * Lower 4 bits keep an index into APM stats array.
 */
#define TFW_SG_F_PSTATS_IDX_MASK	0x000f
#define TFW_SG_F_SCHED_RATIO_STATIC	0x0010
#define TFW_SG_F_SCHED_RATIO_DYNAMIC	0x0020
#define TFW_SG_F_SCHED_RATIO_PREDICT	0x0040

/**
 * Requests scheduling algorithm handler.
 *
 * @name	- name of the algorithm;
 * @list	- member in the list of registered schedulers;
 * @add_grp	- add server group to the scheduler;
 * @del_grp	- delete server group from the scheduler;
 * @add_conn	- add connection and server if it's new, called in process
 * 		  context at configuration time;
 * @sched_grp	- server group scheduling virtual method, typically returns
 *		  result of underlying @sched_srv();
 * @sched_srv	- requests scheduling virtual method, can be called in heavy
 *		  concurrent environment;
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
struct tfw_scheduler_t {
	const char		*name;
	struct list_head	list;
	void			(*add_grp)(TfwSrvGroup *sg);
	void			(*del_grp)(TfwSrvGroup *sg);
	void			(*add_conn)(TfwSrvGroup *sg, TfwServer *srv,
					    TfwConnection *conn);
	TfwConnection		*(*sched_grp)(TfwMsg *msg);
	TfwConnection		*(*sched_srv)(TfwMsg *msg,
					      TfwSrvGroup *sg);
};

/* Server specific routines. */
TfwServer *tfw_server_create(const TfwAddr *addr);
int tfw_server_apm_create(TfwServer *srv);
void tfw_server_destroy(TfwServer *srv);

void tfw_srv_conn_release(TfwConnection *conn);

/* Server group routines. */
TfwSrvGroup *tfw_sg_lookup(const char *name);
TfwSrvGroup *tfw_sg_new(const char *name, gfp_t flags);
void tfw_sg_free(TfwSrvGroup *sg);
int tfw_sg_count(void);

void tfw_sg_add(TfwSrvGroup *sg, TfwServer *srv);
void tfw_sg_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwConnection *conn);
int tfw_sg_set_sched(TfwSrvGroup *sg, const char *sched);
int tfw_sg_for_each_srv(int (*cb)(TfwServer *srv));
void tfw_sg_release_all(void);

/* Scheduler routines. */
TfwConnection *tfw_sched_get_srv_conn(TfwMsg *msg);
TfwScheduler *tfw_sched_lookup(const char *name);
int tfw_sched_register(TfwScheduler *sched);
void tfw_sched_unregister(TfwScheduler *sched);

#endif /* __SERVER_H__ */
