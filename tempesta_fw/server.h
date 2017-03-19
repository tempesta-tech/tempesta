/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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

#define TFW_SRV_MAX_CONN	32	/* TfwSrvConn{} per TfwServer{} */
#define TFW_SG_MAX_SRV		32	/* TfwServer{} per TfwSrvGroup{} */
#define TFW_SG_MAX_CONN		(TFW_SG_MAX_SRV * TFW_SRV_MAX_CONN)

typedef struct tfw_srv_group_t TfwSrvGroup;
typedef struct tfw_scheduler_t TfwScheduler;

/**
 * Server descriptor, a TfwPeer successor.
 *
 * @list	- member pointer in the list of servers of a server group;
 * @sg		- back-reference to the server group;
 * @sched_data	- private scheduler data for the server;
 * @apm		- opaque handle for APM stats;
 */
typedef struct {
	TFW_PEER_COMMON;
	struct list_head	list;
	TfwSrvGroup		*sg;
	void			*sched_data;
	void			*apm;
} TfwServer;

/**
 * The servers group with the same load balancing, failovering and eviction
 * policies.
 *
 * Reverse proxy must define load balancing policy. Forward proxy must define
 * eviction policy. While both of them should define failovering policy.
 *
 * @list	- member pointer in the list of server groups;
 * @srv_list	- list of servers belonging to the group;
 * @lock	- synchronizes the group readers with updaters;
 * @sched	- requests scheduling handler;
 * @sched_data	- private scheduler data for the server group;
 * @max_qsize	- maximum queue size of a server connection;
 * @max_refwd	- maximum number of tries for forwarding a request;
 * @max_jqage	- maximum age of a request in a server connection, in jiffies;
 * @max_recns	- maximum number of reconnect attempts;
 * @flags	- server group related flags;
 * @name	- name of the group specified in the configuration;
 */
struct tfw_srv_group_t {
	struct list_head	list;
	struct list_head	srv_list;
	rwlock_t		lock;
	TfwScheduler		*sched;
	void			*sched_data;
	unsigned int		max_qsize;
	unsigned int		max_refwd;
	unsigned long		max_jqage;
	unsigned int		max_recns;
	unsigned int		flags;
	char			name[0];
};

/* Server related flags. */
#define TFW_SRV_RETRY_NIP	0x0001	/* Retry non-idemporent req. */

/**
 * Requests scheduling algorithm handler.
 *
 * @name	- name of the algorithm;
 * @list	- list of registered schedulers;
 * @add_grp	- add server group to the scheduler;
 * @del_grp	- delete server group from the scheduler;
 * @add_conn	- add connection and server if it's new, called in process
 * 		  context at configuration time;
 * @sched_grp	- server group scheduling virtual method, typically returns
 *		  result of underlying @sched_sg_conn();
 * @sched_sg_conn - requests scheduling virtual method, can be called in heavy
 *		  concurrent environment;
 * @sched_srv_conn - requests scheduling virtual method, can be called in heavy
 *		  concurrent environment;
 *
 * All schedulers must be able to scheduler messages among servers of one
 * server group, i.e. @sched_sg_conn must be defined.
 * However, not all the schedulers are able to designate target server group.
 * If a scheduler determines server group, then it should register @sched_grp
 * callback. The callback determines the target server group which references
 * a scheduler responsible to distribute messages in the group.
 * For the avoidance of unnecessary calls, any @sched_grp callback must call
 * @sched_sg_conn callback or @sched_srv_conn of the target scheduler.
 */
struct tfw_scheduler_t {
	const char		*name;
	struct list_head	list;
	void			(*add_grp)(TfwSrvGroup *sg);
	void			(*del_grp)(TfwSrvGroup *sg);
	void			(*add_conn)(TfwSrvGroup *sg, TfwServer *srv,
					    TfwSrvConn *srv_conn);
	TfwSrvConn		*(*sched_grp)(TfwMsg *msg);
	TfwSrvConn		*(*sched_sg_conn)(TfwMsg *msg, TfwSrvGroup *sg);
	TfwSrvConn		*(*sched_srv_conn)(TfwMsg *msg, TfwServer *srv);
};

/* Server specific routines. */
TfwServer *tfw_server_create(const TfwAddr *addr);
int tfw_server_apm_create(TfwServer *srv);
void tfw_server_destroy(TfwServer *srv);

void tfw_srv_conn_release(TfwSrvConn *srv_conn);

static inline bool
tfw_srv_conn_queue_full(TfwSrvConn *srv_conn)
{
	TfwSrvGroup *sg = ((TfwServer *)srv_conn->peer)->sg;
	return ACCESS_ONCE(srv_conn->qsize) >= sg->max_qsize;
}

/*
 * max_recns can be the maximum value for the data type to mean
 * the unlimited number of attempts, which is the value that should
 * never be reached. UINT_MAX seconds is more than 136 years. It's
 * safe to assume that it's not reached in a single run of Tempesta.
 */
static inline bool
tfw_srv_conn_need_resched(TfwSrvConn *srv_conn)
{
	TfwSrvGroup *sg = ((TfwServer *)srv_conn->peer)->sg;
	return (srv_conn->recns == sg->max_recns);
}

/* Server group routines. */
TfwSrvGroup *tfw_sg_lookup(const char *name);
TfwSrvGroup *tfw_sg_new(const char *name, gfp_t flags);
void tfw_sg_free(TfwSrvGroup *sg);
unsigned int tfw_sg_count(void);

void tfw_sg_add(TfwSrvGroup *sg, TfwServer *srv);
void tfw_sg_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwSrvConn *srv_conn);
int tfw_sg_set_sched(TfwSrvGroup *sg, const char *sched);
int tfw_sg_for_each_srv(int (*cb)(TfwServer *srv));
void tfw_sg_release_all(void);

/* Scheduler routines. */
TfwSrvConn *tfw_sched_get_srv_conn(TfwMsg *msg);
TfwSrvConn *tfw_sched_get_sg_srv_conn(TfwMsg *msg, TfwSrvGroup *main_sg,
				      TfwSrvGroup *backup_sg);
TfwScheduler *tfw_sched_lookup(const char *name);
int tfw_sched_register(TfwScheduler *sched);
void tfw_sched_unregister(TfwScheduler *sched);

#endif /* __SERVER_H__ */
