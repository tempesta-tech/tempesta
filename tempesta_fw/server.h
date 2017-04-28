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

/*
 * Maximum values for the number of upstream servers in a group,
 * and the number of connections of an upstream server.
 */
#define TFW_SRV_MAX_CONN_N	USHRT_MAX
#define TFW_SG_MAX_SRV_N	USHRT_MAX
#define TFW_SG_MAX_CONN_N	\
	((unsigned long)TFW_SG_MAX_SRV_N * TFW_SRV_MAX_CONN_N)

typedef struct tfw_srv_group_t TfwSrvGroup;
typedef struct tfw_scheduler_t TfwScheduler;

/**
 * Server descriptor, a TfwPeer successor.
 *
 * @list	- member pointer in the list of servers of a server group;
 * @sg		- back-reference to the server group;
 * @sched_data	- private scheduler data for the server;
 * @apmref	- opaque handle for APM stats;
 * @weight	- static server weight for load balancers;
 * @conn_n	- configured number of connections to the server;
 */
typedef struct {
	TFW_PEER_COMMON;
	struct list_head	list;
	TfwSrvGroup		*sg;
	void			*sched_data;
	void			*apmref;
	unsigned int		weight;
	size_t			conn_n;
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
 * @srv_n	- configured number of servers in the group;
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
	int			srv_n;
	unsigned int		max_qsize;
	unsigned int		max_refwd;
	unsigned long		max_jqage;
	unsigned int		max_recns;
	unsigned int		flags;
	char			name[0];
};

/**
 * @past	- period of time (secs) to keep past APM values;
 * @rate	- rate (times per sec) of retrieval of past APM values;
 * @ahead	- period of time (secs) for a prediction;
 */
typedef struct {
	unsigned int		past;
	unsigned int		rate;
	unsigned int		ahead;
} TfwSchrefPredict;

/* Server and server group related flags.
 * Lower 4 bits keep an index into APM stats array.
 */
#define TFW_SG_F_PSTATS_IDX_MASK	0x000f
#define TFW_SG_F_SCHED_RATIO_STATIC	0x0010
#define TFW_SG_F_SCHED_RATIO_DYNAMIC	0x0020
#define TFW_SG_F_SCHED_RATIO_PREDICT	0x0040

#define TFW_SRV_RETRY_NIP		0x0100	/* Retry non-idemporent req. */
#define TFW_SRV_STICKY			0x0200	/* Use sticky sessions. */
#define TFW_SRV_STICKY_FAILOVER		0x0400	/* Allow failovering. */
#define TFW_SRV_STICKY_FLAGS		\
	(TFW_SRV_STICKY | TFW_SRV_STICKY_FAILOVER)

/**
 * Requests scheduling algorithm handler.
 *
 * @name	- name of the algorithm;
 * @list	- member in the list of registered schedulers;
 * @add_grp	- add server group to the scheduler.
 *		  Called in process context at configuration time.
 *		  Called only after all servers are set up with connections,
 *		  and the group is set up with all servers;
 * @del_grp	- delete server group from the scheduler;
 * @sched_grp	- server group scheduling virtual method.
 *		  Typically returns the result of @tfw_sched_get_sg_srv_conn();
 * @sched_sg_conn	- virtual method. Schedule a request to a server from
 *			  given server group. Returns a server connection;
 * @sched_srv_conn	- schedule a request to the given server.
 *			  Returns a server connection;
 *
 * There can be 2 kind of schedulers. Tier-2 schedulers can determine the
 * target server connection by server or server group (@sched_srv_conn and
 * @sched_sg_conn callbacks). Each server group is bound to one of tier-2
 * schedulers. Group schedulers can determine the target server group from
 * request's content (@sched_grp callback) and then get an outgoing
 * connection by calling @tfw_sched_get_sg_srv_conn().
 */
struct tfw_scheduler_t {
	const char		*name;
	struct list_head	list;
	int			(*add_grp)(TfwSrvGroup *sg);
	void			(*del_grp)(TfwSrvGroup *sg);
	TfwSrvConn		*(*sched_grp)(TfwMsg *msg);
	TfwSrvConn		*(*sched_sg_conn)(TfwMsg *msg, TfwSrvGroup *sg);
	TfwSrvConn		*(*sched_srv_conn)(TfwMsg *msg, TfwServer *srv);
};

/* Server specific routines. */
TfwServer *tfw_server_create(const TfwAddr *addr);
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
int tfw_sg_set_sched(TfwSrvGroup *sg, const char *sched);
int tfw_sg_for_each_srv(int (*cb)(TfwServer *srv));
void tfw_sg_release_all(void);

/* Scheduler routines. */
TfwSrvConn *tfw_sched_get_srv_conn(TfwMsg *msg);
TfwSrvConn *__tfw_sched_get_srv_conn(TfwMsg *msg);
TfwSrvConn *tfw_sched_get_sg_srv_conn(TfwMsg *msg, TfwSrvGroup *main_sg,
				      TfwSrvGroup *backup_sg);
TfwScheduler *tfw_sched_lookup(const char *name);
int tfw_sched_register(TfwScheduler *sched);
void tfw_sched_unregister(TfwScheduler *sched);

#endif /* __SERVER_H__ */
