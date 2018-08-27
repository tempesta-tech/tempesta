/**
 *		Tempesta FW
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
#ifndef __SERVER_H__
#define __SERVER_H__

#include "addr.h"
#include "connection.h"
#include "peer.h"
#include "str.h"

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
 * @gs_timer	- grace shutdown timer;
 * @sg		- back-reference to the server group;
 * @sched_data	- private scheduler data for the server;
 * @apmref	- opaque handle for APM stats;
 * @conn_n	- configured number of connections to the server;
 * @sess_n	- number of pinned sticky sessions;
 * @refcnt	- number of users of the server structure instance;
 * @weight	- static server weight for load balancers;
 * @flags	- server related flags: TFW_CFG_M_ACTION and HM atomic flags;
 * @cleanup	- called right before server is destroyed;
 */
typedef struct {
	TFW_PEER_COMMON;
	struct list_head	list;
	struct timer_list	gs_timer;
	TfwSrvGroup		*sg;
	void __rcu		*sched_data;
	void			*apmref;
	size_t			conn_n;
	atomic64_t		sess_n;
	atomic64_t		refcnt;
	unsigned int		weight;
	unsigned long		flags;
	void			(*cleanup)(void *);
} TfwServer;

/*
 * Bits and corresponding flags for server's health monitor states.
 * These flags are intended for @flags field of 'TfwServer' structure.
 * NOTE: In cfg.h for this field there are also flags definitions, which
 * are responsible for server's configuration processing.
 */
enum {
	/* Health monitor is enabled for the server. */
	TFW_SRV_B_HMONITOR = 0x8,

	/* Server is excluded from processing. */
	TFW_SRV_B_SUSPEND
};

#define	TFW_SRV_F_HMONITOR	(1 << TFW_SRV_B_HMONITOR)
#define	TFW_SRV_F_SUSPEND	(1 << TFW_SRV_B_SUSPEND)

/**
 * The servers group with the same load balancing, failovering and eviction
 * policies.
 *
 * Reverse proxy must define load balancing policy. Forward proxy must define
 * eviction policy. While both of them should define failovering policy.
 *
 * @list	- member pointer in the active server groups list;
 * @list_reconfig - member pointer in the reconfig server groups list;
 *		  See 'Server group management' comment in server.c;
 * @srv_list	- list of servers belonging to the group;
 * @sched	- requests scheduling handler;
 * @sched_data	- private scheduler data for the server group;
 * @srv_n	- configured number of servers in the group;
 * @refcnt	- number of users of the server group structure instance;
 * @max_qsize	- maximum queue size of a server connection;
 * @max_refwd	- maximum number of tries for forwarding a request;
 * @max_jqage	- maximum age of a request in a server connection, in jiffies;
 * @max_recns	- maximum number of reconnect attempts;
 * @flags	- server group related flags;
 * @nlen	- name length;
 * @name	- name of the group specified in the configuration;
 */
struct tfw_srv_group_t {
	struct hlist_node	list;
	struct hlist_node	list_reconfig;
	struct list_head	srv_list;
	TfwScheduler		*sched;
	void __rcu		*sched_data;
	size_t			srv_n;
	atomic64_t		refcnt;
	unsigned int		max_qsize;
	unsigned int		max_refwd;
	unsigned long		max_jqage;
	unsigned int		max_recns;
	unsigned int		flags;
	unsigned int		nlen;
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
#define TFW_SG_M_PSTATS_IDX		0x000f
#define TFW_SG_F_SCHED_RATIO_STATIC	0x0010
#define TFW_SG_F_SCHED_RATIO_DYNAMIC	0x0020
#define TFW_SG_F_SCHED_RATIO_PREDICT	0x0040
#define TFW_SG_M_SCHED_RATIO_TYPE	(TFW_SG_F_SCHED_RATIO_STATIC	\
					 | TFW_SG_F_SCHED_RATIO_DYNAMIC	\
					 | TFW_SG_F_SCHED_RATIO_PREDICT)

#define TFW_SRV_RETRY_NIP		0x0100	/* Retry non-idempotent req. */
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
 * @add_srv	- add single server to the scheduler.
 *		  Called in process context at re-configuration time.
 * @del_srv	- delete single server added via add_srv.
 *		  Called in SoftIRQ context.
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
 * connection by using tier-2 scheduler assigned for a group.
 *
 * sched_*() methods can be called during live reconfiguration. Significant
 * changes of a server group may ruin scheduling process, so the group must be
 * removed from a scheduler before applying such changes. After that the group
 * can be added to a scheduler once again.
 */
struct tfw_scheduler_t {
	const char		*name;
	struct list_head	list;
	int			(*add_grp)(TfwSrvGroup *sg, void *arg);
	void			(*del_grp)(TfwSrvGroup *sg);
	int			(*add_srv)(TfwServer *srv);
	void			(*del_srv)(TfwServer *srv);
	TfwSrvConn		*(*sched_sg_conn)(TfwMsg *msg, TfwSrvGroup *sg);
	TfwSrvConn		*(*sched_srv_conn)(TfwMsg *msg, TfwServer *srv);
};

/* Server specific routines. */
TfwServer *tfw_server_create(const TfwAddr *addr);
void tfw_server_destroy(TfwServer *srv);
TfwServer *tfw_server_lookup(TfwSrvGroup *sg, TfwAddr *addr);
int tfw_server_start_sched(TfwServer *srv);
void tfw_server_stop_sched(TfwServer *srv);

void tfw_srv_conn_release(TfwSrvConn *srv_conn);

static inline bool
tfw_server_live(TfwServer *srv)
{
	return atomic64_read(&srv->refcnt) > 0;
}

static inline void
tfw_server_get(TfwServer *srv)
{
	atomic64_inc(&srv->refcnt);
}

static inline void
tfw_server_put(TfwServer *srv)
{
	long rc;

	if (unlikely(!srv))
		return;

	rc = atomic64_dec_return(&srv->refcnt);
	if (likely(rc))
		return;
	tfw_server_destroy(srv);
}

static inline void
tfw_server_pin_sess(TfwServer *srv)
{
	atomic64_inc(&srv->sess_n);
	tfw_server_get(srv);
}

static inline void
tfw_server_unpin_sess(TfwServer *srv)
{
	atomic64_dec(&srv->sess_n);
	tfw_server_put(srv);
}

/*
 * TODO: The function is racy: we can push into @srv_conn more requests than
 * allowed for the server group if @srv_conn is on hold due to non-idempotent
 * request forwarding. srv_conn->qsize is incremented during push, so values
 * close to UINT_MAX can be vulnerable to integer overflow.
 *
 */
static inline bool
tfw_srv_conn_queue_full(TfwSrvConn *srv_conn)
{
	TfwSrvGroup *sg = ((TfwServer *)srv_conn->peer)->sg;
	return (ACCESS_ONCE(srv_conn->qsize) >= sg->max_qsize);
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
	return ((ACCESS_ONCE(srv_conn->recns) >= sg->max_recns));
}

/*
 * Put server into alive state (in sense of HTTP availability).
 */
static inline void
tfw_srv_mark_alive(TfwServer *srv)
{
	clear_bit(TFW_SRV_B_SUSPEND, &srv->flags);
}

/*
 * Tell if server is suspended.
 */
static inline bool
tfw_srv_suspended(TfwServer *srv)
{
	return test_bit(TFW_SRV_B_SUSPEND, &srv->flags);
}

/* Server group routines. */
TfwSrvGroup *tfw_sg_lookup(const char *name, unsigned int len);
TfwSrvGroup *tfw_sg_lookup_reconfig(const char *name, unsigned int len);
TfwSrvGroup *tfw_sg_new(const char *name, unsigned int len, gfp_t flags);
int tfw_sg_add_reconfig(TfwSrvGroup *sg);
void tfw_sg_apply_reconfig(struct hlist_head *del_sg);
void tfw_sg_drop_reconfig(void);

void tfw_sg_add_srv(TfwSrvGroup *sg, TfwServer *srv);
void __tfw_sg_del_srv(TfwSrvGroup *sg, TfwServer *srv, bool lock);
#define tfw_sg_del_srv(sg, srv)	__tfw_sg_del_srv(sg, srv, true)
int tfw_sg_start_sched(TfwSrvGroup *sg, TfwScheduler *sched, void *arg);
void tfw_sg_stop_sched(TfwSrvGroup *sg);
int __tfw_sg_for_each_srv(TfwSrvGroup *sg,
			  int (*cb)(TfwSrvGroup *, TfwServer *, void *),
			  void *data);
int tfw_sg_for_each_srv(int (*sg_cb)(TfwSrvGroup *sg),
			int (*srv_cb)(TfwServer *srv));
int tfw_sg_for_each_srv_reconfig(int (*cb)(TfwServer *srv));
void tfw_sg_destroy(TfwSrvGroup *sg);
void tfw_sg_release(TfwSrvGroup *sg);
void tfw_sg_release_all(void);
void tfw_sg_wait_release(void);

static inline bool
tfw_sg_live(TfwSrvGroup *sg)
{
	return atomic64_read(&sg->refcnt) > 0;
}

static inline void
tfw_sg_get(TfwSrvGroup *sg)
{
	atomic64_inc(&sg->refcnt);
}

static inline void
tfw_sg_put(TfwSrvGroup *sg)
{
	if (unlikely(!sg))
		return;
	if (likely(atomic64_dec_return(&sg->refcnt)))
		return;
	tfw_sg_destroy(sg);
}

static inline bool
tfw_sg_name_match(TfwSrvGroup *sg, const char *name, unsigned int len)
{
	return len == sg->nlen && !strncasecmp(sg->name, name, len);
}

/* Scheduler routines. */
TfwScheduler *tfw_sched_lookup(const char *name);
int tfw_sched_register(TfwScheduler *sched);
void tfw_sched_unregister(TfwScheduler *sched);

#endif /* __SERVER_H__ */
