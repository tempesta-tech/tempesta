/**
 *              Tempesta FW
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/kernel.h>
#include <linux/module.h>

#include "tempesta_fw.h"
#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta Ratio Scheduler");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

/**
 * Individual upstream server descriptor.
 *
 * Connections may go up or down during failover process.
 * Only fully established connections are considered by scheduler.
 *
 * @conn_n	- number of connections to server.
 * @srv		- pointer to server structure.
 * @conns	- list of pointers to server connection structures.
 * @counter	- monotonic counter for choosing the next connection.
 */
typedef struct {
	size_t		conn_n;
	TfwServer	*srv;
	TfwSrvConn	**conns;
	atomic64_t	counter;
} TfwRatioSrv;

/**
 * Server data for scheduler.
 *
 * @sidx	- server id this data is for.
 * @weight	- server weight.
 * @osratio	- original server ratio.
 * @csratio	- current server ratio.
 */
typedef struct {
	size_t		sidx;
	unsigned int	weight;
	unsigned int	osratio;
	unsigned int	csratio;
} TfwRatioSrvData;

/**
 * Scheduler iteration data.
 *
 * @lock	- must be in the same cache line for faster operations.
 * @csidx	- current server id.
 * @rearm       - next server id which ratio we need to re-arm, or @srv_n
 *		  if no re-arming is needed.
 * @riter	- ratio iteration, indicates the number of times we need
 *		  to choose all servers before the current one until we
 *		  can choose the current server.
 * @crsum	- current sum of all ratios, used to avoid scanning the
 *		  list of servers with fully zeroed ratios.
 * @orsum	- original sum of all ratios, used to re-arm @crsum.
 */
typedef struct {
	spinlock_t	lock;
	size_t		csidx;
	size_t		rearm;
	unsigned int    riter;
	unsigned int    crsum;
	unsigned int    orsum;
} TfwRatioSchedData;

/**
 * Scheduler data.
 */
typedef struct {
	TfwRatioSrvData		*srvdata;
	TfwRatioSchedData	schdata;
} TfwRatioSched;

/**
 * The main Ratio Scheduler structure.
 *
 * All servers, either dead or live, are present in the list during
 * the whole run-time. That may change in the future.
 *
 * @srv_n	- number of upstream servers.
 * @sched	- scheduler data.
 * @srvs	- array of upstream server descriptors, shared between
 *		  RCU pool entries.
 */
typedef struct {
	struct rcu_head	rcu;
	size_t		srv_n;
	TfwRatioSched	sched;
	TfwRatioSrv	*srvs;
} TfwRatio;

/**
 * The pool of TfwRatio{} structures for RCU.
 *
 * @pool	- pool of TfwRatio{} for RCU.
 * @ratio	- pointer to the currently used structure.
 */
typedef struct {
	TfwRatio	*rpool;
	TfwRatio __rcu	*ratio;
} TfwRatioPool;

/**
 * Release Ratio Scheduler data from a server group.
 */
static void
tfw_sched_ratio_cleanup(TfwSrvGroup *sg)
{
	size_t i;
	TfwRatio *ratio;
	TfwRatioPool *rpool = sg->sched_data;

	if (!rpool)
		return;

	/* Free the data that is shared in the pool. */
	ratio = rpool->ratio;
	for (i = 0; i < sg->srv_n; ++i)
		if (ratio->srvs[i].conns)
			kfree(ratio->srvs[i].conns);
	kfree(ratio->srvs);

	/* Free the data that is unique for each pool entry. */
	for (i = 0, ratio = rpool->rpool; i <= nr_cpu_ids; ++i, ++ratio)
		if (ratio->sched.srvdata)
			kfree(ratio->sched.srvdata);

	kfree(rpool);
	sg->sched_data = NULL;
}

/**
 * Delete a server group from Ratio Scheduler.
 */
static void
tfw_sched_ratio_del_grp(TfwSrvGroup *sg)
{
	tfw_sched_ratio_cleanup(sg);
}

/**
 * Add a server group to Ratio Scheduler.
 *
 * At the time this function is called the server group is fully formed
 * and populated with all servers and connections.
 */
static int
tfw_sched_ratio_add_grp(TfwSrvGroup *sg)
{
	int ret = -ENOMEM;
	size_t size, srv_i;
	TfwServer *srv;
	TfwSrvConn *srv_conn;
	TfwRatioPool *rpool;
	TfwRatio *ratio;
	TfwRatioSrv *rsrv;

	/*
	 * Validate the number of servers in the group, and the number
	 * of connections for each server.
	 */
	srv_i = 0;
	list_for_each_entry(srv, &sg->srv_list, list) {
		size_t conn_i = 0;
		list_for_each_entry(srv_conn, &srv->conn_list, list)
			++conn_i;
		if (conn_i > srv->conn_n)
			return -EINVAL;
		++srv_i;
	}
	if (srv_i > sg->srv_n)
		return -EINVAL;

	/* Pool of TfwRatio{}. Initial place for Ratio Scheduler data. */
	size = sizeof(TfwRatioPool) + sizeof(TfwRatio) * (nr_cpu_ids + 1);
	if (!(sg->sched_data = kzalloc(size, GFP_KERNEL)))
		return -ENOMEM;
	rpool = sg->sched_data;
	rpool->rpool = sg->sched_data + sizeof(TfwRatioPool);
	rpool->ratio = rpool->rpool;
	ratio = rpool->ratio;

	/* Array to hold server descriptors. */
	size = sizeof(TfwRatioSrv) * sg->srv_n;
	if (!(ratio->srvs = kzalloc(size, GFP_KERNEL)))
		goto cleanup;

	/* Array to hold server data for scheduler. */
	size = sizeof(TfwRatioSrvData) * sg->srv_n;
	if (!(ratio->sched.srvdata = kzalloc(size, GFP_KERNEL)))
		goto cleanup;
	spin_lock_init(&ratio->sched.schdata.lock);

	/* Initial setup of upstream server descriptors. */
	srv_i = 0;
	rsrv = ratio->srvs;
	list_for_each_entry(srv, &sg->srv_list, list) {
		size_t conn_i = 0;
		size = sizeof(TfwSrvConn *) * srv->conn_n;
		if (!(rsrv->conns = kzalloc(size, GFP_KERNEL)))
			goto cleanup;
		rsrv->srv = srv;
		rsrv->conn_n = srv->conn_n;
		atomic64_set(&rsrv->counter, 0);
		list_for_each_entry(srv_conn, &srv->conn_list, list)
			rsrv->conns[conn_i++] = srv_conn;
		ratio->sched.srvdata[srv_i].weight = srv->weight;
		++rsrv;
		++srv_i;
	}

	/* Set up the initial ratio data. */
	if (sg->flags & TFW_SG_F_SCHED_RATIO_STATIC)
		printk(KERN_ERR "ratio static.\n");
	else if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC)
		printk(KERN_ERR "ratio dynamic: %d\n",
				sg->flags & TFW_SG_F_PSTATS_IDX_MASK);
	else
		BUG();

	return 0;

cleanup:
	tfw_sched_ratio_cleanup(sg);
	return ret;
}

/**
 * Add a connection and a server, if new, to the scheduler.
 * Called at configuration stage, no synchronization is required.
 *
 * The whole server and server connections data for a group is complete
 * at the time the group is added to the scheduler with add_grp(). Thus
 * the actual role of the function is to make cure that data is the same.
 */
static void
tfw_sched_ratio_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwSrvConn *srv_conn)
{
	static size_t srv_i = 0, conn_i = 0;
	TfwRatioPool *rpool = sg->sched_data;
	TfwRatio *ratio;
	TfwRatioSrv *rsrv;
	TfwSrvConn *rconn;

	BUG_ON(!rpool);
	ratio = rpool->ratio;

	/* Make sure that data is the same. */
	rsrv = ratio->srvs + srv_i;
	BUG_ON(rsrv->srv != srv);

	rconn = rsrv->conns[conn_i];
	BUG_ON(rconn != srv_conn);

	if (++conn_i == srv->conn_n) {
		conn_i = 0;
		if (++srv_i == sg->srv_n)
			srv_i = 0;
	}
}

/**
 * On each subsequent call the function returns the next available
 * connection to one of the servers in the group. Connections to a
 * server are rotated in pure round-robin fashion.
 *
 * A server is chosen according to its current weight that can be
 * either static or dynamic. Servers with greater weight are chosen
 * more often than servers with lesser weight.
 *
 * Dead connections and servers w/o live connections are skipped.
 * Initially, connections with non-idempotent requests are also skipped
 * in attempt to increase throughput. However, if all live connections
 * contain a non-idempotent request, then re-run the algorithm and get
 * the first live connection they way it is usually done.
 *
 * Ratio scheduler must be the fastest scheduler. Also, it's essential
 * to maintain a completely fair distribution of requests to servers
 * according to servers weights.
 */
static TfwSrvConn *
tfw_sched_ratio_sched_srv(TfwMsg *msg, TfwSrvGroup *sg)
{
	printk(KERN_ERR "%s scheduler called.\n", sg->sched->name);
	return NULL;
}

static TfwScheduler tfw_sched_ratio = {
	.name		= "ratio",
	.list		= LIST_HEAD_INIT(tfw_sched_ratio.list),
	.add_grp	= tfw_sched_ratio_add_grp,
	.del_grp	= tfw_sched_ratio_del_grp,
	.add_conn	= tfw_sched_ratio_add_conn,
	.sched_srv	= tfw_sched_ratio_sched_srv,
};

int
tfw_sched_ratio_init(void)
{
	TFW_DBG("%s: init\n", tfw_sched_ratio.name);
	return tfw_sched_register(&tfw_sched_ratio);
}
module_init(tfw_sched_ratio_init);

void
tfw_sched_ratio_exit(void)
{
	TFW_DBG("%s: exit\n", tfw_sched_ratio.name);
	tfw_sched_unregister(&tfw_sched_ratio);
}
module_exit(tfw_sched_ratio_exit);
