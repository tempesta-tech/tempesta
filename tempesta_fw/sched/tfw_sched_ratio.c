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
 * @cratio	- current server ratio.
 * @oratio	- original server ratio.
 */
typedef struct {
	size_t		sidx;
	unsigned int	weight;
	unsigned int	cratio;
	unsigned int	oratio;
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
	unsigned int	riter;
	unsigned long	crsum;
	unsigned long	orsum;
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
 * Set up initial or static ratios for all servers in the group.
 */
static void
tfw_sched_ratio_set_static(TfwRatio *ratio)
{
	size_t srv_i;
	unsigned int diff = 0, wequal;

	BUG_ON(!ratio);
	wequal = ratio->srvs[0].srv->weight;

	for (srv_i = 0; srv_i < ratio->srv_n; ++srv_i) {
		unsigned int weight_i = ratio->srvs[srv_i].srv->weight;
		ratio->sched.srvdata[srv_i].sidx = srv_i;
		ratio->sched.srvdata[srv_i].weight = weight_i;
		diff |= (wequal != weight_i);
	}
	if (!diff) {
		for (srv_i = 0; srv_i < ratio->srv_n; ++srv_i) {
			ratio->sched.srvdata[srv_i].cratio =
			ratio->sched.srvdata[srv_i].oratio = 1;
		}
		ratio->sched.schdata.csidx = 0;
		ratio->sched.schdata.riter = 1;
		ratio->sched.schdata.rearm = ratio->srv_n;
		ratio->sched.schdata.crsum =
		ratio->sched.schdata.orsum = ratio->srv_n;
		return;
	}
	printk(KERN_ERR "%s: Different weights are not supported yet.\n",
			__func__);
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
		++rsrv;
		++srv_i;
	}
	ratio->srv_n = sg->srv_n;

	/* Set up the initial ratio data. */
	if (!(sg->flags & (TFW_SG_F_SCHED_RATIO_STATIC
			   | TFW_SG_F_SCHED_RATIO_DYNAMIC)))
		BUG();
	if (sg->flags & TFW_SG_F_SCHED_RATIO_STATIC)
		printk(KERN_ERR "ratio static.\n");
	else if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC)
		printk(KERN_ERR "ratio dynamic: %d\n",
				sg->flags & TFW_SG_F_PSTATS_IDX_MASK);
	tfw_sched_ratio_set_static(ratio);

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
 * The logic is based on the assumption that servers and connections are
 * submitted in the same order as they were when add_grp() was called.
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

static inline bool
tfw_sched_ratio_is_srv_turn(TfwRatio *ratio, size_t csidx)
{
	unsigned int headsum2, tailsum2;
	TfwRatioSrvData *srvdata = ratio->sched.srvdata;
	TfwRatioSchedData *schdata = &ratio->sched.schdata;

	if (!csidx)
		return true;
	headsum2 = (srvdata[0].cratio + srvdata[csidx - 1].cratio) * csidx;
	tailsum2 = (srvdata[csidx].cratio
		    + (srvdata[ratio->srv_n - 1].cratio
		       ? : srvdata[ratio->srv_n - 1].cratio))
		   * (ratio->srv_n - csidx);
	return tailsum2 * schdata->riter > headsum2;
}

/*
 * Get the index of the next server
 *
 * The function is synchronized by a plain spin lock. A lock-free
 * implementation of the algorithm as it is would require too many
 * atomic operations including CMPXCHG and checking loops, so it seems
 * we won't win anything.
 */
static size_t
tfw_sched_ratio_next_srv(TfwRatio *ratio)
{
	size_t csidx;
	TfwRatioSrvData *srvdata = ratio->sched.srvdata;
	TfwRatioSchedData *schdata = &ratio->sched.schdata;

	spin_lock(&schdata->lock);
retry:
	csidx = schdata->csidx;
	if (!srvdata[csidx].cratio) {
		if (schdata->rearm != csidx) {
			++schdata->csidx;
			if (schdata->csidx == ratio->srv_n) {
				schdata->csidx = 0;
				schdata->riter = 1;
			}
			goto retry;
		}
		srvdata[csidx].cratio = srvdata[csidx].oratio;
		++schdata->rearm;
	}
	/*
	 * If it's the turn of the current server then take off a point
	 * from the server's current ratio (decrement it). Then prepare
	 * for the next time this function is called. If ratios of all
	 * servers got down to zero, then rearm everything and start
	 * from the beginning. Otherwise, if it's the last server in
	 * the group, then also start from the beginning, but do not
	 * re-arm as it's been re-armed already (make sure of that).
	 */
	if (likely(tfw_sched_ratio_is_srv_turn(ratio, csidx))) {
		--srvdata[csidx].cratio;
		if (unlikely(!--schdata->crsum)) {
			schdata->csidx = 0;
			schdata->riter = 1;
			schdata->crsum = schdata->orsum;
			schdata->rearm = 0;
		} else if (unlikely(++schdata->csidx == ratio->srv_n)) {
			BUG_ON(schdata->rearm != ratio->srv_n);
			schdata->csidx = 0;
			schdata->riter = 1;
		}
		spin_unlock(&schdata->lock);
		return csidx;
	}
	/*
	 * This is not the turn of the current server. Start
	 * a new iteration from the server with highest ratio.
	 */
	schdata->csidx = 0;
	++schdata->riter;
	goto retry;

	spin_unlock(&schdata->lock);
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
	uint64_t idxval;
	size_t csidx;
	TfwRatioPool *rpool = sg->sched_data;
	TfwRatio *ratio;
	TfwRatioSrv *rsrv;
	TfwSrvConn *srv_conn;

	printk(KERN_ERR "%s scheduler called.\n", sg->sched->name);
	BUG_ON(!rpool);

	rcu_read_lock();
	ratio = rcu_dereference(rpool->ratio);
	BUG_ON(!ratio);

	csidx = tfw_sched_ratio_next_srv(ratio);
	rsrv = &ratio->srvs[csidx];
	idxval = atomic64_inc_return(&rsrv->counter);
	srv_conn = rsrv->conns[idxval % rsrv->conn_n];
	if (tfw_srv_conn_get_if_live(srv_conn)) {
		printk(KERN_ERR "%s: sched srv=[%zd] conn=[%zd]\n",
				__func__, csidx,
				(size_t)(idxval % rsrv->conn_n));
		rcu_read_unlock();
		return(srv_conn);
	}

	rcu_read_unlock();
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
