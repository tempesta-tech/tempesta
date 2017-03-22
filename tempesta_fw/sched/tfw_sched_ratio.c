/**
 *		Tempesta FW
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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
#include <linux/kernel.h>
#include <linux/module.h>

#include "tempesta_fw.h"
#include "apm.h"
#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta ratio scheduler");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

#define	TFW_RATIO_TIMEOUT	(HZ / 20)	/* The timer periodicity. */

/*
 * The size of pool of TfwRatioRated{} entries for RCU substitution.
 * It's best when it's one more than the real number of CPU cores.
 */
#define TFW_RATIO_EPOOLSZ	(16 + 1)

/*
 * The size of scale that is used to range back-end servers.
 * It's most effective in calculations when it's a power of two. 
 */
#define TFW_RATIO_SCALE_64	(1 << 6)
#if TFW_SG_MAX_SRV > TFW_RATIO_SCALE_64
#define TFW_RATIO_SCALE		TFW_SG_MAX_SRV
#else
#define TFW_RATIO_SCALE		TFW_RATIO_SCALE_64
#endif

/**
 * List of connections to an upstream server.
 * Connections can go up and down during failover process. Only
 * fully established connections are considered by the scheduler.
 */
typedef struct {
	atomic64_t		counter;
	size_t			conn_n;
	TfwServer		*srv;
	TfwSrvConn 		*conns[TFW_SRV_MAX_CONN];
} TfwRatioSrv;

/**
 * RCU-fortified array of pointers to TfwRatioSrv{} ranged by each
 * back-end server's weight. The number of times a server is found
 * in the array is defined by the server's weight relative to other
 * back-end servers in the group.
 */
typedef struct {
	struct rcu_head		rcu;
	size_t			listsz;
	TfwRatioSrv		*list[TFW_RATIO_SCALE];
	atomic_t		free;
} TfwRatioRated;

/**
 * List of upstream servers.
 * The list is considered static, i.e. all servers, either dead
 * or alive, are present in the list during the whole run-time.
 * That may change in the future.
 */
typedef struct {
	atomic64_t		counter;
	size_t			srv_n;
	atomic_t		rearm;
	struct timer_list	timer;
	TfwRatioSrv		srvs[TFW_SG_MAX_SRV];
	TfwRatioRated		epool[TFW_RATIO_EPOOLSZ];
	TfwRatioRated __rcu	*rated;
} TfwRatioSrvList;

static void
tfw_sched_ratio_calc(int *weight, int *ratio, size_t sz)
{
	size_t s;
	unsigned long calc[sz], sum = 0, unit;

	for (s = 0; s < sz; ++s) {
		calc[s] = ((1 << 16) * TFW_RATIO_SCALE) / weight[s];
		sum += calc[s];
	}
	unit = ((1 << 16) * TFW_RATIO_SCALE) / sum;
	for (s = 0; s < sz; ++s)
		ratio[s] = (calc[s] * unit) / (1 << 16) ? : 1;
}

static inline void
tfw_sched_fill_rated(TfwSrvGroup *sg, int *ratio, TfwRatioRated *rated)
{
	size_t s, i, n;
	TfwRatioSrvList *sl = sg->sched_data;

	for (s = 0, i = 0; s < sl->srv_n; ++s)
		for (n = 0; n < ratio[s]; ++n, ++i)
			rated->list[i] = &sl->srvs[s];
	rated->listsz = i;
}

static inline void
tfw_sched_fill_equal(TfwSrvGroup *sg, int *ratio, TfwRatioRated *rated)
{
	size_t s, i, n;
	int eqshare = ratio[0];
	TfwRatioSrvList *sl = sg->sched_data;

	for (n = 0, i = 0; n < eqshare; ++n)
		for (s = 0; s < sl->srv_n; ++s, ++i)
			rated->list[i] = &sl->srvs[s];
	rated->listsz = i;
}

/*
 * Calculate server ratios based on specific dynamic weights.
 * Return 1 if no recalculation is required.
 * Return 0 if the ratios were recalculated.
 */
static int
tfw_sched_ratio_dynamic(TfwSrvGroup *sg, int *ratio)
{
	size_t s;
	TfwRatioSrvList *sl = sg->sched_data;
	int recalc = 0, weight[sl->srv_n];
	int idx = sg->flags & TFW_SG_F_PSTATS_IDX_MASK;
	unsigned int val[ARRAY_SIZE(tfw_pstats_ith)] = { 0 };
	TfwPrcntlStats pstats = {
		.ith = tfw_pstats_ith,
		.val = val,
		.psz = ARRAY_SIZE(tfw_pstats_ith)
	};

	for (s = 0; s < sl->srv_n; ++s) {
		recalc |= tfw_apm_stats(sl->srvs[s].srv->apm, &pstats);
		weight[s] = pstats.val[idx] ? : 1;
	}
	if (!recalc)
		return 1;

	tfw_sched_ratio_calc(weight, ratio, sl->srv_n);

	return 0;
}

/*
 * Calculate ratios for servers with equal weights.
 * Return 1 to indicate that all ratios/weights are equal.
 */
static int
tfw_sched_ratio_equal(TfwSrvGroup *sg, int *ratio)
{
	size_t s;
	TfwRatioSrvList *sl = sg->sched_data;
	int eqshare = TFW_RATIO_SCALE / sl->srv_n ? : 1;

	for (s = 0; s < sl->srv_n; ++s)
		ratio[s] = eqshare;

	return 1;
}

/*
 * Calculate ratios for servers with static, possibly different weights.
 * Return 1 to indicate that all ratios/weights are equal.
 * Return 0 to indicate that ratios are calculated by individial weights.
 */
static int
tfw_sched_ratio_static(TfwSrvGroup *sg, int *ratio)
{
	size_t s;
	TfwRatioSrvList *sl = sg->sched_data;
	int diff = 0, wequal, weight[sl->srv_n];

	wequal = sl->srvs[0].srv->weight;
	for (s = 0; s < sl->srv_n; ++s) {
		weight[s] = sl->srvs[s].srv->weight;
		diff |= (wequal != weight[s]);
	}
	if (!diff) {
		tfw_sched_ratio_equal(sg, ratio);
		return 1;
	}

	tfw_sched_ratio_calc(weight, ratio, sl->srv_n);

	return 0;
}

/**
 * Add a connection and a server, if new, to the scheduler.
 * Called at configuration stage, no synchronization is required.
 */
static void
tfw_sched_ratio_add_conn(TfwSrvGroup *sg, TfwServer *srv, TfwSrvConn *srv_conn)
{
	size_t s, c;
	TfwRatioSrv *cl;
	TfwRatioSrvList *sl = sg->sched_data;

	BUG_ON(!sl);

	for (s = 0; s < sl->srv_n; ++s)
		if (sl->srvs[s].srv == srv)
			break;
	BUG_ON(s == TFW_SG_MAX_SRV);

	cl = &sl->srvs[s];

	if (s == sl->srv_n) {
		int nodiff, ratio[sl->srv_n + 1];
		TfwRatioRated *rated = sl->rated;

		cl->srv = srv;
		++sl->srv_n;

		if (sg->flags & TFW_SG_F_SCHED_RATIO_STATIC)
			nodiff = tfw_sched_ratio_static(sg, ratio);
		else if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC)
			nodiff = tfw_sched_ratio_equal(sg, ratio);
		else
			BUG();

		if (nodiff)
			tfw_sched_fill_equal(sg, ratio, rated);
		else
			tfw_sched_fill_rated(sg, ratio, rated);
	}

	for (c = 0; c < cl->conn_n; ++c) {
		if (cl->conns[c] == srv_conn) {
			TFW_WARN("sched=[%s]: attempt to add an existing "
				 "connection: sg=[%s] srv=[%zd] conn=[%zd]\n",
				 sg->sched->name, sg->name, s, c);
			return;
		}
	}
	BUG_ON(c == TFW_SRV_MAX_CONN);

	cl->conns[c] = srv_conn;
	++cl->conn_n;
}

/**
 * On each subsequent call the function returns the next available
 * connection to one of the servers in the group. Connections to a
 * server are rotated in pure round-robin manner. The server is chosen
 * according to its current weight. Servers with more weight are chosen
 * more often than servers with less weight. 
 * Dead connections and servers w/o live connections are skipped.
 */
static TfwSrvConn *
tfw_sched_ratio_get_srv_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	size_t s, c, n;
	uint64_t idx;
	TfwSrvConn *srv_conn;
	TfwRatioSrvList *sl = sg->sched_data;
	TfwRatioSrv *cl, *cl_down = NULL;
	TfwRatioRated *rated;

	BUG_ON(!sl);

	rcu_read_lock();
	rated = rcu_dereference(sl->rated);

	for (s = 0, n = 0; s < sl->srv_n; ++s) {
		do {
			idx = atomic64_inc_return(&sl->counter);
			cl = rated->list[idx % rated->listsz];
			if (likely(cl != cl_down))
				break;
		} while (++n < rated->listsz);

		if (unlikely(n == rated->listsz))
			continue;

		for (c = 0; c < cl->conn_n; ++c) {
			idx = atomic64_inc_return(&cl->counter);
			srv_conn = cl->conns[idx % cl->conn_n];
			if (tfw_srv_conn_get_if_live(srv_conn)) {
				rcu_read_unlock();
				return srv_conn;
			}
		}
		cl_down = cl;
	}

	rcu_read_unlock();
	return NULL;
}

/*
 * Get a free for use entry from the RCU pool.
 */
static TfwRatioRated *
tfw_sched_rated_get(TfwRatioSrvList *sl)
{
	int i;

	for (i = 0; i < TFW_RATIO_EPOOLSZ; ++i) {
		smp_mb__before_atomic();
		if (atomic_read(&sl->epool[i].free)) {
			atomic_set(&sl->epool[i].free, 0);
			return &sl->epool[i];
		}
	}

	return NULL;
}

/*
 * Return an entry to the RCU pool.
 */
static void
tfw_sched_rated_put(struct rcu_head *rcup)
{
	TfwRatioRated *rated = container_of(rcup, TfwRatioRated, rcu);

	rated->listsz = 0;
	atomic_set(&rated->free, 1);
	smp_mb__after_atomic();
}

/*
 * Calculate the latest load balancing data if necessary.
 * This code runs periodically on timer and recalculates each server's
 * share according to current weight of each server. The calculated data
 * is used in tfw_sched_ratio_get_srv_conn()
 *
 * RCU is used to avoid locks here and in tfw_sched_ratio_get_srv_conn().
 * When recalculation is required, new data is placed in an available
 * entry from RCU pool. The new entry is then seamlessly set as the
 * current entry. The previous entry is made available when all users
 * of it are gone.
 * That makes things somewhat non-deterministic. It may happen that no
 * entry is available at the moment. That's not a big deal. Scheduling
 * of destination servers will continue to run on current data.
 * The timer is scheduled to run ASAP and catch a new entry the moment
 * it gets available.
 */
static void
tfw_sched_ratio_tmfn(unsigned long fndata)
{
	TfwSrvGroup *sg = (TfwSrvGroup *)fndata;
	TfwRatioSrvList *sl = sg->sched_data;
	uint64_t idx;
	static uint64_t lastidx = 0;
	TfwRatioRated *prev_rated, *this_rated;
	int timeout = TFW_RATIO_TIMEOUT, ratio[sl->srv_n];

	/* No need to do anything if there was no activity. */
	smp_mb__before_atomic();
	idx = atomic64_read(&sl->counter);
	if (unlikely(idx == lastidx))
		goto rearm;

	/* Just re-arm if no recalculation is required. */
	if (tfw_sched_ratio_dynamic(sg, ratio))
		goto rearm;
	/*
	 * Get an available entry from the pool. If there's none,
	 * then re-schedule the timer to run as soon as possible,
	 * and get an entry the moment it is available.
	 */
	this_rated = tfw_sched_rated_get(sl);
	if (unlikely(!this_rated)) {
		TFW_DBG3("%s: No available RCU entry\n", __func__);
		timeout = 1;
		goto rearm;
	}

	tfw_sched_fill_rated(sg, ratio, this_rated);

	prev_rated = sl->rated;
	rcu_assign_pointer(sl->rated, this_rated);
	call_rcu(&prev_rated->rcu, tfw_sched_rated_put);

	lastidx = idx;
rearm:
	smp_mb__before_atomic();
	if (atomic_read(&sl->rearm))
		mod_timer(&sl->timer, jiffies + timeout);
}

/*
 * Called when a scheduler is set for a server group.
 * That's when a server group becomes full-functioning.
 */
static void
tfw_sched_ratio_alloc_data(TfwSrvGroup *sg)
{
	int i;
	TfwRatioSrvList *sl;

	BUG_ON(!(sg->flags & ~TFW_SG_F_PSTATS_IDX_MASK));

	sl = kzalloc(sizeof(TfwRatioSrvList), GFP_KERNEL);
	BUG_ON(!sl);

	for (i = 1; i < TFW_RATIO_EPOOLSZ; ++i)
		atomic_set(&sl->epool[i].free, 1);
	rcu_assign_pointer(sl->rated, &sl->epool[0]);
	sg->sched_data = sl;

	/* Set up ALB recalculation timer. */
	if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC) {
		atomic_set(&sl->rearm, 1);
		setup_timer(&sl->timer, tfw_sched_ratio_tmfn,
			    (unsigned long)sg);
		mod_timer(&sl->timer, jiffies + TFW_RATIO_TIMEOUT);
	}
}

static void
tfw_sched_ratio_free_data(TfwSrvGroup *sg)
{
	TfwRatioSrvList *sl = sg->sched_data;

	atomic_set(&sl->rearm, 0);
	smp_mb__after_atomic();
	del_timer_sync(&sl->timer);

	kfree(sg->sched_data);
}

static TfwScheduler tfw_sched_ratio = {
	.name		= "ratio",
	.list		= LIST_HEAD_INIT(tfw_sched_ratio.list),
	.add_grp	= tfw_sched_ratio_alloc_data,
	.del_grp	= tfw_sched_ratio_free_data,
	.add_conn	= tfw_sched_ratio_add_conn,
	.sched_srv	= tfw_sched_ratio_get_srv_conn,
};

int
tfw_sched_ratio_init(void)
{
	TFW_DBG("sched_ratio: init\n");
	return tfw_sched_register(&tfw_sched_ratio);
}
module_init(tfw_sched_ratio_init);

void
tfw_sched_ratio_exit(void)
{
	TFW_DBG("sched_ratio: exit\n");
	tfw_sched_unregister(&tfw_sched_ratio);
	synchronize_rcu();
}
module_exit(tfw_sched_ratio_exit);

