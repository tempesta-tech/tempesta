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
#include <linux/sort.h>

#include "tempesta_fw.h"
#include "apm.h"
#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta Ratio Scheduler");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

#define TFW_SCHED_RATIO_INTVL	(HZ / 20)	/* The timer periodicity. */

/**
 * Individual upstream server descriptor.
 *
 * Connections may go up or down during failover process.
 * Only fully established connections are considered by scheduler.
 *
 * @srv		- pointer to server structure.
 * @conns	- list of pointers to server connection structures.
 * @counter	- monotonic counter for choosing the next connection.
 * @conn_n	- number of connections to server.
 * @seq		- current sequence number for APM stats.
 */
typedef struct {
	TfwServer	*srv;
	TfwSrvConn	**conns;
	atomic64_t	counter;
	size_t		conn_n;
	unsigned int	seq;
} TfwRatioSrvDesc;

/**
 * Server data for scheduler.
 *
 * @sdidx	- index of server descriptor this data is for.
 * @weight	- server weight.
 * @cratio	- current server ratio.
 * @oratio	- original server ratio.
 */
typedef struct {
	size_t		sdidx;
	unsigned int	weight;
	unsigned int	cratio;
	unsigned int	oratio;
} TfwRatioSrvData;

/**
 * Scheduler iteration data.
 *
 * @lock	- must be in the same cache line for faster operations.
 * @csidx	- index of current server data entry.
 * @reidx       - index of next server data entry which ratio we need
 *		  to reset, or @srv_n if no resetting is needed.
 * @riter	- ratio iteration, indicates the number of times we need
 *		  to choose all servers before the current one until we
 *		  can choose the current server.
 * @crsum	- current sum of all ratios, used to avoid scanning the
 *		  list of servers with fully zeroed ratios.
 * @orsum	- original sum of all ratios, used to reset @crsum.
 */
typedef struct {
	spinlock_t	lock;
	size_t		csidx;
	size_t		reidx;
	unsigned int	riter;
	unsigned long	crsum;
	unsigned long	orsum;
} TfwRatioSchData;

/**
 * The main Ratio Scheduler structure.
 *
 * All servers, either dead or live, are present in the list during
 * the whole run-time. That may change in the future.
 *
 * @rcu		- RCU control structure;
 * @free	- indicates that the pool entry is available for use.
 * @srv_n	- number of upstream servers.
 * @psidx	- APM pstats[] value index for dynamic ratios.
 * @sched	- scheduler data.
 * @srvdesc	- array of upstream server descriptors, shared between
 *		  RCU pool entries.
 * @srvdata	- scheduler data specific to each server in the group.
 * @schdata	- scheduler data common to all servers in the group.
 */
typedef struct {
	struct rcu_head		rcu;
	atomic_t		free;
	size_t			srv_n;
	size_t			psidx;
	TfwRatioSrvDesc		*srvdesc;
	TfwRatioSrvData		*srvdata;
	TfwRatioSchData		schdata;
} TfwRatio;

/**
 * The pool of TfwRatio{} structures for RCU.
 *
 * @pool	- pool of TfwRatio{} for RCU.
 * @ratio	- pointer to the currently used structure.
 * @rearm	- indicates if the timer can be re-armed.
 * @timer	- periodic timer for dynamic APM data.
 */
typedef struct {
	TfwRatio		*rpool;
	TfwRatio __rcu		*ratio;
	atomic_t		rearm;
	struct timer_list	timer;
} TfwRatioPool;

/**
 * Swap two server data entries. Required for sorting by sort().
 */
static void
tfw_sched_ratio_srvdata_swap(void *lhs, void *rhs, int size)
{
	TfwRatioSrvData *lhs_data = (TfwRatioSrvData *)lhs;
	TfwRatioSrvData *rhs_data = (TfwRatioSrvData *)rhs;
	TfwRatioSrvData tmp = *lhs_data;
	*lhs_data = *rhs_data;
	*rhs_data = tmp;
}

/**
 * Sort server data entries by ratio in descending order. Entries
 * with higher ratios are moved towards the start of the array.
 */
static int
tfw_sched_ratio_srvdata_cmp(const void *lhs, const void *rhs)
{
	unsigned int lhs_ratio = ((const TfwRatioSrvData *)lhs)->oratio;
	unsigned int rhs_ratio = ((const TfwRatioSrvData *)rhs)->oratio;

	if (lhs_ratio > rhs_ratio)
		return -1;
	if (lhs_ratio < rhs_ratio)
		return 1;
	return 0;
}

/**
 * Calculate and set up ratios for each server in the group.
 *
 * Return 0 if done with the ratios.
 * Return a non-zero value if additional actions are needed.
 */
static int
tfw_sched_ratio_calc(TfwRatio *ratio, unsigned int *arg_max_val_idx)
{
	size_t si;
	unsigned int diff, max_val_idx, max_wgt, oratio;
	unsigned long unit, sum_wgt = 0, sum_ratio = 0;
	TfwRatioSrvData *srvdata = ratio->srvdata;
	TfwRatioSchData *schdata = &ratio->schdata;

	BUG_ON(!ratio);

	/*
	 * Calculate the sum of server's weights in the group. Remember
	 * the index of server data entry with maximum weight. That same
	 * entry will also have the maximum ratio. See if all weights in
	 * the group are the same.
	 */
	diff = max_val_idx = 0;
	for (si = 0; si < ratio->srv_n; ++si) {
		if (srvdata[max_val_idx].weight < srvdata[si].weight)
			max_val_idx = si;
		sum_wgt += srvdata[si].weight;
		diff |= (srvdata[si].weight != srvdata[0].weight);
	}

	/* Set up the common part of scheduler data. */
	schdata->csidx = 0;
	schdata->riter = 1;
	schdata->reidx = ratio->srv_n;

	/*
	 * If all server weights are the same, then there's no need to do
	 * anything else. Set up all ratios to 1 and be done with it.
	 */
	if (!diff) {
		for (si = 0; si < ratio->srv_n; ++si)
			srvdata[si].cratio = srvdata[si].oratio = 1;
		schdata->crsum = schdata->orsum = ratio->srv_n;
		return 0;
	}

	/*
	 * Calculate each server's ratio using a special formula. See
	 * if all calculated ratios are the same. Set up scheduler data.
	 */
	max_wgt = srvdata[max_val_idx].weight;
	unit = ((max_wgt + ratio->srv_n) * max_wgt) / sum_wgt;
	for (si = 0; si < ratio->srv_n; ++si) {
		oratio = (unit * srvdata[si].weight) / max_wgt ? : 1;
		srvdata[si].cratio = srvdata[si].oratio = oratio;
		diff |= (oratio != srvdata[0].oratio);
		sum_ratio += oratio;
	}
	schdata->crsum = schdata->orsum = sum_ratio;

	/* Return the index of server data entry with maximum ratio. */
	*arg_max_val_idx = max_val_idx;

	return diff;
}

/*
 * Calculate and set up ratios for each server in a group based on
 * weights that are statically defined in the configuration file.
 */
static void
tfw_sched_ratio_calc_static(TfwRatio *ratio)
{
	size_t si;
	unsigned int max_val_idx = 0;
	TfwRatioSrvDesc *srvdesc = ratio->srvdesc;
	TfwRatioSrvData *srvdata = ratio->srvdata;

	/* Collect server weights from the configuration. */
	for (si = 0; si < ratio->srv_n; ++si) {
		srvdata[si].sdidx = si;
		srvdata[si].weight = srvdesc[si].srv->weight;
	}

	/* Calculate ratios based on server weights. */
	if (!tfw_sched_ratio_calc(ratio, &max_val_idx))
		return;

	/* Sort server data entries by ratio in descending order. */
	sort(srvdata, ratio->srv_n, sizeof(srvdata[0]),
	     tfw_sched_ratio_srvdata_cmp, tfw_sched_ratio_srvdata_swap);
}

/**
 * Calculate ratios for each server in a group based on dynamic data.
 * the function runs periodically on timer and provides the data that
 * is used by the ratio scheduler for outgoing requests.
 *
 * Latest dynamic data is provided by APM module and represent RTT values
 * for each server in a group. Ratios are calculated on those RTT values.
 * However that way the ratios do not represent the real weight of each
 * server because a bigger RTT value mean that a server is less favorable
 * and has a lesser, NOT bigger weight.
 *
 * Based on ratios calculated from RTT values, the algorithm here assigns
 * a correct ratio to each server in the group.
 * 1. If the minimal ratio is 1, then fill the entries with minimal ratio
 *    with values from an entry with the maximum ratio. Fill the entries
 *    with maximum ratio with values from an entry with minimal ratio.
 * 2. Sort the resulting array by ratio in descending order as required
 *    by the scheduling algorithm.
 * 3. Select the part of the array that omits entries from step 1 if any.
 *    Those are entries at the start and at the end of the array. Reverse
 *    the sequence of server descriptor indices in that part of the array.
 *    The resulting pairing of servers to ratios is the target.
 *
 * Return 0 if there are no new ratio values.
 * Return a non-zero value if new ratio values were calculated.
 */
static int
tfw_sched_ratio_calc_dynamic(TfwRatio *ratio)
{
	size_t si, left = 0, right = 0;
	unsigned int recalc = 0, max_ratio = 0;
	unsigned int has_one_val = 0, max_val_idx = 0;
	unsigned int val[ARRAY_SIZE(tfw_pstats_ith)] = { 0 };
	TfwPrcntlStats pstats = {
		.ith = tfw_pstats_ith,
		.val = val,
		.psz = ARRAY_SIZE(tfw_pstats_ith)
	};
	TfwRatioSrvData *srvdata = ratio->srvdata;
	TfwRatioSrvDesc *srvdesc = ratio->srvdesc;

	/*
	 * Collect server RTT values from APM module. See if APM may have
	 * provided new data, and a recalculation is required. Otherwise
	 * there's nothing to do.
	 *
	 * TODO: The following cases should be considered.
	 * 1. APM recalculates the stats on each request-response pair.
	 *    It's quite possible that the actual stats values did not
	 *    change. However, the APM doesn't know of that and reports
	 *    that the values may have changed. It would be great to
	 *    catch that and avoid the recalculation of ratios.
	 * 2. Depending on actual RTT values a small deviation from the
	 *    previous value should be acceptable. It should not cause
	 *    a recalculation of ratio.
	 * 3. Finally, a typical case is that only a handful of servers
	 *    misbehave in a large group of servers. Is there a way to
	 *    detect that and do a partial recalculation of ratios?
	 */
	for (si = 0; si < ratio->srv_n; ++si) {
		pstats.seq = srvdesc[si].seq;
		recalc |= tfw_apm_stats(srvdesc[si].srv->apm, &pstats);
		srvdesc[si].seq = pstats.seq;

		srvdata[si].sdidx = si;
		srvdata[si].weight = pstats.val[ratio->psidx] ? : 1;
	}
	if (!recalc)
		return 0;

	/* Calculate ratios based on server RTT values. */
	if (!tfw_sched_ratio_calc(ratio, &max_val_idx))
		return 1;

	/*
	 * It's guaranteed here that NOT all calculated ratio values are
	 * equal. See if there are ratio values that equal to 1. If so,
	 * do actions described in step 1 in the function's description.
	 * Adjust the sum of ratios that is changed in this procedure.
	 */
	for (si = 0; si < ratio->srv_n; ++si) {
		if (srvdata[si].oratio == 1) {
			has_one_val = 1;
			break;
		}
	}
	if (has_one_val) {
		unsigned int orsum = ratio->schdata.orsum;
		TfwRatioSrvData sdent_one = srvdata[si];
		TfwRatioSrvData sdent_max = srvdata[max_val_idx];

		/* Save maximum ratio value for future use. */
		max_ratio = srvdata[max_val_idx].oratio;

		for (si = 0; si < ratio->srv_n; ++si) {
			if (srvdata[si].oratio == 1) {
				srvdata[si].weight = sdent_max.weight;
				srvdata[si].oratio =
				srvdata[si].cratio = sdent_max.oratio;
				orsum += sdent_max.oratio - 1;
			} else if (srvdata[si].oratio == sdent_max.oratio) {
				srvdata[si].weight = sdent_one.weight;
				srvdata[si].oratio =
				srvdata[si].cratio = sdent_one.oratio;
				orsum -= sdent_max.oratio - 1;
			}
		}
		ratio->schdata.crsum = ratio->schdata.orsum = orsum;
	}

	/* Sort server data entries by ratio in descending order. */
	sort(srvdata, ratio->srv_n, sizeof(srvdata[0]),
	     tfw_sched_ratio_srvdata_cmp, tfw_sched_ratio_srvdata_swap);

	/*
	 * Do actions described in step 3 in the function's description.
	 * Select the part of the array that omits entries from step 1
	 * if there are any. Those are entries at the start and at the
	 * end of the array. Reverse the sequence of server descriptor
	 * indices in that part of the array.
	 */
	if (has_one_val) {
		left = 0;
		right = ratio->srv_n - 1;
	} else {
		for (si = 0; si < ratio->srv_n; ++si)
			if (srvdata[si].oratio == max_ratio) {
				left = si + 1;
			} else if (srvdata[si].oratio == 1) {
				right = si - 1;
				break;
			}
	}
	while (left < right) {
		size_t left_sdidx = srvdata[left].sdidx;
		srvdata[left++].sdidx = srvdata[right].sdidx;
		srvdata[right--].sdidx = left_sdidx;
	}

	return 1;
}

/*
 *  * Get a free for use entry from the RCU pool.
 *   */
static TfwRatio *
tfw_sched_ratio_rpool_get(TfwRatioPool *rpool)
{
	int si;
	TfwRatio *ratio = rpool->rpool;

	for (si = 0; si <= nr_cpu_ids; ++si, ++ratio) {
		smp_mb__before_atomic();
		if (atomic_read(&ratio->free)) {
			atomic_set(&ratio->free, 0);
			return ratio;
		}
	}

        return NULL;
}

/*
 * Return an entry to the RCU pool.
 */
static inline void
__tfw_sched_ratio_rpool_put(TfwRatio *ratio)
{
        atomic_set(&ratio->free, 1);
        smp_mb__after_atomic();
}

static void
tfw_sched_ratio_rpool_put(struct rcu_head *rcup)
{
        TfwRatio *ratio = container_of(rcup, TfwRatio, rcu);
	__tfw_sched_ratio_rpool_put(ratio);
}

/**
 * Calculate the latest ratios for each server in the group in real time.
 *
 * RCU is used to avoid locks. When recalculation is in order, the new
 * data is placed in an available entry from the RCU pool. The new entry
 * then is seamlessly set as the current entry. The formerly active entry
 * is returned to the RCU pool when all users of it are done and gone.
 *
 * It may happen that no RCU pool entry is available at the moment.
 * That's not a big deal. Scheduling of upstream servers will continue
 * to run on currently active data. The timer is scheduled to run ASAP
 * and catch an RCU pool entry the moment it gets available.
 * To make this case less probable, the number of RCU pool entries
 * is chosen as one more than the number of CPU slots in the system.
 */
static void
tfw_sched_ratio_tmfn(unsigned long tmfn_data)
{
	TfwSrvGroup *sg = (TfwSrvGroup *)tmfn_data;
	TfwRatioPool *rpool = sg->sched_data;
	TfwRatio *cratio, *nratio;
	int interval = TFW_SCHED_RATIO_INTVL;

	/*
	 * Get an available ratio entry from the RCU pool. If there's
	 * none at the moment, then try it again in a short while on
	 * the next run of timer function.
	 */
	nratio = tfw_sched_ratio_rpool_get(rpool);
	if (unlikely(!nratio)) {
		interval = 1;
		goto rearm;
	}

	/*
	 * Calculate dynamic ratios. If there's nothing to do, then
	 * return the ratio entry back to the RCU pool.
	 */
	if (!tfw_sched_ratio_calc_dynamic(nratio)) {
		__tfw_sched_ratio_rpool_put(nratio);
		goto rearm;
	}

	/*
	 * Substitute the current ratio entry with the new one for
	 * scheduler. The former entry will be returned to the RCU
	 * pool when there are no users of it.
	 */
	cratio = rpool->ratio;
	rcu_assign_pointer(rpool->ratio, nratio);
	call_rcu(&cratio->rcu, tfw_sched_ratio_rpool_put);

rearm:
	smp_mb__before_atomic();
	if (atomic_read(&rpool->rearm))
		mod_timer(&rpool->timer, jiffies + interval);
}

/*
 * Determine if it's the turn of the server described by the server
 * data entry at index @csidx.
 *
 * It's the turn of server at @csidx if sums of ratios to the left and
 * to the right of this entry are proportional to the current iteration.
 * As the scheduler algorithm moves forward, the sum of ratios on the
 * left side decreases. When a server is selected, its current ratio
 * is decremented, so the sum of ratios decreases by 1 as well.
 *
 * With that in mind, ratios that have a huge difference should not be
 * specified for servers in the same group. A decrement of a huge sum
 * would be too insignificant to affect the scheduling algorithm. Thus
 * weights like { 10, 1 } make more sense than weights like { 1000, 10 }.
 * Requests are distributed proportionally in both cases, but significant
 * bursts are possible in the first case.
 *
 * TODO: The algorithm may and should be improved.
 */
static inline bool
tfw_sched_ratio_is_srv_turn(TfwRatio *ratio, size_t csidx)
{
	unsigned int headsum2, tailsum2;
	TfwRatioSrvData *srvdata = ratio->srvdata;
	TfwRatioSchData *schdata = &ratio->schdata;

	if (!csidx)
		return true;

	headsum2 = (srvdata[0].cratio + srvdata[csidx - 1].cratio) * csidx;
	tailsum2 = (srvdata[csidx].cratio
		    + (srvdata[ratio->srv_n - 1].cratio
		       ? : srvdata[ratio->srv_n - 1].oratio))
		   * (ratio->srv_n - csidx);

	return tailsum2 * schdata->riter > headsum2;
}

/*
 * Get the index of the next server descriptor.
 *
 * The array of server data entries used by the algorithm must be sorted
 * by ratio in descending order, with the higher weight entries moved
 * towards the start of the array.
 *
 * For concurrent use the algorithm is synchronized by a plain spin lock.
 * A lock-free implementation of the algorithm as it is would require too
 * many atomic operations including CMPXCHG and checking loops. It seems
 * that it won't give any advantage.
 */
static TfwRatioSrvDesc *
tfw_sched_ratio_next_srv(TfwRatio *ratio)
{
	size_t csidx;
	TfwRatioSrvData *srvdata = ratio->srvdata;
	TfwRatioSchData *schdata = &ratio->schdata;

	/* Start with server that has the highest ratio. */
	spin_lock(&schdata->lock);
retry:
	csidx = schdata->csidx;
	if (!srvdata[csidx].cratio) {
		/*
		 * The server's counter (current ratio) is depleted, but
		 * the server is not due yet for re-arming. Don't choose
		 * this server. This is a likely branch for ratios like
		 * { N, 1, 1, 1, ... } where N > 1 at some point. This
		 * is not the case if all server weights (and therefore
		 * ratios) were specified as 1. In that case it's down
		 * to plain round-robin.
		 */
		if (schdata->reidx != csidx) {
			++schdata->csidx;
			if (schdata->csidx == ratio->srv_n) {
				schdata->csidx = 0;
				schdata->riter = 1;
			}
			goto retry;
		}
		srvdata[csidx].cratio = srvdata[csidx].oratio;
		++schdata->reidx;
		/* Fall through */
	}
	/*
	 * If it's the turn of the current server then take off a point
	 * from the server's current ratio (decrement it). Then prepare
	 * for the next time this function is called. If ratios of all
	 * servers got down to zero, then reset everything and start
	 * from the beginning. Otherwise, if it's the last server in
	 * the group, then also start from the beginning, but do not
	 * reset as it's been reset already (make sure of that).
	 */
	if (likely(tfw_sched_ratio_is_srv_turn(ratio, csidx))) {
		--srvdata[csidx].cratio;
		if (unlikely(!--schdata->crsum)) {
			schdata->csidx = 0;
			schdata->riter = 1;
			schdata->crsum = schdata->orsum;
			schdata->reidx = 0;
		} else if (unlikely(++schdata->csidx == ratio->srv_n)) {
			BUG_ON(schdata->reidx != ratio->srv_n);
			schdata->csidx = 0;
			schdata->riter = 1;
		}
		spin_unlock(&schdata->lock);
		return ratio->srvdesc + srvdata[csidx].sdidx;
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

static inline TfwSrvConn *
__sched_srv(TfwRatioSrvDesc *srvdesc, int skipnip, int *nipconn)
{
	size_t ci;

	for (ci = 0; ci < srvdesc->conn_n; ++ci) {
		unsigned long idxval = atomic64_inc_return(&srvdesc->counter);
		TfwSrvConn *srv_conn = srvdesc->conns[idxval % srvdesc->conn_n];

		if (unlikely(tfw_srv_conn_restricted(srv_conn)
			     || tfw_srv_conn_queue_full(srv_conn)))
			continue;
		if (skipnip && tfw_srv_conn_hasnip(srv_conn)) {
			if (likely(tfw_srv_conn_live(srv_conn)))
				++(*nipconn);
			continue;
		}
		if (likely(tfw_srv_conn_get_if_live(srv_conn)))
			return srv_conn;
	}

	return NULL;
}

/**
 * Same as @tfw_sched_ratio_sched_sg_conn(), but schedule a connection
 * to a specific server in a group.
 */
static TfwSrvConn *
tfw_sched_ratio_sched_srv_conn(TfwMsg *msg, TfwServer *srv)
{
        int skipnip = 1, nipconn = 0;
        TfwRatioSrvDesc *srvdesc = srv->sched_data;
        TfwSrvConn *srv_conn;

        /*
	 * For @srv without connections @srvdesc will be NULL. Normally,
	 * it doesn't happen in real life, but unit tests check this case.
	 */
        if (unlikely(!srvdesc))
                return NULL;
rerun:
        if ((srv_conn = __sched_srv(srvdesc, skipnip, &nipconn)))
                return srv_conn;

        if (skipnip && nipconn) {
                skipnip = 0;
                goto rerun;
        }

        return NULL;
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
tfw_sched_ratio_sched_sg_conn(TfwMsg *msg, TfwSrvGroup *sg)
{
	size_t srv_tried_n = 0;
        int skipnip = 1, nipconn = 0;
	TfwRatioPool *rpool = sg->sched_data;
	TfwRatioSrvDesc *srvdesc, *srvdesc_last = NULL;
	TfwSrvConn *srv_conn;
	TfwRatio *ratio;

	BUG_ON(!rpool);

	rcu_read_lock();
	ratio = rcu_dereference(rpool->ratio);
	BUG_ON(!ratio);
rerun:
	/*
	 * Try each server in a group. Attempt to schedule a connection
	 * to a server that doesn't fall under a set of restrictions.
	 *
	 * FIXME: The way the algorithm works, same server may be chosen
	 * multiple times in a row, even if that's the server where all
	 * connections were under restrictions for one reason or another.
	 * The idea is that the conditions for server's connections may
	 * change any time, and so the next time one or more connections
	 * to the same server will not be restricted.
	 * Perhaps, though, it makes sense to skip these servers that
	 * were restricted, and go directly to the next server. Getting
	 * the next server reqires a lock, so perhaps it makes sense to
	 * to skip these repetitive servers while under the lock.
	 */
	while (srv_tried_n < ratio->srv_n) {
		srvdesc = tfw_sched_ratio_next_srv(ratio);
		if ((srv_conn = __sched_srv(srvdesc, skipnip, &nipconn))) {
			rcu_read_unlock();
			return srv_conn;
		}
		if (srvdesc != srvdesc_last)
			++srv_tried_n;
	}
	/* Relax the restrictions and re-run the search cycle. */
	if (skipnip && nipconn) {
		skipnip = 0;
		goto rerun;
	}

	rcu_read_unlock();
	return NULL;
}

/**
 * Release Ratio Scheduler data from a server group.
 */
static void
tfw_sched_ratio_cleanup(TfwSrvGroup *sg)
{
	size_t si;
	TfwRatio *ratio;
	TfwRatioPool *rpool = sg->sched_data;

	if (!rpool)
		return;

	/* Free the data that is shared between pool entries. */
	ratio = rpool->rpool;
	for (si = 0; si < sg->srv_n; ++si)
		if (ratio->srvdesc[si].conns)
			kfree(ratio->srvdesc[si].conns);
	kfree(ratio->srvdesc);

	/* Free the data that is unique for each pool entry. */
	ratio = rpool->rpool;
	for (si = 0; si <= nr_cpu_ids; ++si)
		if (ratio[si].srvdata)
			kfree(ratio[si].srvdata);

	kfree(rpool);
	sg->sched_data = NULL;
}

/**
 * Delete a server group from Ratio Scheduler.
 */
static void
tfw_sched_ratio_del_grp(TfwSrvGroup *sg)
{
	TfwRatioPool *rpool = sg->sched_data;

	if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC) {
		atomic_set(&rpool->rearm, 0);
		smp_mb__after_atomic();
		del_timer_sync(&rpool->timer);
	}
	synchronize_rcu();
	tfw_sched_ratio_cleanup(sg);
}

/**     
 * Validate the integrity of a group.
 *
 * Make sure that number of servers in the group, and the number
 * of connections for each server match the recorded values.
 */
static int
tfw_sched_hash_validate_grp(TfwSrvGroup *sg)
{
	size_t si = 0, ci;
	TfwServer *srv;
	TfwSrvConn *srv_conn;

	list_for_each_entry(srv, &sg->srv_list, list) {
		ci = 0;
		list_for_each_entry(srv_conn, &srv->conn_list, list)
			++ci;
		if (ci > srv->conn_n)
			return -EINVAL;
		++si;
	}
	if (si > sg->srv_n)
		return -EINVAL;

	return 0;
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
	size_t size, si, ci;
	TfwServer *srv;
	TfwSrvConn *srv_conn;
	TfwRatio *ratio;
	TfwRatioPool *rpool;
	TfwRatioSrvDesc *trsdesc, *srvdesc;

	if (!tfw_sched_hash_validate_grp(sg))
		return -EINVAL;

	/* Pool of TfwRatio{}. Initial place for Ratio Scheduler data. */
	size = sizeof(TfwRatioPool) + sizeof(TfwRatio) * (nr_cpu_ids + 1);
	if (!(sg->sched_data = kzalloc(size, GFP_KERNEL)))
		return -ENOMEM;
	rpool = sg->sched_data;
	rpool->rpool = sg->sched_data + sizeof(TfwRatioPool);
	rpool->ratio = rpool->rpool;

	/* Array for server descriptors. Shared between RCU pool entries. */
	size = sizeof(TfwRatioSrvDesc) * sg->srv_n;
	if (!(trsdesc = kzalloc(size, GFP_KERNEL)))
		goto cleanup;
	rpool->rpool[0].srvdesc = trsdesc;

	/* Set up each RCU pool entry with required arrays and data. */
	size = sizeof(TfwRatioSrvData) * sg->srv_n;
	for (si = 0, ratio = rpool->rpool; si <= nr_cpu_ids; ++si, ++ratio) {
		if (!(ratio->srvdata = kzalloc(size, GFP_KERNEL)))
			goto cleanup;
		spin_lock_init(&ratio->schdata.lock);
		ratio->srvdesc = trsdesc;
		ratio->srv_n = sg->srv_n;
		ratio->psidx = sg->flags & TFW_SG_F_PSTATS_IDX_MASK;
		atomic_set(&ratio->free, 1);
	}

	/* Initial setup of upstream server descriptors. */
	srvdesc = trsdesc;
	list_for_each_entry(srv, &sg->srv_list, list) {
		size = sizeof(TfwSrvConn *) * srv->conn_n;
		if (!(srvdesc->conns = kzalloc(size, GFP_KERNEL)))
			goto cleanup;
		ci = 0;
		list_for_each_entry(srv_conn, &srv->conn_list, list)
			srvdesc->conns[ci++] = srv_conn;
		srvdesc->conn_n = srv->conn_n;
		srvdesc->srv = srv;
		atomic64_set(&srvdesc->counter, 0);
		srv->sched_data = srvdesc;
		++srvdesc;
	}

	/*
	 * Set up the initial ratio data. For dynamic ratios it's all
	 * equal initial weights.
	 */
	if (!(sg->flags & (TFW_SG_F_SCHED_RATIO_STATIC
			   | TFW_SG_F_SCHED_RATIO_DYNAMIC)))
		BUG();

	tfw_sched_ratio_calc_static(rpool->ratio);

	if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC) {
		atomic_set(&rpool->rearm, 1);
		setup_timer(&rpool->timer,
			    tfw_sched_ratio_tmfn, (unsigned long)sg);
		mod_timer(&rpool->timer, jiffies + TFW_SCHED_RATIO_INTVL);
	}

	return 0;

cleanup:
	tfw_sched_ratio_cleanup(sg);
	return ret;
}

static TfwScheduler tfw_sched_ratio = {
	.name		= "ratio",
	.list		= LIST_HEAD_INIT(tfw_sched_ratio.list),
	.add_grp	= tfw_sched_ratio_add_grp,
	.del_grp	= tfw_sched_ratio_del_grp,
	.sched_sg_conn	= tfw_sched_ratio_sched_sg_conn,
	.sched_srv_conn	= tfw_sched_ratio_sched_srv_conn,
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
