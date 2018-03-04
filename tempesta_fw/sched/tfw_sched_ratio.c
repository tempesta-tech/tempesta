/**
 *              Tempesta FW
 *
 * Copyright (C) 2017-2018 Tempesta Technologies, Inc.
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
#include "http.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta Ratio Scheduler");
MODULE_VERSION("0.1.2");
MODULE_LICENSE("GPL");

#define TFW_SCHED_RATIO_INTVL	(HZ / 20)	/* The timer periodicity. */

/**
 * Individual upstream server descriptor.
 *
 * Connections may go up or down during failover process.
 * Only fully established connections are considered by scheduler.
 *
 * @rcu		- RCU control structure.
 * @srv		- pointer to server structure.
 * @conn	- list of pointers to server connection structures.
 * @counter	- monotonic counter for choosing the next connection.
 * @conn_n	- number of connections to server.
 * @seq		- current sequence number for APM stats.
 */
typedef struct {
	struct rcu_head		rcu;
	TfwServer		*srv;
	TfwSrvConn		**conn;
	atomic64_t		counter;
	size_t			conn_n;
	unsigned int		seq;
} TfwRatioSrvDesc;

/**
 * Individual server data for scheduler.
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
 * @reidx	- index of next server data entry which ratio we need
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
 * Historic (past) data unit for an individual upstream server.
 *
 * @cnt		- count of timer function invocations.
 * @rtt		- RTT from APM in msecs.
 */
typedef struct {
	unsigned long	cnt;
	unsigned long	rtt;
} TfwRatioHstUnit;

/**
 * Historic (past) data set for an individual upstream server.
 * This is the data set for simple linear regression calculation.
 *
 * @coeff_a		- coefficient for rtt = coeff_a + coeff_b * cnt + eps.
 * @coeff_b		- coefficient for rtt = coeff_a + coeff_b * cnt + eps.
 * @cnt_avg		- average cnt value.
 * @rtt_avg		- average rtt value.
 * @cnt_rtt_avg		- avg(cnt * rtt).
 * @cnt_avg_rtt_avg	- avg(cnt) * avg(rtt).
 * @cnt_sq_avg		- avg(cnt * cnt).
 * @cnt_avg_sq		- avg(cnt) * avg(cnt).
 * @hist		- array of history data units.
 */
typedef struct {
	long		coeff_a;
	long		coeff_b;
	long		cnt_avg;
	long		rtt_avg;
	long		cnt_rtt_avg;
	long		cnt_avg_rtt_avg;
	long		cnt_sq_avg;
	long		cnt_avg_sq;
	TfwRatioHstUnit	*hist;
} TfwRatioHstDesc;

/**
 * Historic (past) data for predictive scheduler.
 *
 * @ahead	- predict for this number of @intvl ahead.
 * @slot_n	- total number of slots for past data.
 * @counter	- slot that is available for storing past data.
 * @hstdesc	- past data for each server (@hstdesc[@srv_n]).
 */
typedef struct {
	unsigned int	ahead;
	size_t		slot_n;
	unsigned long	counter;
	TfwRatioHstDesc	*hstdesc;
} TfwRatioHstData;

/**
 * The main Ratio Scheduler data structure.
 *
 * All servers, either dead or live, are present in the list during
 * the whole run-time. That may change in the future.
 *
 * @rcu		- RCU control structure.
 * @srvdata	- scheduler data specific to each server in the group.
 * @schdata	- scheduler data common to all servers in the group.
 */
typedef struct {
	struct rcu_head		rcu;
	TfwRatioSrvData		*srvdata;
	TfwRatioSchData		schdata;
} TfwRatioData;

/**
 * The main structure for the group.
 *
 * @rcu		- RCU control structure.
 * @srv_n	- number of upstream servers.
 * @psidx	- APM pstats[] value index for dynamic ratios.
 * @intvl	- interval for re-arming the timer.
 * @rearm	- indicates if the timer can be re-armed.
 * @timer	- periodic timer for dynamic APM data.
 * @hstdata	- historic data for predictive scheduler.
 * @srvdesc	- array of upstream server descriptors.
 * @rtodata	- pointer to the currently used scheduler data.
 */
typedef struct {
	struct rcu_head		rcu;
	size_t			srv_n;
	size_t			psidx;
	unsigned int		intvl;
	atomic_t		rearm;
	struct timer_list	timer;
	TfwRatioHstData		*hstdata;
	TfwRatioSrvDesc		*srvdesc;
	TfwRatioData __rcu	*rtodata;
} TfwRatio;

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

	return (rhs_ratio < lhs_ratio) ? -1 : (rhs_ratio > lhs_ratio);
}

/**
 * Calculate and set up ratios for each server in the group.
 *
 * Return 0 if done with the ratios.
 * Return a non-zero value if additional actions are needed.
 */
static int
tfw_sched_ratio_calc(TfwRatio *ratio, TfwRatioData *rtodata,
		     unsigned long sum_wgt, size_t max_val_idx,
		     size_t *arg_ovidx)
{
	size_t si, one_val_idx;
	unsigned int diff, max_wgt, oratio;
	unsigned long unit, sum_ratio = 0;
	TfwRatioSrvData *srvdata = rtodata->srvdata;
	TfwRatioSchData *schdata = &rtodata->schdata;

	/* Set up the common part of scheduler data. */
	schdata->csidx = 0;
	schdata->riter = 1;
	schdata->reidx = ratio->srv_n;

	/*
	 * Calculate each server's ratio using the following formula:
	 * unit = (MAX_WEIGHT + SRV_NUM) * MAX_WEIGHT / sum(weight);
	 * ratio[i] = unit * weight[i] / MAX_WEIGHT;
	 *
	 * See if all calculated ratios are the same. Set scheduler data.
	 */
	diff = one_val_idx = 0;
	max_wgt = srvdata[max_val_idx].weight;
	unit = ((max_wgt + ratio->srv_n) * max_wgt) / sum_wgt;
	for (si = 0; si < ratio->srv_n; ++si) {
		oratio = (unit * srvdata[si].weight) / max_wgt ? : 1;
		srvdata[si].cratio = srvdata[si].oratio = oratio;
		diff |= (oratio != srvdata[0].oratio);
		sum_ratio += oratio;
		if ((oratio == 1) && !one_val_idx)
			one_val_idx = si;
	}
	schdata->crsum = schdata->orsum = sum_ratio;

	/* Return the index of server data entry with value of 1. */
	*arg_ovidx = one_val_idx;

	return diff;
}

/*
 * Calculate and set up ratios for each server in a group based on
 * weights that are statically defined in the configuration file.
 */
static void
tfw_sched_ratio_calc_static(TfwRatio *ratio, TfwRatioData *rtodata)
{
	unsigned long sum_wgt;
	unsigned int diff;
	size_t si, max_val_idx, one_val_idx;
	TfwRatioSrvDesc *srvdesc = ratio->srvdesc;
	TfwRatioSrvData *srvdata = rtodata->srvdata;

	/*
	 * Collect server weights from the configuration. Calculate the
	 * sum of server's weights in the group. Remember the index of
	 * server data entry with maximum weight. That same entry will
	 * also have the maximum ratio. See if all weights in the group
	 * are the same.
	 */
	sum_wgt = diff = max_val_idx = 0;
	for (si = 0; si < ratio->srv_n; ++si) {
		unsigned int weight = srvdesc[si].srv->weight;
		srvdata[si].sdidx = si;
		srvdata[si].weight = weight;
		srvdata[si].cratio = srvdata[si].oratio = 1;
		if (srvdata[max_val_idx].weight < weight)
			max_val_idx = si;
		sum_wgt += weight;
		diff |= (weight != srvdata[0].weight);
	}

	/*
	 * If all server weights are the same, then there's no need to
	 * do anything else. Set up all ratios to 1 and be done with it.
	 */
	if (!diff) {
		TfwRatioSchData *schdata = &rtodata->schdata;

		/* Set up the common part of scheduler data. */
		schdata->csidx = 0;
		schdata->riter = 1;
		schdata->reidx = ratio->srv_n;

		schdata->crsum = schdata->orsum = ratio->srv_n;
	}

	/* Calculate ratios based on different weights of servers. */
	if (!tfw_sched_ratio_calc(ratio, rtodata, sum_wgt,
				  max_val_idx, &one_val_idx))
		return;

	/* Sort server data entries by ratio in descending order. */
	sort(srvdata, ratio->srv_n, sizeof(srvdata[0]),
	     tfw_sched_ratio_srvdata_cmp, tfw_sched_ratio_srvdata_swap);
}

/**
 * Calculate ratios for each server in a group based on dynamic data.
 *
 * Latest dynamic data is provided by APM module and represent RTT values
 * for each server in a group. Ratios are calculated on those RTT values.
 * However that way the ratios do not represent the real weight of each
 * server. A bigger RTT value leads to a bigger ratio, while in fact that
 * server is less favorable and should have a lesser, NOT bigger weight.
 *
 * Based on ratios calculated from RTT values, the algorithm here adjusts
 * that and assigns a correct ratio to each server in the group.
 *
 * 1. If the minimal calculated ratio is 1, then find entries that have
 *    ratio of 1, and set them up with the weight and ratio of an entry
 *    with maximum calculated ratio. Likewise, set up entries with the
 *    maximum calculated ratio with weight and ratio of an entry with
 *    ratio of 1.
 *    For example, this is after the calculation of ratios:
 *    sdidx:   1   2   3   4   5   6   7   8   9   10
 *    ratio:   10  5   1   30  1   25  1   60  15  50
 *    After this step the result will be:
 *    sdidx:   1   2   3   4   5   6   7   8   9   10
 *    ratio:   10  5   60  30  60  25  60  1   15  50
 *
 * 2. Sort the resulting array by ratio in descending order as required
 *    by the scheduling algorithm. The result will be as follows:
 *    sdidx:   7   5   3   10   4   6   9   1   2   8
 *    ratio:   60  60  60  50   30  25  15  10  5   1
 *
 * 3. Select the part of the array that omits entries from step 1 if any.
 *    Those are entries at the start and at the end of the array. Reverse
 *    the sequence of server descriptor indices in that part of the array.
 *    The resulting pairing of servers to ratios is the target. Servers
 *    with a lesser RTT are assigned a larger ratio. Servers with a larger
 *    RTT are assigned a lesser ratio. The result will be as follows:
 *    sdidx:   7   5   3   2   1   9   6   4   10   8
 *    ratio:   60  60  60  50  30  25  15  10   5   1
 */
static void
__tfw_sched_ratio_calc_dynamic(TfwRatio *ratio, TfwRatioData *rtodata,
			       unsigned long sum_wgt, size_t max_val_idx)
{
	size_t si, one_val_idx, left = 0, right = 0;
	unsigned int max_ratio, has_one_val;
	TfwRatioSrvData *srvdata = rtodata->srvdata;

	/* Calculate ratios based on server RTT values. */
	if (!tfw_sched_ratio_calc(ratio, rtodata, sum_wgt,
				  max_val_idx, &one_val_idx))
		return;

	/*
	 * It's guaranteed here that NOT all calculated ratio values are
	 * equal. See if there are ratio values that equal to 1. If so,
	 * do actions described in step 1 in the function's description.
	 * Adjust the sum of ratios that is changed in this procedure.
	 */
	has_one_val = (srvdata[one_val_idx].oratio == 1);

	if (has_one_val) {
		unsigned long orsum = rtodata->schdata.orsum;
		TfwRatioSrvData sdent_one = srvdata[one_val_idx];
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
		rtodata->schdata.crsum = rtodata->schdata.orsum = orsum;
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
	if (!has_one_val) {
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

	return;
}

/**
 * Get specific server's data (RTT) from the APM module.
 *
 * While all stats values are returned by the APM, only one specific
 * value is taken as the current RTT. That is the configured value,
 * one of MIN, MAX, AVG, or a specific percentile.
 *
 * Return 0 if there is no new APM data.
 * Return a non-zero value otherwise.
 *
 * TODO: The following cases should be considered.
 * 1. It's possible that the actual stats values calculated by the APM
 *    module did not change. However, the APM doesn't know of that and
 *    just reports that the values may have changed. It would be great
 *    to catch that and avoid the recalculation of ratios in some cases.
 * 2. Depending on specific RTT value a small deviation from the previous
 *    value might be acceptable. That should not cause a recalculation
 *    of ratio.
 * 3. A typical case is that only a handful of servers misbehave in
 *    a large group of servers. Is there a way to detect that and do
 *    a partial recalculation of ratios?
 */
static inline int
__tfw_sched_ratio_get_rtt(size_t si, TfwRatio *ratio, TfwRatioData *rtodata)
{
	unsigned int recalc;
	unsigned int val[ARRAY_SIZE(tfw_pstats_ith)] = { 0 };
	TfwPrcntlStats pstats = {
		.ith = tfw_pstats_ith,
		.val = val,
		.psz = ARRAY_SIZE(tfw_pstats_ith)
	};
	TfwRatioSrvData *srvdata = rtodata->srvdata;
	TfwRatioSrvDesc *srvdesc = ratio->srvdesc;

	pstats.seq = srvdesc[si].seq;
	recalc = tfw_apm_stats(srvdesc[si].srv->apmref, &pstats);
	srvdesc[si].seq = pstats.seq;

	srvdata[si].sdidx = si;
	srvdata[si].weight = pstats.val[ratio->psidx] ? : 1;

	return recalc;
}

/**
 * Calculate ratios for each server in a group based on dynamic data.
 * Latest dynamic data is provided by APM module and represent RTT values
 * for each server in a group. Ratios are calculated on those RTT values.
 *
 * The function runs periodically on timer and provides the data that is
 * used by the ratio scheduler for outgoing requests.
 */
static void
tfw_sched_ratio_calc_dynamic(TfwRatio *ratio, TfwRatioData *rtodata)
{
	size_t si, max_val_idx = 0;
	unsigned long sum_wgt = 0;
	TfwRatioSrvData *srvdata = rtodata->srvdata;

	/*
	 * Calculate the sum of server's weights in the group. Remember
	 * the index of server data entry with maximum weight. That same
	 * entry will also have the maximum ratio.
	 */
	for (si = 0; si < ratio->srv_n; ++si) {
		__tfw_sched_ratio_get_rtt(si, ratio, rtodata);
		if (srvdata[max_val_idx].weight < srvdata[si].weight)
			max_val_idx = si;
		sum_wgt += srvdata[si].weight;
	}

	__tfw_sched_ratio_calc_dynamic(ratio, rtodata, sum_wgt, max_val_idx);
}

/**
 * Calculate ratios for each server in a group based on predicted values
 * derived from dynamic data. The dynamic data is provided by APM module
 * and represent RTT values for each server in a group. The RTT values
 * are collected within a latest period of time (time window) and then
 * used to predict the future RTT values that will be in action until
 * the next run of this function. Server ratios are calculated on those
 * predicted RTT values.
 *
 * A simple linear regression calculation on a sliding data window is
 * used to predict future RTT values for each server. @rtt is an RTT
 * value from APM, and @cnt is the current number of invocations of
 * this timer function (every @intvl msecs). Essentially, @cnt is
 * a measure of time.
 *
 * The POC (proof of concept) implementation of this algorithm can be
 * found in t/unit/user_space/slr.cc. @cnt corresponds to @x in the POC,
 * and @rtt corresponds to @y.
 *
 * The function runs periodically on timer and provides the data that
 * is used by the ratio scheduler for outgoing requests.
 */
static void
tfw_sched_ratio_calc_predict(TfwRatio *ratio, TfwRatioData *rtodata)
{
	static const long MUL = 1000;
	int ni, sz;
	size_t si, max_val_idx;
	unsigned long sum_wgt;
	long cnt, rtt, ahead, prediction;
	TfwRatioHstData *hstdata = ratio->hstdata;
	TfwRatioSrvData *srvdata = rtodata->srvdata;

	ni = hstdata->counter % hstdata->slot_n;
	cnt = hstdata->counter * MUL;
	ahead = hstdata->counter + hstdata->ahead;

	sum_wgt = max_val_idx = 0;
	for (si = 0; si < ratio->srv_n; ++si) {
		TfwRatioHstDesc *hd = &hstdata->hstdesc[si];

		__tfw_sched_ratio_get_rtt(si, ratio, rtodata);

		rtt = srvdata[si].weight * MUL;

		/*
		 * The calculations are slightly different for the case
		 * in the beginning where there's insufficient data for
		 * a whole window into the historic data set.
		 */
		if (unlikely(hstdata->counter < hstdata->slot_n)) {
			sz = ni + 1;
			hd->cnt_avg = (hd->cnt_avg * ni + cnt) / sz;
			hd->rtt_avg = (hd->rtt_avg * ni + rtt) / sz;
			hd->cnt_rtt_avg =
				(hd->cnt_rtt_avg * ni + cnt * rtt) / sz;
			hd->cnt_avg_rtt_avg = hd->cnt_avg * hd->rtt_avg;
			hd->cnt_sq_avg =
				(hd->cnt_sq_avg * ni + cnt * cnt) / sz;
			hd->cnt_avg_sq = hd->cnt_avg * hd->cnt_avg;
		} else {
			long h_cnt = hd->hist[ni].cnt;
			long h_rtt = hd->hist[ni].rtt;
			sz = hstdata->slot_n;
			hd->cnt_avg = hd->cnt_avg - (h_cnt - cnt) / sz;
			hd->rtt_avg = hd->rtt_avg - (h_rtt - rtt) / sz;
			hd->cnt_rtt_avg = hd->cnt_rtt_avg
					  - (h_cnt * h_rtt - cnt * rtt) / sz;
			hd->cnt_avg_rtt_avg = hd->cnt_avg * hd->rtt_avg;
			hd->cnt_sq_avg = hd->cnt_sq_avg
					 - (h_cnt * h_cnt - cnt * cnt) / sz;
			hd->cnt_avg_sq = hd->cnt_avg * hd->cnt_avg;
		}

		hd->hist[ni].cnt = cnt;
		hd->hist[ni].rtt = rtt;

		if (hd->cnt_sq_avg == hd->cnt_avg_sq) {
			hd->coeff_a = 0;
			hd->coeff_b = hd->cnt_avg
				    ? hd->rtt_avg / hd->cnt_avg : 1;
		} else {
			hd->coeff_b = (hd->cnt_rtt_avg - hd->cnt_avg_rtt_avg)
				      / (hd->cnt_sq_avg - hd->cnt_avg_sq);
			hd->coeff_a = (hd->rtt_avg - hd->coeff_b * hd->cnt_avg)
				      / MUL;
		}

		prediction = hd->coeff_a + hd->coeff_b * ahead;
		srvdata[si].weight = prediction <= 0 ? 1 : prediction;

		if (srvdata[max_val_idx].weight < srvdata[si].weight)
			max_val_idx = si;
		sum_wgt += srvdata[si].weight;
	}

	++hstdata->counter;

	__tfw_sched_ratio_calc_dynamic(ratio, rtodata, sum_wgt, max_val_idx);
}

/**
 * Get and set up a new ratio data entry.
 */
static TfwRatioData *
tfw_sched_ratio_rtodata_get(TfwRatio *ratio)
{
	size_t size;
	TfwRatioData *rtodata;

	size = sizeof(TfwRatioData) + sizeof(TfwRatioSrvData) * ratio->srv_n;
	if (!(rtodata = kmalloc(size, GFP_ATOMIC)))
		return NULL;
	rtodata->srvdata = (TfwRatioSrvData *)(rtodata + 1);
	spin_lock_init(&rtodata->schdata.lock);

	return rtodata;
}

/**
 * Release a ratio data entry that is no longer used.
 */
static void
tfw_sched_ratio_rtodata_put(struct rcu_head *rcup)
{
	TfwRatioData *rtodata = container_of(rcup, TfwRatioData, rcu);
	kfree(rtodata);
}

/**
 * Calculate the latest ratios for each server in the group in real time.
 *
 * RCU is used to avoid locks. When recalculation is in order, the new
 * data is placed in a new allocated entry. The new entry is seamlessly
 * set as the current entry by using RCU. The formerly active entry is
 * released in due time when all users of it are done and gone.
 */
static void
tfw_sched_ratio_calc_tmfn(TfwRatio *ratio,
			  void (*calc_fn)(TfwRatio *, TfwRatioData *))
{
	TfwRatioData *crtodata, *nrtodata;

	/*
	 * Get a new ratio data entry. Usually, if unsuccessful, that's
	 * not a big deal. Scheduling of upstream servers will continue
	 * to run on currently active data. However, the lack of memory
	 * is a critical issue in itself.
	 */
	if (!(nrtodata = tfw_sched_ratio_rtodata_get(ratio))) {
		TFW_ERR("Sched ratio: Insufficient memory\n");
		goto rearm;
	}

	/* Calculate dynamic ratios. */
	calc_fn(ratio, nrtodata);

	/*
	 * Substitute the current ratio data entry with the new one for
	 * the scheduler. The former entry will be released when there
	 * are no users of it. Use the faster non-lazy RCU.
	 */
	crtodata = ratio->rtodata;
	rcu_assign_pointer(ratio->rtodata, nrtodata);
	call_rcu_bh(&crtodata->rcu, tfw_sched_ratio_rtodata_put);

rearm:
	smp_mb();
	if (atomic_read(&ratio->rearm))
		mod_timer(&ratio->timer, jiffies + ratio->intvl);
}

/**
 * Periodic function for Dynamic Ratio Scheduler.
 */
static void
tfw_sched_ratio_dynamic_tmfn(unsigned long tmfn_data)
{
	tfw_sched_ratio_calc_tmfn((TfwRatio *)tmfn_data,
				   tfw_sched_ratio_calc_dynamic);
}

/**
 * Periodic function for Predictive Ratio Scheduler.
 */
static void
tfw_sched_ratio_predict_tmfn(unsigned long tmfn_data)
{
	tfw_sched_ratio_calc_tmfn((TfwRatio *)tmfn_data,
				   tfw_sched_ratio_calc_predict);
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
tfw_sched_ratio_is_srv_turn(TfwRatio *ratio, TfwRatioData *rtodata, size_t csidx)
{
	unsigned long headsum2, tailsum2;
	TfwRatioSrvData *srvdata = rtodata->srvdata;
	TfwRatioSchData *schdata = &rtodata->schdata;

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
tfw_sched_ratio_next_srv(TfwRatio *ratio, TfwRatioData *rtodata)
{
	size_t csidx;
	TfwRatioSrvData *srvdata = rtodata->srvdata;
	TfwRatioSchData *schdata = &rtodata->schdata;

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
	if (likely(tfw_sched_ratio_is_srv_turn(ratio, rtodata, csidx))) {
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
}

/*
 * Find an available connection to the server described by @srvdesc.
 * Consider the following restrictions:
 * 1. connection is not in recovery mode.
 * 2. connection's queue is not be full.
 * 3. connection doesn't have active non-idempotent requests.
 *
 * The restriction #3 is controlled by @skipnip and can be removed
 * to get a wider selection of available connections.
 */
static inline TfwSrvConn *
__sched_srv(TfwRatioSrvDesc *srvdesc, int skipnip, int *nipconn)
{
	size_t ci;

	for (ci = 0; ci < srvdesc->conn_n; ++ci) {
		unsigned long idxval = atomic64_inc_return(&srvdesc->counter);
		TfwSrvConn *srv_conn = srvdesc->conn[idxval % srvdesc->conn_n];

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
	TfwRatioSrvDesc *srvdesc;
	TfwSrvConn *srv_conn = NULL;

	/*
	 * Bypass the suspend checking if connection is needed for
	 * helth monitoring of backend server.
	 */
	if (!(((TfwHttpReq *)msg)->flags & TFW_HTTP_HMONITOR)
	    && tfw_srv_suspended(srv))
		return NULL;

	rcu_read_lock_bh();
	srvdesc = rcu_dereference_bh(srv->sched_data);
	if (unlikely(!srvdesc))
		goto done;

rerun:
	if ((srv_conn = __sched_srv(srvdesc, skipnip, &nipconn)))
		goto done;
	if (skipnip && nipconn) {
		skipnip = 0;
		goto rerun;
	}
done:
	rcu_read_unlock_bh();
	return srv_conn;
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
	unsigned int attempts, skipnip = 1, nipconn = 0;
	TfwRatio *ratio;
	TfwRatioSrvDesc *srvdesc;
	TfwSrvConn *srv_conn;
	TfwRatioData *rtodata;

	rcu_read_lock_bh();
	ratio = rcu_dereference_bh(sg->sched_data);
	if (unlikely(!ratio)) {
		rcu_read_unlock_bh();
		return NULL;
	}

	rtodata = rcu_dereference_bh(ratio->rtodata);
	BUG_ON(!rtodata);
rerun:
	/*
	 * Try servers in a group according to their ratios. Attempt to
	 * schedule a connection that is not under a set of restrictions.
	 *
	 * NOTE: The way the algorithm works, same server may be chosen
	 * multiple times in a row, even if that's the server where all
	 * connections were under restrictions for one reason or another.
	 * The idea is that the conditions for server's connections may
	 * change any time, and so the next time one or more connections
	 * to the same server will not be restricted.
	 * Also, servers are chosen concurrently, so a particular thread
	 * may not be able to probe all servers in a group.
	 *
	 * These properties suggest that a limit is needed on the number
	 * of attempts to find the right connection. This limit appears
	 * to be purely empirical.
	 *
	 * A tricky issue here is that the algorithm assumes two passes.
	 * One runs under full set of restrictions, and the other runs
	 * under restrictions that are slightly relaxed. It's likely
	 * that servers probed in these two passes are not the same.
	 *
	 * It doesn't make sense to do lots of attempts. If a suitable
	 * connection can not be found after multiple attempts, then
	 * something is wrong with one or more upstream servers in
	 * this group. Spinning in the loop here would just aggravate
	 * the issue on Tempesta's side.
	 */
	attempts = ratio->srv_n;
	while (attempts--) {
		srvdesc = tfw_sched_ratio_next_srv(ratio, rtodata);
		if (tfw_srv_suspended(srvdesc->srv))
			continue;

		if ((srv_conn = __sched_srv(srvdesc, skipnip, &nipconn))) {
			rcu_read_unlock_bh();
			return srv_conn;
		}
	}
	/* Relax the restrictions and re-run the search cycle. */
	if (skipnip && nipconn) {
		skipnip = 0;
		goto rerun;
	}

	rcu_read_unlock_bh();
	return NULL;
}

/**
 * Release Ratio Scheduler data from a server group.
 */
static void
tfw_sched_ratio_cleanup(TfwRatio *ratio)
{
	size_t si;

	/* Data that is shared between pool entries. */
	for (si = 0; si < ratio->srv_n; ++si)
		kfree(ratio->srvdesc[si].conn);

	kfree(ratio->hstdata);
	kfree(ratio->rtodata);

	kfree(ratio);
}

static void
tfw_sched_ratio_cleanup_rcu_cb(struct rcu_head *rcu)
{
	TfwRatio *ratio = container_of(rcu, TfwRatio, rcu);
	tfw_sched_ratio_cleanup(ratio);
}

/**
 * Delete a server group from Ratio Scheduler.
 */
static void
tfw_sched_ratio_del_grp(TfwSrvGroup *sg)
{
	TfwRatio *ratio = rcu_dereference_bh_check(sg->sched_data, 1);
	TfwServer *srv;

	RCU_INIT_POINTER(sg->sched_data, NULL);
	list_for_each_entry(srv, &sg->srv_list, list) {
		WARN_ON_ONCE(rcu_dereference_bh_check(srv->sched_data, 1)
			     && !ratio);
		RCU_INIT_POINTER(srv->sched_data, NULL);
	}
	if (!ratio)
		return;
	/*
	 * Make sure the timer doesn't re-arms itself. This
	 * also ensures that no more RCU callbacks are created.
	 */
	if (sg->flags & (TFW_SG_F_SCHED_RATIO_DYNAMIC
			 | TFW_SG_F_SCHED_RATIO_PREDICT))
	{
		atomic_set(&ratio->rearm, 0);
		smp_mb__after_atomic();
		del_timer_sync(&ratio->timer);
	}

	/* Release all memory allocated for the group. */
	call_rcu_bh(&ratio->rcu, tfw_sched_ratio_cleanup_rcu_cb);
}

static int
tfw_sched_ratio_srvdesc_setup_srv(TfwServer *srv, TfwRatioSrvDesc *srvdesc)
{
	size_t size, ci = 0;
	TfwSrvConn **conn, *srv_conn;

	size = sizeof(TfwSrvConn *) * srv->conn_n;
	if (!(srvdesc->conn = kzalloc(size, GFP_KERNEL)))
		return -ENOMEM;

	conn = srvdesc->conn;
	list_for_each_entry(srv_conn, &srv->conn_list, list) {
		if (unlikely(ci++ == srv->conn_n))
			return -EINVAL;
		*conn++ = srv_conn;
	}
	if (unlikely(ci != srv->conn_n))
		return -EINVAL;

	srvdesc->conn_n = srv->conn_n;
	srvdesc->srv = srv;
	atomic64_set(&srvdesc->counter, 0);

	return 0;
}

/**
 * Add a server group to Ratio Scheduler.
 *
 * At the time this function is called the server group is fully formed
 * and populated with all servers and connections.
 *
 * Additional configuration data required for Predictive scheduler are
 * passed via @sg->sched_data.
 */

/* Set up the upstream server descriptors. */
static int
tfw_sched_ratio_srvdesc_setup(TfwSrvGroup *sg, TfwRatio *ratio)
{
	int r;
	size_t si = 0;
	TfwServer *srv;
	TfwRatioSrvDesc *srvdesc = ratio->srvdesc;

	list_for_each_entry(srv, &sg->srv_list, list) {
		if (unlikely((si++ == sg->srv_n) || !srv->conn_n
			     || list_empty(&srv->conn_list)))
			return -EINVAL;
		if ((r = tfw_sched_ratio_srvdesc_setup_srv(srv, srvdesc)))
			return r;
		++srvdesc;
	}
	if (unlikely(si != sg->srv_n))
		return -EINVAL;

	return 0;
}

static TfwRatio *
tfw_sched_ratio_add_grp_common(TfwSrvGroup *sg)
{
	int ret;
	size_t size;
	TfwRatio *ratio;
	TfwRatioData *rtodata;

	TFW_DBG2("%s: SG=[%s]\n", __func__, sg->name);

	size = sizeof(TfwRatio) + sizeof(TfwRatioSrvDesc) * sg->srv_n;
	if (!(ratio = kzalloc(size, GFP_KERNEL)))
		return NULL;

	ratio->srv_n = sg->srv_n;
	ratio->psidx = sg->flags & TFW_SG_M_PSTATS_IDX;

	ratio->srvdesc = (TfwRatioSrvDesc *)(ratio + 1);
	if ((ret = tfw_sched_ratio_srvdesc_setup(sg, ratio)))
		goto cleanup;

	if (!(rtodata = tfw_sched_ratio_rtodata_get(ratio)))
		goto cleanup;
	rcu_assign_pointer(ratio->rtodata, rtodata);

	return ratio;

cleanup:
	tfw_sched_ratio_cleanup(ratio);
	return NULL;
}

static TfwRatio *
tfw_sched_ratio_add_grp_static(TfwSrvGroup *sg)
{
	TfwRatio *ratio;

	if (!(ratio = tfw_sched_ratio_add_grp_common(sg)))
		return ratio;

	/* Calculate the static ratio data for each server. */
	tfw_sched_ratio_calc_static(ratio, ratio->rtodata);

	return ratio;
}

static TfwRatio *
tfw_sched_ratio_add_grp_dynamic(TfwSrvGroup *sg, void *arg)
{
	TfwRatio *ratio;
	TfwSchrefPredict *schref = arg;

	TFW_DBG2("%s: SG=[%s]\n", __func__, sg->name);

	if (!(ratio = tfw_sched_ratio_add_grp_common(sg)))
		return ratio;

	/* Set up the necessary workspace for predictive scheduler. */
	if (sg->flags & TFW_SG_F_SCHED_RATIO_PREDICT) {
		size_t size, slot_n;
		TfwRatioHstUnit *hunit;
		TfwRatioHstData *hdata;
		TfwRatioHstDesc *hdesc, *hdesc_end;

		BUG_ON(!schref);

		slot_n = schref->past * schref->rate;
		size = sizeof(TfwRatioHstData)
		       + sizeof(TfwRatioHstDesc) * sg->srv_n
		       + sizeof(TfwRatioHstUnit) * sg->srv_n * slot_n;
		if (!(ratio->hstdata = kzalloc(size, GFP_KERNEL)))
			goto cleanup;

		hdata = ratio->hstdata;
		hdata->hstdesc = (TfwRatioHstDesc *)(hdata + 1);
		hdata->slot_n = slot_n;
		hdata->ahead = schref->ahead * schref->rate;

		hdesc_end = hdata->hstdesc + sg->srv_n;
		hunit = (TfwRatioHstUnit *)hdesc_end;
		for (hdesc = hdata->hstdesc; hdesc < hdesc_end; ++hdesc) {
			hdesc->hist = hunit;
			hunit += slot_n;
		}
	}

	/*
	 * Calculate the initial ratio data for each server. That's
	 * based on equal initial (default) weights that are set by
	 * the configuration processing routines.
	 */
	tfw_sched_ratio_calc_static(ratio, ratio->rtodata);

	/* Set up periodic re-calculation of ratios. */
	if (sg->flags & TFW_SG_F_SCHED_RATIO_DYNAMIC) {
		ratio->intvl = TFW_SCHED_RATIO_INTVL;
		atomic_set(&ratio->rearm, 1);
		smp_mb__after_atomic();
		setup_timer(&ratio->timer,
			    tfw_sched_ratio_dynamic_tmfn, (unsigned long)ratio);
		mod_timer(&ratio->timer, jiffies + ratio->intvl);
	} else if (sg->flags & TFW_SG_F_SCHED_RATIO_PREDICT) {
		ratio->intvl = msecs_to_jiffies(1000 / schref->rate);
		atomic_set(&ratio->rearm, 1);
		smp_mb__after_atomic();
		setup_timer(&ratio->timer,
			    tfw_sched_ratio_predict_tmfn, (unsigned long)ratio);
		mod_timer(&ratio->timer, jiffies + ratio->intvl);
	}

	return ratio;

cleanup:
	tfw_sched_ratio_cleanup(ratio);
	return NULL;
}

void
tfw_sched_ratio_set_sched_data(TfwSrvGroup *sg, TfwRatio *ratio)
{
	size_t i;

	if (!ratio)
		return;

	for (i = 0; i < ratio->srv_n; ++i) {
		TfwRatioSrvDesc *srvdesc = &ratio->srvdesc[i];

		rcu_assign_pointer(srvdesc->srv->sched_data, srvdesc);
	}
	rcu_assign_pointer(sg->sched_data, ratio);
}

static int
tfw_sched_ratio_add_grp(TfwSrvGroup *sg, void *arg)
{
	TfwRatio *ratio = NULL;

	if (unlikely(!sg->srv_n || list_empty(&sg->srv_list)))
		return -EINVAL;

	switch (sg->flags & TFW_SG_M_SCHED_RATIO_TYPE) {
	case TFW_SG_F_SCHED_RATIO_STATIC:
		ratio = tfw_sched_ratio_add_grp_static(sg);
		break;
	case TFW_SG_F_SCHED_RATIO_DYNAMIC:
	case TFW_SG_F_SCHED_RATIO_PREDICT:
		ratio = tfw_sched_ratio_add_grp_dynamic(sg, arg);
		break;
	default:
		return -EINVAL;
	}
	tfw_sched_ratio_set_sched_data(sg, ratio);

	return ratio ? 0 : -EINVAL;
}

static int
tfw_sched_ratio_add_srv(TfwServer *srv)
{
	TfwRatioSrvDesc *srvdesc = rcu_dereference_bh_check(srv->sched_data, 1);
	int r;

	if (unlikely(srvdesc))
		return -EEXIST;

	if (!(srvdesc = kzalloc(sizeof(TfwRatioSrvDesc), GFP_KERNEL)))
		return -ENOMEM;
	if ((r = tfw_sched_ratio_srvdesc_setup_srv(srv, srvdesc)))
		return r;

	rcu_assign_pointer(srv->sched_data, srvdesc);

	return 0;
}

static void
tfw_sched_ratio_put_srv_data(struct rcu_head *rcu)
{
	TfwRatioSrvDesc *srvdesc = container_of(rcu, TfwRatioSrvDesc, rcu);
	kfree(srvdesc);
}

static void
tfw_sched_ratio_del_srv(TfwServer *srv)
{
	TfwRatioSrvDesc *srvdesc = rcu_dereference_bh_check(srv->sched_data, 1);

	RCU_INIT_POINTER(srv->sched_data, NULL);
	if (srvdesc)
		call_rcu_bh(&srvdesc->rcu, tfw_sched_ratio_put_srv_data);
}

static TfwScheduler tfw_sched_ratio = {
	.name		= "ratio",
	.list		= LIST_HEAD_INIT(tfw_sched_ratio.list),
	.add_grp	= tfw_sched_ratio_add_grp,
	.del_grp	= tfw_sched_ratio_del_grp,
	.add_srv	= tfw_sched_ratio_add_srv,
	.del_srv	= tfw_sched_ratio_del_srv,
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

	/* Wait for outstanding RCU callbacks to complete. */
	rcu_barrier_bh();
	tfw_sched_unregister(&tfw_sched_ratio);
}
module_exit(tfw_sched_ratio_exit);
