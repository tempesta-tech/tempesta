/**
 *		Tempesta FW
 *
 * Prototype for fast percentiles calculation.
 *
 * The algorithm is constructed to be as efficient as possible sacrificing
 * accuracy and answering questions different from originally asked by user.
 * The main concepts and requirements are:
 *
 * 1. Small O(1) update time with only few conditions and cache line accesses;
 *
 * 2. Very fast O(1) calculation of several percentiles in parallel;
 *
 * 3. Very small overall memory footprint for inexpensive handling of
 *    performance trends of many servers;
 *
 * 4. Buckets must dynamically rearrange since we don't know server response
 *    times a priori;
 *
 * 5. The buckets adjustments must be done in lock-less fashion on multi-core
 *    environment;
 *
 * 6. If user ask for Nth percentile, e.g. 75th, we can return inaccurate
 *    value for different percentile, e.g. 81st. This is very possible if we
 *    don't have enough data for accurate percentiles calculation.
 *
 * Copyright (C) 2016-2017 Tempesta Technologies, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/atomic.h>
#include <linux/kernel.h>

#define min(a,b)	(((a) < (b)) ? (a) : (b))
#define SET(s)		{ARRAY_SIZE(s), s}

/*
 * Keep arrays sorted to make our simple basic algorithm for percentiles
 * calculation work.
 */
static const struct {
	size_t		len;
	unsigned int	*set;
} sets[] = {
	/* Not enough data for 1-percentile, so show 0 for 1-percentile. */
	SET(((unsigned int[]){1, 2, 3, 4, 5, 6, 7, 8, 9, 10})),
	/*
	 * `3` is outlier in first range (count=4, bucket=2).
	 * Right bound of last range is extended to 1069.
	 */
	SET(((unsigned int[]){1, 2, 3, 3, 3, 3, 4, 4, 5, 1001, 1002, 1010})),
	/* All percentiles should be calculated accurately. */
	SET(((unsigned int[]){1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
			      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
			      27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
			      39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
			      51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
			      63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
			      75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
			      87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98,
			      99, 100})),
};

/*
 * @ith	- percentile number;
 * @val	- percentile value;
 */
typedef struct {
	int	ith;
	int	val;
} Percentile;

/**
 * Calculate @np percentiles from @pcnts over @set of size @len.
 */
static void
basic_percentile(const unsigned int *set, size_t len, Percentile *pcnts,
		  size_t np)
{
	int i;

	for (i = 0; i < np; ++i) {
		/* How many items we need to collect for each percentile. */
		int n = len * pcnts[i].ith / 100;
		pcnts[i].val = n ? set[n - 1] : 0;
	}
}

/**
 * Response time statistic data structures.
 *
 * @order	- ranges' orders. The ranges are logarithmically growing.
 *		  Motivation: time estimation error becomes negligible as
 *		  the time grows, so higher response times can be estimated
 *		  less accurately;
 * @begin	- ranges' bases;
 * @end		- ranges' ends;
 * @__atomic	- atomic control handler to update all the control fields above
 * 		  atomically by single write operation;
 * @tot_cnt	- global counter for all the ranges;
 * @cnt		- basically, range[i] keeps observation counter for
 *		  response_time >> order[i].
 *
 * Keep the members cache line aligned to minimize false sharing: each range is
 * placed at separate cache line and control hadlers are also at their own
 * cache line.
 */
#define TFW_STATS_RANGES	4
#define TFW_STATS_RLAST		(TFW_STATS_RANGES - 1)
#define TFW_STATS_BCKTS_ORDER	4
#define TFW_STATS_BCKTS		(1 << TFW_STATS_BCKTS_ORDER)

#define TFW_STATS_RSPAN(order)		((TFW_STATS_BCKTS - 1) << (order))
#define TFW_STATS_RSPAN_UL(order)	((TFW_STATS_BCKTS - 1UL) << (order))

typedef struct {
	unsigned int	order;
	unsigned int	begin;
	unsigned int	end;
} TfwPcntCtl;

typedef struct {
	TfwPcntCtl	ctl[TFW_STATS_RANGES];
	unsigned long	tot_cnt;
	unsigned long	__padding[TFW_STATS_RLAST];
	unsigned long	cnt[TFW_STATS_RANGES][TFW_STATS_BCKTS];
} TfwPcntRanges __attribute__((aligned(L1_CACHE_BYTES)));

static inline unsigned long *
__rng(TfwPcntCtl *pc, unsigned long *cnt, unsigned int r_time)
{
	if (r_time <= pc->begin)
		return &cnt[0];
	return &cnt[(r_time - pc->begin + ((1 << pc->order) - 1)) >> pc->order];
}

static void
__range_grow_right(TfwPcntRanges *rng, TfwPcntCtl *pc, int r)
{
	int i;

	++pc->order;
	pc->end = pc->begin + TFW_STATS_RSPAN(pc->order);;

	printf("  -- extend right bound of range %d to begin=%u order=%u"
	       " end=%u\n", r, pc->begin, pc->order, pc->end);

	/* Coalesce counters to buckets on the left half of the range. */
	for (i = 0; i < TFW_STATS_BCKTS / 2; ++i)
		rng->cnt[r][i] = rng->cnt[r][2 * i] + rng->cnt[r][2 * i + 1];
}

static void
__range_shrink_left(TfwPcntRanges *rng, TfwPcntCtl *pc, int r)
{
	int i;
	unsigned long cnt_full, cnt_half;

	--pc->order;
	pc->begin = pc->end - TFW_STATS_RSPAN(pc->order);

	printf("  -- shrink left bound of range %d to begin=%u order=%u"
	       " end=%u\n", r, pc->begin, pc->order, pc->end);

	/*
	 * Write sum of the left half counters to the first bucket and equally
	 * split counters of the right half among the rest of the buckets.
	 */
	for (i = 1; i < TFW_STATS_BCKTS / 2; ++i)
		rng->cnt[r][0] += rng->cnt[r][i];
	cnt_full = rng->cnt[r][TFW_STATS_BCKTS / 2];
	cnt_half = cnt_full / 2;
	rng->cnt[r][0] += cnt_half;
	rng->cnt[r][1] = cnt_full - cnt_half;
	for (i = 1; i < TFW_STATS_BCKTS / 2; ++i) {
		cnt_full = rng->cnt[r][TFW_STATS_BCKTS / 2 + i];
		cnt_half = cnt_full / 2;
		rng->cnt[r][i * 2] = cnt_half;
		rng->cnt[r][i * 2 + 1] = cnt_full - cnt_half;
	}
}

/**
 * Extend the last range so that larger response times can be handled.
 */
static void
tfw_stats_extend(TfwPcntRanges *rng, unsigned int r_time)
{
	int i, b;
	TfwPcntCtl *pc = &rng->ctl[TFW_STATS_RLAST];
	unsigned int sum, parts, units, shift, order = pc->order;

	do {
		++order;
		pc->end = pc->begin + TFW_STATS_RSPAN_UL(order);
	} while (pc->end < r_time);

	shift = min(order - pc->order, TFW_STATS_BCKTS_ORDER);
	units = 1 << shift;
	parts = TFW_STATS_BCKTS >> shift;

	pc->order = order;

	printf("  -- extend last range to begin=%u order=%u end=%u\n",
	       pc->begin, pc->order, pc->end);

	/*
	 * Coalesce counters to buckets on the left side of the range.
	 * Clear the buckets that represent the new extended range.
	 */
	for (i = 0; i < parts; ++i) {
		switch (units) {
		case 2:
			rng->cnt[TFW_STATS_RLAST][i] =
				rng->cnt[TFW_STATS_RLAST][2 * i]
				+ rng->cnt[TFW_STATS_RLAST][2 * i + 1];
			break;
		case 4:
			rng->cnt[TFW_STATS_RLAST][i] =
				rng->cnt[TFW_STATS_RLAST][4 * i]
				+ rng->cnt[TFW_STATS_RLAST][4 * i + 1]
				+ rng->cnt[TFW_STATS_RLAST][4 * i + 2]
				+ rng->cnt[TFW_STATS_RLAST][4 * i + 3];
			break;
		default:
			sum = 0;
			for (b = i * units; b < (i + 1) * units; ++b)
				sum += rng->cnt[TFW_STATS_RLAST][b];
			rng->cnt[TFW_STATS_RLAST][i] = sum;
			break;
		}
	}
	memset(&rng->cnt[TFW_STATS_RLAST][parts], 0,
	       sizeof(rng->cnt[0][0]) * (TFW_STATS_BCKTS - parts));
}

/**
 * See if range @r contains large outliers. Adjust it if so.
 *
 * The leftmost bound is fixed to 1ms. The rightmost bound is only growing
 * to handle large values. So the adjustment may either increase the gaps
 * between ranges by decreasing a range order and moving left range bounds,
 * or decrease the gaps by increasing a range order and moving right range
 * bounds. I.e. ranges worm to the right and the algorithm converges at the
 * largest response time faced.
 */
static void
tfw_stats_adjust(TfwPcntRanges *rng, int r)
{
	int i;
	TfwPcntCtl *pc, *prepc;
	unsigned long prend, cnt = 0, sum = 0, max = 0, i_max = 0;

	BUG_ON(r == 0);

	for (i = 0; i < TFW_STATS_BCKTS; ++i) {
		if (rng->cnt[r][i]) {
			sum += rng->cnt[r][i];
			++cnt;
		}
		if (max < rng->cnt[r][i]) {
			max = rng->cnt[r][i];
			i_max = i;
		}
	}
	BUG_ON(!cnt);

	/* outlier means (max < avg * 2) */
	if (likely(max <= sum * 2 / cnt))
		return;

	printf("  -- range %d has outlier %lu (avg=%lu total=%lu) at"
	       " bucket %lu\n", r, max, sum / cnt, sum, i_max);

	/*
	 * If too many hits fall in the gap between r'th and (r - 1)'th
	 * ranges, and (r - 1)'th range can grow, then grow that range
	 * and spread these hits evenly in the right half of (r - 1)'th
	 * range as a rough approximation. Afterwards, move on to reduce
	 * the range order. The first bucket gets a higher count. Since
	 * the left bound has been moved, the right bound of (r - 1)'th
	 * range will be moved next time.
	 */
	pc = &rng->ctl[r];
	prepc = &rng->ctl[r - 1];
	prend = prepc->begin + TFW_STATS_RSPAN_UL(prepc->order + 1);

	if ((i_max == 0) && (prend < pc->begin)) {
		__range_grow_right(rng, prepc, r - 1);

		cnt = max / (TFW_STATS_BCKTS / 2 + 1);
		rng->cnt[r][0] -= cnt * (TFW_STATS_BCKTS / 2);
		for (i = TFW_STATS_BCKTS / 2; i < TFW_STATS_BCKTS; ++i)
			rng->cnt[r - 1][i] = cnt;
	}

	/*
	 * The range order is too big. Reduce it by moving the left bound.
	 * If servers are too fast (all responses within 1ms), then there's
	 * nothing to do here.
	 */
	if (likely(pc->order))
		__range_shrink_left(rng, pc, r);
}

/**
 * Update server response time statistic.
 * @r_time is in milliseconds (1/HZ second), use jiffies to get it.
 */
static void
tfw_stats_upd(TfwPcntRanges *rng, unsigned int r_time)
{
	TfwPcntCtl *pc3, *pc2 = &rng->ctl[2];

	/* Binary search of appropriate range. */
	if (r_time <= pc2->end) {
		TfwPcntCtl *pc0, *pc1 = &rng->ctl[1];

		if (r_time > pc1->end) {
			++(*__rng(pc2, rng->cnt[2], r_time));
			tfw_stats_adjust(rng, 2);
			goto totals;
		}

		pc0 = &rng->ctl[0];
		BUG_ON(pc0->begin != 1); /* left bound is never moved */
		if (r_time > pc0->end) {
			++(*__rng(pc1, rng->cnt[1], r_time));
			tfw_stats_adjust(rng, 1);
			goto totals;
		}

		++(*__rng(pc0, rng->cnt[0], r_time));
		goto totals;
	}

	pc3 = &rng->ctl[3];
	if (unlikely(r_time > pc3->end))
		tfw_stats_extend(rng, r_time);
	++(*__rng(pc3, rng->cnt[3], r_time));
	tfw_stats_adjust(rng, 3);

totals:
	++rng->tot_cnt;

	return;
}

/**
 * Retrieve nearest to @pcnts->ith percentiles.
 * @pcnts must be sorted.
 */
static void
tfw_stats_calc(TfwPcntRanges *rng, Percentile *pcnts, size_t np, bool clear)
{
	int i, r, b, p = 0;
	unsigned long cnt, tot_cnt = rng->tot_cnt;
	unsigned long pval[np];

	if (unlikely(!tot_cnt))
		return;

	/* How many items we need to collect for each percentile. */
	for (i = 0; i < np; ++i) {
		pval[i] = tot_cnt * pcnts[i].ith / 100;
		if (!pval[i])
			pcnts[p++].val = 0;
	}

	for (cnt = 0, r = 0; r < TFW_STATS_RANGES; ++r)
		for (b = 0; b < TFW_STATS_BCKTS; ++b) {
			cnt += rng->cnt[r][b];
			for ( ; p < np && pval[p] <= cnt; ++p) {
				pcnts[p].ith = cnt * 100 / tot_cnt;
				pcnts[p].val = rng->ctl[r].begin
					       + (b << rng->ctl[r].order);
			}
			if (clear)
				rng->cnt[r][b] = 0;
		}

	BUG_ON (p < np);
	if (clear)
		rng->tot_cnt = 0;
}

/*
 * [1ms, 349ms] should be enough for almost any installation,
 * including crossatalantic.
 */
static TfwPcntRanges rng = {
	.ctl = { {0, 1, 16},
		 {1, 17, 47},
		 {2, 48, 108},
		 {4, 109, 349}
	}
};

static void
tfw_percentile(const unsigned int *set, size_t len, Percentile *pcnts,
		size_t np)
{
	int i;

	/* 1. Emulate getting @set in stream manner. */
	for (i = 0; i < len; ++i)
		tfw_stats_upd(&rng, set[i]);

	/*
	 * 2. Perform percentiles calculation.
	 * Zero the statistic on each call. In real life this should be done
	 * once per T, configurable time.
	 */
	tfw_stats_calc(&rng, pcnts, np, true);
}

int
main(int argc, char *argv[])
{
	int i, j;

	printf("Format: <percentile number> -> <value>\n\n");

	for (i = 0; i < ARRAY_SIZE(sets); ++i) {
		Percentile pprev[6], pnext[6];
		Percentile p0[6] = { {1}, {50}, {75}, {90}, {95}, {99} };
		Percentile p1[6] = { {1}, {50}, {75}, {90}, {95}, {99} };

		/* Store previous statistic for Tempesta trends.
		 * This should be used for /proc/tempesta/perfstat since
		 * tfw_stats_calc() should be called on timer.
		 * BTW (for further extensions) it's also good to send probe
		 * request to all the servers on the timer to estimate their
		 * availability.
		 */
		memcpy(pprev, p1, sizeof(p1));

		/* Usual percentiles calculation, use it as reference. */
		basic_percentile(sets[i].set, sets[i].len, p0, ARRAY_SIZE(p0));
		printf("base:\t1->%u\t50->%u\t75->%u\t90->%u\t95->%u\t99->%u\n",
		       p0[0].val, p0[1].val, p0[2].val, p0[3].val, p0[4].val,
		       p0[5].val);

		/* Tempesta percentiles. */
		tfw_percentile(sets[i].set, sets[i].len, p1, ARRAY_SIZE(p1));
		printf("tfw:\t%d->%u\t%d->%u\t%d->%u\t%d->%u\t%d->%u\t%d->%u\n",
		       p1[0].ith, p1[0].val, p1[1].ith, p1[1].val,
		       p1[2].ith, p1[2].val, p1[3].ith, p1[3].val,
		       p1[4].ith, p1[4].val, p1[5].ith, p1[5].val);

		/*
		 * Linear (actually just dummy) prediction for next statistic
		 * values.
		 * TODO do more reasonable trend calculation.
		 *
		 * @pnext should be used for servers' weights calculation in
		 * predictive dynamic load balancing (#565).
		 *
		 * Keep in mind that negative values are possible.
		 */
		for (j = 0; j < ARRAY_SIZE(p1); ++j) {
			if (unlikely(!p1[j].ith)) {
				pnext[j].ith = pprev[j].ith;
				pnext[j].val = pprev[j].val;
				continue;
			}
			if (unlikely(!pprev[j].ith)) {
				pnext[j].ith = p1[j].ith;
				pnext[j].val = p1[j].val;
				continue;
			}
			pnext[j].ith = (p1[j].ith + pprev[j].ith) / 2;
			if (unlikely(!p1[j].val)) {
				pnext[j].val = pprev[j].val;
			}
			else if (unlikely(!pprev[j].val)) {
				pnext[j].val = p1[j].val;
			}
			else {
				pnext[j].val = p1[j].val * 2 - pprev[j].val;
			}
		}
		printf("trend:\t%d->%d\t%d->%d\t%d->%d\t%d->%d\t%d->%d\t%d->%d"
		       "\n\n",
		       pnext[0].ith, pnext[0].val, pnext[1].ith, pnext[1].val,
		       pnext[2].ith, pnext[2].val, pnext[3].ith, pnext[3].val,
		       pnext[4].ith, pnext[4].val, pnext[5].ith, pnext[5].val);
	}

	return 0;
}
