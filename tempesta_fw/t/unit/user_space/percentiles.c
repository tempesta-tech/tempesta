/**
 *		Tempesta FW
 *
 * Prototype for fast precentilies calculation.
 *
 * The algorithm is constructed to be as efficient as possible sacrificing
 * accuracy and answering questions different from originaly asked by user.
 * The main concepts and requirements are:
 *
 * 1. Small O(1) update time with only few conditions and cache line accesses;
 *
 * 2. Very fast O(1) calculation of several percentilies in parallel;
 *
 * 3. Very small overall memory footprint for inexpensive handling of
 *    performance trends of many servers;
 *
 * 4. Buckets must dynamicaly rearrange since we don't know server response
 *    times a-priori;
 *
 * 5. The buckets adjustments must be done in lock-less fashion on multi-core
 *    environment;
 *
 * 6. If user ask for Nth percentile, e.g. 75th, we can return inaccurate
 *    value for different percentilie, e.g. 81st. This is very possibe if we
 *    don't have enough data for accurate percentilies calculation.
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
#include <string.h>

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>

#define SET(s)		{ARRAY_SIZE(s), s}

/*
 * Keep arrays sorted to make our simple basic algorithm for percentlies
 * calculation work.
 */
static const struct {
	size_t		len;
	unsigned int	*set;
} sets[] = {
	/* Not enough data for 1-percentilie, so show 0 for 1-percentilie. */
	SET(((unsigned int[]){1, 2, 3, 4, 5, 6, 7, 8, 9, 10})),
	/*
	 * `3` is outlier in first range (count=4, bucket=2).
	 * Right bound of last range is extened to 1069.
	 */
	SET(((unsigned int[]){1, 2, 3, 3, 3, 3, 4, 4, 5, 1001, 1002, 1010})),
	/* All percentilies should be calculated accurately. */
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
 * @ith	- percentilie number;
 * @val	- percentilie value;
 */
typedef struct {
	int	ith;
	int	val;
} Percentilie;

/**
 * Calculate @np percentilies from @pcnts over @set of size @len.
 */
static void
basic_percentilie(const unsigned int *set, size_t len, Percentilie *pcnts,
		  size_t np)
{
	int i;

	for (i = 0; i < np; ++i) {
		/* How many items we need to collect for each percentilie. */
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
#define TFW_STAT_RANGES		4
#define TFW_STAT_RLAST		(TFW_STAT_RANGES - 1)
#define TFW_STAT_BCKTS		16

typedef union {
	struct {
		unsigned int	order;
		unsigned short	begin;
		unsigned short	end;
	} __attribute__((packed));
	unsigned long		atomic;
} TfwPcntCtl;

typedef struct {
	TfwPcntCtl	ctl[TFW_STAT_RANGES];
	atomic64_t	tot_cnt;
	unsigned long	__padding[TFW_STAT_RLAST];
	atomic_t	cnt[TFW_STAT_RANGES][TFW_STAT_BCKTS];
} TfwPcntRanges __attribute__((aligned(L1_CACHE_BYTES)));

static inline atomic_t *
__rng(TfwPcntCtl *pc, atomic_t *cnt, unsigned int r_time)
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
	pc->end = pc->begin + ((TFW_STAT_BCKTS - 1) << pc->order);
	rng->ctl[r].atomic = pc->atomic;

	printf("  -- extend right bound of range %d to begin=%u order=%u"
	       " end=%u\n", r, pc->begin, pc->order, pc->end);

	/*
	 * Coalesce all counters to left half of the buckets.
	 * Some concurrent updates can be lost.
	 */
	for (i = 0; i < TFW_STAT_BCKTS / 2; ++i)
		atomic_set(&rng->cnt[r][i],
			   atomic_read(&rng->cnt[r][2 * i])
			   + atomic_read(&rng->cnt[r][2 * i + 1]));
}

static void
__range_shrink_left(TfwPcntRanges *rng, TfwPcntCtl *pc, int r)
{
	int i;
	unsigned long cnt_full, cnt_half;

	--pc->order;
	pc->begin = pc->end - ((TFW_STAT_BCKTS - 1) << pc->order);
	rng->ctl[r].atomic = pc->atomic;

	printf("  -- shrink left bound of range %d to begin=%u order=%u"
	       " end=%u\n", r, pc->begin, pc->order, pc->end);

	/*
	 * Write sum of the left half counters to the first bucket and equally
	 * split counters of the right half among rest of the buckets.
	 * Some concurrent updates can be lost.
	 */
	for (i = 1; i < TFW_STAT_BCKTS / 2; ++i)
		atomic_add(atomic_read(&rng->cnt[r][i]), &rng->cnt[r][0]);
	cnt_full = atomic_read(&rng->cnt[r][TFW_STAT_BCKTS / 2]);
	cnt_half = cnt_full / 2;
	atomic_add(cnt_half, &rng->cnt[r][0]);
	atomic_set(&rng->cnt[r][1], cnt_full - cnt_half);
	for (i = 1; i < TFW_STAT_BCKTS / 2; ++i) {
		cnt_full = atomic_read(&rng->cnt[r][TFW_STAT_BCKTS / 2 + i]);
		cnt_half = cnt_full / 2;
		atomic_set(&rng->cnt[r][i * 2], cnt_half);
		atomic_set(&rng->cnt[r][i * 2 + 1], cnt_full - cnt_half);
	}
}

/**
 * Extend last range so that we can handle large response times.
 */
static void
tfw_stat_extend(TfwPcntRanges *rng, unsigned int r_time)
{
	int i;
	TfwPcntCtl pc = { .atomic = rng->ctl[TFW_STAT_RLAST].atomic };

	do {
		++pc.order;
		pc.end = pc.begin + ((TFW_STAT_BCKTS - 1) << pc.order);
	} while (pc.end < r_time);
	rng->ctl[TFW_STAT_RLAST].atomic = pc.atomic;

	printf("  -- extend last range to begin=%u order=%u end=%u\n",
	       pc.begin, pc.order, pc.end);

	/*
	 * Coalesce all counters to left half of the buckets.
	 * Some concurrent updates can be lost.
	 */
	for (i = 0; i < TFW_STAT_BCKTS / 2; ++i)
		atomic_set(&rng->cnt[TFW_STAT_RLAST][i],
			   atomic_read(&rng->cnt[TFW_STAT_RLAST][2 * i])
			   + atomic_read(&rng->cnt[TFW_STAT_RLAST][2 * i + 1]));
}

/**
 * Check range @r whether it contains large outliers and adjust it if so.
 *
 * The most left bound is fixed to 1ms. The most right bound is only growing
 * to handle large values. So adjustment can increase gaps between ranges
 * moving left range bounds only with reducing a range order or decrease the
 * gaps moving right range bounds with enlarging a range order. I.e. ranges
 * worms right and the algorithm converges at the largest faced response time.
 */
static void
tfw_stat_adjust(TfwPcntRanges *rng, int r)
{
	TfwPcntCtl pc;
	static spinlock_t sa_guard = __RAW_SPIN_LOCK_UNLOCKED(sa_guard);
	unsigned long i, cnt = 0, sum = 0, max = 0, i_max = 0;

	if (!spin_trylock(&sa_guard))
		return; /* somebody is already adjusting statistic ranges */

	for (i = 0; i < TFW_STAT_BCKTS; ++i) {
		if (atomic_read(&rng->cnt[r][i])) {
			sum += atomic_read(&rng->cnt[r][i]);
			++cnt;
		}
		if (max < atomic_read(&rng->cnt[r][i])) {
			max = atomic_read(&rng->cnt[r][i]);
			i_max = i;
		}
	}
	if (likely(max <= sum * 2 / cnt))
		/* outlier means (max < avg * 2) */
		goto out;

	printf("  -- range %d has outlier %lu (avg=%lu total=%lu) at"
	       " bucket %lu\n", r, max, sum / cnt, sum, i_max);

	if (r && i_max == 0) {
		/*
		 * Too many hits at the gap between r'th and (r - 1)'th ranges.
		 * Move right bound of (r - 1)'th range to the right.
		 */
		TfwPcntCtl pc_curr = { .atomic = rng->ctl[r].atomic };
		pc.atomic = rng->ctl[r - 1].atomic;
		if (pc.begin + ((TFW_STAT_BCKTS - 1) << (pc.order + 1))
		    < pc_curr.begin)
		{
			__range_grow_right(rng, &pc, r - 1);
			/*
			 * Evenly distibute 0'th among right half of (r - 1)'th
			 * range. This is rough approximation.
			 */
			cnt = max / (TFW_STAT_BCKTS / 2 + 1);
			atomic_sub(cnt * (TFW_STAT_BCKTS / 2),
				   &rng->cnt[r][0]);
			for (i = TFW_STAT_BCKTS / 2; i < TFW_STAT_BCKTS; ++i)
				atomic_set(&rng->cnt[r - 1][i], cnt);

		}
		/*
		 * Fall through to reduce the interval order: the first bucket
		 * gets ever higher counter, but since the left bound is moved,
		 * we'll move right bound of (r - 1)'th range next time.
		 */
	}

	/*
	 * Too large order - reduce it by moving left bound.
	 * If servers are too fast (all responses within 1ms),
	 * then there is nothing to do for us.
	 */
	if (!r)
		goto out;
	pc.atomic = rng->ctl[r].atomic;
	if (likely(pc.order))
		__range_shrink_left(rng, &pc, r);

out:
	spin_unlock(&sa_guard);
}

/**
 * Update server response time statistic.
 * @r_time is in milliseconds (1/HZ second), use jiffies to get it.
 *
 * Can be ran concurrently w/ tfw_stat_adjust(), so counter to update is
 * decided by range control handlers read at the begin. During the function
 * execution the control handlers may change, so we can update wrong
 * bucket and/or range. That's acceptable by our model. We only care about
 * correct array indexing.
 */
static void
tfw_stat_upd(TfwPcntRanges *rng, unsigned int r_time)
{
	TfwPcntCtl pc3, pc2 = { .atomic = rng->ctl[2].atomic };

	atomic64_inc(&rng->tot_cnt);

	/* Binary search of appropriate range. */
	if (r_time <= pc2.end) {
		TfwPcntCtl pc0, pc1 = { .atomic = rng->ctl[1].atomic };
		if (pc1.end < r_time) {
			atomic_inc(__rng(&pc2, rng->cnt[2], r_time));
			tfw_stat_adjust(rng, 2);
			return;
		}

		pc0.atomic = rng->ctl[0].atomic;
		BUG_ON(pc0.begin != 1); /* left bound is never moved */
		if (pc0.end < r_time) {
			atomic_inc(__rng(&pc1, rng->cnt[1], r_time));
			tfw_stat_adjust(rng, 1);
			return;
		}
		atomic_inc(__rng(&pc0, rng->cnt[0], r_time));
		tfw_stat_adjust(rng, 0);
		return;
	}

	pc3.atomic = rng->ctl[3].atomic;
	if (unlikely(r_time > pc3.end)) {
		tfw_stat_extend(rng, r_time);
		pc3.atomic = rng->ctl[3].atomic;
	}
	atomic_inc(__rng(&pc3, rng->cnt[3], r_time));
	tfw_stat_adjust(rng, 3);
}

/**
 * Retrieve nearest to @pcnts->ith percentilies.
 * @pcnts must be sorted.
 */
static void
tfw_stat_calc(TfwPcntRanges *rng, Percentilie *pcnts, size_t np, bool clear)
{
	int i, r, b, p = 0;
	unsigned long cnt, tot_cnt = atomic64_read(&rng->tot_cnt);
	unsigned long pval[np];

	if (unlikely(!tot_cnt))
		return;

	/* How many items we need to collect for each percentilie. */
	for (i = 0; i < np; ++i) {
		pval[i] = tot_cnt * pcnts[i].ith / 100;
		if (!pval[i])
			pcnts[p++].val = 0;
	}

	for (cnt = 0, r = 0; r < TFW_STAT_RANGES; ++r)
		for (b = 0; b < TFW_STAT_BCKTS; ++b) {
			cnt += atomic_read(&rng->cnt[r][b]);
			for ( ; p < np && pval[p] <= cnt; ++p) {
				pcnts[p].ith = cnt * 100 / tot_cnt;
				pcnts[p].val = rng->ctl[r].begin
					       + (b << rng->ctl[r].order);
			}
			if (clear)
				atomic_set(&rng->cnt[r][b], 0);
		}

	BUG_ON (p < np);
	if (clear)
		atomic64_set(&rng->tot_cnt, 0);
}

/*
 * [1ms, 349ms] should be enough for almost any installation,
 * including crossatalantic.
 */
static TfwPcntRanges rng = {
	.ctl = { {{0, 1, 16}},
		 {{1, 17, 47}},
		 {{2, 48, 108}},
		 {{4, 109, 349}}
	}
};

static void
tfw_percentilie(const unsigned int *set, size_t len, Percentilie *pcnts,
		size_t np)
{
	int i;

	/* 1. Emulate getting @set in stream manner. */
	for (i = 0; i < len; ++i)
		tfw_stat_upd(&rng, set[i]);

	/*
	 * 2. Perform percentilies calculation.
	 * Zero the statistic on each call. In real life this should be done
	 * once per T, configurable time.
	 */
	tfw_stat_calc(&rng, pcnts, np, true);
}

int
main(int argc, char *argv[])
{
	int i, j;

	printf("Format: <percentilie number> -> <value>\n\n");

	for (i = 0; i < ARRAY_SIZE(sets); ++i) {
		Percentilie pprev[6], pnext[6];
		Percentilie p0[6] = { {1}, {50}, {75}, {90}, {95}, {99} };
		Percentilie p1[6] = { {1}, {50}, {75}, {90}, {95}, {99} };

		/* Store previous statistic for Tempesta trends.
		 * This should be used for /proc/tempesta/perfstat since
		 * tfw_stat_calc() should be called on timer.
		 * BTW (for further extensions) it's also good to send probe
		 * request to all the servers on the timer to estimate their
		 * availability.
		 */
		memcpy(pprev, p1, sizeof(p1));

		/* Usual percentilies calculation, use it as refference. */
		basic_percentilie(sets[i].set, sets[i].len, p0, ARRAY_SIZE(p0));
		printf("base:\t1->%u\t50->%u\t75->%u\t90->%u\t95->%u\t99->%u\n",
		       p0[0].val, p0[1].val, p0[2].val, p0[3].val, p0[4].val,
		       p0[5].val);

		/* Tempesta percentilies. */
		tfw_percentilie(sets[i].set, sets[i].len, p1, ARRAY_SIZE(p1));
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
