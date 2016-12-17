/*
 *		Tempesta FW
 *
 * Copyright (C) 2016-2017 Tempesta Technologies, Inc.
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
 * Prototype for fast precentiles calculation.
 */
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stringify.h>

#include "apm.h"
#include "cfg.h"
#include "log.h"
#include "pool.h"
#include "procfs.h"

/*
 * The algorithm is constructed to be as efficient as possible. That's
 * done by sacrificing the accuracy and giving possibly inexact answers
 * to questions asked by users. The main concepts and requirements are:
 *
 * 1. Small O(1) update time with only few conditions and cache line accesses;
 *
 * 2. Very fast O(1) calculation of several percentiles in parallel;
 *
 * 3. Very small overall memory footprint for inexpensive handling of
 *    performance trends of many servers;
 *
 * 4. Buckets must be dynamicaly rearranged since server response times
 *    are unknown apriori;
 *
 * 5. The adjustments of buckets must be performed in a lock-less fashion
 *    in a multi-core environment;
 *
 * 6. If a user asks for Nth percentile, e.g. 75th, an inaccurate value
 *    may be returned that is in fact for a different percentile, e.g.
 *    81st. That is very possible if there is insufficient data for an
 *    accurate percentiles calculation.
 */

/*
 * Response time statistics data structures.
 *
 * A time range is split into a number of buckets, such that each bucket
 * is efficiently calculated as @begin + (1 << @order).
 *
 * @order	- The order of a range. The ranges grow logarithmically.
 *		  Motivation: time estimation error becomes negligible as
 *		  the time grows, so higher response times can be estimated
 *		  less accurately;
 * @begin	- the start response time value of a range;
 * @end		- the end response time value of a range;
 * @atomic	- atomic control handler to update all control fields
 * 		  above atomically with a single write operation;
 * @tot_cnt	- global hits counter for all ranges;
 * @tot_val	- the sum of all response time values, for AVG calculation;
 * @min_val	- the minimum response time value;
 * @max_val	- the maximum response time value;
 * @cnt		- the number of hits with a specific response time that
 *		  fall to a specific bucket in a range.
 *
 * Keep the members cache line aligned to minimize false sharing: each range
 * is placed on a separate cache line, and control hadlers are also on their
 * own cache lines.
 */
#define TFW_STATS_RANGES	4
#define TFW_STATS_RLAST		(TFW_STATS_RANGES - 1)
#define TFW_STATS_BCKTS		16
#define TFW_STATS_TOTAL_BCKTS	(TFW_STATS_RANGES * TFW_STATS_BCKTS)

typedef union {
	struct {
		unsigned int	order;
		unsigned short	begin;
		unsigned short	end;
	} __attribute__((packed));
	unsigned long		atomic;
} TfwPcntCtl;

typedef struct {
	TfwPcntCtl	ctl[TFW_STATS_RANGES];
	char		__reset_from[0];
	atomic64_t	tot_cnt;
	atomic64_t	tot_val;
	atomic_t	min_val;
	atomic_t	max_val;
	unsigned long	__pad_ulong;
	atomic_t	cnt[TFW_STATS_RANGES][TFW_STATS_BCKTS];
	char		__reset_till[0];
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
	pc->end = pc->begin + ((TFW_STATS_BCKTS - 1) << pc->order);
	rng->ctl[r].atomic = pc->atomic;

	TFW_DBG3("  -- extend right bound of range %d to begin=%u order=%u"
		 " end=%u\n", r, pc->begin, pc->order, pc->end);
	/*
	 * Coalesce all counters to left half of the buckets.
	 * Some concurrent updates can be lost.
	 */
	for (i = 0; i < TFW_STATS_BCKTS / 2; ++i)
		atomic_set(&rng->cnt[r][i],
			   atomic_read(&rng->cnt[r][2 * i])
			   + atomic_read(&rng->cnt[r][2 * i + 1]));
}

static void
__range_shrink_left(TfwPcntRanges *rng, TfwPcntCtl *pc, int r)
{
	int i;
	unsigned long tmp;

	--pc->order;
	pc->begin = pc->end - ((TFW_STATS_BCKTS - 1) << pc->order);
	rng->ctl[r].atomic = pc->atomic;

	TFW_DBG3("  -- shrink left bound of range %d to begin=%u order=%u"
		 " end=%u\n", r, pc->begin, pc->order, pc->end);
	/*
	 * Write sum of the left half counters to the first bucket and equally
	 * split counters of the right half among rest of the buckets.
	 * Some concurrent updates may be lost.
	 */
	for (i = 1; i < TFW_STATS_BCKTS / 2; ++i)
		atomic_add(atomic_read(&rng->cnt[r][i]), &rng->cnt[r][0]);
	tmp = atomic_read(&rng->cnt[r][TFW_STATS_BCKTS / 2]) / 2;
	atomic_add(tmp, &rng->cnt[r][0]);
	atomic_set(&rng->cnt[r][1], tmp);
	for (i = 1; i < TFW_STATS_BCKTS / 2; ++i) {
		tmp = atomic_read(&rng->cnt[r][TFW_STATS_BCKTS / 2 + i]);
		tmp /= 2;
		atomic_set(&rng->cnt[r][i * 2], tmp);
		atomic_set(&rng->cnt[r][i * 2 + 1], tmp);
	}
}

/**
 * Extend the last range so that larger response times can be handled.
 */
static void
tfw_stats_extend(TfwPcntRanges *rng, unsigned int r_time)
{
	int i;
	TfwPcntCtl pc = { .atomic = rng->ctl[TFW_STATS_RLAST].atomic };

	do {
		++pc.order;
		pc.end = pc.begin + ((TFW_STATS_BCKTS - 1) << pc.order);
	} while (pc.end < r_time);
	rng->ctl[TFW_STATS_RLAST].atomic = pc.atomic;

	TFW_DBG3("  -- extend last range to begin=%u order=%u end=%u\n",
		 pc.begin, pc.order, pc.end);
	/*
	 * Coalesce all counters to the left half of the buckets.
	 * Some concurrent updates may be lost.
	 */
	for (i = 0; i < TFW_STATS_BCKTS / 2; ++i)
		atomic_set(&rng->cnt[TFW_STATS_RLAST][i],
			   atomic_read(&rng->cnt[TFW_STATS_RLAST][2 * i])
			   + atomic_read(&rng->cnt[TFW_STATS_RLAST][2 * i + 1]));
}

/**
 * See if the range @r contains large outliers. Adjust it if so.
 * This is the unlocked version.
 *
 * The leftmost bound is fixed to 1ms. The rightmost bound is only growing
 * to handle large values. So the adjustment may either increase the gaps
 * between ranges by decreasing a range order and moving left range bounds,
 * or decrease the gaps by increasing a range order and moving right range
 * bounds. I.e. ranges worm to the right and the algorithm converges at the
 * largest response time faced.
 */
static void
__tfw_stats_adjust(TfwPcntRanges *rng, int r)
{
	TfwPcntCtl pc;
	unsigned long i, cnt = 0, sum = 0, max = 0, i_max = 0;

	for (i = 0; i < TFW_STATS_BCKTS; ++i) {
		if (atomic_read(&rng->cnt[r][i])) {
			sum += atomic_read(&rng->cnt[r][i]);
			++cnt;
		}
		if (max < atomic_read(&rng->cnt[r][i])) {
			max = atomic_read(&rng->cnt[r][i]);
			i_max = i;
		}
	}
	/* outlier means (max < avg * 2) */
	if (likely(max <= sum * 2 / cnt))
		return;

	if (r && i_max == 0) {
		/*
		 * Too many hits in the gap between r'th and (r - 1)'th ranges.
		 * Move the right bound of the (r - 1)'th range to the right.
		 */
		TfwPcntCtl pc_curr = { .atomic = rng->ctl[r].atomic };
		pc.atomic = rng->ctl[r - 1].atomic;
		if (pc.begin + ((TFW_STATS_BCKTS - 1) << (pc.order + 1))
		    < pc_curr.begin)
		{
			__range_grow_right(rng, &pc, r - 1);
			/*
			 * Evenly distibute hits among the right half of the
			 * (r - 1)'th range. This is a rough approximation.
			 */
			cnt = max / (TFW_STATS_BCKTS / 2 + 1);
			atomic_sub(cnt * (TFW_STATS_BCKTS / 2),
				   &rng->cnt[r][0]);
			for (i = TFW_STATS_BCKTS / 2; i < TFW_STATS_BCKTS; ++i)
				atomic_set(&rng->cnt[r - 1][i], cnt);
		}
		/*
		 * Fall through to reduce the range order. The first bucket
		 * gets a higher count. Since the left bound has been moved,
		 * the right bound of (r - 1)'th range will be moved next time.
		 */
	}

	/*
	 * The range order is too big. Reduce it by moving the left bound.
	 * If servers are too fast (all responses within 1ms), then there's
	 * nothing to do here.
	 */
	if (!r)
		return;
	pc.atomic = rng->ctl[r].atomic;
	if (likely(pc.order)) {
		__range_shrink_left(rng, &pc, r);
	}
}

/*
 * See if the range @r contains large outliers. Adjust it if so.
 * This is the locked version.
 *
 * If the lock is busy then either the ranges are being adjusted
 * or the percentiles are being calculated at this very moment.
 * Just skip the adjustment of ranges and do it next time.
 */
static inline void
tfw_stats_adjust(TfwPcntRanges *rng, int r, spinlock_t *slock)
{
	if (!spin_trylock(slock))
		return;
	__tfw_stats_adjust(rng, r);
	spin_unlock(slock);
}

/*
 * Set the new maximum value.
 * Return true if the new value has been set.
 * Return false if the maximum value remained the same.
 */
static inline bool
tfw_stats_adj_max(TfwPcntRanges *rng, unsigned int r_time)
{
	int old_val, max_val = atomic_read(&rng->max_val);

	while (r_time > max_val) {
		old_val = atomic_cmpxchg(&rng->max_val, max_val, r_time);
		if (likely(old_val == max_val))
			return true;
		max_val = old_val;
	}

	return false;
}

/*
 * Set the new minimum value.
 * Return true if the new value has been set.
 * Return false if the minimum value remained the same.
 */
static inline bool
tfw_stats_adj_min(TfwPcntRanges *rng, unsigned int r_time)
{
	int old_val, min_val = atomic_read(&rng->min_val);

	while (r_time < min_val) {
		old_val = atomic_cmpxchg(&rng->min_val, min_val, r_time);
		if (likely(old_val == min_val))
			return true;
		min_val = old_val;
	}

	return false;
}

/**
 * Update server response time statistic.
 * @r_time is in milliseconds (1/HZ second), use jiffies to get it.
 *
 * The control handlers may be changed during the execution of this
 * function. In that case a wrong bucket and/or range may be updated
 * in a parallel thread of execution. That's acceptable in our model.
 * We only care about correct array indexing.
 */
static void
tfw_stats_update(TfwPcntRanges *rng, unsigned int r_time, spinlock_t *slock)
{
	TfwPcntCtl pc3, pc2 = { .atomic = rng->ctl[2].atomic };

	/* Adjust min/max values. */
	if (!tfw_stats_adj_min(rng, r_time))
		tfw_stats_adj_max(rng, r_time);
	/* Add to @tot_val for AVG calculation. */
	atomic64_add(r_time, &rng->tot_val);

	/* Binary search of an appropriate range. */
	if (r_time <= pc2.end) {
		TfwPcntCtl pc0, pc1 = { .atomic = rng->ctl[1].atomic };
		if (pc1.end < r_time) {
			atomic_inc(__rng(&pc2, rng->cnt[2], r_time));
			tfw_stats_adjust(rng, 2, slock);
			atomic64_inc(&rng->tot_cnt);
			return;
		}

		pc0.atomic = rng->ctl[0].atomic;
		BUG_ON(pc0.begin != 1); /* left bound is never moved */
		if (pc0.end < r_time) {
			atomic_inc(__rng(&pc1, rng->cnt[1], r_time));
			tfw_stats_adjust(rng, 1, slock);
			atomic64_inc(&rng->tot_cnt);
			return;
		}
		atomic_inc(__rng(&pc0, rng->cnt[0], r_time));
		tfw_stats_adjust(rng, 0, slock);
		atomic64_inc(&rng->tot_cnt);
		return;
	}

	if (!spin_trylock(slock))
		return;
	pc3.atomic = rng->ctl[3].atomic;
	if (unlikely(r_time > pc3.end)) {
		tfw_stats_extend(rng, r_time);
		pc3.atomic = rng->ctl[3].atomic;
	}
	atomic_inc(__rng(&pc3, rng->cnt[3], r_time));
	__tfw_stats_adjust(rng, 3);
	atomic64_inc(&rng->tot_cnt);
	spin_unlock(slock);
}

/*
 * APM ring buffer.
 *
 * It consists of the predefined number of entries that are "reused" as
 * the buffer gets full. The ring buffer as a whole keeps the APM stats
 * for the latest time interval (the time window), and each entry of
 * the buffer keeps the APM stats for a piece of that time (an interval).
 */
/*
 * A ring buffer entry structure.
 * @pcntrng	- Struct for response time data by the percentiles algorithm.
 * @jtmistamp	- The start of the time interval for the current entry.
 * @reset	- The entry can be reset by one thread at a time.
 */
typedef struct {
	TfwPcntRanges	pcntrng;
	unsigned long	jtmistamp;
	atomic_t	reset;
} TfwApmRBEnt;

/*
 * The ring buffer contol structure.
 * This is a supporting structure. It keeps related data that is useful
 * in making decisions on the need of recalculation of percentiles.
 * @jtmwstamp	- The start of the time window the percentiles are for.
 * @entry_cnt	- The number of hits in the current buffer ring entry.
 * @total_cnt	- The number of hits within the current time window.
 */

typedef struct {
	unsigned long	jtmwstamp;
	unsigned long	entry_cnt;
	unsigned long	total_cnt;
} TfwApmRBCtl;

/*
 * The ring buffer structure.
 * @rbent	- Array of ring buffer entries.
 * @slock	- The lock to adjust the ranges in the current entry.
 * @rbufsz	- The size of @rbent.
 */
typedef struct {
	TfwApmRBEnt	*rbent;
	spinlock_t	slock;
	int		rbufsz;
} TfwApmRBuf;

/*
 * The stats entry data structure.
 * Keeps the latest values of calculated percentiles.
 * @pstats	- The percentile stats structure.
 * @rwlock	- Protect updates.
 */
typedef struct {
	TfwPrcntlStats	pstats;
	rwlock_t	rwlock;
} TfwApmSEnt;

/*
 * The stats data structure.
 * There's only one updater that runs on timer. It calculates the latest
 * percentiles and updates the stored values. There are multiple readers
 * of the stored values. The stored values of the latest percentiles are
 * a shared resource that needs a lock to access. An array of two entries
 * is used to decrease the lock contention. Readers read the stored values
 * at @asent[@rdidx % 2]. The writer writes the new percentile values to
 * @asent[(@rdidx + 1) % 2], and then increments @rdidx. The reading and
 * the writing are protected by a rwlock.
 * @asent	- The stats entries for reading/writing (flip-flop manner).
 * @rdidx	- The current index in @asent for readers.
 */
typedef struct {
	TfwApmSEnt	asent[2];
	atomic_t	rdidx;
} TfwApmStats;

/*
 * APM Data structure.
 * Note that the organization of the supporting data heavily depends
 * on the fact that there's only one party that does the calculation
 * of percentiles - the function that runs periodically on timer.
 * If there are several different parties that do the calculation,
 * then the data may need to be organized differently.
 * @rbuf	- The ring buffer for the specified time window.
 * @rbctl	- The control data helpful in taking optimizations.
 * @stats	- The latest percentiles.
 * @timer	- The periodic timer handle.
 * @flags	- The atomic flags (see below).
 */
#define TFW_APM_DATA_F_REARM	(0x0001)	/* Re-arm the timer. */
#define TFW_APM_DATA_F_RECALC	(0x0002)	/* Need to recalculate. */
#define TFW_APM_TIMER_TIMEOUT	(HZ/20)		/* The timer periodicity. */

typedef struct {
	TfwApmRBuf		rbuf;
	TfwApmRBCtl		rbctl;
	TfwApmStats		stats;
	struct timer_list	timer;
	unsigned long		flags;
} TfwApmData;

/*
 * [1ms, 349ms] should be sufficient for almost any installation,
 * including cross atlantic.
 */
static const TfwPcntCtl __read_mostly tfw_rngctl_init[TFW_STATS_RANGES] = {
	{{0, 1, 16}},
	{{1, 17, 47}},
	{{2, 48, 108}},
	{{4, 109, 349}}
};

static int tfw_apm_jtmwindow;		/* Time window in jiffies. */
static int tfw_apm_jtmintrvl;		/* Time interval in jiffies. */
static int tfw_apm_tmwscale;		/* Time window scale. */

/*
 * Get the next bucket in the ring buffer entry that has a non-zero
 * hits count. Set the bucket's sequential number, the range number,
 * and the bucket number. Set the response time value for the bucket.
 */
/*
 * Ring buffer entry state structure.
 * @v	- The response time value.
 * @i	- The current sequential bucket number across all ranges.
 * @r	- The current range number.
 * @b	- The current bucket number.
 */
typedef struct {
	u16	v;
	u8	i;
	u8	r : 4;
	u8	b : 4;
} __attribute__((packed)) TfwApmRBEState;

static inline void
__tfw_apm_state_set(TfwApmRBEState *st, u16 v, u8 i, u8 r, u8 b)
{
	st->v = v;
	st->i = i;
	st->r = r;
	st->b = b;
}

static inline void
__tfw_apm_state_next(TfwPcntRanges *rng, TfwApmRBEState *st)
{
	int i = st->i, r, b;
	unsigned short rtt;

	for (r = i / TFW_STATS_BCKTS; r < TFW_STATS_RANGES; ++r) {
		for (b = i % TFW_STATS_BCKTS; b < TFW_STATS_BCKTS; ++b, ++i) {
			if (!atomic_read(&rng->cnt[r][b]))
				continue;
			rtt = rng->ctl[r].begin + (b << rng->ctl[r].order);
			__tfw_apm_state_set(st, rtt, i, r, b);
			return;
		}
	}
	__tfw_apm_state_set(st, USHRT_MAX, i, r, b);
}

static inline void
tfw_apm_state_next(TfwPcntRanges *rng, TfwApmRBEState *st)
{
	BUG_ON(st->i >= TFW_STATS_TOTAL_BCKTS);

	++st->i;
	__tfw_apm_state_next(rng, st);
}

/*
 * Calculate the latest percentiles from the current stats data.
 *
 * Note that the calculation is run under a lock that protects against
 * concurrent updates to ranges in the current ring buffer entry. That
 * makes the values of @tot_cnt and the hits numbers in the buckets
 * mostly consistent. However, there's still a small chance for a race
 * condition. @tot_cnt and the buckets' @cnt[][] are updated without
 * a lock, asynchronously and at slightly different times. Due to a
 * tiny discrepancy between @tot_cnt and the sum of hit counters in
 * @cnt[][], the calculation may not be able to reach the target value.
 * In that case the calculation exits prematurely, and a recalculation
 * is scheduled at the next run of the timer.
 *
 * Returns the number of percentile values that have been filled.
 */
static int
tfw_apm_prnctl_calc(TfwApmRBuf *rbuf, TfwApmRBCtl *rbctl, TfwPrcntlStats *pstats)
{
	int i, p;
	unsigned long cnt = 0, val, pval[pstats->psz];
	TfwApmRBEState st[rbuf->rbufsz];
	TfwPcntRanges *pcntrng;
	TfwApmRBEnt *rbent = rbuf->rbent;

	for (i = 0; i < rbuf->rbufsz; i++) {
		pcntrng = &rbent[i].pcntrng;
		__tfw_apm_state_set(&st[i], pcntrng->ctl[0].begin, 0, 0, 0);
		__tfw_apm_state_next(pcntrng, &st[i]);
	}
	/* The number of items to collect for each percentile. */
	for (i = p = 0; i < pstats->psz; ++i) {
		pval[i] = rbctl->total_cnt * pstats->ith[i] / 100;
		if (!pval[i])
			pstats->val[p++] = 0;
	}
	while (p < pstats->psz) {
		int v_min = USHRT_MAX;
		for (i = 0; i < rbuf->rbufsz; i++) {
			if (st[i].v < v_min)
				v_min = st[i].v;
		}
		/*
		 * If the race condition has occured, then the results
		 * are incomplete and can be used only partially.
		 */
		if (unlikely(v_min == USHRT_MAX)) {
			TFW_DBG3("%s: Calculation stopped prematurely: "
				 "cnt [%lu] total_cnt [%lu]\n",
				 __func__, cnt, rbctl->total_cnt);
			TFW_DBG3("%s: [%lu] [%lu] [%lu] [%lu] [%lu] [%lu]\n",
				 __func__, pval[0], pval[1], pval[2],
				 pval[3], pval[4], pval[5]);
			break;
		}
		for (i = 0; i < rbuf->rbufsz; i++) {
			if (st[i].v != v_min)
				continue;
			pcntrng = &rbent[i].pcntrng;
			cnt += atomic_read(&pcntrng->cnt[st[i].r][st[i].b]);
			tfw_apm_state_next(pcntrng, &st[i]);
		}
		for ( ; p < pstats->psz && pval[p] <= cnt; ++p)
			pstats->val[p] = v_min;
	}
	cnt = val = 0;
	pstats->max = 0;
	pstats->min = UINT_MAX;
	for (i = 0; i < rbuf->rbufsz; i++) {
		pcntrng = &rbent[i].pcntrng;
		if (pstats->min > atomic_read(&pcntrng->min_val))
			pstats->min = atomic_read(&pcntrng->min_val);
		if (pstats->max < atomic_read(&pcntrng->max_val))
			pstats->max = atomic_read(&pcntrng->max_val);
		cnt += atomic64_read(&pcntrng->tot_cnt);
		val += atomic64_read(&pcntrng->tot_val);
	}
	if (likely(cnt))
		pstats->avg = val / cnt;

	return p;
}

/*
 * Reset a ring buffer entry.
 * Note that the ranges are not reset. As Tempesta runs the ranges
 * are adjusted to reflect the actual response time values.
 */
static inline void
__tfw_apm_rbent_reset(TfwApmRBEnt *crbent, unsigned long jtmistamp)
{
	memset(crbent->pcntrng.__reset_from, 0,
	       offsetof(TfwPcntRanges, __reset_till) -
	       offsetof(TfwPcntRanges, __reset_from));
	crbent->jtmistamp = jtmistamp;
	smp_mb__before_atomic();
	atomic_set(&crbent->reset, 1);
}

/*
 * Reset a ring buffer entry if it needs to be reused. Only one thread
 * proceeds to reset the entry. While the entry is being reset a number
 * of stats updates may be lost. That's acceptable.
 */
static inline void
tfw_apm_rbent_checkreset(TfwApmRBEnt *crbent, unsigned long jtmistamp)
{
	if (crbent->jtmistamp != jtmistamp) {
		if (!atomic_dec_and_test(&crbent->reset))
			return;
		__tfw_apm_rbent_reset(crbent, jtmistamp);
	}
}

/*
 * Update the control information on the APM ring buffer entries with
 * stats for subsequent calculation of percentiles. Use optimizations
 * to avoid the recalculation whenever possible. Maintain values of
 * @entry_cnt, @total_cnt, @jtmwstamp that are used in optimizations.
 *
 * Return true if recalculation of percentiles is required.
 * Return false if the percentile values don't need the recalculation.
 */
static bool
tfw_apm_rbctl_update(TfwApmData *data, int recalc)
{
	int i, centry;
	unsigned long jtmnow = jiffies;
	unsigned long jtmwstart, jtmistart;
	unsigned long entry_cnt, total_cnt = 0;
	TfwApmRBuf *rbuf = &data->rbuf;
	TfwApmRBCtl *rbctl = &data->rbctl;
	TfwApmRBEnt *rbent = rbuf->rbent;

	/* The start of the current time interval. */
	jtmistart = jtmnow - (jtmnow % tfw_apm_jtmintrvl);
	/* The start of the current time window. */
	jtmwstart = jtmistart - tfw_apm_jtmwindow;
	/* The index of the current entry. */
	centry = (jtmnow / tfw_apm_jtmintrvl) % rbuf->rbufsz;

	/*
	 * If the latest percentiles are for a different time window,
	 * then a recalculation is in order.
	 */
	if (unlikely(rbctl->jtmwstamp != jtmwstart)) {
		tfw_apm_rbent_checkreset(&rbent[centry], jtmistart);

		for (i = 0; i < rbuf->rbufsz; ++i)
			total_cnt += atomic64_read(&rbent[i].pcntrng.tot_cnt);

		rbctl->entry_cnt = 0;
		rbctl->total_cnt = total_cnt;
		rbctl->jtmwstamp = jtmwstart;

		TFW_DBG3("%s: New time window: centry [%d] total_cnt [%lu]\n",
			 __func__, centry, rbctl->total_cnt);

		return true;
	}

	/* The latest percentiles are for the current time window.
	 * In some cases a recalculation is not required. In some
	 * other cases the recalculation set up can be simpler.
	 */

	/* Nothing to do if there were no stats updates. */
	entry_cnt = atomic64_read(&rbent[centry].pcntrng.tot_cnt);
	if (unlikely(rbctl->entry_cnt == entry_cnt)) {
		if (unlikely(recalc)) {
			TFW_DBG3("%s: Old time window: recalculate: "
				 "centry [%d] total_cnt [%lu]\n",
				 __func__, centry, rbctl->total_cnt);
			return true;
		}
		return false;
	}
	BUG_ON(rbctl->entry_cnt > entry_cnt);

	/* Update the counts incrementally. */
	rbctl->total_cnt += entry_cnt - rbctl->entry_cnt;
	rbctl->entry_cnt = entry_cnt;

	TFW_DBG3("%s: Old time window: centry [%d] total_cnt [%lu]\n",
		 __func__, centry, rbctl->total_cnt);

	return true;
}

/*
 * Calculate the latest percentiles if necessary.
 *
 * Return the number of percentile values that have been filled
 * if potentially new percentile values were calculated.
 * Return 0 if the percentile values didn't need the recalculation.
 * REturn -1 of the recalculation could not be performed.
 */
static int
__tfw_apm_calc(TfwApmData *data, TfwPrcntlStats *pstats, int recalc)
{
	int ret;

	if (!spin_trylock(&data->rbuf.slock))
		return -1;
	if ((ret = tfw_apm_rbctl_update(data, recalc)))
		ret = tfw_apm_prnctl_calc(&data->rbuf, &data->rbctl, pstats);
	spin_unlock(&data->rbuf.slock);

	return ret;
}

/*
 * Calculate the latest percentiles if necessary.
 *
 * Note that this function may also be used concurrently by other users
 * than the kernel timer function in this module, should the need arise.
 * That should only be done in exceptional cases (like testing), because
 * it would increase @data->rbuf->slock lock contention.
 */
static void
tfw_apm_calc(TfwApmData *data)
{
	int nfilled, wridx, recalc;
	unsigned int val[ARRAY_SIZE(tfw_pstats_ith)];
	TfwPrcntlStats pstats = {
		.ith = tfw_pstats_ith,
		.val = val,
		.psz = ARRAY_SIZE(tfw_pstats_ith)
	};
	TfwApmSEnt *asent;

	wridx = ((unsigned int)atomic_read(&data->stats.rdidx) + 1) % 2;
	asent = &data->stats.asent[wridx];

	recalc = test_and_clear_bit(TFW_APM_DATA_F_RECALC, &data->flags);
	nfilled = __tfw_apm_calc(data, &pstats, recalc);
	if (!nfilled)
		return;

	if (nfilled < asent->pstats.psz) {
		TFW_DBG3("%s: Percentile calculation incomplete.\n", __func__);
		set_bit(TFW_APM_DATA_F_RECALC, &data->flags);
	} else {
		TFW_DBG3("%s: Percentile values may have changed.\n", __func__);
		write_lock(&asent->rwlock);
		memcpy(asent->pstats.val, pstats.val,
		       asent->pstats.psz * sizeof(asent->pstats.val[0]));
		asent->pstats.min = pstats.min;
		asent->pstats.max = pstats.max;
		asent->pstats.avg = pstats.avg;
		atomic_inc(&data->stats.rdidx);
		write_unlock(&asent->rwlock);
	}
}

/*
 * Calculate the latest percentiles if necessary.
 * Runs periodically on timer. 
 */
static void
tfw_apm_pstats_fn(unsigned long fndata)
{
	TfwApmData *data = (TfwApmData *)fndata;

	tfw_apm_calc(data);

	smp_mb__before_atomic();
	if (test_bit(TFW_APM_DATA_F_REARM, &data->flags))
		mod_timer(&data->timer, jiffies + TFW_APM_TIMER_TIMEOUT);
}

/*
 * Get the latest calculated percentiles.
 *
 * Return 0 if the percentile values didn't need recalculation.
 * Return 1 if potentially new percentile values were calculated.
 *
 * The two functions below differ only by the type of lock used.
 * tfw_apm_stats() should be used for calls in kernel context.
 * tfw_apm_stats_bh() should be used for calls in user context.
 */
#define __tfw_apm_stats_body(apmdata, pstats, fn_lock, fn_unlock)	\
	int rdidx, seq = pstats->seq;					\
	TfwApmData *data = apmdata;					\
	TfwApmSEnt *asent;						\
									\
	BUG_ON(!apmdata);						\
									\
	smp_mb__before_atomic();					\
	rdidx = (unsigned int)atomic_read(&data->stats.rdidx) % 2;	\
	asent = &data->stats.asent[rdidx];				\
									\
	fn_lock(&asent->rwlock);					\
	memcpy(pstats->val, asent->pstats.val,				\
	       pstats->psz * sizeof(pstats->val[0]));			\
	pstats->min = asent->pstats.min;				\
	pstats->max = asent->pstats.max;				\
	pstats->avg = asent->pstats.avg;				\
	fn_unlock(&asent->rwlock);					\
	pstats->seq = rdidx;						\
									\
	return (seq != rdidx);

int
tfw_apm_stats_bh(void *apmdata, TfwPrcntlStats *pstats)
{
	__tfw_apm_stats_body(apmdata, pstats, read_lock_bh, read_unlock_bh);
}

int
tfw_apm_stats(void *apmdata, TfwPrcntlStats *pstats)
{
	__tfw_apm_stats_body(apmdata, pstats, read_lock, read_unlock);
}

/*
 * Verify that an APM Stats user using the same set of percentiles.
 *
 * Note: This module uses a single set of percentiles for all servers.
 * All APM Stats users must use the same set of percentiles.
 */
int
tfw_apm_pstats_verify(TfwPrcntlStats *pstats)
{
	int i;

	if (pstats->psz != ARRAY_SIZE(tfw_pstats_ith))
		return 1;
	for (i = 0; i < pstats->psz; ++i)
		if (pstats->ith[i] != tfw_pstats_ith[i])
			return 1;
	return 0;
}

static inline void
__tfw_apm_update(TfwApmRBuf *rbuf, unsigned long jtstamp, unsigned int rtt)
{
	int centry = (jtstamp / tfw_apm_jtmintrvl) % rbuf->rbufsz;
	unsigned long jtmistart = jtstamp - (jtstamp % tfw_apm_jtmintrvl);
	TfwApmRBEnt *crbent = &rbuf->rbent[centry];

	tfw_apm_rbent_checkreset(crbent, jtmistart);
	tfw_stats_update(&crbent->pcntrng, rtt, &rbuf->slock);
}

void
tfw_apm_update(void *apmdata, unsigned long jtstamp, unsigned long jrtt)
{
	unsigned int rtt = jiffies_to_msecs(jrtt);

	BUG_ON(!apmdata);
	/*
	 * APM stats can't handle response times that are greater than
	 * the maximum value possible for TfwPcntCtl{}->end. Currently
	 * the value is USHRT_MAX which is about 65 secs in milliseconds.
	 */
	if (likely(rtt < (1UL << FIELD_SIZEOF(TfwPcntCtl, end) * 8)))
		__tfw_apm_update(&((TfwApmData *)apmdata)->rbuf, jtstamp, rtt);
}

/*
 * Destroy the specified APM ring buffer.
 */
void
tfw_apm_destroy(void *apmdata)
{
	TfwApmData *data = apmdata;

	if (!data)
		return;
	clear_bit(TFW_APM_DATA_F_REARM, &data->flags);
	smp_mb__after_atomic();
	del_timer_sync(&data->timer);

	kfree(data);
}

/*
 * Initialize a ring buffer entry.
 */
static inline void
tfw_apm_rbent_init(TfwApmRBEnt *rbent, unsigned long jtmistamp)
{
	memcpy(rbent->pcntrng.ctl, tfw_rngctl_init, sizeof(rbent->pcntrng.ctl));
	__tfw_apm_rbent_reset(rbent, jtmistamp);
}

/*
 * Create and initialize an APM ring buffer for a server.
 */
void *
tfw_apm_create(void)
{
	TfwApmData *data;
	TfwApmRBEnt *rbent;
	int i, size;
	unsigned int *val[2];
	int rbufsz = tfw_apm_tmwscale;
	int psz = ARRAY_SIZE(tfw_pstats_ith);

	if (!tfw_apm_tmwscale) {
		TFW_ERR("Late initialization of 'apm_stats' option\n");
		return NULL;
	}

	/* Keep complete stats for the full time window. */
	size = sizeof(TfwApmData) + rbufsz * sizeof(TfwApmRBEnt)
				  + 2 * psz * sizeof(unsigned int);
	if ((data = kzalloc(size, GFP_ATOMIC)) == NULL)
		return NULL;

	/* Set up memory areas. */
	rbent = (TfwApmRBEnt *)(data + 1);
	val[0] = (unsigned int *)(rbent + rbufsz);
	val[1] = (unsigned int *)(val[0] + psz);

	data->rbuf.rbent = rbent;
	data->rbuf.rbufsz = rbufsz;

	data->stats.asent[0].pstats.ith = tfw_pstats_ith;
	data->stats.asent[0].pstats.val = val[0];
	data->stats.asent[0].pstats.psz = psz;

	data->stats.asent[1].pstats.ith = tfw_pstats_ith;
	data->stats.asent[1].pstats.val = val[1];
	data->stats.asent[1].pstats.psz = psz;

	/* Initialize data. */
	for (i = 0; i < rbufsz; ++i)
		tfw_apm_rbent_init(&rbent[i], 0);
	spin_lock_init(&data->rbuf.slock);

	rwlock_init(&data->stats.asent[0].rwlock);
	rwlock_init(&data->stats.asent[1].rwlock);
	atomic_set(&data->stats.rdidx, 0);

	/* Start the timer for the percentile calculation. */
	set_bit(TFW_APM_DATA_F_REARM, &data->flags);
	setup_timer(&data->timer, tfw_apm_pstats_fn, (unsigned long)data);
	mod_timer(&data->timer, jiffies + TFW_APM_TIMER_TIMEOUT);

	return data;
}

#define TFW_APM_MIN_TMWSCALE	1	/* Minimum time window scale. */
#define TFW_APM_MAX_TMWSCALE	50	/* Maximum time window scale. */
#define TFW_APM_DEF_TMWSCALE	5	/* Default time window scale. */

#define TFW_APM_MIN_TMWINDOW	60	/* Minimum time window (secs). */
#define TFW_APM_MAX_TMWINDOW	3600	/* Maximum time window (secs). */
#define TFW_APM_DEF_TMWINDOW	300	/* Default time window (secs). */

#define TFW_APM_MIN_TMINTRVL	5	/* Minimum time interval (secs). */

static int
tfw_apm_cfg_start(void)
{
	unsigned int jtmwindow;

	if (!tfw_apm_jtmwindow)
		tfw_apm_jtmwindow = TFW_APM_DEF_TMWINDOW;
	if (!tfw_apm_tmwscale)
		tfw_apm_tmwscale = TFW_APM_DEF_TMWSCALE;

	if ((tfw_apm_jtmwindow < TFW_APM_MIN_TMWINDOW)
	    || (tfw_apm_jtmwindow > TFW_APM_MAX_TMWINDOW))
	{
		TFW_ERR("apm_stats: window: value '%d' is out of limits.\n",
			tfw_apm_jtmwindow);
		return -EINVAL;
	}
	if ((tfw_apm_tmwscale < TFW_APM_MIN_TMWSCALE)
	    || (tfw_apm_tmwscale > TFW_APM_MAX_TMWSCALE))
	{
		TFW_ERR("apm_stats: scale: value '%d' is out of limits.\n",
			tfw_apm_tmwscale);
		return -EINVAL;
	}

	/* Enforce @tfw_apm_tmwscale to be at least 2. */
	if (tfw_apm_tmwscale == 1)
		tfw_apm_tmwscale = 2;

	jtmwindow = msecs_to_jiffies(tfw_apm_jtmwindow * 1000);
	tfw_apm_jtmintrvl = jtmwindow / tfw_apm_tmwscale
			    + !!(jtmwindow % tfw_apm_tmwscale);

	if (tfw_apm_jtmintrvl < TFW_APM_MIN_TMINTRVL) {
		TFW_ERR("apm_stats window=%d scale=%d: scale is too long.\n",
			tfw_apm_jtmwindow, tfw_apm_tmwscale);
		return -EINVAL;
	}
	tfw_apm_jtmwindow = tfw_apm_jtmintrvl * tfw_apm_tmwscale;

	return 0;
}

/**
 * Cleanup the configuration values when when all server groups are stopped
 * and the APM timers are deleted.
 */
static void
tfw_apm_cfg_cleanup(TfwCfgSpec *cs)
{
	tfw_apm_jtmwindow = tfw_apm_jtmintrvl = tfw_apm_tmwscale = 0;
}

static int
tfw_handle_apm_stats(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int i, r;
	const char *key, *val;

	if (ce->val_n) {
		TFW_ERR_NL("%s: Arguments must be a key=value pair.\n",
			   cs->name);
		return -EINVAL;
	}
	if (!ce->attr_n) {
		TFW_WARN_NL("%s: arguments missing, using default values.\n",
			    cs->name);
		return 0;
	}
	TFW_CFG_ENTRY_FOR_EACH_ATTR(ce, i, key, val) {
		if (!strcasecmp(key, "window")) {
			if ((r = tfw_cfg_parse_int(val, &tfw_apm_jtmwindow)))
				return r;
		} else if (!strcasecmp(key, "scale")) {
			if ((r = tfw_cfg_parse_int(val, &tfw_apm_tmwscale)))
				return r;
		} else {
			TFW_ERR_NL("%s: unsupported argument: '%s=%s'.\n",
				   cs->name, key, val);
			return -EINVAL;
		}
	}

	return 0;
}

static TfwCfgSpec tfw_apm_cfg_specs[] = {
	{
		"apm_stats", NULL,
		tfw_handle_apm_stats,
		.allow_none = true,
		.allow_repeat = false,
		.cleanup  = tfw_apm_cfg_cleanup,
	},
	{}
};

TfwCfgMod tfw_apm_cfg_mod = {
	.name  = "apm",
	.start = tfw_apm_cfg_start,
	.specs = tfw_apm_cfg_specs,
};
