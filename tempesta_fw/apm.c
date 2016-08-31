/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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
 *
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
 * @__atomic	- atomic control handler to update all control fields
 * 		  above atomically with a single write operation;
 * @total_cnt	- global hits counter for all ranges;
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
	atomic64_t	total_cnt;
	unsigned long	__padding[TFW_STATS_RLAST];
	atomic_t	cnt[TFW_STATS_RANGES][TFW_STATS_BCKTS];
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
 *
 * The leftmost bound is fixed to 1ms. The rightmost bound is only growing
 * to handle large values. So the adjustment may either increase the gaps
 * between ranges by decreasing a range order and moving left range bounds,
 * or decrease the gaps by increasing a range order and moving right range
 * bounds. I.e. ranges worm to the right and the algorithm converges at the
 * largest response time faced.
 */
static void
tfw_stats_adjust(TfwPcntRanges *rng, int r, spinlock_t *spinlock)
{
	TfwPcntCtl pc;
	unsigned long i, cnt = 0, sum = 0, max = 0, i_max = 0;

	if (!spin_trylock(spinlock))
		return; /* The ranges and the stats are being adjusted. */

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
		goto out;

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
		goto out;
	pc.atomic = rng->ctl[r].atomic;
	if (likely(pc.order)) {
		__range_shrink_left(rng, &pc, r);
	}
out:
	spin_unlock(spinlock);
}

/**
 * Update server response time statistic.
 * @r_time is in milliseconds (1/HZ second), use jiffies to get it.
 *
 * Can be ran concurrently w/ tfw_stats_adjust(), so the counter to update
 * is decided by the range control handlers read at the start. During the
 * execution of the function the control handlers may be changed, and a
 * wrong bucket and/or range may be updated. That's acceptable in our model.
 * We only care about correct array indexing.
 */
static void
tfw_stats_update(TfwPcntRanges *rng, unsigned int r_time, spinlock_t *spinlock)
{
	TfwPcntCtl pc3, pc2 = { .atomic = rng->ctl[2].atomic };

	atomic64_inc(&rng->total_cnt);

	/* Binary search of an appropriate range. */
	if (r_time <= pc2.end) {
		TfwPcntCtl pc0, pc1 = { .atomic = rng->ctl[1].atomic };
		if (pc1.end < r_time) {
			atomic_inc(__rng(&pc2, rng->cnt[2], r_time));
			tfw_stats_adjust(rng, 2, spinlock);
			return;
		}

		pc0.atomic = rng->ctl[0].atomic;
		BUG_ON(pc0.begin != 1); /* left bound is never moved */
		if (pc0.end < r_time) {
			atomic_inc(__rng(&pc1, rng->cnt[1], r_time));
			tfw_stats_adjust(rng, 1, spinlock);
			return;
		}
		atomic_inc(__rng(&pc0, rng->cnt[0], r_time));
		tfw_stats_adjust(rng, 0, spinlock);
		return;
	}

	pc3.atomic = rng->ctl[3].atomic;
	if (unlikely(r_time > pc3.end)) {
		tfw_stats_extend(rng, r_time);
		pc3.atomic = rng->ctl[3].atomic;
	}
	atomic_inc(__rng(&pc3, rng->cnt[3], r_time));
	tfw_stats_adjust(rng, 3, spinlock);
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
 * @jtmistamp	- The time the ring buffer entry has been started, in jiffies.
 * @reset	- The entry can be reset by one thread at a time.
 * @lock	- The lock to adjust the ranges of response times.
 */
typedef struct {
	TfwPcntRanges	pcntrng;
	unsigned long	jtmistamp;
	atomic_t	reset;
	spinlock_t	spinlock;
} TfwApmRBEnt;

/*
 * The ring buffer contol structure.
 * This is a supporting structure used in the calculation of percentiles.
 * Also it keeps related data that are useful in making decisions on the
 * recalculation of percentiles.
 * @ctlent	- An array of pointers to the response time ranges data.
 * @centry_ctl	- A copy of response time ranges of the current entry.
 * @fentry_ctl	- A copy of response time ranges of the first entry.
 * @jtmwstamp	- The start of the time window the percentiles are for.
 * @entry_cnt	- The number of hits in the current buffer ring entry.
 * @total_cnt	- The number of hits within the current time window.
 */

typedef struct {
	TfwPcntCtl	**ctlent;
	TfwPcntCtl	centry_ctl[TFW_STATS_RANGES];
	TfwPcntCtl	fentry_ctl[TFW_STATS_RANGES];
	unsigned long	jtmwstamp;
	unsigned long	entry_cnt;
	unsigned long	total_cnt;
} TfwApmRBCtl;

/*
 * The ring buffer structure.
 * @rbent	- Array of ring buffer entries.
 * @rbufsz	- The size of @rbent.
 */
typedef struct {
	TfwApmRBEnt	*rbent;
	int		rbufsz;
} TfwApmRBuf;

/*
 * The percentiles data structure.
 * Keeps the latest calculated percentiles.
 * @percentile	- Array of percentiles.
 * @prcntlsz	- The size of @percentile.
 * @flags	- Various flags, protected by @rwlock.
 * @rwlock	- Protect updates.
 */
#define TFW_APM_DATA_F_SAMEOLD	0x0001	/* The values unchanged. */

typedef struct {
	Percentile	*percentile;
	unsigned int	prcntlsz;
	unsigned int	flags;
	rwlock_t	rwlock;
} TfwApmPrcntl;

/*
 * The stats data structure.
 * There's only one updater that runs on timer and calculates the latest
 * percentiles. There may be multiple readers of the latest percentiles.
 * Readers read the latest percentiles at @prcntl[@rdidx % 2]. The writer
 * writes the new percentiles to @prcntl[(@rdidx + 1) % 2], and then
 * increments @rdidx. The reading and writing is protected by a rwlock.
 * @prcntl	- The percentiles for reading/writing (flip-flop manner).
 * @rdidx	- The current index in @prcntl for readers.
 */
typedef struct {
	TfwApmPrcntl	prcntl[2];
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
 * @rblst	- The list of ring buffer entries used in the calculation.
 * @stats	- The latest percentiles.
 * @timer	- The periodic timer handle.
 * @flags	- The atomic flags (see below).
 */
#define TFW_APM_DATA_F_REARM	0x0001		/* Re-arm the timer. */
#define TFW_APM_TIMER_TIMEOUT	(HZ)		/* The timer periodicity. */

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

/*
 * A superset of percentiles for all users. Note that 1%, 50%, and
 * 99% percentiles are used to tell the minimum, the median, and the
 * maximum values correspondingly.
 */
static const Percentile __read_mostly tfw_apm_prcntl[] = {
	{1}, {50}, {75}, {90}, {95}, {99}
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

static void
__tfw_apm_state_next(TfwPcntRanges *rng, TfwPcntCtl *ctl, TfwApmRBEState *st)
{
	int i = st->i, r, b;
	unsigned short rtime;

	for (r = i / TFW_STATS_BCKTS; r < TFW_STATS_RANGES; ++r) {
		for (b = i % TFW_STATS_BCKTS; b < TFW_STATS_BCKTS; ++b, ++i) {
			if (!atomic_read(&rng->cnt[r][b]))
				continue;
			rtime = ctl[r].begin + (b << ctl[r].order);
			__tfw_apm_state_set(st, rtime, i, r, b);
			return;
		}
	}
	__tfw_apm_state_set(st, USHRT_MAX, i, r, b);
}

static void
tfw_apm_state_next(TfwPcntRanges *rng, TfwPcntCtl *ctl, TfwApmRBEState *st)
{
	/* See if there're no more buckets. */
	if (st->i >= TFW_STATS_TOTAL_BCKTS)
		return;
	++st->i;
	__tfw_apm_state_next(rng, ctl, st);
}

/*
 * Calculate the latest percentiles from the current stats data.
 *
 * Note that a race condition exists due to mostly lockless nature of
 * the algorithm that runs concurently with stats updates. That makes
 * it possible for the algorithm to complete prematurely. When ranges
 * are shrunk or extended, the response time counter values may get
 * redistributed to the part of a range that had been counted already
 * in the calculation. In that case the algorithm may never reach the
 * target hits count value. That's acceptable in this model.
 *
 * The other issue is that after the bucket counters are redistrubuted
 * when a range is shrunk or extended, some individual updates may be
 * lost. The sum of all counters in all ranges and buckets then starts
 * to be less than the value of total_cnt. The percentiles calculation
 * is based on total_cnt. Again, in that case the algorithm may never
 * reach the target hits count value, and so it would exit prematurely.
 *
 * Returns the number of percentile values that have been filled.
 */
static int
tfw_apm_prnctl_calc(TfwApmRBuf *rbuf, TfwApmRBCtl *rbctl, TfwApmPrcntl *prcntl)
{
	int i, p;
	unsigned long cnt = 0, pval[prcntl->prcntlsz];
	TfwApmRBEState st[rbuf->rbufsz];
	TfwPcntRanges *pcntrng;
	TfwApmRBEnt *rbent = rbuf->rbent;
	TfwPcntCtl **ctlent = rbctl->ctlent;

	for (i = 0; i < rbuf->rbufsz; i++) {
		__tfw_apm_state_set(&st[i], ctlent[i][0].begin, 0, 0, 0);
		__tfw_apm_state_next(&rbent[i].pcntrng, ctlent[i], &st[i]);
	}
	/* The number of items to collect for each percentile. */
	for (i = 0, p = 0; i < prcntl->prcntlsz; ++i) {
		pval[i] = rbctl->total_cnt * prcntl->percentile[i].ith / 100;
		if (!pval[i])
			prcntl->percentile[p++].val = 0;
	}
	while (p < prcntl->prcntlsz) {
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
			tfw_apm_state_next(pcntrng, ctlent[i], &st[i]);
		}
		for ( ; p < prcntl->prcntlsz && pval[p] <= cnt; ++p)
			prcntl->percentile[p].val = v_min;
	}

	return p;
}

static inline void
tfw_apm_rngctl_copy(TfwPcntCtl *ctl, TfwApmRBEnt *crbent)
{
	spin_lock(&crbent->spinlock);
	memcpy(ctl, crbent->pcntrng.ctl, TFW_STATS_RANGES * sizeof(TfwPcntCtl));
	spin_unlock(&crbent->spinlock);
}

/*
 * Reset a ring buffer entry.
 * Note that the ranges are not reset. As Tempesta runs the ranges
 * are adjusted to reflect the actual response time values.
 */
static inline void
__tfw_apm_rbent_reset(TfwApmRBEnt *crbent, unsigned long jtmistamp)
{
	memset(crbent->pcntrng.cnt, 0, sizeof(crbent->pcntrng.cnt));
	atomic64_set(&crbent->pcntrng.total_cnt, 0);
	crbent->jtmistamp = jtmistamp;
	smp_mb__before_atomic();
	atomic_set(&crbent->reset, 1);
}

/*
 * Reset a ring buffer entry if it needs to be reused. Only one thread
 * proceeds to reset the entry. While the entry is being reset a number
 * of stats updates is lost. That's acceptable.
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
 * Build a new list of ring buffer entries for the calculation of
 * percentiles. Take care of @entry_cnt, @total_cnt, and jtmwstamp
 * values that are used in optimizations.
 */
static void
tfw_apm_rbctl_buildnew(TfwApmData *data, int centry, unsigned long jtmwstart)
{
	int i, end, fentry, ientrymod;
	unsigned long total_cnt = 0;
	TfwApmRBuf *rbuf = &data->rbuf;
	TfwApmRBCtl *rbctl = &data->rbctl;

	/*
	 * Copy @ctl data for the current (last) entry and the first
	 * entry in the time window. These are the entries that may
	 * be active while the percentiles are calculated. All other
	 * entries are inactive. Just set the pointer at @ctl data,
	 * and get the sum of @total_cnt.
	 */
	fentry = (centry + 1) % rbuf->rbufsz;
	ientrymod = fentry + 1 + rbuf->rbufsz;

	for (i = 0, end = rbuf->rbufsz - 2; i < end; ++i, ++ientrymod) {
		int ientry = ientrymod % rbuf->rbufsz;
		TfwApmRBEnt *irbent = &rbuf->rbent[ientry];
		rbctl->ctlent[ientry] = irbent->pcntrng.ctl;
		total_cnt += atomic64_read(&irbent->pcntrng.total_cnt);
	}

	tfw_apm_rngctl_copy(rbctl->centry_ctl, &rbuf->rbent[centry]);
	rbctl->ctlent[centry] = rbctl->centry_ctl;
	total_cnt += atomic64_read(&rbuf->rbent[centry].pcntrng.total_cnt);

	tfw_apm_rngctl_copy(rbctl->fentry_ctl, &rbuf->rbent[fentry]);
	rbctl->ctlent[fentry] = rbctl->fentry_ctl;
	total_cnt += atomic64_read(&rbuf->rbent[fentry].pcntrng.total_cnt);

	rbctl->entry_cnt = 0;
	rbctl->total_cnt = total_cnt;
	rbctl->jtmwstamp = jtmwstart;

	TFW_DBG3("%s: Full rebuild: centry [%d] fentry [%d] total_cnt [%lu]\n",
		 __func__, centry, fentry, total_cnt);
}

/*
 * Update the current list of ring buffer entries for the calculation
 * of percentiles. Use optimizations to avoid the recalculation when
 * that is possible, or to avoid a full rebuild of the current list.
 * Build a new list when there's no other choice. Maintain current
 * values of @entry_cnt, @total_cnt, and jtmwstamp that are used in
 * optimizations.
 *
 * Return true if recalculation of percentiles is required.
 * Return false if the percentile values don't need the recalculation.
 */
static bool
tfw_apm_rbctl_update(TfwApmData *data)
{
	TfwApmRBuf *rbuf = &data->rbuf;
	TfwApmRBCtl *rbctl = &data->rbctl;
	unsigned long jtmnow = jiffies;
	unsigned long jtmwstart, jtmistart, entry_cnt;
	int centry = (jtmnow / tfw_apm_jtmintrvl) % rbuf->rbufsz;
	TfwApmRBEnt *crbent = &rbuf->rbent[centry];

	/* The start of the current time interval. */
	jtmistart = jtmnow - (jtmnow % tfw_apm_jtmintrvl);
	/* The start of the current time window. */
	jtmwstart = jtmistart - tfw_apm_jtmwindow;

	/*
	 * If the latest percentiles are for a different time window,
	 * then a recalculation is in order.
	 */
	if (unlikely(rbctl->jtmwstamp != jtmwstart)) {
		tfw_apm_rbent_checkreset(crbent, jtmistart);
		tfw_apm_rbctl_buildnew(data, centry, jtmwstart);
		return true;
	}

	/* The latest percentiles are for the current time window.
	 * In some cases a recalculation is not required. In some
	 * other cases the recalculation set up can be simpler.
	 */

	/* Nothing to do if there were no stats updates. */
	entry_cnt = atomic64_read(&crbent->pcntrng.total_cnt);
	if (rbctl->entry_cnt == entry_cnt)
		return false;
	BUG_ON(rbctl->entry_cnt > entry_cnt);

	/* Update the current entry's ranges data. */
	BUG_ON(rbctl->ctlent[centry] != rbctl->centry_ctl);
	tfw_apm_rngctl_copy(rbctl->centry_ctl, crbent);

	/* Update the counts incrementally. */
	rbctl->total_cnt += entry_cnt - rbctl->entry_cnt;
	rbctl->entry_cnt = entry_cnt;

	TFW_DBG3("%s: Incremental update: centry [%d] total_cnt [%lu]\n",
		 __func__, centry, rbctl->total_cnt);

	return true;
}

/*
 * Calculate the latest percentiles if necessary.
 *
 * Return the number of percentile values that have been filled
 * if potentially new percentile values were calculated.
 * Return 0 if the percentile values didn't need the recalculation.
 */
static int
__tfw_apm_calc(TfwApmData *data, TfwApmPrcntl *prcntl)
{
	if (!tfw_apm_rbctl_update(data))
		return 0;

	return tfw_apm_prnctl_calc(&data->rbuf, &data->rbctl, prcntl);
}

/*
 * Calculate the latest percentiles if necessary.
 *
 * Return 1 if potentially new percentile values were calculated.
 * Return 0 if the percentile values didn't need recalculation.
 * Set the flag to indicate if potentially new values were calculated.
 */
static int
tfw_apm_calc(TfwApmData *data)
{
	int nfilled, wridx;
	Percentile percentile[ARRAY_SIZE(tfw_apm_prcntl)];
	TfwApmPrcntl wrkprcntl = { percentile, ARRAY_SIZE(percentile) };
	TfwApmPrcntl *prcntl;

	memcpy(percentile, tfw_apm_prcntl, sizeof(tfw_apm_prcntl));

	nfilled = __tfw_apm_calc(data, &wrkprcntl);

	wridx = ((unsigned int)atomic_read(&data->stats.rdidx) + 1) % 2;
	prcntl = &data->stats.prcntl[wridx];

	write_lock(&prcntl->rwlock);
	if (!nfilled) {
		TFW_DBG3("%s: Percentile values DID NOT change.\n", __func__);
		prcntl->flags |= TFW_APM_DATA_F_SAMEOLD;
	} else {
		TFW_DBG3("%s: Percentile values may have changed.\n", __func__);
		prcntl->flags &= ~TFW_APM_DATA_F_SAMEOLD;
		if (unlikely(nfilled < prcntl->prcntlsz)) {
			int val = percentile[nfilled - 1].val;
			while (nfilled < prcntl->prcntlsz)
				prcntl->percentile[nfilled++].val = val;
		}
		memcpy(prcntl->percentile, percentile,
		       prcntl->prcntlsz * sizeof(Percentile));
		atomic_inc(&data->stats.rdidx);
	}
	write_unlock(&prcntl->rwlock);

	return nfilled;
}

/*
 * Calculate the latest percentiles if necessary.
 * Runs periodically on timer. 
 */
static void
tfw_apm_prcntl_fn(unsigned long fndata)
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
 */
int
tfw_apm_stats(void *apmdata, Percentile *percentile, size_t prcntlsz)
{
	int ret, rdidx;
	TfwApmData *data = apmdata;
	TfwApmPrcntl *prcntl;

	BUG_ON(!apmdata);

	rdidx = (unsigned int)atomic_read(&data->stats.rdidx) % 2;
	prcntl = &data->stats.prcntl[rdidx];

	read_lock(&prcntl->rwlock);
	memcpy(percentile, prcntl->percentile, prcntlsz * sizeof(Percentile));
	ret = !(prcntl->flags & TFW_APM_DATA_F_SAMEOLD);
	read_unlock(&prcntl->rwlock);

	return ret;
}

/*
 * Verify that an APM Stats user using the same set of percentiles.
 *
 * Note: This module uses a single set of percentiles for all servers.
 * All APM Stats users must use the same set of percentiles.
 */
int
tfw_apm_percentile_verify(Percentile *prcntl, size_t prcntlsz)
{
	int i;

	if (prcntlsz != ARRAY_SIZE(tfw_apm_prcntl))
		return 1;
	for (i = 0; i < prcntlsz; ++i)
		if (prcntl[i].ith != tfw_apm_prcntl[i].ith)
			return 1;
	return 0;
}

static inline void
__tfw_apm_update(TfwApmRBuf *rbuf, unsigned long jtstamp, unsigned long jrtime)
{
	int centry = (jtstamp / tfw_apm_jtmintrvl) % rbuf->rbufsz;
	unsigned long jtmistart = jtstamp - (jtstamp % tfw_apm_jtmintrvl);
	TfwApmRBEnt *crbent = &rbuf->rbent[centry];

	tfw_apm_rbent_checkreset(crbent, jtmistart);
	tfw_stats_update(&crbent->pcntrng, jiffies_to_msecs(jrtime),
			 &crbent->spinlock);
}

void
tfw_apm_update(void *apmdata, unsigned long jtstamp, unsigned long jrtime)
{
	BUG_ON(!apmdata);
	__tfw_apm_update(&((TfwApmData *)apmdata)->rbuf, jtstamp, jrtime);
}

/*
 * Destroy the specified APM ring buffer.
 */
void
tfw_apm_destroy(void *apmdata)
{
	TfwApmData *data = apmdata;

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
	TfwPcntCtl **ctlent;
	Percentile *percentile[2];
	int i, size;
	int rbufsz = tfw_apm_tmwscale;
	int prcntlsz = ARRAY_SIZE(tfw_apm_prcntl);

	if (!tfw_apm_tmwscale) {
		TFW_ERR("Late unitialization of `apm_stats` option\n");
		return NULL;
	}

	/* Keep complete stats for the full time window. */
	size = sizeof(TfwApmData) + rbufsz * sizeof(TfwApmRBEnt)
				  + rbufsz * sizeof(TfwPcntCtl *)
				  + 2 * sizeof(tfw_apm_prcntl);
	if ((data = kzalloc(size, GFP_ATOMIC)) == NULL)
		return NULL;

	rbent = (TfwApmRBEnt *)(data + 1);
	ctlent = (TfwPcntCtl **)(rbent + rbufsz);
	percentile[0] = (Percentile *)(ctlent + rbufsz);
	percentile[1] = (Percentile *)(percentile[0] + prcntlsz);

	data->rbuf.rbent = rbent;
	data->rbuf.rbufsz = rbufsz;

	data->rbctl.ctlent = ctlent;

	data->stats.prcntl[0].percentile = percentile[0];
	data->stats.prcntl[0].prcntlsz = prcntlsz;

	data->stats.prcntl[1].percentile = percentile[1];
	data->stats.prcntl[1].prcntlsz = prcntlsz;

	for (i = 0; i < rbufsz; ++i) {
		spin_lock_init(&rbent[i].spinlock);
		tfw_apm_rbent_init(&rbent[i], 0);
	}

	memcpy(percentile[0], tfw_apm_prcntl, sizeof(tfw_apm_prcntl));
	memcpy(percentile[1], tfw_apm_prcntl, sizeof(tfw_apm_prcntl));

	rwlock_init(&data->stats.prcntl[0].rwlock);
	rwlock_init(&data->stats.prcntl[1].rwlock);
	atomic_set(&data->stats.rdidx, 0);

	set_bit(TFW_APM_DATA_F_REARM, &data->flags);
	smp_mb__after_atomic();
	setup_timer(&data->timer, tfw_apm_prcntl_fn, (unsigned long)data);
	mod_timer(&data->timer, jiffies + TFW_APM_TIMER_TIMEOUT);

	return data;
}

#define TFW_APM_MIN_TMWSCALE	1	/* Minimal time window scale. */
#define TFW_APM_MAX_TMWSCALE	50	/* Maximum time window scale. */
#define TFW_APM_DEF_TMWSCALE	5	/* Default time window scale. */

#define TFW_APM_MIN_TMWINDOW	60	/* Minimal time window (secs). */
#define TFW_APM_MAX_TMWINDOW	3600	/* Maximum time window (secs). */
#define TFW_APM_DEF_TMWINDOW	300	/* Default time window (secs). */

#define TFW_APM_MIN_TMINTRVL	5	/* Minimal time interval (secs). */

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

static void
tfw_apm_cfg_stop(void)
{
	tfw_apm_jtmwindow = tfw_apm_jtmintrvl = tfw_apm_tmwscale = 0;
}

static int
tfw_handle_apm_stats(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int i, r;
	const char *key, *val;

	if (ce->val_n) {
		TFW_ERR("%s: Arguments must be a key=value pair.\n", cs->name);
		return -EINVAL;
	}
	if (!ce->attr_n) {
		TFW_WARN("%s: arguments missing, using default values.\n",
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
			TFW_ERR("%s: unsupported argument: '%s=%s'.\n",
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
	},
	{}
};

TfwCfgMod tfw_apm_cfg_mod = {
        .name  = "apm",
        .start = tfw_apm_cfg_start,
        .stop  = tfw_apm_cfg_stop,
        .specs = tfw_apm_cfg_specs,
};
