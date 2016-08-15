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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/stringify.h>
#include <linux/sort.h>

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

static DEFINE_SPINLOCK(tfw_stats_sa_guard);

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
tfw_stats_adjust(TfwPcntRanges *rng, int r)
{
	TfwPcntCtl pc;
	unsigned long i, cnt = 0, sum = 0, max = 0, i_max = 0;

	if (!spin_trylock(&tfw_stats_sa_guard))
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
	if (likely(max <= sum * 2 / cnt))
		/* outlier means (max < avg * 2) */
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
	pc.atomic = rng->ctl[r].atomic;
	if (unlikely(!pc.order))
		goto out;
	__range_shrink_left(rng, &pc, r);

out:
	spin_unlock(&tfw_stats_sa_guard);
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
tfw_stats_update(TfwPcntRanges *rng, unsigned int r_time)
{
	TfwPcntCtl pc3, pc2 = { .atomic = rng->ctl[2].atomic };

	atomic64_inc(&rng->total_cnt);

	/* Binary search of an appropriate range. */
	if (r_time <= pc2.end) {
		TfwPcntCtl pc0, pc1 = { .atomic = rng->ctl[1].atomic };
		if (pc1.end < r_time) {
			atomic_inc(__rng(&pc2, rng->cnt[2], r_time));
			tfw_stats_adjust(rng, 2);
			return;
		}

		pc0.atomic = rng->ctl[0].atomic;
//		BUG_ON(pc0.begin != 1); /* left bound is never moved */
		if (pc0.end < r_time) {
			atomic_inc(__rng(&pc1, rng->cnt[1], r_time));
			tfw_stats_adjust(rng, 1);
			return;
		}
		atomic_inc(__rng(&pc0, rng->cnt[0], r_time));
		tfw_stats_adjust(rng, 0);
		return;
	}

	pc3.atomic = rng->ctl[3].atomic;
	if (unlikely(r_time > pc3.end)) {
		tfw_stats_extend(rng, r_time);
		pc3.atomic = rng->ctl[3].atomic;
	}
	atomic_inc(__rng(&pc3, rng->cnt[3], r_time));
	tfw_stats_adjust(rng, 3);
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
 * @pcntrng	Struct for response time data by the percentiles algorithm.
 * @jtstamp	Time the ring buffer entry has been started, in jiffies.
 * @reset	The entry can be reset by one thread at a time.
 */
typedef struct {
	TfwPcntRanges	pcntrng;
	unsigned long	jtstamp;
	atomic_t	reset;
} TfwApmRBufEntry;

/*
 * The ring buffer structure.
 * @rbent	Array of ring buffer entries.
 * @rbentsz	The size of @rbent.
 */
typedef struct {
	TfwApmRBufEntry *rbent;
	int		rbentsz;
} TfwApmRBuf;

/*
 * APM Data structure.
 * @rbuf	The ring buffer.
 */
typedef struct {
	TfwApmRBuf	rbuf;
} TfwApmData;

/*
 * Note: This structure is constructed to fit into 32-bit type. If
 * the basic constants of the algorithm change (see TFW_STATS_BCKTS,
 * TFW_STATS_RANGES), then this structure will need a revision.
 *
 * @rtmval	Response time value.
 * @intrvl	The interval number.
 * @range	The range number.
 * @bucket	The bucket number.
 */
typedef struct {
	u16	rtmval;
	u8	intrvl;
	u8	range  : 4;
	u8	bucket : 4;
} __attribute__((packed)) TfwPcntCalc;

/*
 * [1ms, 349ms] should be sufficient for almost any installation,
 * including cross atlantic.
 */
static const TfwPcntCtl __read_mostly pcntrng_ctl_init[TFW_STATS_RANGES] = {
	{{0, 1, 16}},
	{{1, 17, 47}},
	{{2, 48, 108}},
	{{4, 109, 349}}
};

static int tfw_apm_jtmwindow;		/* Time window in jiffies. */
static int tfw_apm_jtmintrvl;		/* Time interval in jiffies. */
static int tfw_apm_tmwscale;		/* Time window scale. */


static void
tfw_stats_calc(TfwPcntCalc *pcalc, size_t pcsz,
	       TfwPcntRanges **rnglst, size_t rlsz,
	       Percentile *pcntl, size_t plsz)
{
	int i, p = 0;
	unsigned long cnt = 0, total_cnt = 0;
	unsigned long pval[plsz];

	/* Total hits count in all interval entries. */
	for (i = 0; i < rlsz; ++i)
		total_cnt += atomic64_read(&rnglst[i]->total_cnt);
	if (unlikely(!total_cnt))
		return;

	/* The number of items to collect for each percentile. */
	for (i = 0; i < plsz; ++i) {
		pval[i] = total_cnt * pcntl[i].ith / 100;
		if (!pval[i])
			pcntl[p++].val = 0;
	}
	for (i = 0; i < pcsz; ++i) {
		TfwPcntCalc *pc = pcalc + i;
		cnt += atomic_read(&rnglst[pc->intrvl]->cnt[pc->range][pc->bucket]);
		for ( ; p < plsz && pval[p] <= cnt; ++p)
			pcntl[p].val = pc->rtmval;
	}
	BUG_ON (p < plsz);
}

/*
 * Consolidate and merge all entries in @rnglst for correct percentile
 * calculation.
 *
 * The ranges may be changed during the stats updates. Ranges within
 * a single entry are guaranteed to not intersect. However, ranges in
 * different entries may intersect. The intersecting ranges need to be
 * merged carefully and accurately.
 *
 * The algorithm is that all ranges are split into separate buckets.
 * Each bucket is a response time value and the number of hits. All
 * buckets are sorted by the response time value, so that buckets with
 * identical or close time values are placed together. This makes for
 * correct calculation of percentiles by consecutive summing of the
 * number of hits in these buckets.
 */
static int
tfw_apm_calc_cmp(const void *a, const void *b)
{
	const TfwPcntCalc *x = a, *y = b;

	if (x->rtmval > y->rtmval)
		return 1;
	if (x->rtmval < y->rtmval)
		return -1;
	return 0;
}

static int
tfw_apm_rngmerge(TfwPcntCalc *pcalc, TfwPcntRanges **rnglst, size_t rlsz)
{
	int i, r, b, pcsz;
	TfwPcntCtl pctl[TFW_STATS_RANGES];

	for (i = 0, pcsz = 0; i < rlsz; ++i) {
		spin_lock(&tfw_stats_sa_guard);
		for (r = 0; r < TFW_STATS_RANGES; ++r)
			pctl[r].atomic = rnglst[i]->ctl[r].atomic;
		spin_unlock(&tfw_stats_sa_guard);

		for (r = 0; r < TFW_STATS_RANGES; ++r) {
			for (b = 0; b < TFW_STATS_BCKTS; ++b) {
				if (!atomic_read(&rnglst[i]->cnt[r][b]))
					continue;
				pcalc[pcsz].intrvl = i;
				pcalc[pcsz].range = r;
				pcalc[pcsz].bucket = b;
				pcalc[pcsz++].rtmval =
					pctl[r].begin + (b << pctl[r].order);
			}
		}
	}
	sort(pcalc, pcsz, sizeof(TfwPcntCalc), tfw_apm_calc_cmp, NULL);

	return pcsz;
}

static int
tfw_apm_rnglst(TfwApmRBuf *rbuf, TfwPcntRanges **rnglst)
{
	TfwApmRBufEntry *rbent;
	unsigned long jmax = 0, jtmwstart;
	int i, imax = 0, rlsz = 0, i_rlsz;

	/*
	 * Find the entry with the maximim @jtstamp. That's the most
	 * recent entry. The entries that precede the current entry
	 * are used in the calculation of percentiles;
	 */
	for (i = 0; i < rbuf->rbentsz; ++i) {
		if (jmax < rbuf->rbent[i].jtstamp) {
			jmax = rbuf->rbent[i].jtstamp;
			imax = i;
		}
	}
	/*
	 * If the entry with the maximum @jstamp is the current active
	 * entry, then add it to the list of entries. Take care of the
	 * circular nature of the buffer.
	 */
	rlsz = tfw_apm_tmwscale;
	if (rbuf->rbent[imax].jtstamp >= jiffies - tfw_apm_jtmintrvl)
		rlsz++;
	imax += rbuf->rbentsz;
	/*
	 * Collect entries that are within the defined time window.
	 * Most recent entries are put first in the list, older entries
	 * are put last in the list. Take care of periods of inactivity.
	 */
	jtmwstart = jiffies - tfw_apm_jtmwindow;
	for (i = 0, i_rlsz = 0; i < rlsz; ++i, --imax) {
		rbent = &rbuf->rbent[imax % rbuf->rbentsz];
		if (rbent->jtstamp && (rbent->jtstamp >= jtmwstart))
			rnglst[i_rlsz++] = &rbent->pcntrng;
	}

	return i_rlsz;
}

static inline int
__tfw_apm_calc(TfwApmData *data, Percentile *pcntl, size_t plsz, TfwPool *pool)
{
	int size, rlsz, pcsz;
	TfwPcntCalc *pcalc;
	TfwPcntRanges *rnglst[tfw_apm_tmwscale + 1];

	rlsz = tfw_apm_rnglst(&data->rbuf, rnglst);
	BUG_ON(rlsz > tfw_apm_tmwscale + 1);

	size = rlsz * TFW_STATS_RANGES * TFW_STATS_BCKTS;
	if (pool)
		pcalc = tfw_pool_alloc(pool, size * sizeof(TfwPcntCalc));
	else
		pcalc = kmalloc(size * sizeof(TfwPcntCalc), GFP_KERNEL);
	if (!pcalc)
		return -ENOMEM;

	pcsz = tfw_apm_rngmerge(pcalc, rnglst, rlsz);
	BUG_ON(pcsz > size);

	tfw_stats_calc(pcalc, pcsz, rnglst, rlsz, pcntl, plsz);

	if (pool)
		tfw_pool_free(pool, pcalc, size * sizeof(TfwPcntCalc));
	else
		kfree(pcalc);

	return 0;
}

int
tfw_apm_calc(void *data, Percentile *pcntl, size_t plsz, TfwPool *pool)
{
	BUG_ON(!data);
	return __tfw_apm_calc((TfwApmData *)data, pcntl, plsz, pool);
}

/*
 * Destroy the specified APM ring buffer.
 */
void
tfw_apm_destroy(void *data)
{
	kfree(data);
}

/*
 * Initialize a ring buffer entry.
 */
static inline void
tfw_apm_rbent_init(TfwApmRBufEntry *rbent, unsigned long jtstamp)
{
	int i;

	memset(&rbent->pcntrng, 0, sizeof(TfwPcntRanges));
	for (i = 0; i < TFW_STATS_RANGES; ++i)
		rbent->pcntrng.ctl[i] = pcntrng_ctl_init[i];
	rbent->jtstamp = jtstamp;
	smp_mb__before_atomic();
	atomic_set(&rbent->reset, 1);
}

static inline void
__tfw_apm_update(TfwApmRBuf *rbuf, unsigned long jtstamp, unsigned long jrtime)
{
	int entry = (jtstamp / tfw_apm_jtmintrvl) % rbuf->rbentsz;
	TfwApmRBufEntry *rbent = &rbuf->rbent[entry];

	/*
	 * Reset a ring buffer entry if it needs to be reused. Only one
	 * thread proceeds to reset the entry. While the entry is being
	 * reset a number of stats updates is lost. That's acceptable.
	 */
	if (jtstamp - rbent->jtstamp > tfw_apm_jtmintrvl) {
		if (!atomic_dec_and_test(&rbent->reset))
			return;
		tfw_apm_rbent_init(rbent, jtstamp);
	}

	tfw_stats_update(&rbent->pcntrng, jiffies_to_msecs(jrtime));
}

void
tfw_apm_update(void *data, unsigned long jtstamp, unsigned long jrtime)
{
	BUG_ON(!data);
	__tfw_apm_update(&((TfwApmData *)data)->rbuf, jtstamp, jrtime);
}

/*
 * Create and initialize an APM ring buffer for a server.
 */
void *
tfw_apm_create(void)
{
	int i, size, rbentsz = tfw_apm_tmwscale + 2;
	TfwApmData *data;

	if (!tfw_apm_tmwscale) {
		TFW_ERR("Late unitialization of `apm_stats` option\n");
		return NULL;
	}

	/* Keep complete stats for the full time window. */
	size = sizeof(TfwApmData) + sizeof(TfwApmRBufEntry) * rbentsz;
	if ((data = kmalloc(size, GFP_ATOMIC)) == NULL)
		return NULL;

	data->rbuf.rbent = (TfwApmRBufEntry *)
			   ((char *)data + sizeof(TfwApmData));
	data->rbuf.rbentsz = rbentsz;

	for (i = 0; i < data->rbuf.rbentsz; ++i)
		tfw_apm_rbent_init(data->rbuf.rbent + i, 0);

	return data;
}

#define TFW_APM_MIN_TMWSCALE	1	/* Minimal time window scale. */
#define TFW_APM_MAX_TMWSCALE	256	/* Maximum time window scale. */
#define TFW_APM_DEF_TMWSCALE	5	/* Default time window scale. */

#define TFW_APM_MIN_TMWINDOW	1	/* Minimal time window (secs). */
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
