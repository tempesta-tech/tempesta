/*
 *		Tempesta FW
 *
 * Copyright (C) 2016-2025 Tempesta Technologies, Inc.
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
 * Prototype for fast percentiles calculation.
 */
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stringify.h>

#undef DEBUG
#if DBG_APM > 0
#define DEBUG DBG_APM
#endif
#include "lib/fault_injection_alloc.h"
#include "lib/str.h"
#include "apm.h"
#include "cfg.h"
#include "log.h"
#include "pool.h"
#include "http.h"

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
 * 4. Buckets must be dynamically rearranged since server response times
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
 *		  the time grows, so higher response times may be estimated
 *		  with less accuracy;
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
 * is placed on a separate cache line, and control handlers are also on their
 * own cache lines.
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
	char		__reset_from[0];
	unsigned long	tot_cnt;
	unsigned long	tot_val;
	unsigned int	min_val;
	unsigned int	max_val;
	unsigned long	cnt[TFW_STATS_RANGES][TFW_STATS_BCKTS];
	char		__reset_till[0];
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
	pc->end = pc->begin + TFW_STATS_RSPAN(pc->order);

	T_DBG3("  -- extend right bound of range %d to begin=%u order=%u"
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

	T_DBG3("  -- shrink left bound of range %d to begin=%u order=%u"
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
	unsigned long end;
	TfwPcntCtl *pc = &rng->ctl[TFW_STATS_RLAST];
	unsigned int sum, parts, units, shift, order = pc->order;

	BUILD_BUG_ON_NOT_POWER_OF_2(TFW_STATS_BCKTS);

	do {
		++order;
		end = pc->begin + TFW_STATS_RSPAN_UL(order);
	} while (end < r_time);

	/*
	 * It's conceivable that the value of pc->end was already near
	 * the upper end of the range that the data type could hold.
	 * As the value was extended to the next order it's conceivable
	 * that the new value exceeded the maximum for the data type.
	 * Considering that TfwPcntCtl{}->end is of type unsigned int,
	 * it's totally unimaginable that this situation may ever happen.
	 */
	BUG_ON(end >= (1UL << (sizeof_field(TfwPcntCtl, end) * 8)));
	pc->end = end;

	shift = min_t(unsigned int, order - pc->order, TFW_STATS_BCKTS_ORDER);
	units = 1 << shift;
	parts = TFW_STATS_BCKTS >> shift;

	pc->order = order;

	T_DBG3("  -- extend last range to begin=%u order=%u end=%u\n",
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

	T_DBG3("  -- range %d has an outlier %lu (avg=%lu total=%lu) at"
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

/*
 * Set the new maximum value.
 * Return true if the new value has been set.
 * Return false if the maximum value remained the same.
 */
static inline bool
tfw_stats_adj_max(TfwPcntRanges *rng, unsigned int r_time)
{
	if (r_time > rng->max_val) {
		rng->max_val = r_time;
		return true;
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
	if (r_time < rng->min_val) {
		bool ret = rng->min_val != UINT_MAX;
		rng->min_val = r_time;
		return ret;
	}
	return false;
}

/**
 * Update server response time statistic.
 * @r_time is in milliseconds (1/HZ second), use jiffies to get it.
 */
static void
tfw_stats_update(TfwPcntRanges *rng, unsigned int r_time)
{
	TfwPcntCtl *pc3, *pc2 = &rng->ctl[2];

	/* Binary search of an appropriate range. */
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
	/* Adjust min/max values. */
	if (!tfw_stats_adj_min(rng, r_time))
		tfw_stats_adj_max(rng, r_time);
	/* Add to @tot_val for AVG calculation. */
	rng->tot_val += r_time;
	++rng->tot_cnt;

	return;
}

/* Time granularity for HTTP codes accounting during health monitoring. */
#define HM_FREQ		10

/*
 * Structure for health monitor settings ('health_check').
 *
 * @list	- entry in list of all health monitors;
 * @name	- health monitor's name;
 * @url		- url for requests which will be used in health monitoring;
 * @urlsz	- length of @url string (without terminating zero);
 * @req		- full test request health monitoring;
 * @reqsz	- length of @req string (without terminating zero);
 * @crc32	- crc32 value for verification of response body checksum;
 * @codes	- pointer to HTTP response codes bitmap (signals that
 *		  backend server alive);
 * @tmt		- timeout between health monitoring requests;
 * @auto_crc	- flag for enabling of crc32 generation from first response;
 */
typedef struct {
	struct list_head	list;
	char			*name;
	char			*req;
	unsigned long		reqsz;
	char			*url;
	int			urlsz;
	u32			crc32;
	long			*codes;
	unsigned short		tmt;
	bool			auto_crc:1;
} TfwApmHM;

/*
 * Structure for monitoring settings of particular HTTP code
 * ('server_failover_http' or 'health_stat_server').
 *
 * @list	- entry in list of all monitored codes;
 * @tframe	- Time frame in seconds for @code accounting;
 * @limit	- allowed quantity of responses with @code in a @tframe period;
 * @code	- HTTP code; also wildcarded code values (of type 4*, 5* etc.)
 *		  are allowed during configuration, so in this field they will
 *		  have form of single-digit number (e.g. 4 or 5 respectively);
 */
typedef struct {
	struct list_head	list;
	unsigned short		tframe;
	unsigned short		limit;
	int			code;
} TfwApmHMCfg;

/*
 * History accounting record.
 *
 * @ts		- part of timeframe in granularity of HM_FREQ;
 * @resp	- amount responses counted in @ts interval;
 */
typedef struct {
	unsigned long		ts;
	unsigned int		resp;
} TfwApmHMHistory;

/*
 * Accounting entry for particular HTTP code.
 *
 * @history	- ring buffer of history records;
 * @hmcfg	- pointer to structure with settings for particular HTTP code;
 * @rsum	- current amount of responses from @history ring buffer;
 * @total	- total amount of responses during all the time;
 * @lock	- spinlock for synchronized work with @history buffer;
 */
typedef struct {
	TfwApmHMHistory		history[HM_FREQ];
	TfwApmHMCfg		*hmcfg;
	unsigned int		rsum;
	u64			total;
	spinlock_t		lock;
} TfwApmHMStats;

/*
 * Controller for whole health monitoring of backend server.
 *
 * @hm		- pointer to settings for specific health monitor;
 * @hmstats	- pointer to array of stat entries for all monitored HTTP codes;
 * @rcount	- current count of health monitoring requests (in @hm->tmt);
 * @jtmstamp	- time in jiffies of last @timer call (for procfs);
 * @timer	- timer for sending health monitoring request;
 * @rearm	- flag for graceful stopping of @timer;
 */
typedef struct {
	TfwApmHM		*hm;
	TfwApmHMStats		*hmstats;
	atomic64_t		rcount;
	unsigned long		jtmstamp;
	struct timer_list	timer;
	atomic_t		rearm;
	TfwServer		*srv;
} TfwApmHMCtl;

/* Entry for configuration of separate health monitors. */
static TfwApmHM		*tfw_hm_entry;
/*
 * Whether an HM config entry with an HTTP code 200 was created. We always want
 * to have information about the amount of 200 responses from servers,
 * regardless of the configuration.
 */
static bool		tfw_hm_cfg_200_created;
/* Entry for configuration of default 'auto' health monitor. */
static TfwApmHM		*tfw_hm_default;
/* Total count of monitored HTTP codes. */
static unsigned int	tfw_hm_codes_cnt;

static LIST_HEAD(tfw_hm_list);
static LIST_HEAD(tfw_hm_codes_list);

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
 *
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
 * The ring buffer structure.
 *
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
 * The ring buffer control structure.
 *
 * This is a supporting structure. It keeps related data that is useful
 * in making decisions on the need of recalculation of percentiles.
 *
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
 * The stats entry data structure.
 * Keeps the latest values of calculated percentiles.
 *
 * @pstats	- The percentile stats structure.
 * @seqlock	- Protect updates.
 */
typedef struct {
	TfwPrcntlStats	pstats;
	seqlock_t	seqlock;
} TfwApmSEnt;

/*
 * The stats data structure.
 *
 * There's only one updater that runs on timer. It calculates the latest
 * percentiles and updates the stored values. There are multiple readers
 * of the stored values. The stored values of the latest percentiles are
 * a shared resource that needs a lock to access. An array of two entries
 * is used to decrease the lock contention. Readers read the stored values
 * at @asent[@rdidx % 2]. The writer writes the new percentile values to
 * @asent[(@rdidx + 1) % 2], and then increments @rdidx. The reading and
 * the writing are protected by a seqlock.
 *
 * @asent	- The stats entries for reading/writing (flip-flop manner).
 * @rdidx	- The current index in @asent for readers.
 */
typedef struct {
	TfwApmSEnt	asent[2];
	atomic_t	rdidx;
} TfwApmStats;

/*
 * An update buffer entry that holds RTT data for updates.
 *
 * The value of @centry depends on @jtstamp that comes as part of data
 * for the update. Ideally, @jtstamp and @rtt would be stored instead
 * of @centry and @rtt. However, together they occupy more than 64 bits,
 * and it's highly desirable to read/write them in a single operation.
 *
 * @centry	- The entry number in the array of ring buffer entries.
 * @rtt		- The RTT of the message, in milliseconds.
 */
typedef union {
	struct {
		unsigned int	centry;
		unsigned int	rtt;
	} __attribute__((packed));
	uint64_t		data;
} TfwApmUBEnt;

/*
 * The buffer that holds RTT data for updates, per CPU.
 *
 * The data for an update is stored in an array per CPU. The actual
 * updates,and then the percentile recalculation is done periodically
 * by a single thread, which removes concurrency between updates and
 * the calculation. The data for an update is stored in one array of
 * the two, while the processing thread processes the accumulated
 * data in the other array. The switch between these two arrays is
 * managed by way of @counter by the processing thread.
 *
 * @ubent	- Arrays of ring buffer entries (flip-flop manner).
 * @ubufsz	- The size of @ubent.
 * @counter	- The counter that controls which @ubent to use.
 */
typedef struct {
	TfwApmUBEnt	*ubent[2];
	size_t		ubufsz;
	atomic64_t	counter;
} TfwApmUBuf;

#define TFW_APM_DATA_F_REARM	(0x0001)	/* Re-arm the timer. */
#define TFW_APM_DATA_F_RECALC	(0x0002)	/* Need to recalculate. */

#define TFW_APM_TIMER_INTVL	(HZ / 20)
#define TFW_APM_UBUF_SZ		TFW_APM_TIMER_INTVL	/* a slot per ms. */

#define TFW_APM_MIN_TMWSCALE	1	/* Minimum time window scale. */
#define TFW_APM_MAX_TMWSCALE	50	/* Maximum time window scale. */

#define TFW_APM_MIN_TMWINDOW	60	/* Minimum time window (secs). */
#define TFW_APM_MAX_TMWINDOW	3600	/* Maximum time window (secs). */

#define TFW_APM_MIN_TMINTRVL	5	/* Minimum time interval (secs). */

#define TFW_APM_HM_AUTO		"auto"
#define TFW_APM_DFLT_REQ	"GET / HTTP/1.0\r\n\r\n"
#define TFW_APM_DFLT_URL	"/"

/*
 * APM Data structure.
 *
 * Note that the organization of the supporting data heavily depends
 * on the fact that there's only one party that does the calculation
 * of percentiles - the function that runs periodically on timer.
 * If there are several different parties that do the calculation,
 * then the data may need to be organized differently.
 *
 * @rbuf	- The ring buffer for the specified time window.
 * @rbctl	- The control data helpful in taking optimizations.
 * @stats	- The latest percentiles.
 * @ubuf	- The buffer that holds data for updates, per CPU.
 * @timer	- The periodic timer handle.
 * @flags	- The atomic flags (TFW_APM_DATA_F_REARM only for now).
 */
typedef struct {
	TfwApmRBuf		rbuf;
	TfwApmRBCtl		rbctl;
	TfwApmStats		stats;
	TfwApmUBuf __percpu	*ubuf;
	struct timer_list	timer;
	unsigned long		flags;
} TfwApmData;

/*
 * The structure containing all the data necessary for the APM module,
 * belonging to each server. Used as an opaque pointer.
 *
 * Order of the members is important for the memory allocation, @data must be
 * at the end.
 *
 * @hmctl	- Data necessary for the health monitor operation.
 *		  Additionally, it contains statistics on the total number of
 *		  requests, divided by HTTP codes ('health_stat_server').
 * @data	- Data required for calculating response statistics for each
 *		  server (min/max/avg/percentiles).
 */
typedef struct {
	TfwApmHMCtl		hmctl;
	TfwApmData		data;
} TfwApmRef;

/*
 * [1ms, 349ms] should be sufficient for almost any installation,
 * including cross atlantic.
 */
static const TfwPcntCtl tfw_rngctl_init[TFW_STATS_RANGES] = {
	{0, 1, 16},
	{1, 17, 47},
	{2, 48, 108},
	{4, 109, 349}
};

static int tfw_apm_jtmwindow;		/* Time window in jiffies. */
static int tfw_apm_jtmintrvl;		/* Time interval in jiffies. */
static int tfw_apm_tmwscale;		/* Time window scale. */

/*
 * Global statistics for all requests passing through Tempesta (whether cached
 * or not). Relies on the 'apm_stats' directive, same as the statistics for
 * individual servers.
 */
static TfwApmData *tfw_apm_global_data;

/*
 * Get the next bucket in the ring buffer entry that has a non-zero
 * hits count. Set the bucket's sequential number, the range number,
 * and the bucket number. Set the response time value for the bucket.
 */
/*
 * Ring buffer entry state structure.
 *
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
	unsigned int rtt;

	for (r = i / TFW_STATS_BCKTS; r < TFW_STATS_RANGES; ++r) {
		for (b = i % TFW_STATS_BCKTS; b < TFW_STATS_BCKTS; ++b, ++i) {
			if (!rng->cnt[r][b])
				continue;
			rtt = rng->ctl[r].begin + (b << rng->ctl[r].order);
			__tfw_apm_state_set(st, rtt, i, r, b);
			return;
		}
	}
	__tfw_apm_state_set(st, USHRT_MAX, TFW_STATS_RANGES * TFW_STATS_BCKTS,
					   TFW_STATS_RANGES, TFW_STATS_BCKTS);
}

static inline void
tfw_apm_state_next(TfwPcntRanges *rng, TfwApmRBEState *st)
{
	BUG_ON(st->i >= TFW_STATS_RANGES * TFW_STATS_BCKTS);

	++st->i;
	__tfw_apm_state_next(rng, st);
}

/*
 * Calculate the latest percentiles from the current stats data.
 *
 * There's a small chance for a race condition, because @tot_cnt and the
 * buckets' @cnt[][] are updated without a lock, asynchronously and at
 * slightly different times (__tfw_apm_update -> tfw_apm_rbent_checkreset).
 * Due to a tiny discrepancy between @tot_cnt and the sum of hit counters
 * in @cnt[][], the calculation may not be able to reach the target value.
 * In that case the calculation exits prematurely, and a recalculation is
 * scheduled at the next run of the timer.
 *
 * Returns the number of percentile values that have been filled.
 */
static int
tfw_apm_prnctl_calc(TfwApmRBuf *rbuf, TfwApmRBCtl *rbctl, TfwPrcntlStats *pstats)
{
#define IDX_MIN		TFW_PSTATS_IDX_MIN
#define IDX_MAX		TFW_PSTATS_IDX_MAX
#define IDX_AVG		TFW_PSTATS_IDX_AVG
#define IDX_ITH		TFW_PSTATS_IDX_ITH

	int i, p;
	unsigned long cnt = 0, val, pval[T_PSZ];
	TfwApmRBEState st[TFW_APM_MAX_TMWSCALE];
	TfwPcntRanges *pcntrng;
	TfwApmRBEnt *rbent = rbuf->rbent;
	unsigned int max_val = 0;

	for (i = 0; i < rbuf->rbufsz; i++) {
		pcntrng = &rbent[i].pcntrng;
		__tfw_apm_state_set(&st[i], pcntrng->ctl[0].begin, 0, 0, 0);
		__tfw_apm_state_next(pcntrng, &st[i]);
	}
	/* The number of items to collect for each percentile. */
	for (i = p = IDX_ITH; i < T_PSZ; ++i) {
		pval[i] = rbctl->total_cnt * pstats->ith[i] / 100;
		if (!pval[i])
			pstats->val[p++] = 0;
	}
	for (i = 0; i < rbuf->rbufsz; i++) {
		pcntrng = &rbent[i].pcntrng;
		if (max_val < pcntrng->max_val)
			max_val = pcntrng->max_val;
	}
	while (p < T_PSZ) {
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
			T_DBG3("%s: Calculation stopped prematurely: "
				 "cnt [%lu] total_cnt [%lu]\n",
				 __func__, cnt, rbctl->total_cnt);
			T_DBG3("%s: [%lu] [%lu] [%lu] [%lu] [%lu] [%lu]\n",
				 __func__, pval[IDX_ITH], pval[IDX_ITH + 1],
				 pval[IDX_ITH + 2], pval[IDX_ITH + 3],
				 pval[IDX_ITH + 4], pval[IDX_ITH + 5]);
			break;
		}
		for (i = 0; i < rbuf->rbufsz; i++) {
			if (st[i].v != v_min)
				continue;
			pcntrng = &rbent[i].pcntrng;
			cnt += pcntrng->cnt[st[i].r][st[i].b];
			tfw_apm_state_next(pcntrng, &st[i]);
		}
		if (v_min > max_val) {
			v_min = max_val;
		}
		for ( ; p < T_PSZ && pval[p] <= cnt; ++p)
			pstats->val[p] = v_min;
	}
	cnt = val = 0;
	pstats->val[IDX_MAX] = 0;
	pstats->val[IDX_MIN] = UINT_MAX;
	for (i = 0; i < rbuf->rbufsz; i++) {
		pcntrng = &rbent[i].pcntrng;
		if (pstats->val[IDX_MIN] > pcntrng->min_val)
			pstats->val[IDX_MIN] = pcntrng->min_val;
		if (pstats->val[IDX_MAX] < pcntrng->max_val)
			pstats->val[IDX_MAX] = pcntrng->max_val;
		cnt += pcntrng->tot_cnt;
		val += pcntrng->tot_val;
	}

	if (pstats->val[IDX_MIN] == UINT_MAX)
		pstats->val[IDX_MIN] = 0;

	if (likely(cnt))
		pstats->val[IDX_AVG] = val / cnt;

	return p;

#undef IDX_ITH
#undef IDX_AVG
#undef IDX_MAX
#undef IDX_MIN
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
	       offsetof(TfwPcntRanges, __reset_till)
	       - offsetof(TfwPcntRanges, __reset_from));
	crbent->pcntrng.min_val = UINT_MAX;
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
tfw_apm_rbctl_update(TfwApmData *data, bool recalc)
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
			total_cnt += rbent[i].pcntrng.tot_cnt;
		entry_cnt = rbent[centry].pcntrng.tot_cnt;

		rbctl->entry_cnt = entry_cnt;
		rbctl->total_cnt = total_cnt;
		rbctl->jtmwstamp = jtmwstart;

		T_DBG3("%s: New time window: centry [%d] total_cnt [%lu]\n",
		       __func__, centry, rbctl->total_cnt);

		return true;
	}

	/* The latest percentiles are for the current time window.
	 * In some cases a recalculation is not required. In some
	 * other cases the recalculation set up can be simpler.
	 */

	/* Nothing to do if there were no stats updates. */
	entry_cnt = rbent[centry].pcntrng.tot_cnt;
	if (unlikely(rbctl->entry_cnt == entry_cnt)) {
		if (unlikely(recalc)) {
			T_DBG3("%s: Old time window: recalculate: "
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

	T_DBG3("%s: Old time window: centry [%d] total_cnt [%lu]\n",
	       __func__, centry, rbctl->total_cnt);

	return true;
}

/*
 * Calculate the latest percentiles if necessary.
 *
 * Return true if the calculation is successful.
 * Return false if the calculation is incomplete.
 */
static bool
tfw_apm_calc(TfwApmData *data)
{
	int nfilled, recalc;
	unsigned int rdidx;
	unsigned int val[T_PSZ] = { 0 };
	TfwPrcntlStats pstats = {
		.ith = tfw_pstats_ith,
		.val = val,
	};
	TfwApmSEnt *asent;

	rdidx = atomic_read(&data->stats.rdidx);
	asent = &data->stats.asent[(rdidx + 1) % 2];

	recalc = test_and_clear_bit(TFW_APM_DATA_F_RECALC, &data->flags);
	if (!tfw_apm_rbctl_update(data, recalc))
		return true;

	nfilled = tfw_apm_prnctl_calc(&data->rbuf, &data->rbctl, &pstats);
	if (nfilled < T_PSZ) {
		T_DBG3("%s: Percentile calculation incomplete.\n", __func__);
		set_bit(TFW_APM_DATA_F_RECALC, &data->flags);
	} else {
		T_DBG3("%s: Percentile values may have changed.\n", __func__);
		write_seqlock(&asent->seqlock);
		memcpy_fast(asent->pstats.val, pstats.val,
			    T_PSZ * sizeof(asent->pstats.val[0]));
		atomic_inc(&data->stats.rdidx);
		write_sequnlock(&asent->seqlock);
	}

	return nfilled == T_PSZ;
}

/*
 * Get the latest calculated percentiles.
 *
 * Return false if the percentile values didn't need recalculation.
 * Return true if potentially new percentile values were calculated.
 */
static bool
__tfw_apm_stats(TfwApmData *data, TfwPrcntlStats *pstats)
{
	unsigned int rdidx, s, seq = pstats->seq;
	TfwApmSEnt *asent;

	smp_mb__before_atomic();
	rdidx = atomic_read(&data->stats.rdidx);
	asent = &data->stats.asent[rdidx % 2];

	do {
		s = read_seqbegin(&asent->seqlock);
		memcpy(pstats->val, asent->pstats.val,
		       T_PSZ * sizeof(pstats->val[0]));
	} while (read_seqretry(&asent->seqlock, s));

	pstats->ith = tfw_pstats_ith;
	pstats->seq = rdidx;

	return seq != rdidx;
}

int
tfw_apm_stats(void *apmref, TfwPrcntlStats *pstats)
{
	TfwApmData *data;
	BUG_ON(!apmref);
	data = &((TfwApmRef *)apmref)->data;
	return __tfw_apm_stats(data, pstats);
}

int
tfw_apm_stats_global(TfwPrcntlStats *pstats)
{
	if (!tfw_apm_global_data) {
		T_DBG("tfw_apm: global data not initialized, skipping stats\n");
		memset(pstats, 0, sizeof(*pstats));
		return -ENODATA;
	}
	return __tfw_apm_stats(tfw_apm_global_data, pstats);
}

/*
 * Calculate the latest percentiles if necessary.
 * Runs periodically on timer.
 */
static void
tfw_apm_prcntl_tmfn(struct timer_list *t)
{
	int i, icpu;
	TfwApmData *data = from_timer(data, t, timer);
	TfwApmRBuf *rbuf = &data->rbuf;
	TfwApmRBEnt *rbent = rbuf->rbent;

	/*
	 * Increment the counter and make the updates use the other array
	 * of the two that are available. In the meanwhile, use the array
	 * filled with updates to process them and calculate percentiles.
	 */
	for_each_online_cpu(icpu) {
		TfwApmUBuf *ubuf = per_cpu_ptr(data->ubuf, icpu);
		unsigned long idxval = atomic64_inc_return(&ubuf->counter);
		TfwApmUBEnt *ubent = ubuf->ubent[(idxval - 1) % 2];
		TfwApmUBEnt rtt_data;

		for (i = 0; i < ubuf->ubufsz; ++i) {
			rtt_data.data = READ_ONCE(ubent[i].data);
			if (rtt_data.data == ULONG_MAX)
				continue;
			WRITE_ONCE(ubent[i].data, ULONG_MAX);
			tfw_stats_update(&rbent[rtt_data.centry].pcntrng,
					 rtt_data.rtt);
		}
	}

	if (unlikely(!tfw_apm_calc(data)))
		T_DBG3("%s: Incomplete calculation\n", __func__);

	smp_mb();
	if (test_bit(TFW_APM_DATA_F_REARM, &data->flags))
		mod_timer(&data->timer, jiffies + TFW_APM_TIMER_INTVL);
}

/*
 * Timer callback for checking health monitoring state of backend server
 * and sending test request if necessary.
 */
static void
tfw_apm_hm_timer_cb(struct timer_list *t)
{
	TfwApmHMCtl *hmctl = from_timer(hmctl, t, timer);
	TfwServer *srv = hmctl->srv;
	TfwApmHM *hm = READ_ONCE(hmctl->hm);
	unsigned long now;

	BUG_ON(!hm);
	if (!atomic64_read(&hmctl->rcount))
		tfw_http_hm_srv_send(srv, hm->req, hm->reqsz);

	atomic64_set(&hmctl->rcount, 0);

	smp_mb();
	if (atomic_read(&hmctl->rearm)) {
		now = jiffies;
		mod_timer(&hmctl->timer, now + hm->tmt * HZ);
		WRITE_ONCE(hmctl->jtmstamp, now);
		return;
	}
	WRITE_ONCE(hmctl->jtmstamp, 0);
}

static void
__tfw_apm_update(TfwApmData *data, unsigned long jtstamp, unsigned int rtt)
{
	TfwApmUBuf *ubuf = this_cpu_ptr(data->ubuf);
	unsigned long idxval = atomic64_add_return(0, &ubuf->counter);
	TfwApmUBEnt *ubent = ubuf->ubent[idxval % 2];
	int centry = (jtstamp / tfw_apm_jtmintrvl) % data->rbuf.rbufsz;
	unsigned long jtmistart = jtstamp - (jtstamp % tfw_apm_jtmintrvl);
	TfwApmUBEnt rtt_data = { .centry = centry, .rtt = rtt };

	tfw_apm_rbent_checkreset(&data->rbuf.rbent[centry], jtmistart);
	WRITE_ONCE(ubent[jtstamp % ubuf->ubufsz].data, rtt_data.data);
}

void
tfw_apm_update(void *apmref, unsigned long jtstamp, unsigned long jrtt)
{
	BUG_ON(!apmref);
	__tfw_apm_update(&((TfwApmRef *)apmref)->data, jtstamp,
			 jiffies_to_msecs(jrtt));
}

void
tfw_apm_update_global(unsigned long jtstamp, unsigned long jrtt)
{
	BUG_ON(!tfw_apm_global_data);
	__tfw_apm_update(tfw_apm_global_data, jtstamp, jiffies_to_msecs(jrtt));
}

static void
tfw_apm_free_ubuf(TfwApmData *data)
{
	int icpu;

	if (!data->ubuf)
		return;

	for_each_online_cpu(icpu) {
		TfwApmUBuf *ubuf = per_cpu_ptr(data->ubuf, icpu);
		kfree(ubuf->ubent[0]);
	}
	free_percpu(data->ubuf);
}

static void
tfw_apm_ref_destroy(TfwApmRef *ref)
{
	tfw_apm_free_ubuf(&ref->data);
	kfree(ref);
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

/**
 * Initialize an APM ring buffer for a server.
 * Must be called from process context.
 */
static void *
tfw_apm_data_init(TfwApmData *data)
{
	TfwApmRBEnt *rbent;
	int i, icpu, size;
	unsigned int *val[2];
	int rbufsz = tfw_apm_tmwscale;

	might_sleep();
	if (!tfw_apm_tmwscale) {
		T_ERR("Late initialization of 'apm_stats' option\n");
		return ERR_PTR(-EINVAL);
	}

	size = sizeof(TfwApmUBuf);
	data->ubuf = __alloc_percpu_gfp(size, sizeof(int64_t), GFP_KERNEL);
	if (!data->ubuf) {
		return ERR_PTR(-ENOMEM);
	}

	/* Set up memory areas. */
	rbent = (TfwApmRBEnt *)(data + 1);
	val[0] = (unsigned int *)(rbent + rbufsz);
	val[1] = (unsigned int *)(val[0] + T_PSZ);

	data->rbuf.rbent = rbent;
	data->rbuf.rbufsz = rbufsz;
	data->stats.asent[0].pstats.ith = tfw_pstats_ith;
	data->stats.asent[0].pstats.val = val[0];
	data->stats.asent[1].pstats.ith = tfw_pstats_ith;
	data->stats.asent[1].pstats.val = val[1];

	/* Initialize data. */
	for (i = 0; i < rbufsz; ++i)
		tfw_apm_rbent_init(&rbent[i], 0);
	spin_lock_init(&data->rbuf.slock);

	seqlock_init(&data->stats.asent[0].seqlock);
	seqlock_init(&data->stats.asent[1].seqlock);
	atomic_set(&data->stats.rdidx, 0);

	size = 2 * TFW_APM_UBUF_SZ * sizeof(TfwApmUBEnt);
	for_each_online_cpu(icpu) {
		TfwApmUBEnt *ubent;
		TfwApmUBuf *ubuf = per_cpu_ptr(data->ubuf, icpu);
		ubent = tfw_kmalloc_node(size, GFP_KERNEL, cpu_to_node(icpu));
		if (!ubent)
			return ERR_PTR(-ENOMEM);
		for (i = 0; i < 2 * TFW_APM_UBUF_SZ; ++i)
			WRITE_ONCE(ubent[i].data, ULONG_MAX);
		ubuf->ubent[0] = ubent;
		ubuf->ubent[1] = ubent + TFW_APM_UBUF_SZ;
		ubuf->ubufsz = TFW_APM_UBUF_SZ;
	}

	/* Return end of the structure, for further memory areas setting. */
	return val[1] + T_PSZ;
}
ALLOW_ERROR_INJECTION(tfw_apm_data_init, ERRNO);

static TfwApmRef *
tfw_apm_ref_create(void)
{
	int i;
	int rbufsz = tfw_apm_tmwscale;
	int hm_size = tfw_hm_codes_cnt * sizeof(TfwApmHMStats);
	int size = sizeof(TfwApmRef)
		+ rbufsz * sizeof(TfwApmRBEnt)
		+ 2 * T_PSZ * sizeof(unsigned int)
		+ hm_size;
	TfwApmRef *ref;
	TfwApmHMStats *hmstats;
	TfwApmHMCfg *ent;

	if ((ref = tfw_kzalloc(size, GFP_ATOMIC)) == NULL)
		return ERR_PTR(-ENOMEM);

	/*
	 * End of the TfwApmData structure is the beginning of the TfwApmHMStats
	 * of the TfwApmHMCtl.
	 */
	hmstats = tfw_apm_data_init(&ref->data);
	if (IS_ERR(hmstats)) {
		tfw_apm_ref_destroy(ref);
		return (void *)hmstats;
	}

	if (hm_size) {
		i = 0;
		list_for_each_entry(ent, &tfw_hm_codes_list, list) {
			hmstats[i].hmcfg = ent;
			spin_lock_init(&hmstats[i].lock);
			i++;
		}
		BUG_ON(tfw_hm_codes_cnt != i);
		ref->hmctl.hmstats = hmstats;
	}

	return ref;
}

static void
tfw_apm_data_destroy(TfwApmData *data)
{
	tfw_apm_free_ubuf(data);
	kfree(data);
}

static TfwApmData *
tfw_apm_data_create(void)
{
	int rbufsz = tfw_apm_tmwscale;
	int size = sizeof(TfwApmData)
		+ rbufsz * sizeof(TfwApmRBEnt)
		+ 2 * T_PSZ * sizeof(unsigned int);
	TfwApmData *data;
	void *r;

	if ((data = tfw_kzalloc(size, GFP_ATOMIC)) == NULL)
		return ERR_PTR(-ENOMEM);

	r = tfw_apm_data_init(data);
	if (IS_ERR(r)) {
		tfw_apm_data_destroy(data);
		return r;
	}

	return data;
}

/* Start the timer for the percentile calculation. */
static inline void
tfw_apm_data_start_timer(TfwApmData *data)
{
	set_bit(TFW_APM_DATA_F_REARM, &data->flags);
	timer_setup(&data->timer, tfw_apm_prcntl_tmfn, 0);
	mod_timer(&data->timer, jiffies + TFW_APM_TIMER_INTVL);
}

/* Stop the timer and the percentile calculation. */
static inline void
tfw_apm_data_stop_timer(TfwApmData *data)
{
	clear_bit(TFW_APM_DATA_F_REARM, &data->flags);
	smp_mb__after_atomic();
	del_timer_sync(&data->timer);
}

int
tfw_apm_add_srv(TfwServer *srv)
{
	TfwApmRef *ref;

	BUG_ON(srv->apmref);
	ref = tfw_apm_ref_create();
	if (IS_ERR(ref))
		return PTR_ERR(ref);

	tfw_apm_data_start_timer(&ref->data);
	srv->apmref = ref;

	return 0;
}

void
tfw_apm_del_srv(TfwServer *srv)
{
	TfwApmRef *ref = srv->apmref;

	if (!ref)
		return;

	/* Stop health monitor. */
	if (test_bit(TFW_SRV_B_HMONITOR, &srv->flags))
		tfw_apm_hm_disable_srv(srv);

	tfw_apm_data_stop_timer(&ref->data);
	tfw_apm_ref_destroy(ref);
	srv->apmref = NULL;
}

void
tfw_apm_hm_srv_rcount_update(TfwStr *uri_path, void *apmref)
{
	TfwApmHMCtl *hmctl = &((TfwApmRef *)apmref)->hmctl;
	TfwApmHM *hm = READ_ONCE(hmctl->hm);

	BUG_ON(!hm);
	if (tfw_str_eq_cstr(uri_path, hm->url, hm->urlsz, TFW_STR_EQ_CASEI))
		atomic64_inc(&hmctl->rcount);
}

static inline u32
__tfw_apm_crc32_calc(TfwMsgIter *it, TfwStr *chunk)
{
	u32 crc = 0;

	TFW_BODY_ITER_WALK(it, chunk)
		crc = crc32(crc, chunk->data, chunk->len);

	return crc;
}

/**
* Validate response from the given server.
* Check:
* - Is response status code belongs to monitored set
* - Integrity of the response body
* - CRC
* Successful passing all of the checks considered
* as a sign that the server is alive.
*/
bool
tfw_apm_hm_srv_alive(TfwHttpResp *resp, TfwServer *srv)
{
	int status = resp->status;
	TfwStr *body = &resp->body;
	TfwApmHM *hm = READ_ONCE(((TfwApmRef *)(srv->apmref))->hmctl.hm);
	u32 crc32 = 0;
	TfwMsgIter it;
	TfwStr chunk = {0};

	BUG_ON(!hm);
	if (hm->codes && !test_bit(HTTP_CODE_BIT_NUM(status), hm->codes)) {
		T_WARN_NL("Response for health monitor '%s': status '%d' "
			  "mismatched\n", hm->name, status);
		return false;
	}

	if (!body->len) {
		if (hm->crc32 != 0)
			goto crc_err;
		return true;
	}

	if (unlikely(tfw_body_iter_init(&it, &chunk, body->data, body->skb,
					resp->msg.skb_head)))
	{
		T_WARN_NL("Invalid body. Health monitor '%s': status '%d' \n",
			  hm->name, status);
		return false;
	}

	/*
	 * Special case for 'auto' monitor: generate crc32
	 * from body of first response and store it into monitor.
	 */
	if (!hm->crc32 && hm->auto_crc) {
		hm->crc32 = __tfw_apm_crc32_calc(&it, &chunk);
	} else if (hm->crc32) {
		crc32 = __tfw_apm_crc32_calc(&it, &chunk);
		if (hm->crc32 != crc32)
			goto crc_err;
	}

	return true;
crc_err:
	T_WARN_NL("Response for health monitor '%s': crc32"
		  " value '%u' mismatched (expected value:"
		 " '%u')\n", hm->name, crc32, hm->crc32);
	return false;
}

bool
tfw_apm_hm_srv_limit(int status, void *apmref)
{
	unsigned int i, sum = 0;
	TfwApmHMStats *hmstats = ((TfwApmRef *)apmref)->hmctl.hmstats;
	TfwApmHMHistory *history = NULL;
	TfwApmHMCfg *cfg = NULL;
	unsigned long ts;

	if (!hmstats)
		return false;

	for (i = 0; i < tfw_hm_codes_cnt; ++i) {
		if (tfw_http_status_eq(status, hmstats[i].hmcfg->code))
		{
			history = hmstats[i].history;
			cfg = hmstats[i].hmcfg;
			hmstats = &hmstats[i];
			break;
		}
	}

	if (!history)
		return false;
	BUG_ON(!cfg);

	spin_lock(&hmstats->lock);

	/*
	 * 'health_stat_server' directive reuses the same data structure as
	 * 'server_failover_http' (TfwApmHMCfg) but without the set @tframe
	 * and @limit (refer to tfw_cfgop_apm_health_stat_srv()). Thus, these
	 * attributes are optional.
	 */
	if (cfg->tframe) {
		ts = jiffies * HM_FREQ / (cfg->tframe * HZ);
		i = ts % HM_FREQ;
		if (history[i].ts != ts) {
			history[i].ts = ts;
			history[i].resp = 0;
		}
		++history[i].resp;
		for (i = 0; i < HM_FREQ; ++i)
			if (history[i].ts + HM_FREQ > ts)
				sum += history[i].resp;
		WRITE_ONCE(hmstats->rsum, sum);
	}
	++hmstats->total;

	spin_unlock(&hmstats->lock);

	if (cfg->limit && sum > cfg->limit)
		return true;

	return false;
}

static TfwApmHM *
tfw_apm_get_hm(const char *name)
{
	TfwApmHM *hm;

	list_for_each_entry(hm, &tfw_hm_list, list) {
		if (!strcasecmp(name, hm->name))
			return hm;
	}
	return NULL;
}

void
tfw_apm_hm_enable_srv(TfwServer *srv, const char *hm_name)
{
	TfwApmHMCtl *hmctl;
	unsigned long now;
	TfwApmHM *hm;

	BUG_ON(!srv->apmref);

	hm = tfw_apm_get_hm(hm_name);
	BUG_ON(!hm);
	WARN_ON_ONCE(test_bit(TFW_SRV_B_HMONITOR, &srv->flags));
	WARN_ON_ONCE(test_bit(TFW_SRV_B_SUSPEND, &srv->flags));

	/* Set new health monitor for server. */
	hmctl = &((TfwApmRef *)srv->apmref)->hmctl;
	WRITE_ONCE(hmctl->hm, hm);
	WRITE_ONCE(hmctl->srv, srv);
	atomic64_set(&hmctl->rcount, 0);

	/* Start server's health monitoring timer. */
	atomic_set(&hmctl->rearm, 1);
	smp_mb__after_atomic();
	timer_setup(&hmctl->timer, tfw_apm_hm_timer_cb, 0);
	now = jiffies;
	mod_timer(&hmctl->timer, now + hm->tmt * HZ);
	WRITE_ONCE(hmctl->jtmstamp, now);

	/* Activate server's health monitor. */
	set_bit(TFW_SRV_B_HMONITOR, &srv->flags);
}

static inline void
tfw_apm_hm_stop_timer(TfwApmHMCtl *hmctl) {
	atomic_set(&hmctl->rearm, 0);
	smp_mb__after_atomic();
	del_timer_sync(&hmctl->timer);
}

void
tfw_apm_hm_disable_srv(TfwServer *srv)
{
	clear_bit(TFW_SRV_B_HMONITOR, &srv->flags);
	tfw_srv_mark_alive(srv);
	BUG_ON(!srv->apmref);
	tfw_apm_hm_stop_timer(&((TfwApmRef *)srv->apmref)->hmctl);
}

bool
tfw_apm_hm_srv_eq(const char *name, TfwServer *srv)
{
	TfwApmHM *hm;

	BUG_ON(!srv->apmref);
	hm = ((TfwApmRef *)srv->apmref)->hmctl.hm;
	BUG_ON(!hm);
	if(!strcasecmp(name, hm->name))
		return true;

	return false;
}

/*
 * Calculation of general health monitoring statistics (for procfs).
 * Function allocates new TfwHMStats object which must be freed by
 * the caller.
 */
TfwHMStats *
tfw_apm_hm_stats(void *apmref)
{
	int i;
	long rtime = 0;
	TfwHMStats *stats;
	TfwApmHMCtl *hmctl = &((TfwApmRef *)apmref)->hmctl;
	TfwApmHM *hm = READ_ONCE(hmctl->hm);

	if (!hmctl->hmstats)
		return NULL;

	stats = tfw_kmalloc(tfw_hm_stats_size(tfw_hm_codes_cnt), GFP_KERNEL);
	if (!stats)
		return NULL;
	tfw_hm_stats_init(stats, tfw_hm_codes_cnt);

	for (i = 0; i < stats->ccnt; ++i) {
		BUG_ON(!hmctl->hmstats[i].hmcfg);
		stats->rsums[i].code = hmctl->hmstats[i].hmcfg->code;
		stats->rsums[i].tf_total = READ_ONCE(hmctl->hmstats[i].rsum);
		stats->rsums[i].total = READ_ONCE(hmctl->hmstats[i].total);
	}

	if (hm)
		rtime = (long)hm->tmt - (jiffies - READ_ONCE(hmctl->jtmstamp)) / HZ;
	stats->rtime = rtime < 0 ? 0 : rtime;

	return stats;
}

bool
tfw_apm_check_hm(const char *name)
{
	if (!tfw_hm_codes_cnt) {
		T_ERR_NL("No response 'server_failover_http' directives "
			 "specified for server's health monitoring\n");
		return false;
	}

	if (tfw_apm_get_hm(name))
		return true;

	T_ERR_NL("health monitor with name '%s' does not exist\n", name);

	return false;
}

static int
tfw_cfgop_apm_add_hm(const char *name)
{
	int size = strlen(name) + 1;
	BUG_ON(tfw_hm_entry);
	tfw_hm_entry = tfw_kzalloc(sizeof(TfwApmHM) + size, GFP_KERNEL);
	if (!tfw_hm_entry) {
		T_ERR_NL("Can't allocate health check entry '%s'\n", name);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&tfw_hm_entry->list);
	tfw_hm_entry->name = (char *)(tfw_hm_entry + 1);
	memcpy(tfw_hm_entry->name, name, size);
	list_add(&tfw_hm_entry->list, &tfw_hm_list);

	return 0;
}

static int
tfw_cfgop_apm_add_hm_req(const char *req_cstr, TfwApmHM *hm_entry)
{
	unsigned long size;

	size = strlen(req_cstr);
	hm_entry->req = (char *)__get_free_pages(GFP_KERNEL,
						     get_order(size));
	if (!hm_entry->req) {
		T_ERR_NL("Can't allocate memory for health monitoring request"
			 "\n");
		return -ENOMEM;
	}
	memcpy(hm_entry->req, req_cstr, size);
	hm_entry->reqsz = size;

	return 0;
}

static int
tfw_cfgop_apm_add_hm_url(const char *url, TfwApmHM *hm_entry)
{
	char *mptr;
	int size;

	size = strlen(url);
	mptr = tfw_kzalloc(size, GFP_KERNEL);
	if (!mptr) {
		T_ERR_NL("Can't allocate memory for '%s'\n", url);
		return -ENOMEM;
	}
	memcpy(mptr, url, size);
	hm_entry->url = mptr;
	hm_entry->urlsz = size;

	return 0;
}

static inline int
tfw_cfgop_apm_alloc_hm_codes(TfwApmHM *hm_entry)
{
	tfw_hm_entry->codes = tfw_kzalloc(BITS_TO_LONGS(512) * sizeof(long),
					  GFP_KERNEL);
	if (!tfw_hm_entry->codes) {
		T_ERR_NL("Can't allocate memory for HTTP codes field for '%s' "
			 "health check entry\n",
			 tfw_hm_entry->name);
		return -ENOMEM;
	}
	return 0;
}

static void
__tfw_cfgop_cleanup_apm_hm(void)
{
	TfwApmHM *hm, *tmp;

	tfw_hm_entry = NULL;
	tfw_hm_default = NULL;
	tfw_hm_cfg_200_created = false;

	list_for_each_entry_safe(hm, tmp, &tfw_hm_list, list) {
		free_pages((unsigned long)hm->req, get_order(hm->reqsz));
		kfree(hm->url);
		kfree(hm->codes);
		list_del(&hm->list);
		kfree(hm);
	}
	INIT_LIST_HEAD(&tfw_hm_list);
}

static void
tfw_cfgop_cleanup_apm_hm(TfwCfgSpec *cs)
{
	__tfw_cfgop_cleanup_apm_hm();
}

/**
 * Create 'auto' health monitor for default mode if explicit one have not been
 * created during configuration parsing stage.
 */
static int
tfw_apm_create_def_hm(void)
{
	int r;

	if (tfw_apm_get_hm(TFW_APM_HM_AUTO))
		return 0;

	if ((r = tfw_cfgop_apm_add_hm(TFW_APM_HM_AUTO)))
		return r;

	if ((r = tfw_cfgop_apm_add_hm_req(TFW_APM_DFLT_REQ, tfw_hm_entry)))
		return r;

	if ((r = tfw_cfgop_apm_add_hm_url(TFW_APM_DFLT_URL, tfw_hm_entry)))
		return r;

	if ((r = tfw_cfgop_apm_alloc_hm_codes(tfw_hm_entry)))
		return r;
	/*
	 * Default values for health response code is 200, for
	 * crc32 is 'auto', and for monitor request timeout is 10s.
	 */
	__set_bit(HTTP_CODE_BIT_NUM(200), tfw_hm_entry->codes);
	tfw_hm_entry->auto_crc = true;
	tfw_hm_entry->tmt = 10;
	tfw_hm_entry = NULL;
	return 0;
}

static TfwApmHMCfg *
tfw_apm_create_hm_entry(void)
{
	TfwApmHMCfg *hm_entry = tfw_kzalloc(sizeof(TfwApmHMCfg), GFP_KERNEL);
	if (!hm_entry)
		return NULL;

	INIT_LIST_HEAD(&hm_entry->list);
	list_add(&hm_entry->list, &tfw_hm_codes_list);
	++tfw_hm_codes_cnt;

	return hm_entry;
}

static int
tfw_apm_create_def_health_stat_srv(void)
{
	TfwApmHMCfg *hm_entry;

	if (tfw_hm_cfg_200_created)
		return 0;

	hm_entry = tfw_apm_create_hm_entry();
	if (!hm_entry)
		return -ENOMEM;

	hm_entry->code = 200;
	return 0;
}

static int
tfw_apm_cfgend(void)
{
	int r;
	TfwApmData *r2;

	if (tfw_runstate_is_reconfig())
		return 0;

	r2 = tfw_apm_data_create();
	if (IS_ERR(r2))
		return PTR_ERR(r2);

	tfw_apm_global_data = r2;
	tfw_apm_data_start_timer(tfw_apm_global_data);

	if ((r = tfw_apm_create_def_hm()))
		return r;

	return tfw_apm_create_def_health_stat_srv();
}

static void
tfw_cfgop_apm_cleanup_server_failover(TfwCfgSpec *cs)
{
	TfwApmHMCfg *ent, *tmp;

	list_for_each_entry_safe(ent, tmp, &tfw_hm_codes_list, list) {
		list_del_init(&ent->list);
		kfree(ent);
	}
	INIT_LIST_HEAD(&tfw_hm_codes_list);
	tfw_hm_codes_cnt = 0;
}

static void
tfw_apm_cfgclean(void)
{
	if (tfw_runstate_is_reconfig())
		return;

	if (tfw_apm_global_data) {
		tfw_apm_data_stop_timer(tfw_apm_global_data);
		tfw_apm_data_destroy(tfw_apm_global_data);
		tfw_apm_global_data = NULL;
	}

	/*
	 * 'auto' health monitor may be created implicitly in cfgend(),
	 * even if no `health_check` directive found.
	 */
	__tfw_cfgop_cleanup_apm_hm();
	tfw_cfgop_apm_cleanup_server_failover(NULL);
}

/**
 * Cleanup the configuration values when all server groups are stopped
 * and the APM timers are deleted.
 */
static void
tfw_cfgop_cleanup_apm(TfwCfgSpec *cs)
{
	tfw_apm_jtmwindow = tfw_apm_tmwscale = 0;
}

static int
tfw_cfgop_apm_stats(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int i, r;
	const char *key, *val;
	unsigned int jtmwindow;

	if (ce->val_n) {
		T_ERR_NL("%s: Arguments must be a key=value pair.\n", cs->name);
		return -EINVAL;
	}
	if (!ce->attr_n) {
		T_WARN_NL("%s: arguments missing, using default values.\n",
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
			T_ERR_NL("%s: unsupported argument: '%s=%s'.\n",
				 cs->name, key, val);
			return -EINVAL;
		}
	}

	if ((tfw_apm_jtmwindow < TFW_APM_MIN_TMWINDOW)
	    || (tfw_apm_jtmwindow > TFW_APM_MAX_TMWINDOW))
	{
		T_ERR_NL("apm_stats: window: value '%d' is out of limits.\n",
			 tfw_apm_jtmwindow);
		return -EINVAL;
	}

	if ((tfw_apm_tmwscale < TFW_APM_MIN_TMWSCALE)
	    || (tfw_apm_tmwscale > TFW_APM_MAX_TMWSCALE))
	{
		T_ERR_NL("apm_stats: scale: value '%d' is out of limits.\n",
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
		T_ERR_NL("apm_stats window=%d scale=%d: scale is too long.\n",
			 tfw_apm_jtmwindow, tfw_apm_tmwscale);
		return -EINVAL;
	}
	tfw_apm_jtmwindow = tfw_apm_jtmintrvl * tfw_apm_tmwscale;

	return 0;
}

static void
tfw_hm_entry_set_code(TfwApmHMCfg *hm_entry, int code)
{
	hm_entry->code = code;
	if (code == 200)
		tfw_hm_cfg_200_created = true;
}

static int
tfw_cfgop_apm_server_failover(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwApmHMCfg *hm_entry;
	int code, limit, tframe;

	TFW_CFG_CHECK_VAL_N(==, 3, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (tfw_cfgop_parse_http_status(ce->vals[0], &code)) {
		T_ERR_NL("Unable to parse http code value: '%s'\n",
			 ce->vals[0]);
		return -EINVAL;
	}
	if (tfw_cfg_parse_int(ce->vals[1], &limit)) {
		T_ERR_NL("Unable to parse http limit value: '%s'\n",
			 ce->vals[1]);
		return -EINVAL;
	}
	if (tfw_cfg_check_range(limit, 1, USHRT_MAX))
		return -EINVAL;

	if (tfw_cfg_parse_int(ce->vals[2], &tframe)) {
		T_ERR_NL("Unable to parse http tframe value: '%s'\n",
			 ce->vals[2]);
		return -EINVAL;
	}
	if (tfw_cfg_check_range(tframe, 1, USHRT_MAX))
		return -EINVAL;

	hm_entry = tfw_apm_create_hm_entry();
	if (!hm_entry)
		return -ENOMEM;
	tfw_hm_entry_set_code(hm_entry, code);
	hm_entry->limit = limit;
	hm_entry->tframe = tframe;

	return 0;
}

static int
tfw_cfgop_apm_health_stat_srv(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int i, code;
	const char *val;
	TfwApmHMCfg *hm_entry;

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfgop_parse_http_status(val, &code))
		{
			T_ERR_NL("Unable to parse http code value: '%s'\n",
				 val);
			return -EINVAL;
		}
		hm_entry = tfw_apm_create_hm_entry();
		if (!hm_entry)
			return -ENOMEM;
		tfw_hm_entry_set_code(hm_entry, code);
		/*
		 * With no set timeframe and response limit, we just accumulate
		 * total response statistics.
		 */
	}
	return 0;
}

static int
tfw_cfgop_begin_apm_hm(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TfwApmHM *hm;
	int r;

	TFW_CFG_CHECK_VAL_N(==, 1, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	list_for_each_entry(hm, &tfw_hm_list, list) {
		if (!strcasecmp(hm->name, ce->vals[0])) {
			T_ERR_NL("Duplicate health check entry: '%s'\n",
				 ce->vals[0]);
			return -EINVAL;
		}
	}

	if ((r = tfw_cfgop_apm_add_hm(ce->vals[0])))
		return r;

	if (!strcasecmp(ce->vals[0], TFW_APM_HM_AUTO)) {
		tfw_hm_default = tfw_hm_entry;
	}

	return 0;
}

static int
tfw_cfgop_finish_apm_hm(TfwCfgSpec *cs)
{
	BUG_ON(!tfw_hm_entry);
	BUG_ON(list_empty(&tfw_hm_list));
	if (!tfw_hm_entry->codes && !tfw_hm_entry->crc32) {
		T_ERR_NL("At least one of 'resp_code' or 'resp_crc32' explicit "
			 "(not 'auto') values must be configured for '%s'\n",
			 cs->name);
		return -EINVAL;
	}
	tfw_hm_entry = NULL;
	tfw_hm_default = NULL;

	return 0;
}

static int
tfw_cfgop_apm_hm_request(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	BUG_ON(!tfw_hm_entry);
	return tfw_cfgop_apm_add_hm_req(ce->vals[0], tfw_hm_entry);
}

static int
tfw_cfgop_apm_hm_req_url(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	BUG_ON(!tfw_hm_entry);
	return tfw_cfgop_apm_add_hm_url(ce->vals[0], tfw_hm_entry);
}

static int
tfw_cfgop_apm_hm_resp_code(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int r, i, code;
	const char *val;

	TFW_CFG_CHECK_VAL_N(>, 0, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if ((r = tfw_cfgop_apm_alloc_hm_codes(tfw_hm_entry)))
		return r;

	TFW_CFG_ENTRY_FOR_EACH_VAL(ce, i, val) {
		if (tfw_cfgop_parse_http_status(val, &code))
		{
			T_ERR_NL("Unable to parse http code value: '%s'\n",
				 val);
			kfree(tfw_hm_entry->codes);
			return -EINVAL;
		}
		__set_bit(HTTP_CODE_BIT_NUM(code), tfw_hm_entry->codes);
	}
	return 0;
}

static int
tfw_cfgop_apm_hm_resp_crc32(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	u32 crc32;

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;

	if (!strcasecmp(ce->vals[0], TFW_APM_HM_AUTO)) {
		if (tfw_hm_default)
			tfw_hm_default->auto_crc = true;
		return 0;
	}

	if (tfw_cfg_parse_uint(ce->vals[0], &crc32)) {
		T_ERR_NL("Unable to parse crc32 value: '%s'\n", ce->vals[0]);
		return -EINVAL;
	}

	tfw_hm_entry->crc32 = crc32;

	return 0;
}

static int
tfw_cfgop_apm_hm_timeout(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	int timeout;

	if (tfw_cfg_check_single_val(ce))
		return -EINVAL;
	if (tfw_cfg_parse_int(ce->vals[0], &timeout)) {
		T_ERR_NL("Unable to parse http timeout value: '%s'\n",
			 ce->vals[0]);
		return -EINVAL;
	}
	if (tfw_cfg_check_range(timeout, 1, USHRT_MAX))
		return -EINVAL;

	tfw_hm_entry->tmt = timeout;

	return 0;
}

static TfwCfgSpec tfw_apm_hm_specs[] = {
	{
		.name		= "request",
		.deflt		= TFW_APM_DFLT_REQ,
		.handler	= tfw_cfgop_apm_hm_request,
		.allow_none	= false,
		.allow_repeat	= false,
	},
	{
		.name		= "request_url",
		.deflt		= TFW_APM_DFLT_URL,
		.handler	= tfw_cfgop_apm_hm_req_url,
		.allow_none	= false,
		.allow_repeat	= false,
	},
	{
		.name		= "resp_code",
		.deflt		= NULL,
		.handler	= tfw_cfgop_apm_hm_resp_code,
		.allow_none	= true,
		.allow_repeat	= false,
	},
	{
		.name		= "resp_crc32",
		.deflt		= NULL,
		.handler	= tfw_cfgop_apm_hm_resp_crc32,
		.allow_none	= true,
		.allow_repeat	= false,
	},
	{
		.name		= "timeout",
		.deflt		= NULL,
		.handler	= tfw_cfgop_apm_hm_timeout,
		.allow_none	= false,
		.allow_repeat	= false,
	},
	{ 0 }
};

static TfwCfgSpec tfw_apm_specs[] = {
	{
		.name		= "apm_stats",
		.deflt		= "window=300 scale=5",
		.handler	= tfw_cfgop_apm_stats,
		.cleanup	= tfw_cfgop_cleanup_apm,
		.allow_none	= true,
		.allow_repeat	= false,
	},
	{
		.name		= "server_failover_http",
		.deflt		= NULL,
		.handler	= tfw_cfgop_apm_server_failover,
		.allow_none	= true,
		.allow_repeat	= true,
		.cleanup	= tfw_cfgop_apm_cleanup_server_failover,
	},
	{
		.name		= "health_stat_server",
		.deflt		= NULL,
		.handler	= tfw_cfgop_apm_health_stat_srv,
		.allow_none	= true,
		.cleanup	= tfw_cfgop_apm_cleanup_server_failover,
	},
	{
		.name		= "health_check",
		.deflt		= NULL,
		.handler	= tfw_cfg_handle_children,
		.dest		= tfw_apm_hm_specs,
		.spec_ext	= &(TfwCfgSpecChild ) {
			.begin_hook = tfw_cfgop_begin_apm_hm,
			.finish_hook = tfw_cfgop_finish_apm_hm
		},
		.allow_none	= true,
		.allow_repeat	= true,
		.cleanup	= tfw_cfgop_cleanup_apm_hm,
	},
	{ 0 }
};

TfwMod tfw_apm_mod = {
	.name		= "apm",
	.cfgend		= tfw_apm_cfgend,
	.cfgclean	= tfw_apm_cfgclean,
	.specs		= tfw_apm_specs,
};

int
tfw_apm_init(void)
{
	tfw_mod_register(&tfw_apm_mod);
	return 0;
}

void
tfw_apm_exit(void)
{
	tfw_mod_unregister(&tfw_apm_mod);
}
