/**
 * 		Tempesta FW training and defence subsystem.
 *
 * This file implements a lightweight anomaly detection mechanism used to
 * protect against abnormal client behaviour (e.g. excessive number of
 * connections, requests, memory usage or CPU consumption).
 *
 * The subsystem operates in three modes:
 * - training:
 *	Statistics are collected for selected metrics. For each observation,
 *	the first and second moments (sum and sum of squares) are accumulated
 *	using per-CPU counters to minimize contention.
 *
 * - defence:
 *	Runtime values are compared against the learned distribution using
 *	z-score (z = (x - mean) / stddev) If the computed z-score exceeds
 *	a configured threshold, the event is considered anomalous and
 *	connection will be dropped.
 * - disabled:
 *	Transient state used during mode transitions to safely update shared
 *	data structures. In this state both training and defence paths are
 *	bypassed.
 *
 * Implementation details:
 *
 *   - All arithmetic is performed using fixed-point integers (see
 *     SCALE_SHIFT) to avoid floating point usage in kernel space.
 *
 *   - Global statistics are maintained in RCU-protected structures and
 *     updated via percpu_counter to provide scalability on multi-core
 *     systems.
 *
 *   - Mean and standard deviation are computed at the end of the training
 *     phase and then used in defence mode without further modification.
 * 
 * Several approaches for online variance calculation were evaluated, including
 * Welford’s algorithm and the “sum/squared-sum” method. It was found that the
 * “sum/squared-sum” method is better for our purposes:
 *
 *   - Original form Welford assumes an append-only stream of samples, where
 *     each new observation increases the total sample count. In our case,
 *     however, "n" represents the number of clients rather than the number
 *     of events, so we need a modified reversible version of Welford’s
 *     algorithm, which significantly complicates the implementation and
 *     slower then it's classic version.
 *
 *   - Kernel-space constraints prohibit floating-point arithmetic, requiring
 *     the use of fixed-point integer arithmetic instead. While Welford’s
 *     algorithm is known for its excellent numerical stability with
 *     floating-point arithmetic, its fixed-point implementation introduces
 *     truncation errors during repeated division operations.
 *
 *   - “sum/squared-sum” method is generally considered less numerically
 *      stable than Welford’s algorithm because subtracting two large close
 *      values may lead to catastrophic cancellation and precision loss.
 *      However, this issue primarily affects workloads with very large
 *      numbers and extremely small variance. For the considered workload,
 *      where client metrics are bounded and remain relatively small, the
 *      “sum/squared-sum” approach provides sufficient numerical accuracy
 *      while being substantially simpler and faster.
 *
 * According to the selected algorithm at the end of the training phase
 * the following statistics are derived from the accumulated "sum" and
 * "sumsq":
 *
 *       sum
 *   μ = ───
 *        n
 *
 *        sumsq
 *   σ² = ───── - μ²
 *          n
 *
 *   σ = √σ²
 *
 * The resulting mean (μ) and standard deviation (σ) are then used in the
 * defence mode to compute z-scores.
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
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

#ifndef __TFW_ADAPTIVE_LIMITS_H__
#define __TFW_ADAPTIVE_LIMITS_H__

#include <linux/spinlock.h>
#include "asm-generic/rwonce.h"
#include "lib/fault_injection_alloc.h"

/*
 * Fixed-point scaling factor used for integer arithmetic.
 * Kernel code avoids floating point operations, so all fractional
 * calculations (e.g. mean, variance, z-score) are performed using
 * scaled integers. SCALE_SHIFT defines the number of fractional bits.
 *
 * A value X is represented internally as:
 *
 *     X_scaled = X << SCALE_SHIFT
 *
 * For example, with SCALE_SHIFT = 10:
 *
 *     1.0 -> 1024
 *     2.5 -> 2560
 */
#define SCALE_SHIFT 10

/*
 * Adaptive limits mode.
 *
 * defence 	- defence mode. For each event Tempesta FW computes z-score
 *		  and compares it against a configured threshold. If the
 *		  threshold is exceeded, the connection is dropped (TCP RST).
 *
 * training	- training mode. Statistics are collected and accumulated to
 *		  build mean and standard deviation used later in defence mode.
 *
 * disabled	- internal state used during mode transitions. While in this
 *		  mode, both training and defence paths are disabled to
 *		  provide safe synchronization.
 */
typedef enum {
	TFW_ADAPTIVE_LIMITS_MODE_IS_DEFENCE = 0,
	TFW_ADAPTIVE_LIMITS_MODE_IS_TRAINING = 1,
	TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED = 2
} TfwAdaptiveLimitsMode;

/* * Current adaptive limits mode (see TfwAdaptiveLimitsMode). */
extern unsigned int tfw_adaptive_limits_mode;
/*
 * Global training epoch counter.
 * Incremented each time a new training cycle starts. Used by per-object
 * state to detect epoch changes and reset local statistics.
 */
extern unsigned int g_training_epoch;

/*
 * A simple adaptive limit structure used to track events,
 * which is already protected by an external lock.
 *
 * @counter	- current value (e.g. active connections).
 * @max		- maximum observed value within the current epoch.
 * @epoch	- training epoch identifier. compared against the global
 *		  @g_training_epoch to detect epoch change and trigger
 *		  reinitialization of @max and @counter.
 */
typedef struct {
	int		counter;
	unsigned int	max;
	u16		epoch;
} TfwAdaptiveLimit;

/*
 * counter	- percpu array to track current value of the tracked metric;
 * lock		- spinlock for serialized reset of @max and @counter when a
 *		  new training epoch starts.
 * max		- maximum observed value of the tracked metric within the
 *		  current training epoch;
 * @epoch	- training epoch identifier. Compared against the global
 *		  @g_training_epoch to detect epoch change and trigger
 *		  reinitialization of @max and @counter;
 */
typedef struct {
	s64 __percpu		*counter;
	spinlock_t		lock;
	atomic64_t		max;
	u16			epoch;
} TfwAdaptiveLimitLock;

int tfw_adaptive_limits_init(void);
void tfw_adaptive_limits_exit(void);

bool tfw_adaptive_limits_check_conn_num(TfwAdaptiveLimit *limit, int delta,
					u16 *epoch);
void tfw_adaptive_limits_acc_req_num(TfwAdaptiveLimitLock *limit,
				     int delta, u16 *epoch);
bool tfw_adaptive_limits_check_req_num(TfwAdaptiveLimitLock *limit);
int tfw_ctlfn_adaptive_limits_mode_change(unsigned int mode);

int tfw_adaptive_limit_lock_init(TfwAdaptiveLimitLock *limit, gfp_t flags);
void tfw_adaptive_limit_lock_destroy(TfwAdaptiveLimitLock *limit);

static inline void
tfw_adaptive_limit_init(TfwAdaptiveLimit *limit)
{
	limit->counter = 0;
	limit->max = 0;
	limit->epoch = 0;
}

static inline bool
tfw_adaptive_limits_mode_is_disabled(void)
{
	return READ_ONCE(tfw_adaptive_limits_mode) ==
		TFW_ADAPTIVE_LIMITS_MODE_IS_DISABLED;
}

static inline bool
tfw_adaptive_limits_mode_is_training(void)
{
	return READ_ONCE(tfw_adaptive_limits_mode) ==
		TFW_ADAPTIVE_LIMITS_MODE_IS_TRAINING;
}

static inline bool
tfw_adaptive_limits_mode_is_defence(void)
{
	return READ_ONCE(tfw_adaptive_limits_mode) ==
		TFW_ADAPTIVE_LIMITS_MODE_IS_DEFENCE;
}

#define PERCPU_COUNTER_SUMM(type)				\
static inline type						\
tfw_percpu_##type##_counter_sum(type __percpu *counter)		\
{								\
	type total = 0;						\
	int cpu;						\
								\
	for_each_online_cpu(cpu)				\
		total += *(per_cpu_ptr(counter, cpu));		\
								\
	return total;						\
}

PERCPU_COUNTER_SUMM(u128)
PERCPU_COUNTER_SUMM(u64)
PERCPU_COUNTER_SUMM(u32)
PERCPU_COUNTER_SUMM(s64)

#undef PERCPU_COUNTER_SUMM

#endif /* __TFW_ADAPTIVE_LIMITS_H__ */
