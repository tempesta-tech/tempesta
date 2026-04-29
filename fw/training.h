/**
 * 		Tempesta FW training and defence subsystem.
 *
 * This file implements a lightweight anomaly detection mechanism used to
 * protect against abnormal client behaviour (e.g. excessive number of
 * connections, requests or CPU consumption).
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
 *   - Per-object state (TfwTrainingStat) tracks current and peak values
 *     and lazily resets on training epoch change using a global epoch
 *     counter (@g_training_epoch).
 *
 *   - Mean and standard deviation are computed at the end of the training
 *     phase and then used in defence mode without further modification.
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

#ifndef __TFW_TRAINING_H__
#define __TFW_TRAINING_H__

#include <linux/spinlock.h>
#include "asm-generic/rwonce.h"
#include "lib/fault_injection_alloc.h"

/*
 * Fixed-point scaling factor used for integer arithmetic.
 * Kernel code avoids floating point operations, so all fractional
 * calculations (e.g. mean, variance, z-score) are performed using
 * scaled integers. SCALE_SHIFT defines the number of fractional bits.
 */
#define SCALE_SHIFT 10

/*
 * Training mode state.
 *
 * defence 	- defence mode. For each event Tempesta FW computes z-score
 *		  and compares it against a configured threshold. If the
 *		  threshold is exceeded, the connection is dropped (TCP RST).
 *
 * training	- training mode. Statistics are collected and accumulated to
 *		  build mean and standard deviation used later in defence mode.
 *
 * disabled	- internal state used during mode transitions. While in this
 *		  state, both training and defence paths are disabled to
 *		  provide safe synchronization.
 */
typedef enum {
	TFW_MODE_IS_DEFENCE = 0,
	TFW_MODE_IS_TRAINING = 1,
	TFW_MODE_DISABLED = 2
} TfwTrainingMode;

/*
 * max		- maximum observed value of the tracked metric within the
 *		  current training epoch (e.g. peak number of in-flight
 *		  non-idempotent requests);
 * curr		- current value of the tracked metric;
 * lock		- spinlock for serialized reset of @max and @curr when a
 *		  new training epoch starts.
 * @epoch	- training epoch identifier. Compared against the global
 *		  @g_training_epoch to detect epoch change and trigger
 *		  reinitialization of @max and @curr.
 */
typedef struct {
	atomic64_t	max;
	atomic64_t	curr;
	spinlock_t	lock;
	unsigned int	epoch;
} TfwTrainingStat;

/* * Current training mode (see TfwTrainingMode). */
extern unsigned int tfw_training_mod_state;
/*
 * Global training epoch counter.
 * Incremented each time a new training cycle starts. Used by per-object
 * state to detect epoch changes and reset local statistics.
 */
extern unsigned int g_training_epoch;

int tfw_training_mode_init(void);
void tfw_training_mode_exit(void);

void tfw_training_mode_adjust_conn_num(u64 delta1, u64 delta2, bool new_client);
bool tfw_training_mode_defence_conn_num(u64 val);
int tfw_ctlfn_training_mode_state_change(unsigned int training_mode);
bool tfw_training_mode_update_req_num_stat(TfwTrainingStat *stat, int delta,
					   unsigned int *training_epoch);
bool tfw_training_mode_update_cpu_num_stat(TfwTrainingStat *stat, int delta,
					   unsigned int *training_epoch);

static inline void
tfw_training_stat_init(TfwTrainingStat *stat)
{
	atomic64_set(&stat->max, 0);
	atomic64_set(&stat->curr, 0);
	spin_lock_init(&stat->lock);
	stat->epoch = 0;
}

static inline bool
tfw_mode_is_disabled(void)
{
	return READ_ONCE(tfw_training_mod_state) == TFW_MODE_DISABLED;
}

static inline bool
tfw_mode_is_training(void)
{
	return READ_ONCE(tfw_training_mod_state) == TFW_MODE_IS_TRAINING;
}

static inline bool
tfw_mode_is_defence(void)
{
	return READ_ONCE(tfw_training_mod_state) == TFW_MODE_IS_DEFENCE;
}

#endif /* __TFW_TRAINING_H__ */