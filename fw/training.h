/**
 *		Tempesta FW
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
 * We use integer calculation in kernel mode, so use
 * scale for more accuracy calculation.
 */
#define SCALE_SHIFT 10

typedef enum {
	TFW_MODE_IS_DEFENCE = 0,
	TFW_MODE_IS_TRAINING = 1,
	TFW_MODE_DISABLED = 2
} TfwTrainingMode;

typedef struct {
	atomic64_t	max;
	atomic64_t	curr;
	spinlock_t	lock;
	unsigned int	num;
	u64 __percpu	*inc;
} TfwTrainingStat;

extern unsigned int tfw_training_mod_period;
extern unsigned int tfw_training_mod_state;
extern int g_training_num;

int tfw_training_mode_init(void);
void tfw_training_mode_exit(void);

void tfw_training_mode_adjust_conn_num(u64 delta1, u64 delta2, bool new_client);
bool tfw_training_mode_defence_conn_num(u64 val);
int tfw_ctlfn_training_mode_state_change(unsigned int training_mode);
bool tfw_training_mode_update_req_num_stat(TfwTrainingStat *stat, int delta);
bool tfw_training_mode_update_cpu_num_stat(TfwTrainingStat *stat, int delta);

static inline int
tfw_training_stat_init(TfwTrainingStat *stat)
{
	stat->inc = tfw_alloc_percpu_gfp(u64, GFP_ATOMIC | __GFP_ZERO);
	if (unlikely(!stat->inc))
		return -ENOMEM;

	atomic64_set(&stat->max, 0);
	atomic64_set(&stat->curr, 0);
	spin_lock_init(&stat->lock);
	stat->num = 0;

	return 0;
}

static inline void
tfw_training_stat_destroy(TfwTrainingStat *stat)
{
	free_percpu(stat->inc);
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