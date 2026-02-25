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

#include "asm-generic/rwonce.h"

typedef enum {
	TFW_MODE_IS_DEFENCE = 0,
	TFW_MODE_IS_TRAINING = 1,
	TFW_MODE_DISABLED = 2
} TfwTrainingMode;

extern unsigned int tfw_training_mod_period;
extern unsigned int tfw_training_mod_state;
extern unsigned int g_training_num; 

int tfw_training_mode_init(void);
void tfw_training_mode_exit(void);

void tfw_training_mode_adjust_new_conn(int cpu, u64 delta1, u64 delta2,
				       bool new_client);
bool tfw_training_mode_defence_conn_num(u64 val);
int tfw_ctlfn_training_mode_state_change(unsigned int training_mode);

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