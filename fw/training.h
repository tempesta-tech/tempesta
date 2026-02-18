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

typedef enum {
	TFW_TRAINING_MODE_DISABLED,
	TFW_TRAINING_MODE_ENABLED,
	TFW_TRAINING_DEFENCE_MODE_ENABLED,
} TfwTrainingMode;

extern int tfw_training_mod_period;
extern TfwTrainingMode tfw_training_mod_state;

int tfw_training_mode_init(void);
void tfw_training_mode_exit(void);

void tfw_training_start(void);
void tfw_training_stop(TfwTrainingMode mode);

static inline TfwTrainingMode
tfw_training_mode_is_enabled(void)
{
	return tfw_training_mod_state;
}

#endif /* __TFW_TRAINING_H__ */