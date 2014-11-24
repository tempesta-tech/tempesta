/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_CFG_MOD_H__
#define __TFW_CFG_MOD_H__

#include <linux/list.h>
#include "cfg_spec.h"

typedef struct {
	/* Private fields. Used internally, don't even initialize them. */
	struct list_head list;

	/* Public fields. To be filled by modules. */

	/* Text name of the module. At this point used only for logging. */
	const char *name;

	/* These two act like module_init()/module_exit(). They are used only
	 * within this Tempesta FW kernel module to avoid boilerplate code. */
	int (*init)(void);
	void (*exit)(void);

	/* An array (terminated by an empty element) that specifies rules
	 * for handling configuration entries for this module. */
	const TfwCfgSpec *cfg_spec_arr;

	int (*setup)(void);
	int (*start)(void);
	void (*stop)(void);
	void (*cleanup)(void);
} TfwCfgMod;

/* Call init/exit and subscribe to start/stop events. */
int tfw_cfg_mod_init(TfwCfgMod *mod);
void tfw_cfg_mod_exit(TfwCfgMod *mod);

/* Publish start/stop events. */
int tfw_cfg_mod_start_all(TfwCfgNode *cfg_root);
void tfw_cfg_mod_stop_all(void);

/* A shutdown routine. */
void tfw_cfg_mod_exit_all(void);

#endif /* __TFW_CFG_MOD_H__ */
