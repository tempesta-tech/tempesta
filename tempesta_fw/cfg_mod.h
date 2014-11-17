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
	bool is_started;

	/* Public fields. To be filled by modules. */
	const char *name;
	const TfwCfgSpec *spec_arr;  /* Terminated by an empty element. */
	int (*start)(void);
	void (*stop)(void);
} TfwCfgMod;

int tfw_cfg_mod_register(TfwCfgMod *mod);
void tfw_cfg_mod_unregister(TfwCfgMod *mod);

int tfw_cfg_mod_publish_new_cfg(TfwCfgNode *root);
int tfw_cfg_mod_start_all(void);
void tfw_cfg_mod_stop_all(void);

#endif /* TEMPESTA_FW_CFG_MOD_H_ */
