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
#ifndef __TFW_CFG_MODULE_H__
#define __TFW_CFG_MODULE_H__

#include "cfg_parser.h"

typedef struct {
	const char *path;

	/* Node-related fields. */
	const char *deflt;
	const char *doc;
	void (*call_node)(const TfwCfgNode *node);


	/* Value or attribute related fields. */
	const char *attr;
	struct {
		u8 val_each : 1;
		u8 val_pos  : 7;
	};

	void (*call_int)(int value);
	void (*call_bool)(bool value);
	void (*call_str)(const char *str);
	void (*call_addr)(const TfwAddr *addr);

	int *set_int;
	bool *set_bool;
	const char **set_str;
	const TfwAddr **set_addr;
} TfwCfgSpec;


int tfw_cfg_spec_apply(const TfwCfgSpec spec_arr[], TfwCfgNode *node);


#endif /* __TFW_CFG_MODULE_H__ */
