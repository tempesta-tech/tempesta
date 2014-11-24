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
#ifndef __TFW_CFG_SPEC_H__
#define __TFW_CFG_SPEC_H__

#include "cfg_node.h"

typedef struct {
	const char *path;

	/* Node-related fields. */
	const char *deflt;
	const char *doc;
	int (*call_node)(const TfwCfgNode *node);
	bool is_not_singleton;


	/* Value or attribute related fields. */
	const char *attr;
	struct {
		u8 val_each : 1;
		u8 val_pos  : 7;
	};

	int (*call_int)(int value);
	int (*call_bool)(bool value);
	int (*call_addr)(const TfwAddr *addr);
	int (*call_str)(const char *str);

	int *set_int;
	bool *set_bool;
	const char **set_str;
	const TfwAddr **set_addr;
} TfwCfgSpec;


/* Create nodes and values specified by the @dflt field in TfwCfgSpec. */
void tfw_cfg_spec_set_defaults(const TfwCfgSpec spec_arr[],
			       TfwCfgNode *cfg_root);

/* Handle validation-related fields of the TfwCfgSpec. */
int tfw_cfg_spec_validate(const TfwCfgSpec spec_arr[],
			  const TfwCfgNode *cfg_root);

/* Handle set/callback fields in the TfwCfgSpec. */
int tfw_cfg_spec_apply(const TfwCfgSpec spec_arr[],
		       const TfwCfgNode *cfg_root);


#endif /* __TFW_CFG_SPEC_H__ */
