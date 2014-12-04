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

/**
 * A TfwCfgSpec describes a single rule, according to which configuration is
 * somehow processed.
 *
 *
 * @deflt is a default value.
 * It is specified for the whole node as raw text, e.g.:
 *     .dflt = "server example.com 127.0.0.1;"
 * The string is parsed, and the resulting TfwCfgNode is used as a source of
 * default values. This is ugly, but allows to reduce the amount of extra fields
 * for each kind of value.
 *
 * @doc is a documentation string.
 * It is used for generating default config file with documentation comments
 * and basically to make your source code easier to understand.
 *
 * @call_node is called when node with the given @path is met.
 * The callback (just like all other callbacks in this structure) may signal an
 * error by returning an error. In this case processing of the whole spec is
 * stopped and a major error is issued.
 *
 * @is_not_singleton says whether there must be only one node with the
 * given @path in any configuration tree.
 * Usually, there are two kinds of data expressed in configuration files:
 *  1. Singletons - regular entities: sections and settings.
 *  2. Non-singletons - repetitive things like a rules for tfw_sched_http.
 * For singletons @dflt creates a node if it doesn't exist.
 * For non-singletons @deflt merges-in default values and attributes into each
 * node with given @path (doesn't create a node if it doesn't exist).
 *
 *
 * @attr, @val_each and @val_pos specify a value for which all actions
 * described below are performed.
 *
 * @set_int, @set_bool, @set_str and @set_addr allows to save the value to
 * a variable or a structure. If there is no value of given type, then zero
 * is saved by the given pointer.
 *
 * @call_int, @call_bool, @call_addr and @call_str allow to invoke a custom
 * callback when a value at specified position is met. A callback is not invoked
 * at all when there is no value of such type.
 */
typedef struct {
	/* Node-related fields. */
	const char *path;
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
