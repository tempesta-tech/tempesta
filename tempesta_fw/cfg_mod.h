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

	/* These two act like module_init()/module_exit(). They are called when
	 * a module is registered/unregistered and used to eliminate some
	 * boilerplate code (init/exit function declarations and calls). */
	int (*init)(void);
	void (*exit)(void);

	/* An array (terminated by an empty element) that stores rules for
	 * processing configuration for this module. */
	const TfwCfgSpec *cfg_spec_arr;

	/* These four callbacks are invoked when start/stop events are received.
	 * Basically, the system life cycle looks like this:
	 *   1. Receive a "start" event, and then:
	 *        a. Call @setup for each module.
	 *        b. Process @cfg_spec_arr of each module.
	 *        c. Call @start for each module.
	 *   2. Modules are started and doing something useful.
	 *   3. Receive "stop" event, and then:
	 *        a. Call @stop for each module.
	 *        b. Call @cleanup for each module.
	 *        c. Free configuration passed to @cfg_spec_arr callbacks.
	 *
	 * We need separate @setup/@cleanup callbacks to determine lifetime of
	 * allocated memory: modules shall allocate memory in @setup and free
	 * it in @cleanup, so other modules may reference it in @start/@stop
	 * callbacks. Also after @cleanup all the parsed configuration dies, so
	 * modules must clean references to objects like TfwCfgNode and TfwAddr.
	 */
	int (*setup)(void);
	int (*start)(void);
	void (*stop)(void);
	void (*cleanup)(void);
} TfwCfgMod;

/* Call init/exit and subscribe to start/stop events. */
int tfw_cfg_mod_register(TfwCfgMod *mod);
void tfw_cfg_mod_unregister(TfwCfgMod *mod);

/* Publish start/stop events. */
int tfw_cfg_mod_start_all(TfwCfgNode *cfg_root);
void tfw_cfg_mod_stop_all(void);

/* A shutdown routine. */
void tfw_cfg_mod_exit_all(void);

#endif /* __TFW_CFG_MOD_H__ */
