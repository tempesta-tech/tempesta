/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TEMPESTA_FW_H__
#define __TEMPESTA_FW_H__

#include <linux/in6.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/tempesta.h>
#include <linux/types.h>
#include <net/sock.h>

#include "lib/log.h"
#include "cfg.h"

#define TFW_AUTHOR		"Tempesta Technologies, Inc"
#define TFW_NAME		"Tempesta FW"
#define TFW_VERSION		"0.6.0"

#define DEF_MAX_PORTS		8

/**
 * Internally, Tempesta FW code is split into modules. These are not
 * necessarily kernel modules, but rather loosely coupled pieces of code.
 * Parsed configuration data and start/stop events need to be delivered
 * to the modules. The parser should not depend on all possible modules,
 * so a late binding approach is utilized here.
 *
 * Each module defines a TfwMod{} structure and calls tfw_mod_register().
 * A list of registered modules is maintained. Events and configuration
 * data are pushed to modules via callbacks.
 *
 * @name is a unique text identifier of the module. Just like C language
 * identifiers, it must consist of alphanumeric characters and start with
 * a letter and so on.
 *
 * @specs is the specification for the configuration parser. It lists
 * all possible configuration sections and directives for the module and
 * describes how to handle them. @specs must be an array of TfwCfgSpec{}
 * structures which is terminated by a null (zeroed) element.
 *
 * @start and @stop callbacks are invoked when corresponding events are
 * received via sysctl. The @start is called after the configuration is
 * parsed and all @specs are handled by modules.
 *
 * @cfgstart, @cfgend and @cfgclean are optional callbacks that are invoked
 * during configuration parsing. @cfgstart is called just before parsing if
 * additional initialization is required. @cfgend is called after
 * configuration was successfully parsed till the end. It's helpful for a
 * module, that require configuration information from other modules.
 * @cfgclean is called as the final step during configuration cleanup.
 */
/**
 * @list	- member in the list of modules;
 * @name	- module name, [A-Za-z0-9_], starts with a letter;
 * @cfgstart	- called before configuration is parsed;
 * @cfgend	- called after configuration is fully parsed;
 * @cfgclean	- called after @specs was cleaned to finish cleanup process;
 * @start	- called to start or reconfig a module;
 * @stop	- called to stop a module when Tempesta is stopped;
 * @specs	- array of configuration directives specifications
 *		  for a module, terminated by a null element;
 */
typedef struct {
	struct list_head	list;
	const char		*name;
	int			(*cfgstart)(void);
	int			(*cfgend)(void);
	void			(*cfgclean)(void);
	int			(*start)(void);
	void			(*stop)(void);
	TfwCfgSpec		*specs;
} TfwMod;

#define MOD_FOR_EACH(pos, head)		\
	list_for_each_entry(pos, head, list)

#define MOD_FOR_EACH_REVERSE(pos, head)	\
	list_for_each_entry_reverse(pos, head, list)

void tfw_mod_register(TfwMod *mod);
void tfw_mod_unregister(TfwMod *mod);
TfwMod *tfw_mod_find(const char *name);

bool tfw_runstate_is_reconfig(void);

void tfw_objects_wait_release(const atomic64_t *counter, int delay,
			      const char *name);
/**
 * For !CONFIG_PREEMPT kernels, a CPU looping anywhere in the kernel without
 * invoking schedule() can lead to RCU CPU stall, so the function call the
 * scheduler and waits for RCU callbacks to catch up the calling context
 * (e.g. massive server groups updates on configuration reload).
 * Should be used from process context only and for potentially long running
 * loops.
 */
static inline void
tfw_srv_loop_sched_rcu(void)
{
	cond_resched_rcu_qs();
	rcu_barrier_bh();
}

#endif /* __TEMPESTA_FW_H__ */
