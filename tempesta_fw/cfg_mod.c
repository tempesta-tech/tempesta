/**
 *		Tempesta FW
 *
 * This unit implements a global list of Tempesta FW modules.
 *
 * Basically it implements a publish-subscribe pattern.
 * Modules subscribe to start/stop events and some sysctl handler publishes
 * the event (and attaches a new configuration tree).
 *
 * So the responsibility of this unit is to distribute start/stop events and
 * configuration updates across all modules registered in a running system.
 *
 * Also, new configuration has to be applied before starting the modules,
 * so tfw_cfg_mod_start_all() takes the parsed TfwCfgNode as an argument and
 * distributes it across the registered modules before starting them.
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

#include "cfg_mod.h"
#include "cfg_private.h"

/* TODO: synchronize access to these global variables. */

/**
 * At this point we start/stop the whole system and don't allow separate modules
 * to change the state. Also that implies, that a new module may be added only
 * when the system is stopped.
 * So this variable is used to check this constraint.
 */
static bool mods_are_started;

/**
 * Modules may hold references to parsed confugration objects during their
 * operation, so we are storing it here between setup/cleanup events.
 */
TfwCfgNode *current_cfg;

/* The global list of all registered modules (consists of TfwCfgMod objects). */
static LIST_HEAD(tfw_cfg_mod_list);

#define FOR_EACH_MOD(pos) \
	list_for_each_entry(pos, &tfw_cfg_mod_list, list)

#define FOR_EACH_MOD_REVERSE(pos) \
	list_for_each_entry_reverse(pos, &tfw_cfg_mod_list, list)

#define FOR_EACH_MOD_SAFE_REVERSE(pos, tmp) \
	list_for_each_entry_safe_reverse(pos, tmp, &tfw_cfg_mod_list, list)

/**
 * Iterate over modules in the reverse order starting from an element which
 * is previous to the @curr_pos.
 *
 * Assume you are iterating over all modules and do some operation, and it is
 * failed for the current module (pointed by @curr_pos). Then you would like to
 * iterate over already processed modules and cancel the operation for them,
 * so this macro helps you to do that.
 */
#define FOR_EACH_MOD_REVERSE_FROM_PREV(pos, curr_pos) \
	for (pos = list_entry(curr_pos->list.prev, TfwCfgMod, list);  \
	     &pos->list != &tfw_cfg_mod_list; \
	     pos = list_entry(pos->list.prev, TfwCfgMod, list))


/* The following macros generate shortcut functions for invoking
 * callbacks specified in TfwCfgMod.
 *
 * A generated function looks like this:
 *
 *    int call_mod_start(const TfwCfgMod *mod)
 *    {
 *            int ret = 0;
 *            if (mod->mod_start)
 *                    ret = mod->mod_start();
 *            return ret;
 *    }
 */

#define DEFINE_CB(callback_name) 				\
static void 							\
call_mod_##callback_name(const TfwCfgMod *mod)			\
{								\
	DBG("mod_%s(): %s\n", #callback_name, mod->name);	\
	if (mod->callback_name)					\
		mod->callback_name();				\
}

#define DEFINE_CB_RET(callback_name)				\
static int							\
call_mod_##callback_name(const TfwCfgMod *mod)			\
{								\
	int ret = 0;						\
	DBG("mod_%s(): %s\n", #callback_name, mod->name);	\
	if (mod->callback_name)					\
		ret = mod->callback_name();			\
	if (ret)						\
		ERR("failed: mod_%s(): %s\n", #callback_name, mod->name); \
	return ret;						\
}

DEFINE_CB_RET(init);
DEFINE_CB_RET(setup);
DEFINE_CB_RET(start);
DEFINE_CB(stop);
DEFINE_CB(cleanup);
DEFINE_CB(exit);


/**
 * Add @mod to the global list of registered modules and call @mod->init.
 *
 * After the registration the module starts receiving start/stop/setup/cleanup
 * events and configuration updates.
 */
int
tfw_cfg_mod_register(TfwCfgMod *mod)
{
	int ret;

	BUG_ON(!mod || !mod->name);

	LOG("register module: %s\n", mod->name);

	if (mods_are_started) {
		ERR("can't register module: %s - other modules are running and"
		    "have to be stopped before a new module can be added\n",
		    mod->name);

		/* Should not do BUG() here because the function may be called
		 * from other kernel modules, and inserting a module while the
		 * Tempesta is running should return an error code. */
		return -EPERM;
	}

	ret = call_mod_init(mod);
	if (ret) {
		ERR("can't register module: %s - init callback returned error: "
		    "%d\n", mod->name, ret);
		return ret;
	}

	INIT_LIST_HEAD(&mod->list);
	list_add_tail(&mod->list, &tfw_cfg_mod_list);

	return 0;
}
EXPORT_SYMBOL(tfw_cfg_mod_register);

/**
 * Remove the @mod from the global list and call the @mod->exit callback.
 */
void
tfw_cfg_mod_unregister(TfwCfgMod *mod)
{
	BUG_ON(!mod || !mod->name);

	/* The function is called from a module_exit() routine, so there is no
	 * sense to return an error code here. */
	WARN(mods_are_started, "removing module '%s' while other modules "
	     "are running. Modules may hold references to each other, so "
	     "removing a module while the system is running is dangerous.",
	     mod->name);

	list_del(&mod->list);
	call_mod_exit(mod);
}
EXPORT_SYMBOL(tfw_cfg_mod_unregister);

/**
 * Propagate new configuration to all modules and then start them.
 *
 * The operation is done in 5 passes (1 pass = iterate across all modules):
 *  1. Populate @new_cfg with default values.
 *  2. Validate @new_cfg against module specs.
 *  3. Invoke "setup" callbacks.
 *  4. Apply @new_cfg (push it to modules according to rules specified in
 *     their specs).
 *  5. Invoke "start" callbacks.
 *
 *  So many separate passes are done for:
 *  - Easier error handling: we don't start modules unless all the configuration
 *    is valid and accepted by all modules.
 *  - Simpler and more structured code: modules have to provide different
 *    callbacks for distinct tasks.
 *  - Weaker module initialization order: in a "start" callback, a module may
 *    reference another module and safely assume that it is ready to start.
 *
 * In case of any error the function tries to roll-back: it stops and cleans
 * already started modules and thus leaves them in a consistent state.
 *
 * In case of success, you must not free @new_cfg, it is saved until all
 * modules are stopped (a "cleanup" is performed), and then freed automatically.
 */
int
tfw_cfg_mod_start_all(TfwCfgNode *new_cfg)
{
	int ret;
	TfwCfgMod *mod, *tmp_mod;

	DBG("starting all modules\n");

	BUG_ON(mods_are_started);
	BUG_ON(current_cfg);
	WARN_ON(list_empty(&tfw_cfg_mod_list));

	FOR_EACH_MOD(mod) {
		if (mod->cfg_spec_arr) {
			DBG("set config defaults: %s\n", mod->name);
			tfw_cfg_spec_set_defaults(mod->cfg_spec_arr, new_cfg);
		}
	}

	FOR_EACH_MOD(mod) {
		if (mod->cfg_spec_arr) {
			DBG("validate config: %s\n", mod->name);
			ret = tfw_cfg_spec_validate(mod->cfg_spec_arr, new_cfg);
			if (ret)
				goto err_norecover;
		}
	}

	FOR_EACH_MOD(mod) {
		ret = call_mod_setup(mod);
		if (ret)
			goto err_recover_cleanup;
	}

	FOR_EACH_MOD(mod) {
		if (mod->cfg_spec_arr) {
			DBG("apply config: %s\n", mod->name);
			ret = tfw_cfg_spec_apply(mod->cfg_spec_arr, new_cfg);
			if (ret)
				goto err_recover_cleanup;
		}
	}

	FOR_EACH_MOD(mod) {
		ret = call_mod_start(mod);
		if (ret)
			goto err_recover_stop;
	}

	mods_are_started = true;
	current_cfg = new_cfg;

	return 0;

err_recover_stop:
	DBG("stopping already stared modules\n");
	FOR_EACH_MOD_REVERSE_FROM_PREV(tmp_mod, mod) {
		call_mod_stop(tmp_mod);
	}

err_recover_cleanup:
	DBG("cleaning up already initialized modules\n");
	FOR_EACH_MOD_REVERSE_FROM_PREV(tmp_mod, mod) {
		call_mod_cleanup(tmp_mod);
	}

err_norecover:
	return ret;
}

/**
 * Propagate 'stop' command to all registered modules.
 *
 * That is done in two passes:
 * 1. Invoke "stop" callback for all modules.
 * 2. Invoke "cleanup" callback for all modules.
 *
 * The two distinct passes are done because modules may hold references to
 * each other, so we want to make sure that at the point of "cleanup" (where
 * memory is freed) all modules are stopped and no work is happening in the
 * background and therefore no already freed memory can be accessed.
 *
 * Passes are done in reverse order of tfw_cfg_mod_start_all()
 * (modules are started/stopped in LIFO manner).
 */
void tfw_cfg_mod_stop_all(void)
{
	TfwCfgMod *mod;

	DBG("stopping all modules\n");

	BUG_ON(!mods_are_started);
	BUG_ON(!current_cfg);
	WARN_ON(list_empty(&tfw_cfg_mod_list));

	FOR_EACH_MOD_REVERSE(mod) {
		call_mod_stop(mod);
	}

	FOR_EACH_MOD_REVERSE(mod) {
		call_mod_cleanup(mod);
	}

	tfw_cfg_node_free(current_cfg);
	current_cfg = NULL;
	mods_are_started = false;
}

/**
 * The shutdown routine: stop and unregister all modules.
 */
void
tfw_cfg_mod_exit_all(void)
{
	TfwCfgMod *mod, *tmp;

	DBG("unregistering all modules\n");

	if (mods_are_started)
		tfw_cfg_mod_stop_all();

	FOR_EACH_MOD_SAFE_REVERSE(mod, tmp) {
		tfw_cfg_mod_unregister(mod);
	}
}
