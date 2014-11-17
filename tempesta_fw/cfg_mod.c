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

#include "cfg_private_log.h"
#include "cfg_mod.h"

/* TODO: synchronize access to these variables. */
static LIST_HEAD(tfw_cfg_mod_list);
static bool mods_are_started;


static int
mod_start(TfwCfgMod *mod)
{
	int ret = 0;

	LOG("start module: %s\n", mod->name);

	BUG_ON(mod->is_started);
	if (mod->start) {
		ret = mod->start();
		if (ret)
			ERR("can't start module: '%s', err: %d\n",
			    mod->name, ret);
	}
	mod->is_started = true;

	return ret;
}

static void
mod_stop(TfwCfgMod *mod)
{
	DBG("stop module: %s\n", mod->name);

	BUG_ON(!mod->is_started);
	if (mod->stop)
		mod->stop();
	mod->is_started = false;
}

int
tfw_cfg_mod_register(TfwCfgMod *mod)
{
	BUG_ON(!mod || !mod->name);

	DBG("register module: %s\n", mod->name);

	/* Nothing to do at all? Why register then? */
	BUG_ON(!mod->spec_arr && !mod->start && !mod->stop);

	INIT_LIST_HEAD(&mod->list);
	list_add(&mod->list, &tfw_cfg_mod_list);

	if (mods_are_started)
		return mod_start(mod);

	return 0;
}

void
tfw_cfg_mod_unregister(TfwCfgMod *mod)
{
	BUG_ON(!mod || !mod->name);

	DBG("unregister module: %s\n", mod->name);

	if (mods_are_started)
		mod_stop(mod);

	/* If the module was not registered, then the list_del() will BUG(). */
	list_del(&mod->list);
}

int tfw_cfg_mod_start_all(void)
{
	int ret;
	TfwCfgMod *mod;

	DBG("starting all modules\n");

	BUG_ON(mods_are_started);
	WARN_ON(list_empty(&tfw_cfg_mod_list));

	list_for_each_entry(mod, &tfw_cfg_mod_list, list) {
		ret = mod_start(mod);
		if (ret)
			break;

	}

	if (ret) {
		DBG("stopping already started modules\n");
		list_for_each_entry_reverse(mod, &tfw_cfg_mod_list, list) {
			if (mod->is_started)
				mod_stop(mod);
		}
	} else {
		mods_are_started = true;
	}

	return ret;
}

void tfw_cfg_mod_stop_all(void)
{
	TfwCfgMod *mod;

	DBG("stopping all modules\n");

	BUG_ON(!mods_are_started);
	WARN_ON(list_empty(&tfw_cfg_mod_list));

	list_for_each_entry(mod, &tfw_cfg_mod_list, list) {
		mod_stop(mod);
	}

	mods_are_started = false;
}

int
tfw_cfg_mod_publish_new_cfg(TfwCfgNode *parsed_cfg_root)
{
	int ret;
	TfwCfgMod *mod;

	DBG("publishing new configuration across all registered modules\n");

	list_for_each_entry(mod, &tfw_cfg_mod_list, list) {
		if (!mod->spec_arr) {
			DBG("module has no spec defined: %s\n", mod->name);
		} else {
			DBG("pushing new cfg to module: %s\n", mod->name)

			ret = tfw_cfg_spec_apply(mod->spec_arr, parsed_cfg_root);
			if (ret) {
				ERR("can't push new configuration to module: %s\n",
				    mod->name);
				break;
			}
		}
	}

	return ret;
}
