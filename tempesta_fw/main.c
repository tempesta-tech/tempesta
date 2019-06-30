/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include <linux/types.h> /* must be the first */
#include <asm/fpu/api.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/net_namespace.h> /* for sysctl */

#include "tempesta_fw.h"
#include "cfg.h"
#include "client.h"
#include "log.h"
#include "str.h"
#include "sync_socket.h"
#include "server.h"
#include "vhost.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION(TFW_NAME);
MODULE_VERSION(TFW_VERSION);
MODULE_LICENSE("GPL");

typedef void (*exit_fn)(void);
exit_fn exit_hooks[32];
size_t  exit_hooks_n;

DEFINE_MUTEX(tfw_sysctl_mtx);
static bool tfw_started = false;
static bool tfw_reconfig = false;

/*
 * The global list of all registered modules
 * (consists of TfwMod{} objects).
 */
static LIST_HEAD(tfw_mods);
static DEFINE_RWLOCK(tfw_mods_lock);

/**
 * Return true if Tempesta is running, and false otherwise.
 */
bool
tfw_runstate_is_reconfig(void)
{
	return READ_ONCE(tfw_reconfig);
}
EXPORT_SYMBOL(tfw_runstate_is_reconfig);

/**
 * Add @mod to the global list of registered modules.
 *
 * After the registration the module will start receiving
 * start/stop/setup/cleanup events and configuration updates.
 */
void
tfw_mod_register(TfwMod *mod)
{
	BUG_ON(!mod || !mod->name);
	TFW_DBG2("%s: %s\n", __func__, mod->name);

	write_lock(&tfw_mods_lock);
	INIT_LIST_HEAD(&mod->list);
	list_add_tail(&mod->list, &tfw_mods);
	write_unlock(&tfw_mods_lock);
}
EXPORT_SYMBOL(tfw_mod_register);

/**
 * Remove the @mod from the global list.
 */
void
tfw_mod_unregister(TfwMod *mod)
{
	BUG_ON(!mod || !mod->name);
	TFW_DBG2("%s: %s\n", __func__, mod->name);

	write_lock(&tfw_mods_lock);
	list_del(&mod->list);
	write_unlock(&tfw_mods_lock);
}
EXPORT_SYMBOL(tfw_mod_unregister);

TfwMod *
tfw_mod_find(const char *name)
{
	TfwMod *mod;

	read_lock(&tfw_mods_lock);
	list_for_each_entry(mod, &tfw_mods, list) {
		if (!name || !strcasecmp(name, mod->name)) {
			read_unlock(&tfw_mods_lock);
			return mod;
		}
	}
	read_unlock(&tfw_mods_lock);

	return NULL;
}

static inline void
tfw_cleanup(struct list_head *mod_list)
{
	/*
	 * Wait until all network activity is stopped
	 * before data in modules can be cleaned up safely.
	 */
	if (!tfw_runstate_is_reconfig())
		ss_synchronize();

	tfw_cfg_cleanup(mod_list);

	if (!tfw_runstate_is_reconfig())
		tfw_sg_wait_release();
	TFW_LOG("New configuration is cleaned.\n");
}

static inline void
tfw_mods_stop(struct list_head *mod_list)
{
	TfwMod *mod;

	ss_stop();

	TFW_LOG("Stopping all modules...\n");
	MOD_FOR_EACH_REVERSE(mod, mod_list) {
		TFW_DBG2("mod_stop(): %s\n", mod->name);
		if (mod->stop && mod->started) {
			mod->stop();
			mod->started = 0;
		}
	}

	TFW_LOG("modules are stopped\n");
}

static void
tfw_stop(struct list_head *mod_list)
{
	tfw_mods_stop(mod_list);
	tfw_cleanup(mod_list);
}

static int
tfw_mods_cfgstart(struct list_head *mod_list)
{
	int ret;
	TfwMod *mod;

	TFW_DBG2("Prepare the configuration processing...\n");
	MOD_FOR_EACH(mod, mod_list) {
		if (!mod->cfgstart)
			continue;
		TFW_DBG2("mod_cfgstart(): %s\n", mod->name);
		if ((ret = mod->cfgstart())) {
			TFW_ERR_NL("Unable to prepare for the configuration "
				   "of module '%s': %d\n", mod->name, ret);
			return ret;
		}
	}
	TFW_LOG("Preparing for the configuration processing.\n");

	return 0;
}

static int
tfw_mods_start(struct list_head *mod_list)
{
	int ret;
	TfwMod *mod;

	TFW_DBG2("starting modules...\n");
	MOD_FOR_EACH(mod, mod_list) {
		if (!mod->start)
			continue;
		TFW_DBG2("mod_start(): %s\n", mod->name);
		if ((ret = mod->start())) {
			TFW_ERR_NL("Unable to start module '%s': %d\n",
				   mod->name, ret);
			return ret;
		}
		mod->started = 1;
	}
	TFW_LOG("modules are started\n");

	return 0;
}

static int
tfw_mods_cfgend(struct list_head *mod_list)
{
	int ret;
	TfwMod *mod;

	TFW_DBG2("Completing the configuration processing...\n");
	MOD_FOR_EACH(mod, mod_list) {
		if (!mod->cfgend)
			continue;
		TFW_DBG2("mod_cfgend(): %s\n", mod->name);
		if ((ret = mod->cfgend())) {
			TFW_ERR_NL("Unable to complete the configuration "
				   "of module '%s': %d\n", mod->name, ret);
			return ret;
		}
	}
	TFW_LOG("Configuration processing is completed.\n");

	return 0;
}

static int
tfw_start(struct list_head *mod_list)
{
	int ret;

	ss_start();
	if ((ret = tfw_mods_cfgstart(mod_list)))
		goto cleanup;
	if ((ret = tfw_cfg_parse(mod_list)))
		goto cleanup;
	if ((ret = tfw_mods_cfgend(mod_list)))
		goto cleanup;
	if ((ret = tfw_mods_start(mod_list)))
		goto stop_mods;
	tfw_cfg_conclude(mod_list);
	WRITE_ONCE(tfw_started, true);
	return 0;
stop_mods:
	/*
	 * Live reconfiguration successfully parsed but failed just in the
	 * middle of replacing the old configuration. This cannot be fixed
	 * and Tempesta must be fully stopped and cleared.
	 */
	WRITE_ONCE(tfw_reconfig, false);
	tfw_mods_stop(mod_list);
	WRITE_ONCE(tfw_started, false);
cleanup:
	TFW_WARN_NL("Configuration parsing has failed. Clean up...\n");
	tfw_cleanup(mod_list);
	return ret;
}

/**
 * Process command received from sysctl as string (either "start" or "stop").
 * Do corresponding actions, but only if the state is changed.
 */
static int
tfw_ctlfn_state_change(const char *old_state, const char *new_state)
{
	TFW_DBG2("got state via sysctl: %s\n", new_state);

	if (!strcasecmp("start", new_state)) {
		int r;

		if (READ_ONCE(tfw_started)) {
			WRITE_ONCE(tfw_reconfig, true);
			TFW_LOG("Live reconfiguration of Tempesta.\n");
		}

		r = tfw_start(&tfw_mods);
		WRITE_ONCE(tfw_reconfig, false);

		return r;
	}

	if (!strcasecmp("stop", new_state)) {
		if (!READ_ONCE(tfw_started)) {
			TFW_WARN_NL("Trying to stop an inactive system\n");
			return -EINVAL;
		}

		tfw_stop(&tfw_mods);
		WRITE_ONCE(tfw_started, false);

		return 0;
	}

	TFW_ERR_NL("invalid state: '%s'. Should be either 'start' or 'stop'\n",
		   new_state);

	return -EINVAL;
}

/**
 * Syctl handler for tempesta.state read/write operations.
 */
static int
tfw_ctlfn_state_io(struct ctl_table *ctl, int is_write,
		   void __user *user_buf, size_t *lenp, loff_t *ppos)
{
	int r = 0;

	mutex_lock(&tfw_sysctl_mtx);

	if (is_write) {
		char new_state_buf[ctl->maxlen];
		char *new_state, *old_state;
		size_t copied_data_len;

		copied_data_len = min((size_t)ctl->maxlen, *lenp);
		r = strncpy_from_user(new_state_buf, user_buf, copied_data_len);
		if (r < 0)
			goto out;

		new_state_buf[r] = 0;
		new_state = strim(new_state_buf);
		old_state = ctl->data;

		r = tfw_ctlfn_state_change(old_state, new_state);
		if (r)
			goto out;
	}

	r = proc_dostring(ctl, is_write, user_buf, lenp, ppos);
out:
	mutex_unlock(&tfw_sysctl_mtx);
	return r;
}

/**
 * Wait until all objects of some specific type @obj_name are
 * destructed. The count of objects is specified in atomic @counter.
 * The maximum time to wait is @delay seconds. The function is called
 * after ss_synchronize(), after configuration cleanup: there shouldn't
 * be any active connections, but this is still possible.
 */
void
tfw_objects_wait_release(const atomic64_t *counter, int delay,
			 const char *obj_name)
{
	unsigned long tend = jiffies + HZ * delay;
	long last_n = atomic64_read(counter), curr_n;

	might_sleep();
	/*
	 * Wait in a cycle until all objects will be destroyed.
	 */
	while ((curr_n = atomic64_read(counter))) {
		schedule();
		if (time_is_after_jiffies(tend))
			continue;
		if (curr_n < 0) {
			TFW_ERR_NL("Bug in %s reference counting!\n", obj_name);
			break;
		}
		else if (curr_n == last_n) {
			TFW_ERR_NL("Got stuck in releasing of %s objects! "
				   "%ld objects was not released.\n",
				   obj_name, curr_n);
			break;
		}
		TFW_WARN_NL("pending for %s callbacks to complete for %ds, "
			    "%ld objects was released, %ld still exist\n",
			    obj_name, delay, last_n - curr_n, curr_n);
		tend = jiffies + HZ * delay;
		last_n = curr_n;
	}
}

static char tfw_sysctl_state_buf[32];
static struct ctl_table_header *tfw_sysctl_hdr;
static struct ctl_table tfw_sysctl_tbl[] = {
	{
		.procname	= "state",
		.data		= tfw_sysctl_state_buf,
		.maxlen		= sizeof(tfw_sysctl_state_buf) - 1,
		.mode		= 0644,
		.proc_handler	= tfw_ctlfn_state_io,
	},
	{}
};

#define DO_INIT(mod)						\
do {								\
	extern int tfw_##mod##_init(void);			\
	extern void tfw_##mod##_exit(void);			\
	BUG_ON(exit_hooks_n >= ARRAY_SIZE(exit_hooks));		\
	TFW_DBG("init: %s\n", #mod);				\
	r = tfw_##mod##_init();					\
	if (r) {						\
		TFW_ERR_NL("can't initialize Tempesta FW module: '%s' (%d)\n", \
			   #mod, r);				\
		goto err;					\
	}							\
	exit_hooks[exit_hooks_n++] = tfw_##mod##_exit;		\
} while (0)

static void
tfw_exit(void)
{
	int i;

	TFW_LOG("exiting...\n");

	/* Wait for outstanding RCU callbacks to complete. */
	rcu_barrier_bh();

	for (i = exit_hooks_n - 1; i >= 0; --i)
		exit_hooks[i]();

	unregister_net_sysctl_table(tfw_sysctl_hdr);
}

static int __init
tfw_init(void)
{
	int r;

	TFW_LOG("Initializing Tempesta FW kernel module...\n");

#ifndef AVX2
	TFW_LOG("ATTENTION: TEMPESTA IS BUILT WITHOUT AVX2 SUPPORT, "
		"PERFORMANCE IS DEGRADED.");
#endif

	tfw_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta",
					     tfw_sysctl_tbl);
	if (!tfw_sysctl_hdr) {
		TFW_ERR_NL("can't register sysctl table\n");
		return -1;
	}

	/* The order of initialization is highly important. */
	DO_INIT(pool);
	DO_INIT(cfg);
	DO_INIT(apm);
	DO_INIT(vhost);

	/*
	 * Register in order TLS -> HTTP -> limits, for correct
	 * registration of FSM hooks.
	 */
	DO_INIT(tls);
	DO_INIT(http);
	DO_INIT(http_limits);
	DO_INIT(filter);
	DO_INIT(cache);
	DO_INIT(http_sess);

	DO_INIT(sync_socket);
	DO_INIT(server);
	DO_INIT(client);
	DO_INIT(sock_srv);
	DO_INIT(sock_clnt);
	DO_INIT(procfs);
	DO_INIT(http_tbl);
	DO_INIT(sched_hash);
	DO_INIT(sched_ratio);

	return 0;
err:
	tfw_exit();
	return r;
}

module_init(tfw_init);
module_exit(tfw_exit);
