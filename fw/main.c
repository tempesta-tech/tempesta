/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#include <linux/string.h>
#include <net/net_namespace.h> /* for sysctl */

#include "tempesta_fw.h"
#include "cfg.h"
#include "client.h"
#include "log.h"
#include "server.h"
#include "str.h"
#include "sync_socket.h"
#include "lib/fsm.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION(TFW_NAME);
MODULE_VERSION(TFW_VERSION);
MODULE_LICENSE("GPL");

#define T_SYSCTL_STBUF_LEN		32UL

typedef void (*exit_fn)(void);
exit_fn exit_hooks[32];
size_t  exit_hooks_n;

typedef enum {
	TFW_STATE_STOPPED = 0,
	TFW_STATE_STARTED,
	TFW_STATE_STARTED_FAIL_RECONFIG,
} TfwState;

DEFINE_MUTEX(tfw_sysctl_mtx);
static TfwState tfw_state = TFW_STATE_STOPPED;
static bool tfw_reconfig = false;
static int tfw_ss_users = 0;

/*
 * The global list of all registered modules
 * (consists of TfwMod{} objects).
 */
static LIST_HEAD(tfw_mods);
static DEFINE_RWLOCK(tfw_mods_lock);

/**
 * Return true if Tempesta is reconfiguring, and false otherwise.
 */
bool
tfw_runstate_is_reconfig(void)
{
	return READ_ONCE(tfw_reconfig);
}

bool
tfw_runstate_is_started_success(void)
{
	return READ_ONCE(tfw_state) == TFW_STATE_STARTED;
}

/**
 * Return true if Tempesta is started, and false otherwise.
 */
bool
tfw_runstate_is_started(void)
{
	return READ_ONCE(tfw_state) != TFW_STATE_STOPPED;
}

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
	T_DBG2("%s: %s\n", __func__, mod->name);

	write_lock(&tfw_mods_lock);
	INIT_LIST_HEAD(&mod->list);
	list_add_tail(&mod->list, &tfw_mods);
	write_unlock(&tfw_mods_lock);
}

/**
 * Remove the @mod from the global list.
 */
void
tfw_mod_unregister(TfwMod *mod)
{
	BUG_ON(!mod || !mod->name);
	T_DBG2("%s: %s\n", __func__, mod->name);

	write_lock(&tfw_mods_lock);
	list_del(&mod->list);
	write_unlock(&tfw_mods_lock);
}

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

static void
tfw_cleanup(void)
{
	tfw_cfg_cleanup(&tfw_mods);

	if (!tfw_runstate_is_reconfig())
		tfw_sg_wait_release();
	T_DBG("New configuration is cleaned.\n");
}

static void
tfw_mods_stop(void)
{
	TfwMod *mod;
	bool ss_synced = false;

	ss_stop();

	T_DBG("Stopping all modules...\n");
	MOD_FOR_EACH_REVERSE(mod, &tfw_mods) {
		T_DBG2("mod_stop(): %s\n", mod->name);
		if (!mod->stop || !mod->started)
			continue;

		mod->stop();
		mod->started = 0;

		tfw_ss_users -= mod->sock_user;
		if (ss_synced || tfw_ss_users)
			continue;
		/*
		 * Wait until all network activity is stopped before data in
		 * modules can be cleaned up safely. We must do this between
		 * stopping modules using synchronous sockets and modules
		 * providing data structures for the first modules.
		 * In particular, we need to stop all networking activity after
		 * stopping sock_clnt and during the synchronization period the
		 * client database must provide valid references to stored
		 * clients.
		 */
		if (!ss_synchronize()) {
			tfw_cli_abort_all();
			/* Check that all the connections are terminated now. */
			WARN_ON(!ss_synchronize());
		}
		ss_synced = true;
	}
	BUG_ON(tfw_ss_users);

	T_LOG("modules are stopped\n");
}

static void
tfw_stop(void)
{
	tfw_mods_stop();
	tfw_cleanup();
}

static int
tfw_mods_cfgstart(void)
{
	int ret;
	TfwMod *mod;

	T_DBG2("Prepare the configuration processing...\n");
	MOD_FOR_EACH(mod, &tfw_mods) {
		if (!mod->cfgstart)
			continue;
		T_DBG2("mod_cfgstart(): %s\n", mod->name);
		if ((ret = mod->cfgstart())) {
			T_ERR_NL("Unable to prepare for the configuration "
				 "of module '%s': %d\n", mod->name, ret);
			return ret;
		}
	}
	T_DBG("Preparing for the configuration processing.\n");

	return 0;
}

static int
tfw_mods_start(void)
{
	int ret;
	TfwMod *mod;

	T_DBG2("starting modules...\n");
	MOD_FOR_EACH(mod, &tfw_mods) {
		BUG_ON(mod->sock_user && (!mod->start || !mod->stop));

		if (!mod->start)
			continue;
		T_DBG2("mod_start(): %s\n", mod->name);
		if ((ret = mod->start())) {
			T_ERR_NL("Unable to start module '%s': %d\n",
				 mod->name, ret);
			if (mod->stop) {
				mod->stop();
				mod->started = 0;
			}
			return ret;
		}
		mod->started = 1;

		if (!tfw_runstate_is_reconfig())
			tfw_ss_users += mod->sock_user;
	}
	T_DBG("modules are started\n");

	return 0;
}

static int
tfw_mods_cfgend(void)
{
	int ret;
	TfwMod *mod;

	T_DBG2("Completing the configuration processing...\n");
	MOD_FOR_EACH(mod, &tfw_mods) {
		if (!mod->cfgend)
			continue;
		T_DBG2("mod_cfgend(): %s\n", mod->name);
		if ((ret = mod->cfgend())) {
			T_ERR_NL("Unable to complete the configuration "
				 "of module '%s': %d\n", mod->name, ret);
			return ret;
		}
	}
	T_LOG("Configuration processing is completed.\n");

	return 0;
}

static int
tfw_start(void)
{
	int ret;

	ss_start();
	if ((ret = tfw_mods_cfgstart()))
		goto cleanup;
	if ((ret = tfw_cfg_parse(&tfw_mods)))
		goto cleanup;
	if ((ret = tfw_mods_cfgend()))
		goto cleanup;
	if ((ret = tfw_mods_start()))
		goto stop_mods;
	tfw_cfg_conclude(&tfw_mods);
	WRITE_ONCE(tfw_state, TFW_STATE_STARTED);

	T_LOG_NL("Tempesta FW is ready\n");

	return 0;
stop_mods:
	/*
	 * Live reconfiguration successfully parsed but failed just in the
	 * middle of replacing the old configuration. This cannot be fixed
	 * and Tempesta must be fully stopped and cleared.
	 */
	WRITE_ONCE(tfw_reconfig, false);
	tfw_mods_stop();
	WRITE_ONCE(tfw_state, TFW_STATE_STOPPED);
cleanup:
	T_WARN_NL("Configuration parsing has failed. Clean up...\n");
	if (READ_ONCE(tfw_state) == TFW_STATE_STARTED)
		WRITE_ONCE(tfw_state, TFW_STATE_STARTED_FAIL_RECONFIG);
	tfw_cleanup();
	return ret;
}

/**
 * Process command received from sysctl as string (either "start" or "stop").
 * Do corresponding actions, but only if the state is changed.
 */
static int
tfw_ctlfn_state_change(const char *new_state)
{
	T_DBG2("got state via sysctl: %s\n", new_state);

	if (!strcasecmp("start", new_state)) {
		int r;

		if (tfw_runstate_is_started()) {
			WRITE_ONCE(tfw_reconfig, true);
			T_LOG("Live reconfiguration of Tempesta.\n");
		}

		r = tfw_start();
		WRITE_ONCE(tfw_reconfig, false);

		return r;
	}

	if (!strcasecmp("stop", new_state)) {
		if (!tfw_runstate_is_started()) {
			T_WARN_NL("Trying to stop an inactive system\n");
			return -EINVAL;
		}

		tfw_stop();
		WRITE_ONCE(tfw_state, TFW_STATE_STOPPED);

		return 0;
	}

	T_ERR_NL("invalid state: '%s'. Should be either 'start' or 'stop'\n",
		 new_state);

	return -EINVAL;
}

/**
 * Syctl handler for tempesta.state read/write operations.
 */
static int
tfw_ctlfn_state_io(struct ctl_table *ctl, int is_write,
		   void *user_buf, size_t *lenp, loff_t *ppos)
{
	int r = 0;
	static char new_state_buf[T_SYSCTL_STBUF_LEN];
	struct ctl_table tmp = *ctl;

	mutex_lock(&tfw_sysctl_mtx);

	if (is_write) {
		char buf[T_SYSCTL_STBUF_LEN];
		char start[T_SYSCTL_STBUF_LEN] = "start";
		char stop[T_SYSCTL_STBUF_LEN] = "stop";
		char start_fail_reconfig[T_SYSCTL_STBUF_LEN] =
			"start (failed reconfig)";

		tmp.data = buf;
		if ((r = proc_dostring(&tmp, is_write, user_buf, lenp, ppos)))
			goto out;

		r = tfw_ctlfn_state_change(buf);
		if (READ_ONCE(tfw_state) == TFW_STATE_STOPPED) {
			strlcpy(new_state_buf, stop, T_SYSCTL_STBUF_LEN);
		} else if (READ_ONCE(tfw_state) == TFW_STATE_STARTED) {
			strlcpy(new_state_buf, start, T_SYSCTL_STBUF_LEN);
		} else {
			strlcpy(new_state_buf, start_fail_reconfig,
				T_SYSCTL_STBUF_LEN);
		}
	} else {
		tmp.data = new_state_buf;
		r = proc_dostring(&tmp, is_write, user_buf, lenp, ppos);
	}
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
			T_ERR_NL("Bug in %s reference counting!\n", obj_name);
			break;
		}
		else if (curr_n == last_n) {
			T_ERR_NL("Got stuck in releasing of %s objects! "
				 "%ld objects was not released.\n",
				 obj_name, curr_n);
			break;
		}
		T_WARN_NL("pending for %s callbacks to complete for %ds, "
			  "%ld objects was released, %ld still exist\n",
			  obj_name, delay, last_n - curr_n, curr_n);
		tend = jiffies + HZ * delay;
		last_n = curr_n;
	}
}

static struct ctl_table_header *tfw_sysctl_hdr;
static struct ctl_table tfw_sysctl_tbl[] = {
	{
		.procname	= "state",
		.maxlen		= T_SYSCTL_STBUF_LEN - 1,
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
	T_DBG("init: %s\n", #mod);				\
	r = tfw_##mod##_init();					\
	if (r) {						\
		T_ERR_NL("can't initialize Tempesta FW module: '%s' (%d)\n", \
			   #mod, r);				\
		goto err;					\
	}							\
	exit_hooks[exit_hooks_n++] = tfw_##mod##_exit;		\
} while (0)

static void
tfw_exit(void)
{
	int i;

	T_LOG_NL("exiting...\n");

	/* Let's put this under the same mutex as the sysctl callback
	 * to avoid concurrent shutdown calls */
	mutex_lock(&tfw_sysctl_mtx);
	if (tfw_runstate_is_started()) {
		T_WARN_NL("Tempesta FW is still running, shutting down...\n");
		tfw_stop();
		WRITE_ONCE(tfw_state, TFW_STATE_STOPPED);
	}
	mutex_unlock(&tfw_sysctl_mtx);

	/* Wait for outstanding RCU callbacks to complete. */
	rcu_barrier();

	for (i = exit_hooks_n - 1; i >= 0; --i)
		exit_hooks[i]();

	unregister_net_sysctl_table(tfw_sysctl_hdr);
}

static int __init
tfw_init(void)
{
	int r;

	T_LOG("Initializing Tempesta FW kernel module...\n");

#ifndef AVX2
	T_LOG("ATTENTION: TEMPESTA IS BUILT WITHOUT AVX2 SUPPORT, "
	      "PERFORMANCE IS DEGRADED.");
#endif

	tfw_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta",
					     tfw_sysctl_tbl);
	if (!tfw_sysctl_hdr) {
		T_ERR_NL("can't register sysctl table\n");
		return -1;
	}

	/* The order of initialization is highly important. */
	DO_INIT(pool);
	DO_INIT(cfg);
	DO_INIT(access_log);
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
	DO_INIT(websocket);

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
