/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2017 Tempesta Technologies, Inc.
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
#include <asm/fpu/api.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <net/net_namespace.h> /* for sysctl */

#include "tempesta_fw.h"
#include "cfg.h"
#include "log.h"
#include "str.h"
#include "sync_socket.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION(TFW_NAME);
MODULE_VERSION(TFW_VERSION);
MODULE_LICENSE("GPL");

typedef void (*exit_fn)(void);
exit_fn exit_hooks[32];
size_t  exit_hooks_n;

DEFINE_MUTEX(tfw_sysctl_mtx);
static bool tfw_started = false;

/**
 * Process command received from sysctl as string (either "start" or "stop").
 * Do corresponding actions, but only if the state is changed.
 */
static int
handle_state_change(const char *old_state, const char *new_state)
{
	TFW_DBG2("got state via sysctl: %s\n", new_state);

	if (!strcasecmp(old_state, new_state)) {
		TFW_DBG2("the state '%s' isn't changed, nothing to do\n",
			 new_state);
		return 0;
	}

	if (!strcasecmp("start", new_state)) {
		int r;

		if (READ_ONCE(tfw_started)) {
			TFW_WARN("Trying to start running system\n");
			return -EINVAL;
		}

		ss_start();
		if (!(r = tfw_cfg_start()))
			WRITE_ONCE(tfw_started, true);

		return r;
	}

	if (!strcasecmp("stop", new_state)) {
		if (!READ_ONCE(tfw_started)) {
			TFW_WARN("Trying to stop inactive system\n");
			return -EINVAL;
		}

		ss_stop();
		tfw_cfg_stop();
		WRITE_ONCE(tfw_started, false);

		return 0;
	}

	TFW_ERR("invalid state: '%s'. Should be either 'start' or 'stop'\n",
		new_state);

	return -EINVAL;
}

/**
 * Syctl handler for tempesta.state read/write operations.
 */
static int
handle_sysctl_state_io(struct ctl_table *ctl, int is_write,
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

		r = handle_state_change(old_state, new_state);
		if (r)
			goto out;
	}

	r = proc_dostring(ctl, is_write, user_buf, lenp, ppos);
out:
	mutex_unlock(&tfw_sysctl_mtx);
	return r;
}

static char tfw_sysctl_state_buf[32];
static struct ctl_table_header *tfw_sysctl_hdr;
static struct ctl_table tfw_sysctl_tbl[] = {
	{
		.procname	= "state",
		.data		= tfw_sysctl_state_buf,
		.maxlen		= sizeof(tfw_sysctl_state_buf) - 1,
		.mode		= 0644,
		.proc_handler	= handle_sysctl_state_io,
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
		TFW_ERR("can't initialize Tempesta FW module: '%s' (%d)\n", \
			#mod, r);				\
		goto err;					\
	}							\
	exit_hooks[exit_hooks_n++] = tfw_##mod##_exit;		\
} while (0)

#define DO_CFG_REG(mod)						\
do {								\
	extern TfwCfgMod tfw_##mod##_cfg_mod;			\
	r = tfw_cfg_mod_register(&tfw_##mod##_cfg_mod);		\
	if (r)							\
		goto err;					\
} while (0)

static void
tfw_exit(void)
{
	int i;

	TFW_LOG("exiting...\n");
	for (i = exit_hooks_n - 1; i >= 0; --i)
		exit_hooks[i]();

	unregister_net_sysctl_table(tfw_sysctl_hdr);
}

static int __init
tfw_init(void)
{
	int r;

	/* Initialize strings SIMD constants at first. */
	kernel_fpu_begin();
	tfw_str_init_const();
	kernel_fpu_end();

	TFW_LOG("Initializing Tempesta FW kernel module...\n");

	tfw_sysctl_hdr = register_net_sysctl(&init_net, "net/tempesta",
					     tfw_sysctl_tbl);
	if (!tfw_sysctl_hdr) {
		TFW_ERR("can't register sysctl table\n");
		return -1;
	}

	DO_INIT(pool);
	DO_INIT(cfg);
	DO_INIT(procfs);
	DO_INIT(vhost);

	DO_INIT(classifier);

	/* Register TLS before HTTP, so HTTP FSM can register TLS hooks. */
	DO_INIT(tls);
	DO_INIT(http);
	DO_INIT(http_sess);

	DO_INIT(apm);
	DO_INIT(sync_socket);
	DO_INIT(server);
	DO_INIT(client);
	DO_INIT(sock_srv);
	DO_INIT(sock_clnt);

	DO_CFG_REG(apm);
	DO_CFG_REG(tls);
	DO_CFG_REG(vhost);
	DO_CFG_REG(filter);
	DO_CFG_REG(cache);
	DO_CFG_REG(http_sess);
	DO_CFG_REG(sock_srv);
	DO_CFG_REG(sock_clnt);
	DO_CFG_REG(procfs);

	return 0;
err:
	tfw_exit();
	return r;
}

module_init(tfw_init);
module_exit(tfw_exit);
