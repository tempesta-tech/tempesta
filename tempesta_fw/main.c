/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include "tempesta_fw.h"
#include "log.h"
#include "str.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION(TFW_NAME);
MODULE_VERSION(TFW_VERSION);
MODULE_LICENSE("GPL");

typedef void (*exit_fn)(void);
exit_fn exit_hooks[32];
size_t  exit_hooks_n;

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

	DO_INIT(pool);

	DO_INIT(cfg_if);
	DO_INIT(procfs);
	DO_INIT(vhost);

	DO_INIT(classifier);

	/* Register TLS before HTTP, so HTTP FSM can register TLS hooks. */
	DO_INIT(tls);
	DO_INIT(http);
	DO_INIT(http_sess);

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
