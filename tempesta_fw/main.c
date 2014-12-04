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
#include <linux/kernel.h>
#include <linux/module.h>

#include "tempesta.h"
#include "log.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta FW");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

#define INIT_TFW_MOD(mod_name) 			\
do {						\
	extern TfwCfgMod mod_name; 		\
	r = tfw_cfg_mod_register(&mod_name); 	\
	if (r)					\
		goto err;			\
} while (0)

extern int tfw_cfg_if_init(void);
extern void tfw_cfg_if_exit(void);

static int __init
tfw_init(void)
{
	int r;

	TFW_LOG("Initializing Tempesta kernel module\n");

	r = tfw_cfg_if_init();
	if (r) {
		TFW_ERR("Can't initialize Tempesta configuration interface\n");
		return r;
	}

	INIT_TFW_MOD(tfw_mod_cache);
	INIT_TFW_MOD(tfw_mod_http);
	INIT_TFW_MOD(tfw_mod_server);
	INIT_TFW_MOD(tfw_mod_client);
	INIT_TFW_MOD(tfw_mod_session);
	INIT_TFW_MOD(tfw_mod_connection);
	INIT_TFW_MOD(tfw_mod_sock_backend);
	INIT_TFW_MOD(tfw_mod_sock_frontend);

	return 0;

err:
	tfw_cfg_mod_exit_all();
	tfw_cfg_if_exit();

	return r;
}

static void __exit
tfw_exit(void)
{
	TFW_LOG("Shutdown Tempesta\n");
	tfw_cfg_mod_exit_all();
}

module_init(tfw_init);
module_exit(tfw_exit);
