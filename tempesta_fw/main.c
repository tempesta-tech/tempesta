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
#include <linux/moduleparam.h>

#include "tempesta.h"
#include "cache.h"
#include "client.h"
#include "filter.h"
#include "http.h"
#include "log.h"
#include "server.h"

MODULE_AUTHOR(TFW_AUTHOR);
MODULE_DESCRIPTION("Tempesta FW");
MODULE_VERSION("0.3.0");
MODULE_LICENSE("GPL");

TfwCfg tfw_cfg;

static unsigned int cache_size = 256 * 1024;
module_param(cache_size, uint, 0444);
MODULE_PARM_DESC(cache_size, "Maximum cache size in pages");

static char *cache_path = "/opt/tempesta/cache";
module_param(cache_path, charp, 0444);
MODULE_PARM_DESC(cache_path, "Path to cache directory");

int tfw_connection_init(void);
void tfw_connection_exit(void);

static int __init
tfw_init(void)
{
	int r;

	TFW_LOG("Start Tempesta\n");

	/* Initialize tfw_cfg. */
	init_rwsem(&tfw_cfg.mtx);
	tfw_cfg.c_size = cache_size;
	memcpy(tfw_cfg.c_path, cache_path, DEF_PROC_STR_LEN);

	r = tfw_if_init();
	if (r)
		return r;

	r = tfw_cache_init();
	if (r)
		goto err_cache;

	r = tfw_http_init();
	if (r)
		goto err_http;

	//r = tfw_filter_init();
	if (r)
		goto err_filter;

	r = tfw_server_init();
	if (r)
		goto err_server;

	r = tfw_client_init();
	if (r)
		goto err_client;

	r = tfw_connection_init();
	if (r)
		goto err_connection;

	return 0;

err_connection:
	tfw_client_exit();
err_client:
	tfw_server_exit();
err_server:
	// tfw_filter_stop();
err_filter:
	tfw_http_exit();
err_http:
	tfw_cache_exit();
err_cache:
	tfw_if_exit();

	return r;
}

static void __exit
tfw_exit(void)
{
	TFW_LOG("Shutdown Tempesta\n");

	tfw_connection_exit();
	tfw_client_exit();
	tfw_server_exit();
	//tfw_filter_stop();
	tfw_http_exit();
	tfw_cache_exit();
	tfw_if_exit();
}

module_init(tfw_init);
module_exit(tfw_exit);
