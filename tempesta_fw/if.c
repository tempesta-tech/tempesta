/**
 *		Tempesta FW
 *
 * Handling /proc/sys/net/tempesta for configuration and
 * (TODO) /proc/tempesta for statistic.
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
#include <linux/sysctl.h>

#include "tempesta_fw.h"
#include "cache.h"
#include "addr.h"
#include "log.h"


/**
 * Retrurn number of tokens in @str separated by space ([ \t]+).
 * @str is null-terminated string.
 */
static int
tfw_str_tokens_count(const char *str)
{
	int n = 0;

	/* Eat empty string prefix. */
	while (*str == ' ' || *str == '\t')
		++str;

	while (*str) {
		++n;
		/* Eat a word. */
		while (*str && *str != ' ' && *str != '\t')
			++str;
		/* Eat all separators. */
		while (*str && (*str == ' ' || *str == '\t'))
			++str;
	}

	return n;
}


/*
 * ------------------------------------------------------------------------
 *	Sysctl and /proc interfaces
 * ------------------------------------------------------------------------
 */
#define TFW_MAX_PROC_STR_LEN	DEF_PROC_STR_LEN

typedef struct {
	char	listen[TFW_MAX_PROC_STR_LEN];
	char	backends[TFW_MAX_PROC_STR_LEN];
} TfwSysctlTable;

TfwSysctlTable tfw_param_tbl;

static int
init_addr(TfwAddrCfg **cfg_a, char *str, unsigned int addr,
	  unsigned short port)
{
	int r;

	*cfg_a = kzalloc(SIZE_OF_ADDR_CFG(1), GFP_KERNEL);
	if (!*cfg_a)
		return -ENOMEM;

	(*cfg_a)->count = 1;
	(*cfg_a)->addr[0].v4.sin_family = AF_INET;
	(*cfg_a)->addr[0].v4.sin_addr.s_addr = htonl(addr);
	(*cfg_a)->addr[0].v4.sin_port = htons(port);

	r = tfw_inet_ntop((*cfg_a)->addr, str);
	if (r) {
		kfree(*cfg_a);
		return r;
	}

	return 0;
}

static int
sysctl_addr(ctl_table *ctl, int write, void __user *buffer, size_t *lenp,
	    loff_t *ppos)
{
	int r, i;
	TfwAddrCfg *new_addr = NULL, **cfg_addr = ctl->extra1;
	int (*reinit)(void) = ctl->extra2;

	if (write) {
		char *p, *tmp_buf;
		size_t copied_data_len;

		p = tmp_buf = kzalloc(ctl->maxlen + 1, GFP_KERNEL);
		if (!tmp_buf)
			return -ENOMEM;
		
		copied_data_len = min((size_t)ctl->maxlen, *lenp);
		if (copy_from_user(tmp_buf, buffer, copied_data_len)) {
			kfree(tmp_buf);
			return -EFAULT;
		}

		p = strim(p);
		r = tfw_str_tokens_count(p);
		
		new_addr = kmalloc(SIZE_OF_ADDR_CFG(r), GFP_KERNEL);
		if (!new_addr) {
			kfree(tmp_buf);
			return -ENOMEM;
		}

		new_addr->count = r;
		for (i = 0; i < new_addr->count; ++i) {
			r = tfw_inet_pton(&p, new_addr->addr + i);
			if (r) {
				kfree(new_addr);
				kfree(tmp_buf);
				return r;
			}
		}

		kfree(tmp_buf);
	}

	r = proc_dostring(ctl, write, buffer, lenp, ppos);
	if (r) {
		kfree(new_addr);
		return r;
	}

	if (write) {
		down_write(&tfw_cfg.mtx);

		kfree(*cfg_addr);
		*cfg_addr = new_addr;

		up_write(&tfw_cfg.mtx);

		r = reinit();
	}

	return r;
}

static ctl_table tfw_ctl_main_tbl[] = {
	{
		.procname	= "backend",
		.data		= tfw_param_tbl.backends,
		.maxlen		= TFW_MAX_PROC_STR_LEN,
		.mode		= 0644,
		.proc_handler	= sysctl_addr,
		.extra1		= &tfw_cfg.backends,
		.extra2		= tfw_sock_backend_refresh_cfg,
	},
	{ /* TODO reinitialize/destroy storage on setting/unsetting the var. */
		.procname	= "cache_enable",
		.data		= &tfw_cfg.cache,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ /* TODO read-only for now, make updatable. */
		.procname	= "cache_size",
		.data		= &tfw_cfg.c_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ /* TODO read-only for now, make updatable. */
		.procname	= "cache_path",
		.data		= tfw_cfg.c_path,
		.maxlen		= TDB_PATH_LEN,
		.mode		= 0444,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "listen",
		.data		= tfw_param_tbl.listen,
		.maxlen		= TFW_MAX_PROC_STR_LEN,
		.mode		= 0644,
		.proc_handler	= sysctl_addr,
		.extra1		= &tfw_cfg.listen,
		.extra2		= tfw_reopen_listen_sockets,
	},
	{}
};

static struct ctl_table_header *tfw_ctl_main;

int __init
tfw_if_init(void)
{
	int r;


	r = init_addr(&tfw_cfg.listen, tfw_param_tbl.listen,
		      DEF_LISTEN_ADDR, DEF_LISTEN_PORT);
	if (r)
		return r;
	r = init_addr(&tfw_cfg.backends, tfw_param_tbl.backends,
		      DEF_BACKEND_ADDR, DEF_BACKEND_PORT);
	if (r)
		goto err_backends;

	/* Register sysctl table. */
	r = -ENOENT;
	tfw_ctl_main = register_net_sysctl(&init_net, "net/tempesta",
					   tfw_ctl_main_tbl);
	if (!tfw_ctl_main)
		goto err_cfg;

	return 0;
err_cfg:
	kfree(tfw_cfg.backends);
err_backends:
	kfree(tfw_cfg.listen);
	return r;
}

void
tfw_if_exit(void)
{
	unregister_net_sysctl_table(tfw_ctl_main);

	/*
	 * There are no users of the configuration yet,
	 * so we do all the things w/o locks.
	 */
	kfree(tfw_cfg.listen);
	kfree(tfw_cfg.backends);
}

