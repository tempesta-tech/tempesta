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
#include <linux/ctype.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sysctl.h>

#include "tempesta.h"
#include "cache.h"
#include "lib.h"
#include "log.h"
#include "sock_backend.h"

/*
 * ------------------------------------------------------------------------
 *	Helping routines
 * ------------------------------------------------------------------------
 */
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

/**
 * Replace the trailing '\n' with '\0'.
 * @str must be NULL-terminated.
 */
static void
tfw_remove_trailing_newline(char *str)
{
	size_t len = strlen(str);
	if (len && (str[len - 1] == '\n')) {
		str[len - 1] = '\0'; 
	}
}

static int 
tfw_inet_pton_ipv4(char **p, struct sockaddr_in *addr)
{
	int octet = -1, i = 0, port = 0;
	unsigned char *a = (unsigned char *)&addr->sin_addr.s_addr;

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0;
	for ( ; **p && !isspace(**p); ++*p) {
		if (isdigit(**p)) {
			octet = (octet == -1)
				? **p - '0'
				: octet * 10 + **p - '0';
			if ((!port && octet > 255) || octet > 0xFFFF)
				return -EINVAL;
		}
		else if (octet >= 0 && ((**p == '.' && i < 4)
					|| (**p == ':' && i == 3)))
		{
			a[i++] = octet;
			octet = -1;
			port = **p == ':';
		} else
			return -EINVAL;
	}
	if (octet >= 0) {
		if (i == 3) {
			/* Default port. */
			a[i] = octet;
			addr->sin_port = htons(DEF_PORT);
			return 0;
		}
		else if (i == 4) {
			addr->sin_port = htons(octet);
			return 0;
		}
	}

	return -EINVAL;
}

static int 
tfw_inet_pton_ipv6(char **p, struct sockaddr_in6 *addr)
{
#define XD(x) ((x >= 'a') ? 10 + x - 'a' : x - '0')

	int words[9] = { -1, -1, -1, -1, -1, -1, -1, -1, -1 };
	int a, hole = -1, i = 0, port = -1, ipv4_mapped = 0;

	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;

	for ( ; **p && !isspace(**p); ++*p) {
		if (i > 7 && !(i == 8 && port == 1))
			return -EINVAL;
		if (**p == '[') {
			port = 0;
		}
		else if (**p == ':') {
			if (*(*p + 1) == ':') {
				/*
				 * Leave current (if empty) or next (otherwise)
				 * word as a hole.
				 */
				++*p;
				hole = (words[i] != -1) ? ++i : i;
			} else if (words[i] == -1) {
				return -EINVAL;
			}
			/* Store port in the last word. */
			i = (port == 1) ? 8 : i + 1;
		}
		else if (**p == '.') {
			++i;
			if (ipv4_mapped)
				continue;
			if (words[0] != -1 || words[1] != 0xFFFF
			   || words[2] == -1 || i != 3 || hole != 0)
				return -EINVAL;
			/*
			 * IPv4 mapped address.
			 * Recalculate the first 2 hexademical octets from to
			 * 1 decimal octet.
			 */
			addr->sin6_family = AF_INET;
			words[0] = ((words[2] & 0xF000) >> 12) * 1000
				   + ((words[2] & 0x0F00) >> 8) * 100
				   + ((words[2] & 0x00F0) >> 4) * 10
				   + (words[2] & 0x000F);
			if (words[0] > 255)
				return -EINVAL;
			ipv4_mapped = 1;
			i = 1;
			words[1] = words[2] = -1;
		}
		else if (isxdigit(**p)) {
			words[i] = words[i] == -1 ? 0 : words[i];
			if (ipv4_mapped || port == 1) {
				if (!isdigit(**p))
					return -EINVAL;
				words[i] = words[i] * 10 + **p - '0';
				if (port) {
					if (words[i] > 0xFFFF)
						return -EINVAL;
				}
				else if (ipv4_mapped && words[i] > 255) {
					return -EINVAL;
				}
			} else {
				words[i] = (words[i] << 4) | XD(tolower(**p));
				if (words[i] > 0xFFFF)
					return -EINVAL;
			}
		}
		else if (**p == ']') {
			port = 1;
		}
		else
			return -EINVAL;
	}

	/* Some sanity checks. */
	if (!port || (port != -1 && words[8] <= 0)
	    || (ipv4_mapped && hole == -1)
	    || (ipv4_mapped && port == -1 && i != 3)
	    || (port == 1 && i != 8)
	    || (port == -1 && i < 7 && hole == -1))
		return -EINVAL;

	/* Copy parsed address. */
	if (ipv4_mapped) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		for (i = 0; i < 4; ++i)
			addr4->sin_addr.s_addr |= words[i] << (3 - i) * 8;
	} else {
		for (i = a = 7; i >= 0 && a >= 0; ) {
			if (words[i] == -1) {
				if (i > hole)
					--i;
				else
					if (a-- == i && i)
						--i;
			} else
				addr->sin6_addr.s6_addr16[a--]
					= htons(words[i--]);
		}
	}

	/* Set port. */
	if (port == -1) {
		addr->sin6_port = htons(DEF_PORT);
		return 0;
	}
	addr->sin6_port = htons(words[8]);

	return 0;
#undef XD
}

/**
 * Parse IPv4 and IPv6 addresses with optional port.
 * See RFC5952.
 *
 * @p - string pointer, updated by the function.
 * @addr - distination to write as a pointer to a union of sockaddr_in and
 * 	   sockaddr_in6.
 */
static int
tfw_inet_pton(char **p, void *addr)
{
	int mode = 0;

	/* Eat empty string prefix. */
	while (**p && isspace(**p))
		++*p;

	/* Determine type of the address (IPv4/IPv6). */
	if (**p == '[' || isalpha(**p)) {
		mode = 6;
	} else {
		char *p1 = *p;
		while (*p1 && isdigit(*p1))
			p1++;
		if (*p1 == ':') {
			mode = 6;
		}
		else if (*p1 == '.') {
			mode = 4;
		}
		else {
			TFW_ERR("bad string: %s\n", *p);
			return -EINVAL;
		}
	}

	if (mode == 4)
		return tfw_inet_pton_ipv4(p, addr);
	if (mode == 6)
		return tfw_inet_pton_ipv6(p, addr);

	TFW_ERR("Can't parse address %s\n", *p);
	return -EINVAL;
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

		tfw_remove_trailing_newline(p);
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
		.extra2		= tfw_apply_new_backends_cfg,
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

