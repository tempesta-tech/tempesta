/**
 *              Tempesta FW
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

#include "kallsyms_helper.h"

typedef struct {
	unsigned long addr;
	const char    *name;
} Symdata;

static int
get_sym(void *data, const char *namebuf, struct module *owner,
        unsigned long addr)
{
	Symdata *symdata = data;

	if (strcmp(namebuf, symdata->name))
		return 0;

	symdata->addr = addr;
	return 1;
}

void *
get_sym_ptr(const char *name)
{
	Symdata symdata = { .addr = 0, .name = name };

	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(get_sym, &symdata);
	mutex_unlock(&module_mutex);

	return (void *)symdata.addr;
}
