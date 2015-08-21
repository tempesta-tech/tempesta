/**
 *              Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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

#include "kallsyms_helper.h"

static const char *_name;

static int
get_sym(void *data, const char *namebuf, struct module *owner, unsigned long addr)
{
        if (strcmp(namebuf, _name)) {
            return 0;
        }

        *(unsigned long *)data = addr;
        return 1;
}

void *
get_sym_ptr(const char *name)
{
        unsigned long sym_addr = 0;

        _name = name;

        kallsyms_on_each_symbol(get_sym, &sym_addr);

        return (void *)sym_addr;
}
