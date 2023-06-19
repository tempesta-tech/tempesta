/**
 *		Tempesta FW
 *
 * Error injection library.
 *
 * Application protocol handler layers must implement zero data copy logic
 * on top on native Linux socket buffers. The helpers provide common and
 * convenient wrappers for skb processing.
 *
 * Copyright (C) 2015-2023 Tempesta Technologies, Inc.
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
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/bug.h>
#include <asm-generic/errno-base.h>

#include "errinj.h"

#define ERRINJ_MEMBER(n, t, s) { /* .name = */ #n, /* .type = */ t, /* .state = */ s },

struct errinj errinjs[errinj_id_MAX] = {
        ERRINJ_LIST(ERRINJ_MEMBER)
};
EXPORT_SYMBOL(errinjs);


int
errinj_split_name_val(char *input, char **name, char **val)
{
        char *sep = strchr(input, '=');
        if (!sep)
                return -EINVAL;

        *sep = '\0';
        *name = input;
        *val = (sep + 1);
        return 0;
}
EXPORT_SYMBOL(errinj_split_name_val);

struct errinj *
errinj_by_name(const char *name)
{
        enum errinj_id i;

        for (i = 0 ; i < errinj_id_MAX ; i++) {
                if (!strcmp(errinjs[i].name, name))
                        return &errinjs[i];
        }
        return NULL;
}
EXPORT_SYMBOL(errinj_by_name);

void
errinj_to_str(const struct errinj *inj, char *buf, size_t buf_size)
{
        switch (inj->type) {
        case ERRINJ_BOOL:
                snprintf(buf, buf_size, "%s=%s",
                         inj->name, inj->bparam ? "true" : "false");
                break;
        case ERRINJ_LONG:
                snprintf(buf, buf_size, "\"%s\" = %ld",
                         inj->name, inj->lparam);
                break;
        default:
                BUG(); 
        }
}
EXPORT_SYMBOL(errinj_to_str);

int
str_to_errinj(struct errinj *inj, const char *buf)
{
        int r = -EINVAL;

        switch (inj->type) {
        case ERRINJ_BOOL:
                r = kstrtobool(buf, &inj->bparam);
                break;
        case ERRINJ_LONG:
                r = kstrtol(buf, 10, &inj->lparam);
                break;
        default:
                BUG();
        }

        return r;
}
EXPORT_SYMBOL(str_to_errinj);
