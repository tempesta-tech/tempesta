/**
 *		Tempesta FW
 *
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
#include "str.h"

extern TfwPool *str_pool;

void create_str_pool(void);
void free_all_str(void);

TfwStr *make_plain_str(const char *data);
TfwStr *make_compound_str(const char *data);
TfwStr *make_compound_str2(const char *data1, const char *data2);
TfwStr *collect_compound_str(TfwStr *res_str, const TfwStr *in_str);
TfwStr *collect_compound_str2(TfwStr *res_str, char *str, unsigned long len);

#define TFW_STR(name, literal)	TfwStr *name = make_compound_str(literal)
#define TFW_STR2(name, literal1, literal2) TfwStr *name = make_compound_str2(literal1, literal2)
