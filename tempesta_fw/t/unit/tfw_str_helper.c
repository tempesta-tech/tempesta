/**
 *		Tempesta FW
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

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "lib/str.h"
#include "tfw_str_helper.h"

TfwPool *str_pool;

void
create_str_pool(void)
{
	BUG_ON(str_pool);
	str_pool = __tfw_pool_new(1);
	BUG_ON(!str_pool);
}

void
free_all_str(void)
{
	tfw_pool_destroy(str_pool);
	str_pool = NULL;
}

static TfwStr *
alloc_str(void)
{
	TfwStr *s;

	s = tfw_pool_alloc(str_pool, sizeof(*s));
	BUG_ON(!s);
	TFW_STR_INIT(s);

	return s;
}

TfwStr *
make_plain_str(const char *data)
{
	TfwStr *s = alloc_str();

	s->len =  strlen(data);
	s->data = (void *)data;

	return s;
}

TfwStr *
make_compound_str(const char *data)
{
	TfwStr *str, *chunk;
	size_t chunk_len = 1;
	size_t total_len = strlen(data);

	str = alloc_str();
	str->len = min(total_len, chunk_len);
	str->data = (void *)data;

	for (total_len -= str->len; total_len > 0; total_len -= chunk->len) {
		chunk = tfw_str_add_compound(str_pool, str);
		if (!chunk)
			return NULL;
		chunk->len = min(total_len, ++chunk_len % 8);
		chunk->data = (void *)(data + str->len);
		str->len += chunk->len;
	}

	return str;
}

TfwStr *
make_compound_str2(const char *data1, const char *data2)
{
	TfwStr *str, *chunk;

	str = alloc_str();
	str->len = strlen(data1);
	str->data = (void *)data1;

	chunk = tfw_str_add_compound(str_pool, str);
	if (!chunk)
		return NULL;

	chunk->len = strlen(data2);
	chunk->data = (void *)data2;
	str->len = strlen(data1) + strlen(data2);

	return str;
}

TfwStr *
collect_compound_str(TfwStr *res_str, const TfwStr *in_str)
{
	const TfwStr *c, *end;
	TfwStr *c_new, *c_start = NULL;

	TFW_STR_FOR_EACH_CHUNK(c, in_str, end) {
		c_new = tfw_str_add_compound(str_pool, res_str);
		BUG_ON(!c_new);

		*c_new = *c;
		res_str->len += c_new->len;

		if (!c_start)
			c_start = c_new;
	}
	return c_start;
}

TfwStr *
collect_compound_str2(TfwStr *res_str, char *str, unsigned long len)
{
	TfwStr *c_new = tfw_str_add_compound(str_pool, res_str);

	BUG_ON(!c_new);
	c_new->len = len;
	c_new->data = str;
	res_str->len += len;

	return c_new;
}
