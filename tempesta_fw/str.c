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

#include <linux/bug.h>

#include "str.h"

#define TFW_STR_IS_PLAIN(str) (!(str->flags & TFW_STR_COMPOUND))

#define TFW_STR_FOR_EACH_CHUNK(chunk, str) for ( \
	chunk = (TFW_STR_IS_PLAIN(str) ? str : str->ptr); \
	chunk < (TFW_STR_IS_PLAIN(str) ? str + 1 : (TfwStr *)str->ptr + str->len); \
	++chunk)

static void
tfw_str_validate(const TfwStr *str)
{
	const TfwStr *chunk;

	BUG_ON(!str);
	BUG_ON(str->flags & TFW_STR_COMPOUND2);  /* Not supported yet. */

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		BUG_ON(!chunk);
		BUG_ON(chunk->len && !chunk->ptr);

		/* The flag is not allowed for chunks.
		 * It must be set only for their parent TfwStr object. */
		BUG_ON(chunk->flags & TFW_STR_COMPOUND);
	}
}

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	if (unlikely(str->flags & TFW_STR_COMPOUND)) {
		unsigned int l = str->len * sizeof(TfwStr);
		unsigned char *p = tfw_pool_realloc(pool, str->ptr, l,
						    l + sizeof(TfwStr));
		if (!p)
			return NULL;
		str->len++;
	}
	else {
		TfwStr *a = tfw_pool_alloc(pool, 2 * sizeof(TfwStr));
		if (!a)
			return NULL;
		a[0].ptr = str->ptr;
		a[0].len = str->len;
		str->ptr = a;
		str->len = 2;
		str->flags |= TFW_STR_COMPOUND;
	}

	TFW_STR_INIT((TfwStr *)str->ptr + str->len - 1);

	return ((TfwStr *)str->ptr + str->len - 1);
}

int
tfw_str_len(const TfwStr *str)
{
	int total_len = 0;
	const TfwStr *chunk;

	tfw_str_validate(str);

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		total_len += chunk->len;
	}

	return total_len;
}

int
tfw_str_to_cstr(const TfwStr *str, char *buf, int buf_size)
{
	int total_len = 0;
	int len;
	const TfwStr *chunk;

	tfw_str_validate(str);
	BUG_ON(!buf || (buf_size <= 0));

	--buf_size; /* Reserve one byte for '\0'. */

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		len = min(buf_size, (int)chunk->len);
		strncpy(buf, chunk->ptr, len);
		buf += len;
		buf_size -= len;
		total_len += len;

		if (!buf_size)
			break;
	}

	/* FIXME: The buffer may already contain '\0' before this point. */
	buf = '\0';

	return total_len;
}

static bool
str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len, bool ci)
{
	int ret;
	const TfwStr *chunk;

	tfw_str_validate(str);
	BUG_ON(cstr_len != strlen(cstr));

	if (cstr_len != tfw_str_len(str))
		return false;

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		if (ci)
			ret = strnicmp(cstr, chunk->ptr, chunk->len);
		else
			ret = strncmp(cstr, chunk->ptr, chunk->len);

		if (ret)
			return false;

		cstr += chunk->len;
		cstr_len -= chunk->len;
	}

	BUG_ON(cstr_len != 0);

	return true;
}

bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_eq_cstr(str, cstr, cstr_len, false);
}

bool
tfw_str_eq_cstr_ci(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_eq_cstr(str, cstr, cstr_len, true);
}

bool
tfw_str_startswith_cstr_ci(const TfwStr *str, const char *cstr, int cstr_len)
{
	int len;
	const TfwStr *chunk;

	tfw_str_validate(str);
	BUG_ON(cstr_len != strlen(cstr));

	if (cstr_len > tfw_str_len(str))
		return false;

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		len = min(cstr_len, (int)chunk->len);

		if (strnicmp(cstr, chunk->ptr, len))
			return false;

		cstr += len;
		cstr_len -= len;

		if (!cstr_len)
			break;
	}

	return true;
}

