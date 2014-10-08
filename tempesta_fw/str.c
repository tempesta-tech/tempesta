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
#include "str.h"

#ifndef DEBUG
#define tfw_str_validate(str)
#else
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
#endif /* ifndef DEBUG */

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	tfw_str_validate(str);

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
		a[0].flags = 0;  /* TODO: should we inherit flags here? */
		str->ptr = a;
		str->len = 2;
		str->flags |= TFW_STR_COMPOUND;
	}

	TFW_STR_INIT((TfwStr *)str->ptr + str->len - 1);

	return ((TfwStr *)str->ptr + str->len - 1);
}
EXPORT_SYMBOL(tfw_str_add_compound);

/**
 * Sum lenght of all chunks in a string (either compound or plain).
 */
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
EXPORT_SYMBOL(tfw_str_len);

/**
 * Compare a TfwStr (either compound or plain) with a C string.
 *
 * @cstr_len is strlen() of the C string.
 *           This function doesn't calculate length on its own for optimization
 *           purposes (the length may be pre-computed and saved between calls).
 *
 * If @ci is true then a case-insensitive comparison is used.
 */
static bool
str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len, bool ci)
{
	int ret;
	const TfwStr *chunk;

	/* TODO: Discuss/measure the impact of the length comparison.
	 * Current implementation of tfw_str_len() loops over TfwStr
	 * chunks, but still it may improve performance because:
	 *  - It consumes O(chunks) instead of O(chars) for comparison.
	 *  - Good spatial locality: all TfwStr chunks are packed together in
	 *    the memory (unlike actual strings referenced by the chunks).
	 *  - Generally strings tend to have different lenghts, especially in
	 *    matching tables with a lot of rules.
	 * Even if lengths are equal, the overhead of tfw_str_len() is amortized
	 * by hot caches that contain chunks used in the next loop.
	 */
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

/**
 * Compare TfwStr with a C string (case-sensitive).
 */
bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_eq_cstr(str, cstr, cstr_len, false);
}
EXPORT_SYMBOL(tfw_str_eq_cstr);

/**
 * Compare TfwStr with a C string (case-insensitive).
 */
bool
tfw_str_eq_cstr_ci(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_eq_cstr(str, cstr, cstr_len, true);
}
EXPORT_SYMBOL(tfw_str_eq_cstr_ci);

/**
 * Return true if a given @cstr is a prefix of @str (case-insensitive).
 */
bool
tfw_str_startswith_cstr_ci(const TfwStr *str, const char *cstr, int cstr_len)
{
	int len;
	const TfwStr *chunk;

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
EXPORT_SYMBOL(tfw_str_startswith_cstr_ci);

