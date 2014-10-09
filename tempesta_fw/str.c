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
#define validate_tfw_str(str)
#define validate_cstr(cstr, len)
#else

static void
validate_tfw_str(const TfwStr *str)
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

static void
validate_cstr(const char *cstr, unsigned int len)
{
	/* Usually C strings are patterns for matching against TfwStr, so we
	 * can make some asumptions on them:
	 *  - Length corresponds to strlen().
	 *  - They are shorter than 2^16. Opposite likely means an error,
	 *    perhaps an error code (negative value) is used as an unsigned int.
	 */
	BUG_ON(len >= (1<<16));
	BUG_ON(strnlen(cstr, len) != len);
}

#endif /* ifndef DEBUG */

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	validate_tfw_str(str);

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

	validate_tfw_str(str);

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		total_len += chunk->len;
	}

	return total_len;
}
EXPORT_SYMBOL(tfw_str_len);


#define CMP_PREFIX 0x1
#define CMP_CI     0x2

/**
 * Generic function for comparing TfwStr and C strings.
 *
 * @cstr_len is used for performance purposes.
 * The length may be pre-computed by the caller and saved between calls.
 * Also it allows @cstr to be not terminated.
 *
 * @flags allow to specify the following options:
 *  - CMP_PREFIX - the @cstr is a prefix, only first @cstr_len chars are
 *                 compared, the rest of @str is ignored.
 *  - CMP_CI - use case-insensitive comparison function.
 */
static bool
str_cmp_cstr(const TfwStr *str, const char *cstr, unsigned int cstr_len, u8 flags)
{
	const TfwStr *chunk;
	unsigned int cmp_len;
	typeof(&strncmp) cmp_fn = (flags & CMP_CI) ? strnicmp : strncmp;

	validate_cstr(cstr, cstr_len);
	validate_tfw_str(str);

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		cmp_len = min(cstr_len, chunk->len);

		if (cmp_fn(cstr, chunk->ptr, cmp_len))
			return false;

		if (chunk->len > cstr_len)
			return (flags & CMP_PREFIX);

		cstr += cmp_len;
		cstr_len -= cmp_len;
	}

	return !cstr_len;
}

/**
 * Compare TfwStr with a C string (case-sensitive).
 */
bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_cmp_cstr(str, cstr, cstr_len, 0);
}
EXPORT_SYMBOL(tfw_str_eq_cstr);

/**
 * Compare TfwStr with a C string (case-insensitive).
 */
bool
tfw_str_eq_cstr_ci(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_cmp_cstr(str, cstr, cstr_len, CMP_CI);
}
EXPORT_SYMBOL(tfw_str_eq_cstr_ci);

/**
 * Return true if a given @cstr is a prefix of @str (case-sensitive).
 */
bool
tfw_str_subjoins_cstr(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_cmp_cstr(str, cstr, cstr_len, CMP_PREFIX);
}
EXPORT_SYMBOL(tfw_str_subjoins_cstr);

/**
 * Return true if a given @cstr is a prefix of @str (case-insensitive).
 */
bool
tfw_str_subjoins_cstr_ci(const TfwStr *str, const char *cstr, int cstr_len)
{
	return str_cmp_cstr(str, cstr, cstr_len, (CMP_PREFIX | CMP_CI));
}
EXPORT_SYMBOL(tfw_str_subjoins_cstr_ci);

