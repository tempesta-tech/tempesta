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
#include <linux/ctype.h>
#include "str.h"

#ifndef DEBUG
#define validate_tfw_str(str)
#define validate_cstr(cstr, len)
#define validate_key(key, len)
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
	 * can make some assumptions on them:
	 *  - They don't contain control and non-ASCII characters.
	 *  - Their length corresponds to strlen().
	 *  - They are shorter than 2^16. Opposite likely means an error,
	 *    perhaps an error code (the negative value) was used as an
	 *    unsigned integer.
	 */
	int i;
	for (i = 0; i < len; ++i)
		BUG_ON(iscntrl(cstr[i]) || !isascii(cstr[i]));
	BUG_ON(strnlen(cstr, len) != len);
	BUG_ON(len >= (1<<16));
}

static void
validate_key(const char *key, int len)
{
	/* The term 'key' is even stricter than 'cstr'.
	 * A key must be a valid cstr, but in addition:
	 *  - It should not contain spaces (or tokenization would be tricky).
	 *  - Expected length won't exceed 256 characters.
	 */
	int i;
	for (i = 0; i < len; ++i)
		BUG_ON(isspace(key[i]));
	BUG_ON(len >= (1<<8));
	validate_cstr(key, len);
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
str_cmp_cstr(const TfwStr *str, const char *cstr, unsigned int cstr_len,
             u8 flags)
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



/**
 * Generic function for comparing TfwStr and a key-value pair of C strings.
 *
 * The key-value pair has the following form:
 *   (@key)[:space:]*(@sep)[:space:]*(@val)
 *
 * For example, if:
 *   @key = "Connection"
 *   @sep = ':'
 *   @val = "keep-alive"
 * Then all the following TfwStr values will match it:
 *   "Connection:keep-alive"
 *   "Connection: keep-alive"
 *   "Connection   :   keep-alive"
 *   "Connection \r\n : \t keep-alive"
 *
 * Note: Space characters are tested using isspace(), so chars like \r\n\t
 * are treated as space.
 *
 * @key should not contain spaces (although current implementation allows it).
 * @sep is a single character, no repetitions allowed (e.g "==").
 * @val must not start with a space (because all spaces are eaten after @sep).
 * @str may consist of any number of chunks, there is no limitation
 *     on how @key/@sep/@val are spread across the chunks.
 *
 * @flags allows to specify additional options for comparison:
 *  - CMP_CI
 *    Use case-insensitive comparison for @key and @val.
 *    The @sep is always case-sensitive.
 *
 *  - CMP_PREFIX
 *    Treat @val as a prefix.
 *    For example, if @val = "text", then it will match to:
 *      "Content-Type: text"
 *      "Content-Type: text/html"
 *      "Content-Type: text/html; charset=UTF-8"
 *    The flag affects only @val (the @key comparison is always case-insensitive
 *    and @sep is always case-sensitive).
 */
static bool
str_cmp_kv(const TfwStr *str,  const char *key, int key_len,  char sep,
          const char *val, int val_len,  u8 flags)
{
	const TfwStr *chunk;
	char *p;
	enum {
		NA = 0,
		KEY,
		WS1,
		SEP,
		WS2,
		VAL,
	} state = KEY;
	char c;
	u8 val_case_mask;

	validate_tfw_str(str);
	validate_key(key, key_len);
	validate_cstr(val, val_len);

	/* The mask turns off the case bit in alphabetic ASCII characters. */
	val_case_mask = (flags & CMP_CI) ? 0xDF : 0xEF;
	#define _CMP_KEY(c1, c2) ((c1 ^ c2) & 0xDF)
	#define _CMP_VAL(c1, c2) ((c1 ^ c2) & val_case_mask)

	/* A tiny FSM here. It compares one character at a time, so perhaps it
	 * is not the fastest one, but the overhead is amortized by absence of
	 * function calls.
	 * The switch() below looks a little bit strange, usual 'break's are
	 * omitted intentionally since state transitions are always sequential,
	 * so there is no need to break their code which is ordered naturally.
	 * Read the code keeping in mind that:
	 *  break;   => eat a character and re-enter the current state
	 *  ++state; => switch to the next state, but don't eat a character
	 */
	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		for (p = chunk->ptr; p < ((char *)chunk->ptr + chunk->len); ++p) {
			c = *p;
			switch (state) {
			default:
				BUG();
			case KEY:
				if (key_len) {
					if (_CMP_KEY(c, *key))
						return false;
					++key;
					--key_len;
					break;
				}
				++state;
			case WS1:
				if (isspace(c))
					break;
				++state;
			case SEP:
				if (c != sep)
					return false;
				++state;
				break;
			case WS2:
				if (isspace(c))
					break;
				++state;
			case VAL:
				if (!val_len)
					return (flags & CMP_PREFIX);
				if (_CMP_VAL(c, *val))
					return false;
				++val;
				--val_len;
			}
		}
	}

	return !val_len;
}

bool
tfw_str_eq_kv(const TfwStr *str, const char *key, int key_len,
              char sep, const char *val, int val_len)
{
	return str_cmp_kv(str, key, key_len, sep, val, val_len, 0);
}
EXPORT_SYMBOL(tfw_str_eq_kv);

bool
tfw_str_eq_kv_ci(const TfwStr *str, const char *key, int key_len,
                 char sep, const char *val, int val_len)
{
	return str_cmp_kv(str, key, key_len, sep, val, val_len, CMP_CI);
}
EXPORT_SYMBOL(tfw_str_eq_kv_ci);

bool
tfw_str_subjoins_kv(const TfwStr *str, const char *key, int key_len,
                    char sep, const char *val, int val_len)
{
	return str_cmp_kv(str, key, key_len, sep, val, val_len, CMP_PREFIX);
}
EXPORT_SYMBOL(tfw_str_subjoins_kv);

bool
tfw_str_subjoins_kv_ci(const TfwStr *str, const char *key, int key_len,
                       char sep, const char *val, int val_len)
{
	return str_cmp_kv(str, key, key_len, sep, val, val_len,
	                  (CMP_PREFIX | CMP_CI));
}
EXPORT_SYMBOL(tfw_str_subjoins_kv_ci);
