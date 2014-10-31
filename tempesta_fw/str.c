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

#include "lib.h"
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
 * Sum length of all chunks in a string (either compound or plain).
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

/**
 * Generic function for comparing TfwStr and C strings.
 *
 * @str may be either plain or compound.
 *
 * @cstr_len is used for performance purposes.
 * The length may be pre-computed by the caller and saved between calls.
 *
 * @cstr is not required to be terminated.
 *
 * @flags allow to specify the following options:
 *  - TFW_STR_EQ_PREFIX
 *      The @cstr is a prefix, only first @cstr_len chars are compared, and the
 *      rest of @str is ignored.
 *  - TFW_STR_EQ_CASEI
 *      Use case-insensitive comparison function.
 */
bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
                tfw_str_eq_flags_t flags)
{
	const TfwStr *chunk;
	unsigned int len;
	typeof(&strncmp) cmp = (flags & TFW_STR_EQ_CASEI) ? strnicmp : strncmp;

	validate_cstr(cstr, cstr_len);
	validate_tfw_str(str);

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		len = min(cstr_len, (int)chunk->len);

		if (cmp(cstr, chunk->ptr, len))
			return false;

		if (chunk->len > cstr_len)
			return (flags & TFW_STR_EQ_PREFIX);

		cstr += len;
		cstr_len -= len;
	}

	return !cstr_len;
}
EXPORT_SYMBOL(tfw_str_eq_cstr);

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
 *  - TFW_STR_EQ_CASEI
 *    Use case-insensitive comparison for @key and @val.
 *    The @sep is always case-sensitive.
 *
 *  - TFW_STR_EQ_PREFIX
 *    Treat @val as a prefix.
 *    For example, if @val = "text", then it will match to:
 *      "Content-Type: text"
 *      "Content-Type: text/html"
 *      "Content-Type: text/html; charset=UTF-8"
 *    The flag affects only @val (the @key comparison is always case-insensitive
 *    and @sep is always case-sensitive).
 */
bool
tfw_str_eq_kv(const TfwStr *str, const char *key, int key_len, char sep,
	      const char *val, int val_len, tfw_str_eq_flags_t flags)
{
	const char *key_end = key + key_len;
	const char *val_end = val + val_len;
	const TfwStr *chunk;
	const char *c;
	const char *cend;
	short cnum;

	validate_tfw_str(str);
	validate_key(key, key_len);
	validate_cstr(val, val_len);

/* Try to move to the next chunk (if current chunk is finished).
 * Execute @ok_code on sucess or @err_code if there is no next chunk. */
#define _TRY_NEXT_CHUNK(ok_code, err_code)		\
	if (unlikely(c == cend))	{		\
		++cnum;					\
		chunk = TFW_STR_CHUNK(str, cnum); 	\
		if (chunk) {				\
			c = chunk->ptr;			\
			cend = chunk->ptr + chunk->len; \
			ok_code;			\
		} else {				\
			err_code;			\
			BUG();				\
		}					\
	}

	/* Initialize  the state - get the first chunk. */
	cnum = 0;
	chunk = TFW_STR_CHUNK(str, 0);
	if (!chunk)
		return false;
	c = chunk->ptr;
	cend = chunk->ptr + chunk->len;

	/* A tiny FSM here. Instead of a traditional for+switch construction
	 * it uses a series of small loops to improve branch prediction and
	 * locality of the code (and thus L1i hit).
	 */

state_key:
	while (key != key_end && c != cend) {
		if (tolower(*key++) != tolower(*c++))
			return false;
	}
	_TRY_NEXT_CHUNK(goto state_key, return false);

state_sp1:
	if (!isspace(sep)) {
		while (c != cend && isspace(*c))
			++c;
		_TRY_NEXT_CHUNK(goto state_sp1, return false);
	}

/* state_sep: */
	if (*c++ != sep)
		return false;

state_sp2:
	while (c != cend && isspace(*c))
		++c;
	_TRY_NEXT_CHUNK(goto state_sp2, return (val == val_end));

state_val:
	if (flags & TFW_STR_EQ_CASEI) {
		while (val != val_end && c != cend) {
			if (tolower(*val++) != tolower(*c++))
				return false;
		}
	} else {
		while (val != val_end && c != cend) {
			if (*val++ != *c++)
				return false;
		}
	}

	/* @val is not finished - request the next chunk. */
	if (val != val_end) {
		_TRY_NEXT_CHUNK(goto state_val, return false);
	}

	/* The chunk is not finished - then @val must be a prefix. */
	if (c != cend) {
		return (flags & TFW_STR_EQ_PREFIX);
	}

	/* Both @val and the current chunk are finished - full match. */
	return true;
}
EXPORT_SYMBOL(tfw_str_eq_kv);


unsigned long tfw_str_hash(const TfwStr *str)
{
	const TfwStr *chunk;
	unsigned long hash = 0;

	TFW_STR_FOR_EACH_CHUNK(chunk, str) {
		hash ^= tfw_hash_calc(chunk->ptr, chunk->len);
	}

	return hash;
}
EXPORT_SYMBOL(tfw_str_hash);
