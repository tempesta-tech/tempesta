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

#include <linux/ctype.h>
#include "str.h"

#ifndef IF_DEBUG
#ifdef DEBUG
#define IF_DEBUG if (1)
#else
#define IF_DEBUG if (0)
#endif
#endif

static void
validate_tfw_str(const TfwStr *str)
{
	const TfwStrChunk *chunk;
	int i;
	int total_len = 0;

	BUG_ON(!str);

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		BUG_ON(!chunk);
		BUG_ON(!chunk->len);
		BUG_ON(!chunk->data);

		for (i = 0; i < chunk->len; ++i)
			BUG_ON(iscntrl(chunk->data[i]));
		total_len += chunk->len;
	}

	BUG_ON(total_len != str->len);
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

int
tfw_str_add_chunk(TfwStr *str, const char *start_pos, const char *end_pos,
		  TfwPool *pool)
{
	TfwStrChunk *new_chunk, *new_chunks_tbl;

	IF_DEBUG {
		validate_tfw_str(str);
		BUG_ON(!start_pos);
		BUG_ON(!end_pos);
		BUG_ON(!pool);
		BUG_ON(str->cnum == TFW_STR_CNUM_MAX);
		BUG_ON((end_pos - start_pos) > TFW_STR_CHUNK_LEN_MAX);
		BUG_ON(((end_pos - start_pos) + str->len ) > TFW_STR_LEN_MAX);
		BUG_ON(end_pos < start_pos);
	}

	/* Don't add empty chunks at all. */
	if (unlikely(end_pos == start_pos))
		return 0;

	/* Fast path: we assume, that most strings consist of only one chunk.
	 * If so, then we embed the chunk right into the TfwStr structure
	 * and thus avoid presumably expensive memory allocation. */
	if (likely(str->cnum == 0)) {
		str->single_chunk.data = (char *)start_pos;
		str->single_chunk.len = (end_pos - start_pos);
		str->cnum = 1;
		return 0;
	}

	/* Slow path:
	 * Re-allocate the whole chunks table to get room for the new chunk. */
	if (likely(str->cnum == 1)) {
		/* Already have a single chunk? Then allocate a table for two
		 * chunks and extract the old chunk embedded to the TfwStr. */
		new_chunks_tbl = tfw_pool_alloc(pool, 2*sizeof(TfwStrChunk));
		if (!new_chunks_tbl)
			return -ENOMEM;
		new_chunks_tbl[0] = str->single_chunk;
		new_chunk = &new_chunks_tbl[1];
		str->chunks = new_chunks_tbl;
		str->cnum = 2;
	}
	else {
		/* Have many chunks? Reallocate the table to fit one more. */
		new_chunks_tbl = tfw_pool_realloc(pool, str->chunks,
					sizeof(TfwStrChunk) * (str->cnum),
					sizeof(TfwStrChunk) * (str->cnum + 1));
		if (!new_chunks_tbl)
			return -ENOMEM;
		new_chunk = new_chunks_tbl + str->cnum;
		str->chunks = new_chunks_tbl;
		++str->cnum;
	}

	/* Ok, the chunk is allocated, set it up and update the total length. */
	new_chunk->data = (char *)start_pos;
	new_chunk->len = (end_pos - start_pos);
	str->len += new_chunk->len;

	return 0;
}
EXPORT_SYMBOL(tfw_str_add_chunk);

/**
 * Return sum of lengths of all chunks in the string.
 *
 * At this point the length is simply stored in the TfwStr structure.
 * The value is incremented whenever a new chunk is added.
 */
int
tfw_str_len(const TfwStr *str)
{
	IF_DEBUG {
		validate_tfw_str(str);
	}

	return str->len;
}
EXPORT_SYMBOL(tfw_str_len);

/**
 * Join all chunks of @str to a single plain C string.
 *
 * The function copies all chunks of the @str to the @out_buf.
 * If the buffer has not enough space to fit all chunks, then the output string
 * is cropped (at most @buf_size - 1 bytes is written). The output string is
 * always terminated with '\0'.
 *
 * Returns length of the output string.
 */
int
tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size)
{
	const TfwStrChunk *chunk;
	char *pos = out_buf;
	int len;

	IF_DEBUG {
		validate_tfw_str(str);
		BUG_ON(!out_buf || (buf_size <= 0));
	}

	--buf_size; /* Reserve one byte for '\0'. */

	TFW_STR_FOR_EACH_CHUNK (chunk, str) {
		len = min(buf_size, (int)chunk->len);
		memcpy(pos, chunk->data, len);
		pos += len;
		buf_size -= len;

		if (unlikely(!buf_size))
			break;
	}

	*pos = '\0';

	return (pos - out_buf);
}
EXPORT_SYMBOL(tfw_str_to_cstr);

/**
 * A little bit faster alternative to strnicmp() that can be inlined here.
 * (perhaps slower if __HAVE_ARCH_STRNICMP, but x86 and x86_64 don't have it).
 *
 * Returns zero when all characters are equal (case-insensitive).
 * Does NOT check whether strings are terminated with '\0'.
 */
static int
_tfw_casecmp(const char *s1, const char *s2, size_t len)
{
	char c1, c2;

	IF_DEBUG {
		BUG_ON(!s1);
		BUG_ON(!s2);
		BUG_ON(!len);
	}

	do {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
	} while (c1 == c2 && --len);

	return (c1 != c2);
}

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
	const TfwStrChunk *chunk;
	unsigned int len;

	IF_DEBUG {
		validate_cstr(cstr, cstr_len);
		validate_tfw_str(str);
	}

	/* Fast path: compare strings by their and lengths.
	 * Usually we compare to search one matching string among others.
	 * For example, in http_match unit we compare all strings in a list
	 * until we find a matching one. So we expect that most of the strings
	 * are not equal, and only one string is matching in most cases. */
	if (likely((flags & TFW_STR_EQ_PREFIX)  ? (str->len < cstr_len)
						: (str->len != cstr_len)))
		return false;

	/* TODO: another optimization is possible:
	 * We can calculate hash of the @cstr and compare it with a value
	 * which is cached in the TfwStr structure between calls.
	 * That fits to a scenario of the http_match module where we compare
	 * single TfwStr with many C strings.
	 * This approach allows to avoid walking over TfwStr chunks, but has
	 * an overhead of hashing. Usually I/O overhead dominates, and any
	 * calculation overhead is negligible, so it may be beneficial.
	 * Benchmarks are required to proof that.
	 */

	/* Slow path: compare contents.
	 * The code generation is a bit ugly, but enables an optimization:
	 * instead of checking the CASEI flag on every iteration, we do that
	 * only once in the outer statement. Could be done with a function
	 * pointer, but this is a little bit slower.
	 */
#define __CMP_CHUNKS(cmp_fn) 					\
	TFW_STR_FOR_EACH_CHUNK (chunk, str) {			\
		len = min(cstr_len, (int)chunk->len);		\
		if (cmp_fn(cstr, chunk->data, len))		\
			return false;				\
		if (chunk->len > cstr_len)			\
			return (flags & TFW_STR_EQ_PREFIX);	\
		cstr += len;					\
		cstr_len -= len;				\
	}							\

	if (flags & TFW_STR_EQ_CASEI)
		__CMP_CHUNKS(_tfw_casecmp)
	else
		__CMP_CHUNKS(memcmp)

#undef __CMP_CHUNKS

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
	const TfwStrChunk *chunk;
	const char *c;
	const char *cend;
	short cnum;

	IF_DEBUG {
		validate_tfw_str(str);
		validate_key(key, key_len);
		validate_cstr(val, val_len);
	}

/* Try to move to the next chunk (if current chunk is finished).
 * Execute @ok_code on sucess or @err_code if there is no next chunk. */
#define _TRY_NEXT_CHUNK(ok_code, err_code)		\
	if (unlikely(c == cend))	{		\
		++cnum;					\
		chunk = TFW_STR_CHUNK(str, cnum); 	\
		if (unlikely(chunk)) {			\
			c = chunk->data;		\
			cend = chunk->data + chunk->len;\
			ok_code;			\
		} else {				\
			err_code;			\
			/* err_code should jump. */	\
			IF_DEBUG {			\
				BUG();			\
			}				\
		}					\
	}

	/* Initialize  the state - get the first chunk. */
	cnum = 0;
	chunk = TFW_STR_CHUNK(str, 0);
	if (!chunk)
		return false;
	c = chunk->data;
	cend = chunk->data + chunk->len;

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
