/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
//#include <linux/bug.h>
//#include <linux/kernel.h>
//#include <linux/ctype.h>
#include <ctype.h>
#include "str.h"


void
tfw_str_del_chunk(TfwStr *str, int id)
{
	unsigned int cn = TFW_STR_CHUNKN(str);

	if (unlikely(TFW_STR_PLAIN(str)))
		return;
	BUG_ON(TFW_STR_DUP(str));
	BUG_ON(id >= cn);

	if (TFW_STR_CHUNKN(str) == 2) {
		/* Just fall back to plain string. */
		*str = *((TfwStr *)str->ptr + (id ^ 1));
		return;
	}

	str->len -= TFW_STR_CHUNK(str, id)->len;
	TFW_STR_CHUNKN_SUB(str, 1);
	/* Move all chunks after @id. */
	memmove((TfwStr *)str->ptr + id, (TfwStr *)str->ptr + id + 1,
		(cn - id - 1) * sizeof(TfwStr));
}

/**
 * Grow @str for @n new chunks.
 * New branches of the string tree are created on 2nd level only,
 * i.e. there is no possibility to grow number of chunks of duplicate string.
 * Pass pointer to one of the duplicates to do so.
 * @return pointer to the first of newly added chunk.
 *
 * TODO do we need exponential growing?
 */
static TfwStr *
__str_grow_tree(TfwPool *pool, TfwStr *str, unsigned int flag, int n)
{
	if (str->flags & flag) {
		unsigned int l;
		void *p;

		if (unlikely(TFW_STR_CHUNKN_LIM(str))) {
			TFW_WARN("Reaching chunks hard limit\n");
			return NULL;
		}

		l = TFW_STR_CHUNKN(str) * sizeof(TfwStr);
		p = tfw_pool_realloc(pool, str->ptr, l,
				     l + n * sizeof(TfwStr));
		if (!p)
			return NULL;
		str->ptr = p;
		TFW_STR_CHUNKN_ADD(str, n);
	}
	else {
		TfwStr *a = tfw_pool_alloc(pool, (n + 1) * sizeof(TfwStr));
		if (!a)
			return NULL;
		a[0] = *str;
		str->ptr = a;
		__TFW_STR_CHUNKN_SET(str, n + 1);
	}

	str = (TfwStr *)str->ptr + TFW_STR_CHUNKN(str) - n;
	memset(str, 0, sizeof(TfwStr) * n);

	return str;
}

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	/* Need to specify exact string duplicate to grow. */
	BUG_ON(TFW_STR_DUP(str));

	return __str_grow_tree(pool, str, __TFW_STR_COMPOUND, 1);
}

/**
 * Add place for a new duplicate to string tree @str,
 * the string is probably alredy a set of duplicate compound strings.
 */
TfwStr *
tfw_str_add_duplicate(TfwPool *pool, TfwStr *str)
{
	TfwStr *dup_str = __str_grow_tree(pool, str, TFW_STR_DUPLICATE, 1);

	/* Length for set of duplicate strings has no sense. */
	str->len = 0;
	str->flags |= TFW_STR_DUPLICATE;

	return dup_str;
}

int
tfw_strcpy(TfwStr *dst, const TfwStr *src)
{
	int n1, n2, o1 = 0, o2 = 0, chunks = 0;
	int mode = (TFW_STR_PLAIN(src) << 1) | TFW_STR_PLAIN(dst);
	TfwStr *c1, *c2, *end;

	BUG_ON(TFW_STR_DUP(dst));
	BUG_ON(TFW_STR_DUP(src));

	/* After the check we don't need to control @dst chunks overrun. */
	if (unlikely(src->len > dst->len))
		return -E2BIG;

	switch (mode) {
	case 3: /* The both are plain. */
		memcpy(dst->ptr, src->ptr, min(src->len, dst->len));
		break;
	case 1: /* @src is compound, @dst is plain. */
		n1 = TFW_STR_CHUNKN(src);
		end = (TfwStr *)src->ptr + n1;
		for (c1 = (TfwStr *)src->ptr; c1 < end; ++c1) {
			memcpy((char *)dst->ptr + o2, c1->ptr, c1->len);
			o2 += c1->len;
		}
		BUG_ON(o2 != src->len);
		break;
	case 2: /* @src is plain, @dst is compound. */
		for (c2 = (TfwStr *)dst->ptr; o1 < src->len; ++c2) {
			/* Update length of the last chunk. */
			c2->len = min(c2->len, src->len - o1);
			memcpy(c2->ptr, (char *)src->ptr + o1, c2->len);
			++chunks;
			o1 += c2->len;
		}
		break;
	case 0: /* The both are compound. */
		n1 = TFW_STR_CHUNKN(src);
		n2 = TFW_STR_CHUNKN(dst);
		c1 = (TfwStr *)src->ptr;
		c2 = (TfwStr *)dst->ptr;
		end = c1 + n1 - 1;
		while (1) {
			int _n = min(c1->len - o1, c2->len - o2);
			memcpy((char *)c2->ptr + o2, (char *)c1->ptr + o1, _n);
			if (c1 == end && _n == c1->len - o1) {
				/* Adjust @dst last chunk length. */
				c2->len = o2 + _n;
				++chunks;
				break;
			}
			if (c1->len - o1 == c2->len - o2) {
				++c1;
				++c2;
				++chunks;
				o1 = o2 = 0;
			}
			else if (_n == c1->len - o1) {
				++c1;
				o1 = 0;
				o2 += _n;
			}
			else {
				++c2;
				++chunks;
				o2 = 0;
				o1 += _n;
			}
		}
	}

	/* Set resulting number of chunks, forget about others. */
	__TFW_STR_CHUNKN_SET(dst, chunks);
	dst->len = src->len;

	return 0;
}
EXPORT_SYMBOL(tfw_strcpy);

int
tfw_strcat(TfwPool *pool, TfwStr *dst, TfwStr *src)
{
	int n = TFW_STR_CHUNKN(src);
	TfwStr *to, *c, *end;

	BUG_ON(TFW_STR_DUP(dst));
	BUG_ON(TFW_STR_DUP(src));

	to = __str_grow_tree(pool, dst, __TFW_STR_COMPOUND, n ? : 1);
	if (!to)
		return -ENOMEM;

	n = 0;
	TFW_STR_FOR_EACH_CHUNK(c, src, end) {
		n += c->len;
		to->ptr = c->ptr;
		to->len = c->len;
		to->skb = c->skb;
		++to;
	}
	dst->len += n;

	return 0;
}
EXPORT_SYMBOL(tfw_strcat);

/**
 * Core routine for tfw_stricmpspn() working on flat C strings.
 *
 * Returns:
 *   0 - strings match;
 *   1 - strings match and @stop is found;
 *  -1 - strings do not match;
 *
 * TODO too slow, rewrite on AVX2.
 */
static int
__cstricmpspn(const char *s1, const char *s2, int n, int stop)
{
	unsigned char c1, c2;

	while (n) {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);
		if (c1 != c2)
			return -1;
		if (!c1)
			return 0;
		if (c1 == stop)
			return 1;
		n--;
	}

	return 0;
}

/**
 * Like strcasecmp(3) for TfwStr, but stops matching when faces @stop.
 * Do not use it for duplicate strings, rather call it for each duplicate
 * substring separately.
 */
int
tfw_stricmpspn(const TfwStr *s1, const TfwStr *s2, int stop)
{
	int i1, i2, off1, off2, n;
	const TfwStr *c1, *c2;

	BUG_ON((s1->flags | s2->flags) & TFW_STR_DUPLICATE);

	if (!stop || !s1->len || !s2->len) {
		n = (int)s1->len - (int)s2->len;
		if (n)
			return n;
	}

	i1 = i2 = 0;
	off1 = off2 = 0;
	n = min(s1->len, s2->len);
	c1 = TFW_STR_CHUNK(s1, 0);
	c2 = TFW_STR_CHUNK(s2, 0);
	while (n) {
		int cn = min(c1->len - off1, c2->len - off2);
		int r = stop
			? __cstricmpspn((char *)c1->ptr + off1,
					(char *)c2->ptr + off2, cn, stop)
			: strncasecmp((char *)c1->ptr + off1,
				      (char *)c2->ptr + off2, cn);
		if (r)
			return stop ? !(r > 0) : r;

		n -= cn;
		if (cn == c1->len - off1) {
			off1 = 0;
			++i1;
			c1 = TFW_STR_CHUNK(s1, i1);
		} else {
			off1 += cn;
		}
		if (cn == c2->len - off2) {
			off2 = 0;
			++i2;
			c2 = TFW_STR_CHUNK(s2, i2);
		} else {
			off2 += cn;
		}
		BUG_ON(n && (!c1 || !c2));
	}

	return stop ? -1 : 0;
}
EXPORT_SYMBOL(tfw_stricmpspn);

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
 *
 * @return true if the strings are equal and false otherwise.
 */
bool
tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
		tfw_str_eq_flags_t flags)
{
	int len, clen = cstr_len;
	const TfwStr *chunk, *end;
    __typeof__(&strncmp) cmp = (flags & TFW_STR_EQ_CASEI)
			       ? strncasecmp
			       : strncmp;

	BUG_ON(str->len && !str->ptr);
	TFW_STR_FOR_EACH_CHUNK(chunk, str, end) {
		BUG_ON(chunk->len &&  !chunk->ptr);

		len = min(clen, (int)chunk->len);
		if (cmp(cstr, chunk->ptr, len))
			return false;

		/*
		 * Relatively specific case, so leave it here and
		 * don't move it to begin of the function.
		 */
		if ((int)chunk->len > clen)
			return (flags & TFW_STR_EQ_PREFIX);

		cstr += len;
		clen -= len;
	}

	return !clen;
}
EXPORT_SYMBOL(tfw_str_eq_cstr);

/**
 * Same as @tfw_str_eq_cstr, but compares a substring of @str taken from the
 * position @pos with linear @cstr of length @cstr_len.
 *
 * Beware! The function has side effects and may and likely will **modify** a
 * chunk of the source @str for a while...
 *
 * Uses the @tfw_str_eq_cstr as the basis.
 */
bool
tfw_str_eq_cstr_pos(const TfwStr *str, const char *pos, const char *cstr,
		    int cstr_len, tfw_str_eq_flags_t flags)
{
	bool r = false;
	TfwStr tmp = *str;
	const TfwStr *c, *end;

	BUG_ON(TFW_STR_DUP(str));
	BUG_ON(!pos || !cstr || !cstr_len);

	TFW_STR_FOR_EACH_CHUNK(c, &tmp, end) {
		long offset = pos - (char *)c->ptr;

		if (offset >= 0 && (offset < c->len)) {
			TfwStr t = *c, *v = (TfwStr *)c;

			v->ptr += offset;
			v->len -= offset;

			r = tfw_str_eq_cstr(&tmp, cstr, cstr_len, flags);

			*v = t; /* restore chunk */
			goto out;
		}

		tmp.len -= c->len;
		tmp.ptr += sizeof(TfwStr);

		TFW_STR_CHUNKN_SUB(&tmp, 1);
	}

	TFW_WARN("Desired position is outside the string\n");
out:
	return r;
}
EXPORT_SYMBOL(tfw_str_eq_cstr_pos);

/**
 * The function intentionaly brokes zero-copy string design. And should
 * be used for short-strings only.
 *
 * Join all chunks of @str to a single plain C string.
 *
 * The function copies all chunks of the @str to the @out_buf.
 * If the buffer has not enough space to fit all chunks, then the output string
 * is cropped (at most @buf_size - 1 bytes is written). The output string is
 * always terminated with '\0'.
 *
 * Caveat: Be sure to free memory block as soon as possible. Leaving it
 * allocated could ruin successful tfw_pool_realloc() sequence, and cause
 * excessive copying. Since TfwPool is using stack-like approach, it's
 * possible to allocate temporary storage for tfw_str_to_cstr() result,
 * then free it, and successfully continue tfw_pool_realloc() sequence.
 *
 * Returns length of the output string.
 *
 */
size_t
tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size)
{
	const TfwStr *chunk, *end;
	char *pos = out_buf;
	int len;

	BUG_ON(!out_buf || buf_size <= 0);

	--buf_size; /* Reserve one byte for '\0'. */

	TFW_STR_FOR_EACH_CHUNK(chunk, str, end) {
		len = min(buf_size, (int)chunk->len);
		strncpy(pos, chunk->ptr, len);
		pos += len;
		buf_size -= len;

		if (unlikely(!buf_size))
			break;
	}

	*pos = '\0';

	return (pos - out_buf);
}
EXPORT_SYMBOL(tfw_str_to_cstr);

#ifdef DEBUG
void
tfw_str_dprint(TfwStr *str, const char *msg)
{
	TfwStr *dup, *dup_end, *c, *chunk_end;

	TFW_DBG("%s: addr=%p skb=%p len=%lu flags=%x:\n", msg,
		str, str->skb, str->len, str->flags);
	TFW_STR_FOR_EACH_DUP(dup, str, dup_end) {
		TFW_DBG("  duplicate %p, len=%lu, flags=%x:\n",
			dup, dup->len, dup->flags);
		TFW_STR_FOR_EACH_CHUNK(c, dup, chunk_end)
			TFW_DBG("   len=%lu, ptr=%p '%.*s'\n", c->len,
				c->ptr, (int)c->len, (char *)c->ptr);
	}
}
#endif
