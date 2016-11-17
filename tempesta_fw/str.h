/**
 *		Tempesta FW
 *
 * String handling.
 * There are few design concepts and properties which make our strings special:
 *
 * 1. the string is designed for zero-copy operations, i.e. it hanles pointer
 *    only to actual data stored somewhere else, typically in skb;
 *
 * 2. the string handles possibly chunked data, e.g. splitted among different
 *    skbs. In this case COMPOUND flag is used;
 *
 * 3. it is HTTP specific in that sense that the string aggregates duplicate
 *    headers, where duplicate is not necessary exact string matching
 *    (e.g. LWS should not be considered). Duplicate values are handled using
 *    DUPLICATE flag;
 *
 * 4. (2) and (3) lead to tree-like data structure if some of duplicate
 *    strings are also compound. This makes string processing logic more
 *    complex, but handles plain strings as well as compound and avoids
 *    additional dynamic memory allocations;
 *
 * 5. This is the basic structure for data transformation logic (including TL),
 *    so we must keep skb pointers to be able to rewrite underlying packets.
 *
 * String can either contain plain data, in which case `ptr` field is used as
 * a pointer to a continuos region, or multiple chunks of data, in which case
 * `ptr` points to an array of plain TfwStr's. In other words, a single
 * indirection is expected. If string have more than one chunk, it's called
 * a "compound" string. `len` field of a compound string contains total length
 * of all chunks combined. Same field for a plain string is just length of
 * a data in the region pointed to by `ptr`.
 *
 * Another possibility is a so called duplicate string. A duplicate string is
 * a bunch of strings that describe HTTP fields with the same name.
 * For example, an HTTP server can return mulitple Set-Cookie fields;
 * all of those will end up in a duplicate string. Such strings use `ptr`
 * field as an array of TfwStr's, each of which can be a compound string.
 * A duplicate string can not itself consist of duplicate strings.
 *
 * `flags` field is used for both discerning the types of strings and keeping
 * the number of elements in `ptr` array, if there are any. Lower 8 bits of
 * the field are reserved for flags. Remaining bits are used to store
 * the number of chunks in a compound string. Zero means a plain string.

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
#ifndef __TFW_STR_H__
#define __TFW_STR_H__

#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include "pool.h"

/*
 * ------------------------------------------------------------------------
 *	SIMD C strings
 *
 * BEWARE(!) using the functions in context different from softirq (any HTTP
 * processing). Softirq context is explicitly protected by kernel_fpu_begin()
 * and kernel_fpu_end(), so you must do the same if you need the functions in
 * some other context. Keep in mind that TfwStr uses the functions as well.
 * ------------------------------------------------------------------------
 */
void tfw_str_init_const(void);
size_t tfw_match_uri(const char *s, size_t len);
size_t tfw_match_token(const char *s, size_t len);
size_t tfw_match_qetoken(const char *s, size_t len);
size_t tfw_match_nctl(const char *s, size_t len);
size_t tfw_match_ctext_vchar(const char *s, size_t len);
size_t tfw_match_xff(const char *s, size_t len);
size_t tfw_match_cookie(const char *s, size_t len);

#ifdef AVX2
void __tfw_strtolower_avx2(unsigned char *dest, const unsigned char *src,
			    size_t len);
int __tfw_stricmp_avx2(const char *s1, const char *s2, size_t len);
int __tfw_stricmp_avx2_2lc(const char *s1, const char *s2, size_t len);

static inline void *
tfw_strtolower(void *dest, const void *src, size_t len)
{
	__tfw_strtolower_avx2((unsigned char *)dest, (const unsigned char *)src,
			      len);
	return dest;
}

/**
 * @return 0 if the strings match and non-zero otherwise.
 */
static inline int
tfw_stricmp(const char *s1, const char *s2, size_t len)
{
	return __tfw_stricmp_avx2(s1, s2, len);
}

/**
 * Like GLIBC's strcasecmp(3), but:
 * 1. requires @len <= min(strlen(s1), strlen(s2));
 * 2. returns 0 if the strings match and 1 otherwise;
 * 3. required @s2 is always in lower case.
 */
static inline int
tfw_stricmp_2lc(const char *s1, const char *s2, size_t len)
{
	return __tfw_stricmp_avx2_2lc(s1, s2, len);
}
#else

static inline void *
tfw_strtolower(void *dest, const void *src, size_t len)
{
	int i;
	unsigned char *d = dest;
	const unsigned char *s = src;

	for (i = 0; i < len; ++i)
		d[i] = tolower(s[i]);

	return dest;
}

static inline int
tfw_stricmp(const char *s1, const char *s2, size_t len)
{
	return strncasecmp(s1, s2, len);
}

static inline int
tfw_stricmp_2lc(const char *s1, const char *s2, size_t len)
{
	return strncasecmp(s1, s2, len);
}
#endif

/* Buffer size to hold all possible values of unsigned long */
#define TFW_ULTOA_BUF_SIZ 20
size_t tfw_ultoa(unsigned long ai, char *buf, unsigned int len);

/*
 * ------------------------------------------------------------------------
 *	Tempesta chunked strings
 * ------------------------------------------------------------------------
 */
#define TFW_STR_FBITS		8
#define TFW_STR_FMASK		((1U << TFW_STR_FBITS) - 1)
#define TFW_STR_CN_SHIFT	TFW_STR_FBITS
#define __TFW_STR_CN_MAX	(~TFW_STR_FMASK)
/* Str is compound from many chunks, use indirect table for the chunks. */
#define __TFW_STR_COMPOUND 	(~((1U << TFW_STR_FBITS) - 1))
/*
 * Str constists from compound or plain strings.
 * Duplicate strings are also always compound on root level.
 */
#define TFW_STR_DUPLICATE	0x01
/* The string is complete and will not grow. */
#define TFW_STR_COMPLETE	0x02
/* Some name starts at the string chunk. */
#define TFW_STR_NAME		0x04
/* Some value starts at the string chunk. */
#define TFW_STR_VALUE		0x08

/*
 * @ptr		- pointer to string data or array of nested strings;
 * @skb		- socket buffer containign the string data;
 * @len		- total length of compund or plain string (HTTP message body
 *		  size can be extreme large, so we need 64 bits to handle it);
 * @eolen	- the length of string's line endings, if present (as for now,
 *		  it should be 0 if the string has no EOL at all, 1 for LF and
 *		  2 for CRLF);
 * @flags	- 3 most significant bytes for number of chunks of compound
 * 		  string and the least significant byte for flags;
 */
typedef struct {
	void		*ptr;
	struct sk_buff	*skb;
	unsigned long	len;
	unsigned char	eolen;
	unsigned int	flags;
} TfwStr;

#define DEFINE_TFW_STR(name, val) TfwStr name = { (val), NULL,		\
						  sizeof(val) - 1, 0 }
#define TFW_STR_FROM(s)         ((TfwStr){(char*)s, NULL, strlen(s)})

/* Use this with "%.*s" in printing calls. */
#define PR_TFW_STR(s)		(int)min(20UL, (s)->len), (char *)(s)->ptr

/* Numner of chunks in @s. */
#define TFW_STR_CHUNKN(s)	((s)->flags >> TFW_STR_CN_SHIFT)
#define TFW_STR_CHUNKN_LIM(s)	((s)->flags >= __TFW_STR_CN_MAX)
#define TFW_STR_CHUNKN_ADD(s, n) ((s)->flags += ((n) << TFW_STR_CN_SHIFT))
#define TFW_STR_CHUNKN_SUB(s, n) ((s)->flags -= ((n) << TFW_STR_CN_SHIFT))
#define __TFW_STR_CHUNKN_SET(s, n) ((s)->flags = ((s)->flags & TFW_STR_FMASK) \
						  | ((n) << TFW_STR_CN_SHIFT))
/* Compound string contains at least 2 chunks. */
#define TFW_STR_CHUNKN_INIT(s)	__TFW_STR_CHUNKN_SET(s, 2)

#define TFW_STR_INIT(s)		memset(s, 0, sizeof(TfwStr))

#define TFW_STR_EMPTY(s)	(!((s)->flags | (s)->len))
#define TFW_STR_PLAIN(s)	(!((s)->flags & __TFW_STR_COMPOUND))
#define TFW_STR_DUP(s)		((s)->flags & TFW_STR_DUPLICATE)

/* Get @c'th chunk of @s. */
#define __TFW_STR_CH(s, c)	((TfwStr *)(s)->ptr + (c))
#define TFW_STR_CHUNK(s, c)	(((s)->flags & __TFW_STR_COMPOUND)	\
				 ? ((c) >= TFW_STR_CHUNKN(s)		\
				    ? NULL				\
				    : __TFW_STR_CH(s, (c)))		\
				 : (!(c) ? s : NULL))
/*
 * Get last/current chunk of @s.
 * The most left leaf is taken as the current chunk for duplicate strings tree.
 */
#define TFW_STR_CURR(s)							\
({									\
	typeof(s) _tmp = TFW_STR_DUP(s)					\
		       ? (TfwStr *)(s)->ptr + TFW_STR_CHUNKN(s) - 1	\
		       : (s);						\
	(_tmp->flags & __TFW_STR_COMPOUND)				\
		? (TfwStr *)_tmp->ptr + TFW_STR_CHUNKN(_tmp) - 1	\
		: (_tmp);						\
 })
#define TFW_STR_LAST(s)		TFW_STR_CURR(s)

/* Iterate over all chunks (or just a single chunk if the string is plain). */
#define TFW_STR_FOR_EACH_CHUNK(c, s, end)				\
	/* Iterate over chunks, not duplicates. */			\
	BUG_ON(TFW_STR_DUP(s));						\
	if (TFW_STR_PLAIN(s)) {						\
		(c) = (s);						\
		end = (s) + 1;						\
	} else {							\
		(c) = (s)->ptr;						\
		end = (TfwStr *)(s)->ptr + TFW_STR_CHUNKN(s);		\
	}								\
	for ( ; (c) < end; ++(c))

/* The same as above, but for duplicate strings. */
#define TFW_STR_FOR_EACH_DUP(d, s, end)					\
	if (TFW_STR_DUP(s)) {						\
		(end) = (TfwStr *)(s)->ptr + TFW_STR_CHUNKN(s);		\
		(d) = (s)->ptr;						\
	} else {							\
		(d) = (s);						\
		(end) = (s) + 1;					\
	}								\
	for ( ; (d) < (end); ++(d))

/**
 * Update length of the string which points to new data ending at @curr_p.
 */
static inline void
tfw_str_updlen(TfwStr *s, const char *curr_p)
{
	unsigned int n;

	if (s->flags & __TFW_STR_COMPOUND) {
		TfwStr *chunk = (TfwStr *)s->ptr + TFW_STR_CHUNKN(s) - 1;

		BUG_ON(chunk->len);
		BUG_ON(!chunk->ptr || curr_p <= (char *)chunk->ptr);

		n = curr_p - (char *)chunk->ptr;
		chunk->len = n;
	} else {
		n = curr_p - (char *)s->ptr;
	}
	s->len += n;
}

/**
 * Returns EOL length
 */
static inline int
tfw_str_eolen(const TfwStr *s)
{
	return s->eolen;
}

/**
 * Updates EOL length value
 */
static inline void
tfw_str_set_eolen(TfwStr *s, unsigned int eolen)
{
	BUG_ON(eolen > 2); /* LF and CRLF is the only valid EOL markers */
	s->eolen = (unsigned char)eolen;
}

/**
 * Returns total string length, including EOL
 */
static inline unsigned long
tfw_str_total_len(const TfwStr *s)
{
	return s->len + s->eolen;
}

/**
 * Reduce @str length by @eolen bytes and fill the EOL.
 */
static inline void
tfw_str_fixup_eol(TfwStr *str, int eolen)
{
	BUG_ON(eolen > 2); /* eolen = 0 is a legit value */
	BUG_ON(!TFW_STR_PLAIN(str));

	str->len -= (str->eolen = eolen);
	if (eolen == 1)
		*(char *)(str->ptr + str->len) = 0x0a; /* LF, '\n' */
	else if (eolen == 2)
		*(short *)(str->ptr + str->len) = 0x0a0d; /* CRLF, '\r\n' */
}

void tfw_str_del_chunk(TfwStr *str, int id);

TfwStr *tfw_str_add_compound(TfwPool *pool, TfwStr *str);
TfwStr *tfw_str_add_duplicate(TfwPool *pool, TfwStr *str);

typedef enum {
	TFW_STR_EQ_DEFAULT = 0x0,
	TFW_STR_EQ_PREFIX  = 0x1,
	TFW_STR_EQ_CASEI   = 0x2,
	TFW_STR_EQ_PREFIX_CASEI = (TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI),
} tfw_str_eq_flags_t;

int tfw_strcpy(TfwStr *dst, const TfwStr *src);
int tfw_strcat(TfwPool *pool, TfwStr *dst, TfwStr *src);

int tfw_stricmpspn(const TfwStr *s1, const TfwStr *s2, int stop);
bool tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
                     tfw_str_eq_flags_t flags);
bool tfw_str_eq_cstr_pos(const TfwStr *str, const char *pos, const char *cstr,
			 int cstr_len, tfw_str_eq_flags_t flags);
bool tfw_str_eq_cstr_off(const TfwStr *str, ssize_t offset, const char *cstr,
			 int cstr_len, tfw_str_eq_flags_t flags);

size_t tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size);

#ifdef DEBUG
void tfw_str_dprint(TfwStr *str, const char *msg);
#else
#define tfw_str_dprint(str, msg)
#endif

#endif /* __TFW_STR_H__ */
