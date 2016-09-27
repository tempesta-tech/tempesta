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
 *    skbs. In this case 'chunknum' field is not zero;
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
 * a data in the region pointed to by `data`.
 *
 * Another possibility is a so called duplicate string. A duplicate string is
 * a bunch of strings that describe HTTP fields with the same name.
 * For example, an HTTP server can return mulitple Set-Cookie fields;
 * all of those will end up in a duplicate string. Such strings use `ptr`
 * field as an array of TfwStr's, each of which can be a compound string.
 * A duplicate string can not itself consist of duplicate strings.
 * `flags` field is used for discerning the types of strings.

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
#include <linux/skbuff.h>
#include <linux/string.h>

#include "pool.h"

#define __TFW_STR_CN_MAX	0xffffff
#define TFW_STR_DUPLICATE	0x01
/* The string is complete and will not grow. */
#define TFW_STR_COMPLETE	0x02
/* Some name starts at the string chunk. */
#define TFW_STR_NAME		0x04
/* Some value starts at the string chunk. */
#define TFW_STR_VALUE		0x08

/*
 * @data	- pointer to string data;
*  @chunks	- pointer to array of chunks of a chunked string;
 * @skb		- socket buffer containign the string data;
 * @len		- total length of compund or plain string (HTTP message body
 *		  size can be extreme large, so we need 64 bits to handle it);
 * @eolen	- the length of string's line endings, if present (as for now,
 *		  it should be 0 if the string has no EOL at all, 1 for LF and
 *		  2 for CRLF);
 * @flags	- 8-bit type of string;
 */
typedef struct TfwStr {
	struct sk_buff	*skb;
	unsigned long	len;
	unsigned char	eolen;
	unsigned int	chunknum : 24;
	unsigned int	flags : 8;
	union {
		char *data;
		struct TfwStr *chunks;
	};
} TfwStr;
#define DEFINE_TFW_STR(name, val) TfwStr name = { .data = (val),\
						  .len = sizeof(val) - 1}
						  	
#define TFW_STR_FROM(s)         ((TfwStr){ .data = (char *)s,\
					   .len = sizeof(s) - 1 })
/* For dynamic strings with the strlen().*/
#define TFW_STR_FROMDS(s)         ((TfwStr){ .data = (char *)s,\
					     .len = strlen(s) })

/* Use this with "%.*s" in printing calls. */
#define PR_TFW_STR(s)		(int)min(20UL, (s)->len), (s)->data

/* Numner of chunks in @s. */
#define TFW_STR_CHUNKN(s)	((s)->chunknum)
#define TFW_STR_CHUNKN_LIM(s)	((s)->chunknum >= __TFW_STR_CN_MAX)
#define TFW_STR_CHUNKN_ADD(s, n) ((s)->chunknum += (n))
#define TFW_STR_CHUNKN_SUB(s, n) ((s)->chunknum -= (n))
#define __TFW_STR_CHUNKN_SET(s, n) ((s)->chunknum = (n))
/* Compound string contains at least 2 chunks. */
#define TFW_STR_CHUNKN_INIT(s)	__TFW_STR_CHUNKN_SET(s, 2)

#define TFW_STR_INIT(s)		memset(s, 0, sizeof(TfwStr))

#define TFW_STR_EMPTY(s)	(!(s)->len && !(s)->chunknum)
#define TFW_STR_PLAIN(s)	(!(s)->chunknum)
#define TFW_STR_DUP(s)		((s)->flags & TFW_STR_DUPLICATE)

/* Get @c'th chunk of @s. */
#define __TFW_STR_CH(s, c)	(!TFW_STR_PLAIN(s)? (s)->chunks + (c) : s)
#define TFW_STR_CHUNK(s, c)	(!TFW_STR_PLAIN(s)			\
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
		       ? (s)->chunks + TFW_STR_CHUNKN(s) - 1		\
		       : (s);						\
	(!TFW_STR_PLAIN(_tmp))						\
		? _tmp->chunks + TFW_STR_CHUNKN(_tmp) - 1		\
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
		(c) = (s)->chunks;					\
		end = (s)->chunks + TFW_STR_CHUNKN(s);			\
	}								\
	for ( ; (c) < end; ++(c))

/* The same as above, but for duplicate strings. */
#define TFW_STR_FOR_EACH_DUP(d, s, end)					\
	if (TFW_STR_DUP(s)) {						\
		(end) = (s)->chunks + TFW_STR_CHUNKN(s);		\
		(d) = (s)->chunks;					\
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

	TFW_DBG("str_upd_len:start:sl:%lu;sf:%d\n", s->len, s->flags);
	if (!TFW_STR_PLAIN(s)) {
		TfwStr *chunk = s->chunks + TFW_STR_CHUNKN(s) - 1;

		BUG_ON(chunk->len);
		BUG_ON(!chunk->chunks || curr_p <= chunk->data);

		n = curr_p - chunk->data;
		TFW_DBG("str_upd_len:n:%u\n", n);
		chunk->len = n;
	} else {
		n = curr_p - s->data;
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
 * Reduce @str length by @eolen bytes and fill the EOL.
 */
static inline void
tfw_str_fixup_eol(TfwStr *str, int eolen)
{
	BUG_ON(eolen > 2); /* eolen = 0 is a legit value */
	BUG_ON(!TFW_STR_PLAIN(str));

	str->len -= (str->eolen = eolen);
	if (eolen == 1)
		*(str->data + str->len) = 0x0a; /* LF, '\n' */
	else if (eolen == 2)
		*(short *)(str->data + str->len) = 0x0a0d; /* CRLF, '\r\n' */
}

/**
 * Returns total string length, including EOL
 */
static inline unsigned long
tfw_str_total_len(const TfwStr *s)
{
	return s->len + s->eolen;
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
