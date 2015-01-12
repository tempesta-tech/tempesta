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
#ifndef __TFW_STR2_H__
#define __TFW_STR2_H__

#include "pool.h"

/**
 * The structure is packed. That reduces sizeof() the structure from 16 to 10
 * bytes on x86_64 and thus saves about 40% of memory for fragmented strings.
 * Fragmented strings are not rare:
 *  - Modern web application use big HTTP headers (700-800 bytes on average,
 *    according to Google's SPDY whitepapper). Also there are URIs and HTTP
 *    pipelining, so requests are often fragmented because they reach common
 *    MTU/MSS values of about 1500 bytes.
 *  - HTTP responses are almost always fragmented. An average HTML page size
 *    in the year 2014 is 60KB (according to httparchive.org), so the HTTP
 *    parser almost always creates many chunks for HTTP response bodies.
 * So for fragmented HTTP messages we store chunks more compact, and therefore
 * improve cache hit rate in cost of unaligned access overhead.
 * The exact impact on the performance should be measured with benchmarks,
 * but until then, we try to minimize the memory footprint, because we have many
 * TfwStr/TfwStrChunk structures allocated for each TfwHttpMsg object.
 */
typedef struct  __attribute__ ((packed)) {
	char *data;
	u16 len;
} TfwStrChunk;

/**
 * TfwStr is a chunked string representation.
 * In the Tempesta FW we aim to utilize zero-copy approach everywhere,
 * so instead of copying HTTP requests into some buffers, we collect incoming
 * skb and make (possibly fragmented) TfwStr objects from them.
 *
 * A TfwStr may consist of many fragments (represented by TfwStrChunk).
 * Such string is called "compound". In this case (@cnum > 1) the @chunks points
 * to a dynamically allocated array of chunks.
 *
 * When there is only one chunk, it is embedded right into the TfwStr structure.
 * Such string is called "plain", and in this case (@cnum <= 1) the @chunks
 * field is invalid and the data may be accessed via the @singe_chunk field.
 * That allows to avoid memory allocation. We expect most of strings consist of
 * a single framgnet, and we expect to have a lot of TfwStr objects under load,
 * so this approach helps to save a lot of memory and costly memory allocations.
 * As a drawback, we have to handle the single chunk case in all functions
 * working with the TfwStr; that introduces some overhead too, so benchmarks
 * should be done to measure it, but until then, we are trying to save memory.
 *
 * @len is the sum of all chunks added together.
 * The field is valid for both plain and compound strings, but you should not
 * access them directly because the implementation may change.
 * Use functions and macros defined below.
 */
typedef union {
	struct {
		TfwStrChunk *chunks;
		u32 len;
		u16 cnum;
		/* u16 hash; (TODO: optimize string comparison using it). */
	};
	TfwStrChunk single_chunk;
} TfwStr;

#define TFW_STR_LEN_MAX		0xFFFFFFFF
#define TFW_STR_CNUM_MAX	0xFFFF
#define TFW_STR_CHUNK_LEN_MAX	0xFFFF

#define TFW_STR_IS_COMPOUND(s)  ((s)->cnum > 1)	/* 0 chunks is also plain. */
#define TFW_STR_IS_NOT_EMPTY(s) ((s)->chunks)	/* @chunks is aligned */
#define TFW_STR_IS_EMPTY(s)	(!(s)->chunks)

/* Initialize TfwStr (slightly optimized). */
#define TFW_STR_INIT(s)			\
do {					\
	*((u64 *)s) = U64_C(0);		\
	*((u64 *)s + 1) = U64_C(0);	\
} while (0)

/* Shallow copy: doesn't copy allocated @chunks table. */
#define TFW_STR_COPY(dst, src)	(*(dst) = *(src))

/* Get @c'th chunk of @s (starting from 0). */
#define TFW_STR_CHUNK(s, c)	(TFW_STR_IS_COMPOUND(s)		\
				 ? (c >= (s)->cnum		\
				    ? NULL			\
				    : (s)->chunks + c)		\
				 : (c				\
				    ? NULL 			\
				    : &(s)->single_chunk))

/* Get last/current chunk of @s. */
#define TFW_STR_CURR(s) (TFW_STR_IS_COMPOUND(s)			\
			 ? ((s)->chunks + (s)->cnum - 1)	\
			 : &(s)->single_chunk)

/* Iterate over all chunks (or just a single chunk if the string is plain). */
#define TFW_STR_FOR_EACH_CHUNK(c, s) \
	for ((c) = _TFW_STR_CHUNKS_START(s); (c) < _TFW_STR_CHUNKS_END(s); ++(c))

#define _TFW_STR_CHUNKS_START(s) \
	(TFW_STR_IS_COMPOUND(s) ? (s)->chunks : &(s)->single_chunk)

#define _TFW_STR_CHUNKS_END(s) \
	(_TFW_STR_CHUNKS_START(s) + (s)->cnum)

int tfw_str_add_chunk(TfwStr *str, const char *start_pos, const char *end_pos,
		      TfwPool *pool);
int tfw_str_len(const TfwStr *str);
int tfw_str_to_cstr(const TfwStr *str, char *out_buf, int buf_size);

/* Comparison functions. */

typedef enum {
	TFW_STR_EQ_DEFAULT = 0x0,
	TFW_STR_EQ_PREFIX  = 0x1,
	TFW_STR_EQ_CASEI   = 0x2,
	TFW_STR_EQ_PREFIX_CASEI = (TFW_STR_EQ_PREFIX | TFW_STR_EQ_CASEI),
} tfw_str_eq_flags_t;

bool tfw_str_eq_cstr(const TfwStr *str, const char *cstr, int cstr_len,
                     tfw_str_eq_flags_t flags);
bool tfw_str_eq_kv(const TfwStr *str, const char *key, int key_len, char sep,
                   const char *val, int val_len, tfw_str_eq_flags_t flags);

#endif /* __TFW_STR2_H__ */
