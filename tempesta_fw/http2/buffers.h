/**
 *		Tempesta FW
 *
 * HTTP/2 bufferization layer for fragment-based parser.
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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

#ifndef HTTP2_BUFFERS_H
#define HTTP2_BUFFERS_H

#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "errors.h"

/* -------------------------------------------------- */
/* Input buffers, which are used to handle fragmented */
/* stings as input of the parsers:		      */
/* -------------------------------------------------- */

/* str:     Source string.		       */
/* current: Index of the current TfwStr chunk. */
/* n:	    Total number of unparsed octets    */
/*	    in the string.		       */
/* tail:    Length of the unparsed tail of     */
/*	    the current fragment.	       */
/* offset:  Offset in the current fragment.    */

typedef struct {
	const TfwStr *str;
	uwide current;
	uwide n;
	uwide tail;
	uwide offset;
} HTTP2Input;

/* Initialize input buffer from the TfwStr: */

void buffer_from_tfwstr(HTTP2Input * __restrict p,
			const TfwStr * __restrict str);

/* Get pointer to and length of the current fragment ("m"): */

const uchar *buffer_get(HTTP2Input * __restrict p, uwide * __restrict m);

/* Get the next pointer and length of the next fragment: */

const uchar *buffer_next(HTTP2Input * __restrict p, uwide * __restrict m);

/* Close current parser iteration. Here "m" is the length */
/* of unparsed tail of the current fragment: */

void buffer_close(HTTP2Input * __restrict p, uwide m);

/* Count number of the fragments consumed by the string */
/* of "length" bytes, which starts from the current     */
/* position in the buffer. If the current fragment is	*/
/* fully consumed by decoder, then get pointer to the	*/
/* next fragment and return its length in the "m_new"   */
/* output parameter.					*/

const uchar *buffer_count(HTTP2Input * __restrict p,
			  uwide * __restrict m_new,
			  const uchar * __restrict src,
			  uwide m, uwide length, uwide * __restrict count);

/* Extract string of the "length" bytes from the     */
/* input buffer, starting from the current position. */
/* Here "out" is the pointer to descriptio of the    */
/* output string and "m_new" is the pointer to       */
/* updated length of the current fragment.	     */

const uchar *buffer_extract(HTTP2Input * __restrict p,
			    uwide * __restrict m_new,
			    const uchar * __restrict src,
			    uwide m,
			    uwide length,
			    TfwStr * __restrict out,
			    TfwPool * __restrict pool, ufast * __restrict rc);

/* Copy string of the "length" bytes from the input */
/* buffer (starting from the current position) to   */
/* the output buffer. Here "out" is the pointer to  */
/* the output buffer and "m_new" is the pointer to  */
/* updated length of the current fragment.	    */

typedef struct HTTP2Output HTTP2Output;

const uchar *buffer_copy(HTTP2Input * __restrict p,
			 uwide * __restrict m_new,
			 const uchar * __restrict src,
			 uwide m,
			 uwide length,
			 HTTP2Output * __restrict out, ufast * __restrict rc);

/* ------------------------------------------------- */
/* Output buffers, which are used to store decoded   */
/* stings in the parsers or to store encoded strings */
/* in the packet generators:			     */
/* ------------------------------------------------- */

/* next: Next allocated block.	   */
/* n:	 Block length.		   */
/* tail: Length of the unused tail */
/*	 of the block (in bytes).  */
/* data: Encoded or decoded data.  */

typedef struct HTTP2Block {
	struct HTTP2Block *next;
	uint16 n;
	uint16 tail;
	uchar data[1];
} HTTP2Block;

/* Useful macros for checking before writing one byte: */

#define CheckByte(out)				      \
do {						      \
	if (unlikely(k == 0)) { 		      \
		dst = buffer_expand(out, &k, k);      \
		if (unlikely(k == 0)) { 	      \
			return Err_HTTP2_OutOfMemory; \
		}				      \
	}					      \
} while (0)

#define CheckByte_goto(out)			 \
do {						 \
	if (unlikely(k == 0)) { 		 \
		dst = buffer_expand(out, &k, k); \
		if (unlikely(k == 0)) { 	 \
			goto Bug;		 \
		}				 \
	}					 \
} while (0)

/* first:     First allocated block in the queue.    */
/* last:      Last allocated block in the queue.     */
/* current:   Block where current string is started. */
/* offset:    Offset of the current string in the    */
/*	      first block where it started.	     */
/* tail:      Length of the unused tail of the last  */
/*	      block.				     */
/* count:     Total number of chunks in the current  */
/*	      string.				     */
/* total:     Total length of the current string.    */
/* pool:      Memory allocation pool.		     */
/* def_align: Default alignment for the next block   */
/*	      allocated from this buffer, converted  */
/*	      into a (2^n - 1) mask.		     */
/* align:     Alignment requirement for the current  */
/*	      string (converted into a mask).	     */
/* str:       Last string, which is created in	     */
/*	      the buffer.			     */

struct HTTP2Output {
	uint16 space;
	uint8 def_align;
	uint8 align;
	uint16 tail;
	uint16 offset;
	uwide total;
	uint16 start;
	uint32 count;
	HTTP2Block *last;
	HTTP2Block *current;
	HTTP2Block *first;
	TfwPool *pool;
	TfwStr str;
};

/* Initialize new output buffer: */

void buffer_new(HTTP2Output * __restrict p,
		TfwPool * __restrict pool, ufast alignment);

/* Opens the output buffer. For example it may be used */
/* to stored decoded data while parsing the encoded    */
/* string, which placed in the input buffer. Output    */
/* parameter "n" is the length of available space in   */
/* the opened buffer:				       */

uchar *buffer_open(HTTP2Output * __restrict p,
		   ufast * __restrict n, ufast alignment);

/* Opens the output buffer and reserves the "size" bytes     */
/* in that opened buffer. Output parameter "n" is the length */
/* of available space in the opened buffer:		     */

uchar *buffer_open_small(HTTP2Output * __restrict p,
			 ufast * __restrict n, ufast size, ufast alignment);

/* Reserving "size" bytes in the output buffer without */
/* opening it:					       */

uchar *buffer_small(HTTP2Output * __restrict p, ufast size, ufast alignment);

/* Pause writing to the output buffer without */
/* emitting string. Here "n" is the length of */
/* the unused space in the last fragment:     */

void buffer_pause(HTTP2Output * __restrict p, ufast n);

/* Reopen the output buffer that is paused before. */
/* Here "n" is the length of available space in    */
/* the buffer:					   */

uchar *buffer_resume(HTTP2Output * __restrict p, ufast * __restrict n);

/* Add new block to the output buffer. Returns the NULL    */
/* and zero length ("n_new") if unable to allocate memory. */
/* Here "n" is the number of unused bytes in the current   */
/* fragment of the buffer.				   */

uchar *buffer_expand(HTTP2Output * __restrict p,
		     ufast * __restrict n_new, ufast n);

/* Forms a new string from the data stored in  */
/* the buffer. Returns error code if unable to */
/* allocate memory for the string descriptor.  */
/* Here "n" is the number of unused bytes in   */
/* the last fragment of the buffer.	       */

ufast buffer_emit(HTTP2Output * __restrict p, ufast n);

/* Copy data from the plain memory block to the output	  */
/* buffer and build a TfwStr string from the copied data: */

ufast buffer_put(HTTP2Output * __restrict p,
		 const uchar * __restrict src, uwide length);

/* Copy raw data from the plain memory block to the output */
/* buffer, which already opened by the buffer_open() call: */

uchar *buffer_put_raw(HTTP2Output * __restrict p,
		      uchar * __restrict dst,
		      ufast * __restrict n,
		      const uchar * __restrict src,
		      uwide length, ufast * __restrict rc);

/* Copy raw data from the plain memory block to the output */
/* buffer, which already opened by the buffer_open() call: */

uchar *buffer_put_string(HTTP2Output * __restrict p,
			 uchar * __restrict dst,
			 ufast * __restrict n,
			 const TfwStr * __restrict source,
			 ufast * __restrict rc);

/* ------------------------------------------ */
/* Supplementary functions related to TfwStr: */
/* ------------------------------------------ */

/* Compare plain memory string "x" with array of the   */
/* TfwStr fragments represented by the "fp" pointer.   */
/* Here "n" is the minimum between the total length    */
/* of all "fp" fragments and the length of "x" string: */

int buffer_str_cmp_plain(const uchar * __restrict x,
			 const TfwStr * __restrict fp, uwide n);

/* Compare two arrays of the TfwStr fragments represented */
/* by the "fx" and "fy" pointers. Here "n" is the minimum */
/* between the total length of all "fx" fragments and the */
/* total length of all "fy" fragments:                    */

int buffer_str_cmp_complex(const TfwStr * __restrict fx,
			   const TfwStr * __restrict fy, uwide n);

/* Compare two TfwStr strings: */

wide buffer_str_cmp(const TfwStr * __restrict x, const TfwStr * __restrict y);

/* Calculate simple hash function by the string: */

uwide buffer_str_hash(const TfwStr * __restrict x);

/* Copy data from the TfwStr to plain array: */

void buffer_str_to_array(uchar * __restrict data,
			 const TfwStr * __restrict str);

/* Print TfwStr string: */

void buffer_str_print(const TfwStr * __restrict str);

/* Free memory occupied by the TfwStr descriptors, */
/* which may be allocated for compound strings:    */

common_inline void
buffer_str_free(TfwPool * __restrict pool, TfwStr * __restrict str)
{
	if (!TFW_STR_PLAIN(str)) {
		const ufast count = TFW_STR_CHUNKN(str);

		tfw_pool_free(pool, str->ptr, count * sizeof(TfwStr));
	}
}

#endif
