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

#include <inttypes.h>

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
	uintptr_t current;
	uintptr_t n;
	uintptr_t tail;
	uintptr_t offset;
} HTTP2Input;

/* Initialize input buffer from the TfwStr: */

void buffer_from_tfwstr(HTTP2Input * __restrict p,
			const TfwStr * __restrict str);

/* Get pointer to and length ("m") of the current fragment: */

const unsigned char *buffer_get(HTTP2Input * __restrict p,
				uintptr_t * __restrict m);

/* Get the next pointer and length of the next fragment: */

const unsigned char *buffer_next(HTTP2Input * __restrict p,
				 uintptr_t * __restrict m);

/* Close current parser iteration. Here "m" is the length */
/* of unparsed tail of the current fragment: */

void buffer_close(HTTP2Input * __restrict p, uintptr_t m);

/* Skip "n" bytes in the input buffer: */

const unsigned char *buffer_skip(HTTP2Input * __restrict p,
				 const unsigned char *__restrict src,
				 uintptr_t m,
				 uintptr_t * __restrict m_new, uintptr_t n);

/* Count number of the fragments consumed by the   */
/* string of "length" bytes, which starts from the */
/* current position in the buffer. If the current  */
/* fragment is fully consumed by decoder, then get */
/* pointer to the next fragment and return its	   */
/* length in the "m_new" output parameter:         */

const unsigned char *buffer_count(HTTP2Input * __restrict p,
				  uintptr_t * __restrict m_new,
				  const unsigned char *__restrict src,
				  uintptr_t m,
				  uintptr_t length,
				  uintptr_t * __restrict count);

/* Extract string of the "length" bytes from the     */
/* input buffer, starting from the current position. */
/* Here "out" is the pointer to descriptor of the    */
/* output string and "m_new" is the pointer to       */
/* updated length of the current fragment:	     */

const unsigned char *buffer_extract(HTTP2Input * __restrict p,
				    uintptr_t * __restrict m_new,
				    const unsigned char *__restrict src,
				    uintptr_t m,
				    uintptr_t length,
				    TfwStr * __restrict out,
				    TfwPool * __restrict pool,
				    unsigned int *__restrict rc);

/* Copy string of the "length" bytes from the input */
/* buffer (starting from the current position) to   */
/* the output buffer. Here "out" is the pointer to  */
/* the output buffer and "m_new" is the pointer to  */
/* updated length of the current fragment:	    */

typedef struct HTTP2Output HTTP2Output;

const unsigned char *buffer_copy(HTTP2Input * __restrict p,
				 uintptr_t * __restrict m_new,
				 const unsigned char *__restrict src,
				 uintptr_t m,
				 uintptr_t length,
				 HTTP2Output * __restrict out,
				 unsigned int *__restrict rc);

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
	uint16_t n;
	uint16_t tail;
	unsigned char data[1];
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

#define CheckByte_goto(out, Bug)		 \
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
	uint16_t space;
	uint8_t def_align;
	uint8_t align;
	uint16_t tail;
	uint16_t offset;
	uintptr_t total;
	uint16_t start;
	uint32_t count;
	HTTP2Block *last;
	HTTP2Block *current;
	HTTP2Block *first;
	TfwPool *pool;
	TfwStr str;
};

/* Initialize new output buffer: */

void buffer_new(HTTP2Output * __restrict p,
		TfwPool * __restrict pool, unsigned int alignment);

/* Opens the output buffer. For example it may be used	    */
/* to stored decoded data while parsing the encoded string, */
/* which located in the input buffer. Output parameter "n"  */
/* is the length of available space in the opened buffer:   */

unsigned char *buffer_open(HTTP2Output * __restrict p,
			   unsigned int *__restrict n, unsigned int alignment);

/* Opens the output buffer and reserves the "size" bytes     */
/* in that opened buffer. Output parameter "n" is the length */
/* of available space in the opened buffer:		     */

unsigned char *buffer_open_small(HTTP2Output * __restrict p,
				 unsigned int *__restrict n,
				 unsigned int size, unsigned int alignment);

/* Reserving the "size" bytes in the output buffer */
/* without opening it:				   */

unsigned char *buffer_small(HTTP2Output * __restrict p,
			    unsigned int size, unsigned int alignment);

/* Pause writing to the output buffer without */
/* emitting string. Here "n" is the length of */
/* the unused space in the last fragment:     */

void buffer_pause(HTTP2Output * __restrict p, unsigned int n);

/* Reopen the output buffer that is paused before. */
/* Output parameter "n" is the length of available */
/* space in the buffer: 			   */

unsigned char *buffer_resume(HTTP2Output * __restrict p,
			     unsigned int *__restrict n);

/* Add new block to the output buffer. Returns the NULL    */
/* and zero length ("n_new") if unable to allocate memory. */
/* Here "n" is the number of unused bytes in the current   */
/* fragment of the buffer:				   */

unsigned char *buffer_expand(HTTP2Output * __restrict p,
			     unsigned int *__restrict n_new, unsigned int n);

/* Forms a new string from the data stored in the output   */
/* buffer. Returns error code if unable to allocate memory */
/* for the string descriptor. Input parameter "n" is the   */
/* number of unused bytes of the tail fragment: 	   */

unsigned int buffer_emit(HTTP2Output * __restrict p, unsigned int n);

/* Copy data from the plain memory block to the output	  */
/* buffer and build a TfwStr string from the copied data: */

unsigned int buffer_put(HTTP2Output * __restrict p,
			const unsigned char *__restrict src, uintptr_t length);

/* Copy data from the plain memory block to the output */
/* buffer (which is already opened before this call):  */

unsigned char *buffer_put_raw(HTTP2Output * __restrict p,
			      unsigned char *__restrict dst,
			      unsigned int *__restrict k_new,
			      const unsigned char *__restrict src,
			      uintptr_t length, unsigned int *__restrict rc);

/* Copy data from the TfwStr string to the output      */
/* buffer (which is already opened before this call).  */
/* If error occured, then output parameter "remainder" */
/* contains the length of unprocessed part of the      */
/* TfwStr string (user can supply NULL pointer here):  */

unsigned char *buffer_put_string(HTTP2Output * __restrict p,
				 unsigned char *__restrict dst,
				 unsigned int *__restrict k_new,
				 const TfwStr * __restrict source,
				 unsigned int *__restrict rc,
				 uintptr_t * __restrict remainder);

/* ------------------------------------------ */
/* Supplementary functions related to TfwStr: */
/* ------------------------------------------ */

/* Compare plain memory string "x" with array of the */
/* TfwStr fragments represented by the "fp" pointer. */
/* Parameter "n" is the minimum between the total    */
/* length of all "fp" fragments and the length of    */
/* the "x" string:                                   */

int buffer_str_cmp_plain(const unsigned char *__restrict x,
			 const TfwStr * __restrict fp, uintptr_t n);

/* Compare two arrays of the TfwStr fragments represented */
/* by the "fx" and "fy" pointers. Here "n" is the minimum */
/* between the total length of all "fx" fragments and the */
/* total length of all "fy" fragments:                    */

int buffer_str_cmp_complex(const TfwStr * __restrict fx,
			   const TfwStr * __restrict fy, uintptr_t n);

/* Compare two TfwStr strings: */

intptr_t buffer_str_cmp(const TfwStr * __restrict x,
			const TfwStr * __restrict y);

/* Calculate simple hash function of the TfwStr string: */

uintptr_t buffer_str_hash(const TfwStr * __restrict x);

/* Copy data from the TfwStr string to plain array: */

void buffer_str_to_array(unsigned char *__restrict data,
			 const TfwStr * __restrict str);

/* Print the TfwStr string: */

void buffer_str_print(const TfwStr * __restrict str);

/* Free memory occupied by the TfwStr descriptors, */
/* which may be allocated for compound strings:    */

static __inline__ void
buffer_str_free(TfwPool * __restrict pool, TfwStr * __restrict str)
{
	if (!TFW_STR_PLAIN(str)) {
		const unsigned int count = TFW_STR_CHUNKN(str);

		tfw_pool_free(pool, str->ptr, count * sizeof(TfwStr));
	}
}

#endif
