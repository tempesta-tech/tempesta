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

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "hash.h"
#include "errors.h"
#include "buffers.h"

#define Debug_Buffers 0

#if Debug_Buffers
#define DPRINTF(...) printf("Buffers: " __VA_ARGS__)
#define DPUTS(...) puts("Buffers: " __VA_ARGS__)
#else
#define DPRINTF(...)
#define DPUTS(...)
#endif

/* -------------------------------------------------- */
/* Input buffers, which are used to handle fragmented */
/* stings as input of the parsers:		      */
/* -------------------------------------------------- */

/* Initialize input buffer from the TfwStr: */

void
buffer_from_tfwstr(HTTP2Input * __restrict p, const TfwStr * __restrict str)
{
	p->str = str;
	p->current = 0;
	p->n = str->len;
/* p->tail is initialized here only to avoid */
/* partial writing into cache line, really */
/* it does not used by buffer_get() call: */
	p->tail = 0;
	p->offset = 0;
}

/* Get pointer to and length ("m") of the current fragment: */

const uchar *
buffer_get(HTTP2Input * __restrict p, uwide * __restrict m)
{
	const TfwStr *__restrict fp = p->str;
	const uwide offset = p->offset;
	uwide tail;

	if (TFW_STR_PLAIN(fp)) {
		tail = p->n;
	} else {
		fp = __TFW_STR_CH(fp, p->current);
		tail = fp->len - offset;
	}
	p->tail = tail;
	*m = tail;
	DPRINTF("Open the input buffer at: %" PRIuPTR
		", tail: %" PRIuPTR " bytes...\n", offset, tail);
	return (const uchar *)fp->ptr + offset;
}

/* Get the next pointer and length of the next fragment: */

const uchar *
buffer_next(HTTP2Input * __restrict p, uwide * __restrict m)
{
	const uwide current = p->current + 1;
	const TfwStr *const __restrict fp = __TFW_STR_CH(p->str, current);
	const uwide length = fp->len;

	p->current = current;
	p->n -= p->tail;
	p->tail = length;
	p->offset = 0;
	*m = length;
	DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", length);
	return (const uchar *)fp->ptr;
}

/* Close current parser iteration. Here "m" is the length */
/* of unparsed tail of the current fragment: */

void
buffer_close(HTTP2Input * __restrict p, uwide m)
{
	const uwide bias = p->tail - m;

	if (bias) {
		DPRINTF("Consumed %" PRIuPTR " bytes...\n", bias);
		p->n -= bias;
		if (m) {
			p->offset += bias;
		} else {
			p->current++;
			p->offset = 0;
		}
	}
}

/* Count number of the fragments consumed by the string */
/* of "length" bytes, which starts from the current     */
/* position in the buffer. If the current fragment is	*/
/* fully consumed by decoder, then get pointer to the	*/
/* next fragment and return its length in the "m_new"   */
/* output parameter.					*/

const uchar *
buffer_count(HTTP2Input * __restrict p,
	     uwide * __restrict m_new,
	     const uchar * __restrict src,
	     uwide m, uwide length, uwide * __restrict count)
{
	const TfwStr *const __restrict str = p->str;
	uwide current = p->current;
	const TfwStr *__restrict fp = __TFW_STR_CH(str, current);
	const TfwStr *__restrict fp_start;

	if (unlikely(m == 0)) {
		fp++;
		current++;
		m = fp->len;
		p->current = current;
		p->n -= p->tail;
		p->tail = m;
		p->offset = 0;
		src = (const uchar *)fp->ptr;
		DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", m);
	}
	*m_new = m;
	fp_start = fp;
	do {
		length -= m;
		m = fp->len;
		fp++;
	} while (length > m);
	*count = (fp - fp_start) + 1;
	return src;
}

/* Extract string of the "length" bytes from the     */
/* input buffer, starting from the current position. */
/* Here "out" is the pointer to descriptor of the    */
/* output string and "m_new" is the pointer to       */
/* updated length of the current fragment.	     */

const uchar *
buffer_extract(HTTP2Input * __restrict p,
	       uwide * __restrict m_new,
	       const uchar * __restrict src,
	       uwide m,
	       uwide length,
	       TfwStr * __restrict out,
	       TfwPool * __restrict pool, ufast * __restrict rc)
{
	if (m >= length) {
		*m_new = m - length;
		out->ptr = (uchar *) src;
		out->skb = NULL;
		out->len = length;
		out->eolen = 0;
		out->flags = 0;
		src += length;
		*rc = 0;
	} else {
		ufast count;
		const TfwStr *const __restrict str = p->str;
		uwide current = p->current;
		uwide tail = p->tail;
		const TfwStr *__restrict fp = __TFW_STR_CH(str, current);
		TfwStr *__restrict sp;

		if (unlikely(m == 0)) {
			fp++;
			current++;
			m = fp->len;
			p->n -= tail;
			tail = m;
			src = (const uchar *)fp->ptr;
			DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", m);
		}
		{
			const TfwStr *__restrict __fp = fp;
			uwide __m = m;
			uwide __length = length;

			do {
				__length -= __m;
				__m = __fp->len;
				__fp++;
			} while (__length > __m);
			count = (__fp - fp) + 1;
		}
		sp = tfw_pool_alloc(pool, count * sizeof(TfwStr));
		if (unlikely(sp == NULL)) {
			goto Bug;
		}
		out->ptr = sp;
		out->skb = NULL;
		out->len = length;
		out->eolen = 0;
		out->flags = count << TFW_STR_CN_SHIFT;
		p->n -= length;
		p->offset = 0;
		do {
			uwide copied;

			if (unlikely(m == 0)) {
				fp++;
				current++;
				m = fp->len;
				tail = m;
				src = (const uchar *)fp->ptr;
				DPRINTF("Next fragment: %" PRIuPTR
					" bytes...\n", m);
			}
			copied = m;
			if (m >= length) {
				copied = length;
			}
			sp->ptr = (uchar *) src;
			sp->skb = NULL;
			sp->len = copied;
			sp->eolen = 0;
			sp->flags = 0;
			sp++;
			src += copied;
			m -= copied;
			length -= copied;
		} while (length);
		*rc = 0;
 Save:
		p->current = current;
		p->tail = tail;
		*m_new = m;
	}
	return src;
 Bug:
	*rc = Err_HTTP2_OutOfMemory;
	goto Save;
}

/* Copy string of the "length" bytes from the input */
/* buffer (starting from the current position) to   */
/* the output buffer. Here "out" is the pointer to  */
/* the output buffer and "m_new" is the pointer to  */
/* updated length of the current fragment.	    */

const uchar *
buffer_copy(HTTP2Input * __restrict p,
	    uwide * __restrict m_new,
	    const uchar * __restrict src,
	    uwide m,
	    uwide length, HTTP2Output * __restrict out, ufast * __restrict rc)
{
	uwide tail, fragment;
	ufast k, code;
	const TfwStr *__restrict fp;
	uchar *__restrict dst = buffer_open(out, &k, 0);

	if (m >= length) {
		*m_new = m - length;
		do {
			uwide copied;

			CheckByte_goto(out, Bug);
			copied = k;
			if (k >= length) {
				copied = length;
			}
			memcpy(dst, src, copied);
			dst += copied;
			src += copied;
			k -= copied;
			length -= copied;
		} while (length);
		code = 0;
	} else {
		const TfwStr *const __restrict str = p->str;
		uwide current = p->current;

		tail = p->tail;
		fp = __TFW_STR_CH(str, current);
		if (unlikely(m == 0)) {
			fp++;
			current++;
			m = fp->len;
			p->n -= tail;
			tail = m;
			src = (const uchar *)fp->ptr;
			DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", m);
		}
		p->n -= length;
		p->offset = 0;
		do {
			if (unlikely(m == 0)) {
				fp++;
				current++;
				m = fp->len;
				tail = m;
				src = (const uchar *)fp->ptr;
				DPRINTF("Next fragment: %" PRIuPTR
					" bytes...\n", m);
			}
			fragment = m;
			if (m >= length) {
				fragment = length;
			}
			m -= fragment;
			length -= fragment;
			do {
				uwide copied;

				CheckByte_goto(out, Bug2);
				copied = k;
				if (k >= fragment) {
					copied = fragment;
				}
				memcpy(dst, src, copied);
				dst += copied;
				src += copied;
				k -= copied;
				fragment -= copied;
			} while (fragment);
		} while (length);
		code = 0;
 Save:
		p->current = current;
		p->tail = tail;
		*m_new = m;
	}
 Emit:
	*rc = buffer_emit(out, k);
	if (likely(code == 0)) {
		return src;
	}
	*rc = code;
	return src;
 Bug:
/* Partially rewind the input buffer: */
	*m_new += length;
	code = Err_HTTP2_OutOfMemory;
	goto Emit;
 Bug2:
/* Partially rewind the input buffer: */
	length += fragment;
	m += fragment;
	p->n += length;
	p->offset = fp->len - tail;
	code = Err_HTTP2_OutOfMemory;
	goto Save;
}

/* ------------------------------------------------- */
/* Output buffers, which are used to store decoded   */
/* stings in the parsers or to store encoded strings */
/* in the packet generators:			     */
/* ------------------------------------------------- */

/* Initialize new output buffer: */

void
buffer_new(HTTP2Output * __restrict p,
	   TfwPool * __restrict pool, ufast alignment)
{
	ufast align = Word_Size - 1;

	if (alignment) {
		align = ~alignment & (alignment - 1);
	}
/* Many fields initialized here only to avoid */
/* partial writing into cache lines: */
	p->space = 0;
	p->def_align = align;
	p->align = align;
	p->tail = 0;
	p->offset = 0;
	p->total = 0;
	p->start = 0;
	p->count = 0;
	p->last = NULL;
	p->current = NULL;
	p->first = NULL;
	p->pool = pool;
}

/* Opens the output buffer. For example it may be used	    */
/* to stored decoded data while parsing the encoded string, */
/* which located in the input buffer. Output parameter "n"  */
/* is the length of available space in the opened buffer:   */

uchar *
buffer_open(HTTP2Output * __restrict p, ufast * __restrict n, ufast alignment)
{
	ufast tail = p->tail;
	ufast align;

	if (alignment == 0) {
		align = p->def_align;
	} else {
		align = ~alignment & (alignment - 1);
	}
	p->align = align;
	if (tail) {
		HTTP2Block *const __restrict last = p->last;
		const ufast offset = p->offset;
		uchar *__restrict dst = last->data + offset;

		/* Calculate distance to the next aligned block.    */
		/* Typecast to the signed integer was added here    */
		/* to eliminate compiler warning about unary minus  */
		/* operator (which would be applied to the unsigned */
		/* integer otherwise) - we know exactly what we do: */
		const ufast delta = (ufast) (-(fast) dst) & align;

		if (likely(delta + align <= tail)) {
			tail -= delta;
			*n = tail;
			p->space = tail;
			p->start = offset + delta;
			p->current = last;
			DPRINTF
			    ("Open the output buffer with %u unused bytes...\n",
			     tail);
			DPRINTF("New offset = %u\n", p->start);
			return dst + delta;
		}
	}
	DPUTS("Return the empty output buffer...");
	p->space = 0;
	*n = 0;
	return NULL;
}

#ifndef offsetof
#define offsetof(x, y) ((uwide) &((x *) 0)->y))
#endif

#define Page_Size 4096

/* Opens the output buffer and reserves the "size" bytes     */
/* in that opened buffer. Output parameter "n" is the length */
/* of available space in the opened buffer:		     */

uchar *
buffer_open_small(HTTP2Output * __restrict p,
		  ufast * __restrict n, ufast size, ufast alignment)
{
	ufast tail = p->tail;
	ufast align = ~alignment & (alignment - 1);
	ufast delta, length;
	HTTP2Block *const __restrict last = p->last;
	HTTP2Block *__restrict block;

	if (tail) {
		const ufast offset = p->offset;
		uchar *__restrict dst = last->data + offset;

		/* Calculate distance to the next aligned block.    */
		/* Typecast to the signed integer was added here    */
		/* to eliminate compiler warning about unary minus  */
		/* operator (which would be applied to the unsigned */
		/* integer otherwise) - we know exactly what we do: */
		delta = (ufast) (-(fast) dst) & align;
		if (likely(delta + size <= tail)) {
			tail -= delta;
			*n = tail;
			p->space = tail;
			p->start = offset + delta;
			p->current = last;
			DPRINTF
			    ("Open the output buffer with %u unused bytes...\n",
			     tail);
			DPRINTF("New offset = %u\n", p->start);
			return dst + delta;
		}
	}
	if (last == NULL || (block = last->next) == NULL) {
		block = tfw_pool_alloc(p->pool, Page_Size);
		if (block) {
			block->next = NULL;
			block->n = Page_Size;
			/* Calculate distance to the next aligned block: */
			delta = (ufast) (-(fast) block->data) & align;
			length = Page_Size - offsetof(HTTP2Block, data) - delta;
			if (likely(last != NULL)) {
				last->next = block;
				last->tail = tail;
			} else {
				DPUTS("Initial block was allocated...");
				p->first = block;
			}
		} else {
			DPUTS("Unable to allocate memory block...");
			*n = 0;
			return NULL;
		}
	} else {
		/* Calculate distance to the next aligned block: */
		delta = (ufast) (-(fast) block->data) & align;
		/* Save old and calculate new tail length: */
		last->tail = tail;
		length = block->n - (offsetof(HTTP2Block, data) + delta);
	}
	block->tail = length;
	*n = length;
/* This is the first block of the new string, therefore we need */
/* to initialize start offset (and available space) here:	*/
	p->space = length;
	p->last = block;
	p->start = delta;
	p->current = block;
	DPRINTF("Reserve place for the new item of the %u bytes...\n", size);
	DPRINTF("New offset = %u, buffer has the %u unused bytes...\n",
		delta, length);
	return block->data + delta;
}

/* Reserving the "size" bytes in the output buffer */
/* without opening it:				   */

uchar *
buffer_small(HTTP2Output * __restrict p, ufast size, ufast alignment)
{
	ufast tail = p->tail;
	ufast align = ~alignment & (alignment - 1);
	ufast delta, length;
	HTTP2Block *const __restrict last = p->last;
	HTTP2Block *__restrict block;

	if (tail) {
		ufast shift;
		const ufast offset = p->offset;
		uchar *__restrict dst = last->data + offset;

		/* Calculate distance to the next aligned block.    */
		/* Typecast to the signed integer was added here    */
		/* to eliminate compiler warning about unary minus  */
		/* operator (which would be applied to the unsigned */
		/* integer otherwise) - we know exactly what we do: */
		delta = (ufast) (-(fast) dst) & align;
		shift = delta + size;
		if (likely(shift <= tail)) {
			p->offset = offset + shift;
			p->tail = tail - shift;
			DPRINTF
			    ("Place new item of the %u bytes into output buffer...\n",
			     size);
			DPRINTF
			    ("Item offset = %u, buffer has %u unused bytes...\n",
			     p->offset - size, p->tail);
			return dst + delta;
		}
	}
	if (last == NULL || (block = last->next) == NULL) {
		block = tfw_pool_alloc(p->pool, Page_Size);
		if (block) {
			block->next = NULL;
			block->n = Page_Size;
			/* Calculate distance to the next aligned block: */
			delta = (ufast) (-(fast) block->data) & align;
			length =
			    Page_Size - offsetof(HTTP2Block,
						 data) - (delta + size);
			if (likely(last != NULL)) {
				last->next = block;
				last->tail = tail;
			} else {
				DPUTS("Initial block was allocated...");
				p->first = block;
			}
		} else {
			DPUTS("Unable to allocate memory block...");
			return NULL;
		}
	} else {
		/* Calculate distance to the next aligned block: */
		delta = (ufast) (-(fast) block->data) & align;
		/* Save old and calculate new tail length: */
		last->tail = tail;
		length = block->n - (offsetof(HTTP2Block, data) + delta + size);
	}
	block->tail = length;
	p->tail = length;
	p->offset = delta + size;
	p->last = block;
	DPRINTF("Reserve place for the new item of the %u bytes...\n", size);
	DPRINTF("Item offset = %u, buffer has the %u unused bytes...\n",
		delta, length);
	return block->data + delta;
}

/* Pause writing to the output buffer without */
/* emitting string. Here "n" is the length of */
/* the unused space in the last fragment:     */

void
buffer_pause(HTTP2Output * __restrict p, ufast n)
{
	HTTP2Block *const __restrict last = p->last;

	if (last) {
		last->tail = n;
	}
	DPRINTF("Pausing writing to the output buffer...");
}

/* Reopen the output buffer that is paused before. */
/* Output parameter "n" is the length of available */
/* space in the buffer: 			   */

uchar *
buffer_resume(HTTP2Output * __restrict p, ufast * __restrict n)
{
	HTTP2Block *const __restrict last = p->last;

	if (last) {
		ufast space = last->tail;

		*n = space;
		if (space) {
			/* Recalculate offset from the current block   */
			/* using its size, because the "start" field   */
			/* was currently used to store starting offset */
			/* of the incomplete string and it may points  */
			/* to another block:                           */
			uchar *const __restrict dst =
			    (uchar *) last + (last->n - space);
			DPRINTF
			    ("Reopen output buffer with %u unused bytes...\n",
			     space);
			DPRINTF("Current offset = %u\n",
				(ufast) (dst - last->data));
			return dst;
		}
	} else {
		*n = 0;
	}
	DPUTS("Reopen the empty output buffer...");
	return NULL;
}

/* Add new block to the output buffer. Returns the NULL    */
/* and zero length ("n_new") if unable to allocate memory. */
/* Here "n" is the number of unused bytes in the current   */
/* fragment of the buffer.				   */

uchar *
buffer_expand(HTTP2Output * __restrict p, ufast * __restrict n_new, ufast n)
{
	ufast delta, length;
	const fast align = p->align;
	HTTP2Block *__restrict block;
	HTTP2Block *__restrict last = p->last;

	if (last == NULL || (block = last->next) == NULL) {
		block = tfw_pool_alloc(p->pool, Page_Size);
		if (block) {
			block->next = NULL;
			block->n = Page_Size;
			/* Calculate distance to the next aligned block.    */
			/* Typecast to the signed integer was added here    */
			/* to eliminate compiler warning about unary minus  */
			/* operator (which would be applied to the unsigned */
			/* integer otherwise) - we know exactly what we do: */
			delta = (ufast) (-(fast) block->data) & align;
			length = Page_Size - offsetof(HTTP2Block, data) - delta;
			if (likely(last != NULL)) {
				last->next = block;
			} else {
				DPUTS("Initial block was allocated...");
				p->first = block;
				goto L1;
			}
		} else {
			DPUTS("Unable to allocate memory block...");
			*n_new = n;
			if (last) {
				/* Restore pointer to the current position: */
				return (uchar *) last + (last->n - n);
			} else {
				return NULL;
			}
		}
	} else {
		/* Calculate distance to the next aligned block: */
		delta = (ufast) (-(fast) block->data) & align;
		/* Calculate new tail length: */
		length = block->n - (offsetof(HTTP2Block, data) + delta);
	}
	{
		const ufast space = p->space;
		const ufast used = space - n;

		last->tail = space ? n : p->tail;
		if (likely(used)) {
			p->total += used;
			p->count++;
			DPRINTF
			    ("New fragment of %u bytes was added to the string...\n",
			     used);
		} else {
			/* This is the first block of the new string, therefore */
			/* we need to initialize start offset here:             */
 L1:
			p->start = delta;
			p->current = block;
			DPRINTF("New string started at offset: %u...\n", delta);
		}
	}
	block->tail = length;
	*n_new = length;
	p->space = length;
	p->last = block;
	DPRINTF("New block with %u unused bytes was allocated...\n", length);
	DPRINTF("New offset = %u\n", delta);
	return block->data + delta;
}

/* Forms a new string from the data stored in the output   */
/* buffer. Returns error code if unable to allocate memory */
/* for the string descriptor. Input parameter "n" is the   */
/* number of unused bytes of the tail fragment: 	   */

ufast
buffer_emit(HTTP2Output * __restrict p, ufast n)
{
	ufast used = p->space - n;
	const ufast offset = p->start;
	ufast count = p->count;
	const uwide total = p->total + used;

	DPRINTF("Emitting the new string of the %" PRIuPTR " bytes...\n",
		total);
	if (total) {
		HTTP2Block *__restrict current = p->current;

		if (likely(used)) {
			p->tail = n;
			p->offset = count ? used : used + offset;
		} else {
			/* If the last fragment is not used at all, then */
			/* we should decrement the fragment counter:     */
			if (unlikely(--count == 0)) {
				/* Rewind to the last fragment: */
				p->tail = current->tail;
				p->offset = offset + total;
				p->last = current;
				DPUTS("Rewind to the previous fragment...");
				DPRINTF
				    ("New offset = %u, buffer has the %u unused bytes...\n",
				     p->offset, p->tail);
			}
		}
		p->count = 0;
		p->total = 0;
		DPRINTF("Last added fragment is the %u bytes...\n", used);
		if (likely(count == 0)) {
			p->str.ptr = current->data + offset;
		} else {
			TfwPool *const __restrict pool = p->pool;
			TfwStr *__restrict fp =
			    tfw_pool_alloc(pool, ++count * sizeof(TfwStr));
			if (unlikely(fp == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			p->str.ptr = fp;
			p->str.skb = NULL;
			p->str.len = total;
			p->str.eolen = 0;
			p->str.flags = count << TFW_STR_CN_SHIFT;
			fp->ptr = current->data + offset;
			fp->skb = NULL;
			fp->len = current->n -
			    (offsetof(HTTP2Block, data) + offset +
			     current->tail);
			fp->eolen = 0;
			fp->flags = 0;
			DPRINTF("Fragment: %u bytes...\n", (uint) fp->len);
			fp++;
			count -= 2;
			if (count) {
				do {
					current = current->next;
					fp->ptr = current->data;
					fp->skb = NULL;
					fp->len = current->n - current->tail -
					    offsetof(HTTP2Block, data);
					fp->eolen = 0;
					fp->flags = 0;
					DPRINTF("Fragment: %u bytes...\n",
						(uint) fp->len);
					fp++;
				} while (--count);
			}
			current = current->next;
			fp->ptr = current->data;
			fp->skb = NULL;
			if (likely(used)) {
				fp->len = used;
			} else {
				/* Rewind to the last fragment: */
				const ufast tail = current->tail;

				used =
				    current->n - tail - offsetof(HTTP2Block,
								 data);
				p->tail = tail;
				p->offset = used;
				p->last = current;
				fp->len = used;
				DPUTS("Rewind to the previous fragment...");
				DPRINTF
				    ("New offset = %u, buffer has the %u unused bytes...\n",
				     used, tail);
			}
			fp->eolen = 0;
			fp->flags = 0;
			DPRINTF("Fragment: %u bytes...\n", used);
			return 0;
		}
	} else {
		p->str.ptr = NULL;
	}
	p->str.skb = NULL;
	p->str.len = total;
	p->str.eolen = 0;
	p->str.flags = 0;
	return 0;
}

/* Copy data from the plain memory block to the output	  */
/* buffer and build a TfwStr string from the copied data: */

ufast
buffer_put(HTTP2Output * __restrict p,
	   const uchar * __restrict src, uwide length)
{
	ufast align = p->def_align;

	if (length > align) {
		ufast k;
		uchar *__restrict dst = buffer_open(p, &k, align);

		do {
			uwide copied;

			CheckByte(p);
			copied = k;
			if (k >= length) {
				copied = length;
			}
			memcpy(dst, src, copied);
			dst += copied;
			src += copied;
			k -= copied;
			length -= copied;
		} while (length);
		return buffer_emit(p, k);
	} else if (length) {
		uchar *const __restrict dst = buffer_small(p, length, align);

		if (dst) {
			memcpy(dst, src, length);
			p->str.ptr = dst;
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	} else {
		p->str.ptr = NULL;
	}
	p->str.skb = NULL;
	p->str.len = length;
	p->str.eolen = 0;
	p->str.flags = 0;
	return 0;
}

/* Copy data from the plain memory block to the output */
/* buffer (which is already opened before this call):  */

uchar *
buffer_put_raw(HTTP2Output * __restrict p,
	       uchar * __restrict dst,
	       ufast * __restrict k_new,
	       const uchar * __restrict src,
	       uwide length, ufast * __restrict rc)
{
	ufast k = *k_new;

	if (length <= k) {
		k -= length;
		if (length) {
			memcpy(dst, src, length);
			dst += length;
		}
	} else {
		do {
			uwide copied;

			CheckByte_goto(p, Bug);
			copied = k;
			if (k >= length) {
				copied = length;
			}
			memcpy(dst, src, copied);
			dst += copied;
			src += copied;
			k -= copied;
			length -= copied;
		} while (length);
	}
	*k_new = k;
	*rc = 0;
	return dst;
 Bug:
	*k_new = k;
	*rc = Err_HTTP2_OutOfMemory;
	return dst;
}

/* Copy data from the TfwStr string to the output      */
/* buffer (which is already opened before this call).  */
/* If error occured, then output parameter "remainder" */
/* contains the length of unprocessed part of the      */
/* TfwStr string (user can supply NULL pointer here):  */

uchar *
buffer_put_string(HTTP2Output * __restrict p,
		  uchar * __restrict dst,
		  ufast * __restrict k_new,
		  const TfwStr * __restrict source,
		  ufast * __restrict rc, uwide * __restrict remainder)
{
	ufast k = *k_new;
	uwide length = source->len;
	uwide fragment;

	if (TFW_STR_PLAIN(source)) {
		const uchar *__restrict src = (const uchar *)source->ptr;

		do {
			uwide copied;

			CheckByte_goto(p, Bug);
			copied = k;
			if (k >= length) {
				copied = length;
			}
			memcpy(dst, src, copied);
			dst += copied;
			src += copied;
			k -= copied;
			length -= copied;
		} while (length);
	} else {
		const TfwStr *__restrict fp = (const TfwStr *)source->ptr;
		const uchar *__restrict src = (const uchar *)fp->ptr;
		ufast m = fp->len;

		fp++;
		do {
			if (unlikely(m == 0)) {
				src = (const uchar *)fp->ptr;
				m = fp->len;
				fp++;
			}
			fragment = m;
			if (m >= length) {
				fragment = length;
			}
			m -= fragment;
			length -= fragment;
			do {
				uwide copied;

				CheckByte_goto(p, Bug2);
				copied = k;
				if (k >= fragment) {
					copied = fragment;
				}
				memcpy(dst, src, copied);
				dst += copied;
				src += copied;
				k -= copied;
				fragment -= copied;
			} while (fragment);
		} while (length);
	}
	*rc = 0;
 Save:
	*k_new = k;
	if (remainder) {
		*remainder = length;
	}
	return dst;
 Bug2:
	length += fragment;
 Bug:
	*rc = Err_HTTP2_OutOfMemory;
	goto Save;
}

/* ------------------------------------------ */
/* Supplementary functions related to TfwStr: */
/* ------------------------------------------ */

/* Compare plain memory string "x" with array of the */
/* TfwStr fragments represented by the "fp" pointer. */
/* Parameter "n" is the minimum between the total    */
/* length of all "fp" fragments and the length of    */
/* the "x" string:                                   */

fast
buffer_str_cmp_plain(const uchar * __restrict x,
		     const TfwStr * __restrict fp, uwide n)
{
	const uchar *__restrict y = (const uchar *)fp->ptr;
	uwide length = fp->len;

	fp++;
	do {
		int rc;
		uwide count;

		if (unlikely(length == 0)) {
			y = (const uchar *)fp->ptr;
			length = fp->len;
			fp++;
		}
		count = n;
		if (n > length) {
			count = length;
		}
		rc = memcmp(x, y, count);
		if (rc) {
			return rc;
		}
		x += count;
		y += count;
		length -= count;
		n -= count;
	} while (n);
	return 0;
}

/* Compare two arrays of the TfwStr fragments represented */
/* by the "fx" and "fy" pointers. Here "n" is the minimum */
/* between the total length of all "fx" fragments and the */
/* total length of all "fy" fragments:                    */

fast
buffer_str_cmp_complex(const TfwStr * __restrict fx,
		       const TfwStr * __restrict fy, uwide n)
{
	const uchar *__restrict x = (const uchar *)fx->ptr;
	const uchar *__restrict y = (const uchar *)fy->ptr;
	uwide cx = fx->len;
	uwide cy = fy->len;

	fx++;
	fy++;
	do {
		uwide fragment;

		if (unlikely(cx == 0)) {
			x = (const uchar *)fx->ptr;
			cx = fx->len;
			fx++;
		}
		fragment = n;
		if (n > cx) {
			fragment = cx;
		}
		cx -= fragment;
		n -= fragment;
		do {
			int rc;
			uwide count;

			if (unlikely(cy == 0)) {
				y = (const uchar *)fy->ptr;
				cy = fy->len;
				fy++;
			}
			count = cy;
			if (cy > fragment) {
				count = fragment;
			}
			rc = memcmp(x, y, count);
			if (rc) {
				return rc;
			}
			x += count;
			y += count;
			cy -= count;
			fragment -= count;
		} while (fragment);
	} while (n);
	return 0;
}

/* Compare two TfwStr strings: */

fast
buffer_str_cmp(const TfwStr * __restrict x, const TfwStr * __restrict y)
{
	fast rc;
	wide delta;
	const uwide cx = x->len;
	const uwide cy = y->len;
	uwide min = cx;

	if (cx > cy) {
		min = cy;
	}
	if (TFW_STR_PLAIN(x)) {
		if (TFW_STR_PLAIN(y)) {
			rc = memcmp(x->ptr, y->ptr, min);
		} else {
			rc = buffer_str_cmp_plain((const uchar *)x->ptr,
						  (const TfwStr *)y->ptr, min);
		}
	} else if (TFW_STR_PLAIN(y)) {
		rc = buffer_str_cmp_plain((const uchar *)y->ptr,
					  (const TfwStr *)x->ptr, min);
		if (rc == 0) {
			goto Final;
		}
		return -rc;
	} else {
		rc = buffer_str_cmp_complex((const TfwStr *)x->ptr,
					    (const TfwStr *)y->ptr, min);
	}
	if (rc) {
		return rc;
	}
 Final:
	delta = (cx >> 1) - (cy >> 1);
	if (delta) {
#if Fast_Capacity < Bit_Capacity
		return (delta >> (Bit_Capacity - Fast_Capacity)) | 1;
#else
		return delta;
#endif
	}
	return (fast) (cx - cy);
}

/* Calculate simple hash function of the TfwStr string: */

uwide
buffer_str_hash(const TfwStr * __restrict x)
{
	uwide length = x->len;

	if (TFW_STR_PLAIN(x)) {
		return Byte_Hash_Chain(x->ptr, length, 0);
	} else {
		const TfwStr *__restrict fp = (const TfwStr *)x->ptr;
		uwide processed = fp->len;
		uwide h = Byte_Hash_Chain(fp->ptr, processed, 0);

		fp++;
		length -= processed;
		while (length) {
			const uwide count = fp->len;

			h ^= Byte_Hash_Chain(fp->ptr, count, processed);
			fp++;
			processed += count;
			length -= count;
		}
		return h;
	}
}

/* Copy data from the TfwStr string to plain array: */

void
buffer_str_to_array(uchar * __restrict data, const TfwStr * __restrict str)
{
	ufast count = str->flags >> TFW_STR_CN_SHIFT;

	if (count == 0) {
		const uwide length = str->len;

		if (likely(length)) {
			memcpy(data, str->ptr, length);
		}
	} else {
		const TfwStr *__restrict fp = (const TfwStr *)str->ptr;

		do {
			const uwide length = fp->len;

			if (likely(length)) {
				memcpy(data, fp->ptr, length);
			}
			fp++;
			data += length;
		} while (--count);
	}
}

/* Print the TfwStr string: */

void
buffer_str_print(const TfwStr * __restrict str)
{
	ufast count;
	ufast copied;
	char buf[1025];
	uwide length = str->len;

	if (unlikely(length == 0)) {
		return;
	}
	count = str->flags >> TFW_STR_CN_SHIFT;
	if (count == 0) {
		const char *__restrict ptr = (const char *)str->ptr;

		do {
			copied = length;
			if (length >= sizeof(buf)) {
				copied = sizeof(buf) - 1;
			}
			memcpy(buf, ptr, copied);
			ptr += copied;
			buf[copied] = 0;
			printf("%s", buf);
			length -= copied;
		} while (length);
	} else {
		const TfwStr *__restrict fp = (const TfwStr *)str->ptr;
		char *__restrict bp = buf;
		ufast space = sizeof(buf) - 1;

		do {
			const char *__restrict src = (const char *)fp->ptr;
			uwide m = fp->len;

			fp++;
			do {
				if (unlikely(space == 0)) {
					*bp = 0;
					printf("%s", buf);
					space = sizeof(buf) - 1;
					bp = buf;
				}
				copied = space;
				if (space > m) {
					copied = m;
				}
				memcpy(bp, src, copied);
				src += copied;
				bp += copied;
				space -= copied;
				m -= copied;
			} while (m);
		} while (--count);
		if (bp != buf) {
			*bp = 0;
			printf("%s", buf);
		}
	}
}
