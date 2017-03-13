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
#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "errors.h"
#include "buffers.h"

#define Debug_Buffers 0

/* -------------------------------------------------- */
/* Input buffer (used by parser to handle fragments): */
/* -------------------------------------------------- */

/* Initialize input buffer from the TfwStr: */

void
buffer_from_tfwstr(HTTP2Input * __restrict p, const TfwStr * __restrict str)
{
	p->offset = 0;
	p->n = str->len;
	p->current = 0;
	p->tail = 0;		/* p->tail is initialized here only to avoid */
	/* partial writing into cache line, really */
	/* it does not used by buffer_get() call. */
	p->str = str;
}

/* Get pointer to and length of the current fragment ("m"): */

const uchar *
buffer_get(HTTP2Input * __restrict p, uwide * __restrict m)
{
	const uwide offset = p->offset;
	const TfwStr *__restrict fp = p->str;

	if (TFW_STR_PLAIN(fp)) {
#if Debug_Buffers
		puts("Plain string...");
#endif
		*m = p->n;
	} else {
		uwide tail;

		fp = __TFW_STR_CH(fp, p->current);
		tail = fp->len - offset;
		p->tail = tail;
		*m = tail;
	}
#if Debug_Buffers
	printf("Open at: %u, current: %u bytes...\n", offset, *m);
#endif
	return (const uchar *)fp->ptr + offset;
}

/* Get the next pointer and length of the next fragment: */

const uchar *
buffer_next(HTTP2Input * __restrict p, uwide * __restrict m)
{
	const uwide current = p->current + 1;
	const TfwStr *const __restrict fp = __TFW_STR_CH(p->str, current);
	const uwide length = fp->len;

	p->offset = 0;
	p->n -= p->tail;
	p->current = current;
	p->tail = length;
	*m = length;
#if Debug_Buffers
	printf("Next fragment: %u bytes...\n", length);
#endif
	return (const uchar *)fp->ptr;
}

/* Close current parser iteration. There "m" is the length */
/* of unparsed tail of the current fragment: */

void
buffer_close(HTTP2Input * __restrict p, uwide m)
{
	const uwide tail = p->tail;

	if (m) {
		const uwide bias = tail - m;

		if (bias) {
			p->offset += bias;
			p->n -= bias;
#if Debug_Buffers
			printf("Shift forward to %u bytes...\n", bias);
#endif
		}
	} else {
		p->offset = 0;
		p->n -= tail;
		p->current++;
#if Debug_Buffers
		printf("Consumed %u bytes...\n", tail);
#endif
	}
}

/* Count number of the fragments, which consumed  */
/* by the string of "length" bytes, starting at   */
/* the current position in the buffer. Also, if   */
/* the current fragment is fully consumed by	  */
/* decoder, then get pointer to the next fragment */
/* and return its length via "m_new" pointer.     */

const uchar *
buffer_count(HTTP2Input * __restrict p,
	     uwide * __restrict m_new,
	     const uchar * __restrict src,
	     uwide m, uwide length, uwide * __restrict count)
{
	uwide c;
	uwide current = p->current;
	const TfwStr *const __restrict str = p->str;
	const TfwStr *__restrict fp = __TFW_STR_CH(str, current);

	if (unlikely(m == 0)) {
		fp++;
		p->offset = 0;
		p->n -= p->tail;
		p->current = ++current;
		m = fp->len;
		p->tail = m;
#if Debug_Buffers
		printf("Next fragment: %u bytes...\n", m);
#endif
		src = (const uchar *)fp->ptr;
	}
	*m_new = m;
	c = 1;
	do {
		length -= m;
		m = fp->len;
		fp++;
		c++;
	} while (length > m);
	*count = c;
	return src;
}

/* Extract string of the "length" bytes from the      */
/* input buffer (starting from the current position). */
/* There "out" is the pointer to descriptio of the    */
/* output string and "m_new" is the pointer to        */
/* updated length of the current fragment.	      */

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
		out->ptr = (uchar *) src;
		out->len = length;
		out->skb = NULL;
		out->eolen = 0;
		out->flags = 0;
		*m_new = m - length;
		*rc = 0;
		src += length;
	} else {
		TfwStr *__restrict sp;
		uwide tail = p->tail;
		uwide count;
		uwide current = p->current;
		const TfwStr *const __restrict str = p->str;
		const TfwStr *__restrict fp = __TFW_STR_CH(str, current);

		if (unlikely(m == 0)) {
			fp++;
			current++;
			p->offset = 0;
			p->n -= tail;
			m = fp->len;
			tail = m;
#if Debug_Buffers
			printf("Next fragment: %u bytes...\n", m);
#endif
			src = (const uchar *)fp->ptr;
		}
		{
			const TfwStr *__restrict __fp = fp;
			uwide __m = m;
			uwide __length = length;

			count = 1;
			do {
				__length -= __m;
				__m = __fp->len;
				__fp++;
				count++;
			} while (__length > __m);
		}
		sp = tfw_pool_alloc(pool, count * sizeof(TfwStr));
		if (unlikely(sp == NULL)) {
			goto Bug;
		}
		out->ptr = sp;
		out->len = length;
		out->skb = NULL;
		out->eolen = 0;
		out->flags = count << TFW_STR_CN_SHIFT;
		p->n -= length;
		p->offset = 0;
		do {
			ufast copied;

			if (unlikely(m == 0)) {
				fp++;
				current++;
				tail = fp->len;
#if Debug_Buffers
				printf("Next fragment: %u bytes...\n", tail);
#endif
				src = (const uchar *)fp->ptr;
			}
			copied = m;
			if (m >= length) {
				copied = length;
			}
			sp->ptr = (uchar *) src;
			sp->len = copied;
			sp->skb = NULL;
			sp->eolen = 0;
			sp->flags = 0;
			sp++;
			src += copied;
			m -= copied;
			length -= copied;
		} while (--count);
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

/* Copy string of the "length" bytes from the input   */
/* buffer (starting from the current position) to the */
/* output buffer. There "out" is the pointer to the   */
/* output buffer and "m_new" is pointer to updated    */
/* length of the current fragment.		      */

const uchar *
buffer_copy(HTTP2Input * __restrict p,
	    uwide * __restrict m_new,
	    const uchar * __restrict src,
	    uwide m,
	    uwide length, HTTP2Output * __restrict out, ufast * __restrict rc)
{
	ufast k;
	uchar *__restrict dst = buffer_open(out, &k);

	if (m >= length) {
		*m_new = m - length;
		do {
			uwide copied;

			if (unlikely(k == 0)) {
				dst = buffer_expand(out, &k);
				if (unlikely(dst == NULL)) {
					goto Bug;
				}
			}
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
		uwide tail = p->tail;
		uwide current = p->current;
		const TfwStr *const __restrict str = p->str;
		const TfwStr *__restrict fp = __TFW_STR_CH(str, current);

		if (unlikely(m == 0)) {
			fp++;
			current++;
			p->offset = 0;
			p->n -= tail;
			m = fp->len;
			tail = m;
#if Debug_Buffers
			printf("Next fragment: %u bytes...\n", m);
#endif
			src = (const uchar *)fp->ptr;
		}
		p->n -= length;
		p->offset = 0;
		do {
			ufast copied;

			if (unlikely(m == 0)) {
				fp++;
				current++;
				tail = fp->len;
#if Debug_Buffers
				printf("Next fragment: %u bytes...\n", tail);
#endif
				src = (const uchar *)fp->ptr;
			}
			copied = m;
			if (m >= length) {
				copied = length;
			}
			do {
				uwide fragment;

				if (unlikely(k == 0)) {
					dst = buffer_expand(out, &k);
					if (unlikely(dst == NULL)) {
						goto Bug2;
					}
				}
				fragment = k;
				if (k >= copied) {
					fragment = copied;
				}
				memcpy(dst, src, fragment);
				dst += fragment;
				src += fragment;
				k -= fragment;
				m -= fragment;
				copied -= fragment;
				length -= fragment;
			} while (copied);
		} while (length);
 Save:
		p->current = current;
		p->tail = tail;
		*m_new = m;
	}
 Emit:
	*rc = buffer_emit(out, k);
	return src;
/* Partially rewind last fragment: */
 Bug:
	*m_new += length;
	*rc = Err_HTTP2_OutOfMemory;
	goto Emit;
 Bug2:
	*rc = Err_HTTP2_OutOfMemory;
	goto Save;
}

/* --------------------------------------------- */
/* Output buffer (used to write decoded stings): */
/* --------------------------------------------- */

/* Initialize new output buffer: */

void
buffer_new(HTTP2Output * __restrict p, TfwPool * __restrict pool)
{
/* Many fields initialized here only to avoid */
/* partial writing into cache line: */
	p->last = NULL;
	p->first = NULL;
	p->current = NULL;
	p->offset = 0;
	p->tail = 0;
	p->count = 0;
	p->total = 0;
	p->pool = pool;
}

#ifndef offsetof
#define offsetof(x, y) ((uwide) &((x *) 0)->y))
#endif

/* Add new block to the output buffer. Returns the NULL */
/* and zero length ("n") if unable to allocate memory: */

#define Page_Size 4096
#define Unused_Space (Page_Size - offsetof(HTTP2Block, data))

uchar *
buffer_expand(HTTP2Output * __restrict p, ufast * __restrict n)
{
	HTTP2Block *const __restrict block = tfw_pool_alloc(p->pool, Page_Size);

	if (block) {
		HTTP2Block *__restrict last = p->last;

		block->next = NULL;
		block->n = Page_Size;
		*n = Unused_Space;
		p->last = block;
		if (last) {
			const ufast tail = p->tail;

			last->next = block;
			if (tail) {
				p->tail = Unused_Space;
				p->count++;
				p->total += tail;
#if Debug_Buffers
				printf
				    ("New fragment added to string: %u bytes...\n",
				     tail);
#endif
			} else {
				p->current = block;
				p->offset = 0;
				p->tail = Unused_Space;
#if Debug_Buffers
				puts("New string started at offset 0...");
#endif
			}
		} else {
			p->first = block;
			p->current = block;
			p->offset = 0;	/* p->offset is initialized here */
			/* only to avoid partial writing */
			/* into cache line. */
			p->tail = Unused_Space;
#if Debug_Buffers
			puts("Initial block allocated...");
#endif
		}
#if Debug_Buffers
		printf("New offset = %u\n", p->offset);
		printf("New block allocated: %u unused bytes...\n", p->tail);
#endif
		return block->data;
	} else {
#if Debug_Buffers
		puts("Unable to allocate memory block...");
#endif
		*n = 0;
		return NULL;
	}
}

/* Open output buffer before decoding the new string. */
/* There "n" is the length of available space in the buffer: */

uchar *
buffer_open(HTTP2Output * __restrict p, ufast * __restrict n)
{
	const ufast tail = p->tail;

	*n = tail;
	if (tail) {
		HTTP2Block *const __restrict last = p->last;

		p->current = last;
#if Debug_Buffers
		printf("Open output buffer with %u bytes (offset = %u)...\n",
		       tail, p->offset);
#endif
		return last->data + p->offset;
	} else {
#if Debug_Buffers
		puts("Return empty output buffer...");
#endif
		return NULL;
	}
}

/* Emit the new string. Returns error code if unable */
/* to allocate memory: */

ufast
buffer_emit(HTTP2Output * __restrict p, ufast n)
{
	const ufast offset = p->offset;
	const ufast tail = p->tail - (ufast) n;
	ufast count = p->count;
	const uwide total = p->total + tail;

#if Debug_Buffers
	printf("In emit, total length: %u, last delta: %u...\n", total, tail);
	printf("Offset = %u\n", offset);
#endif
	if (total) {
		TfwPool *const __restrict pool = p->pool;
		HTTP2Block *__restrict current = p->current;

		p->offset = count ? tail : tail + offset;
		p->tail = n;
		p->count = 0;
		p->total = 0;
		if (count == 0) {
			p->str.ptr = current->data + offset;
			p->str.len = total;
			p->str.skb = NULL;
			p->str.eolen = 0;
			p->str.flags = 0;
		} else {
			TfwStr *__restrict fp =
			    tfw_pool_alloc(pool, ++count * sizeof(TfwStr));
			if (unlikely(fp == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			p->str.ptr = fp;
			p->str.len = total;
			p->str.skb = NULL;
			p->str.eolen = 0;
			p->str.flags = count << TFW_STR_CN_SHIFT;
			fp->ptr = current->data + offset;
			fp->len =
			    current->n - offsetof(HTTP2Block, data) - offset;
			fp->skb = NULL;
			fp->eolen = 0;
			fp->flags = 0;
#if Debug_Buffers
			printf("Fragment: %u bytes...\n", fp->len);
#endif
			fp++;
			count -= 2;
			while (count) {
				current = current->next;
				fp->ptr = current->data;
				fp->len =
				    current->n - offsetof(HTTP2Block, data);
				fp->skb = NULL;
				fp->eolen = 0;
				fp->flags = 0;
#if Debug_Buffers
				printf("Fragment: %u bytes...\n", fp->len);
#endif
				fp++;
				count--;
			}
			current = current->next;
			fp->ptr = current->data;
			fp->len = tail;
			fp->skb = NULL;
			fp->eolen = 0;
			fp->flags = 0;
#if Debug_Buffers
			printf("Fragment: %u bytes...\n", fp->len);
#endif
		}
	} else {
		p->str.ptr = NULL;
		p->str.len = 0;
		p->str.skb = NULL;
		p->str.eolen = 0;
		p->str.flags = 0;
	}
	return 0;
}

/* Copy data from the plain memory block to the output */
/* buffer (and build TfwStr in the output buffer):     */

ufast
buffer_put(HTTP2Output * __restrict p,
	   const uchar * __restrict src, uwide length)
{
	ufast k;
	uchar *__restrict dst = buffer_open(p, &k);

	while (length) {
		uwide copied;

		if (unlikely(k == 0)) {
			dst = buffer_expand(p, &k);
			if (unlikely(dst == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
		}
		copied = k;
		if (k >= length) {
			copied = length;
		}
		memcpy(dst, src, copied);
		dst += copied;
		src += copied;
		k -= copied;
		length -= copied;
	}
	return buffer_emit(p, k);
}

/* ------------------------------------------ */
/* Supplementary functions related to TfwStr: */
/* ------------------------------------------ */

/* Copy data from the TfwStr to plain array: */

void
buffer_str_to_array(uchar * __restrict data, TfwStr * __restrict str)
{
	uwide n = str->flags >> TFW_STR_CN_SHIFT;

	if (n == 0) {
		const uwide length = str->len;

		memcpy(data, str->ptr, length);
	} else {
		const TfwStr *__restrict fp = str->ptr;

		do {
			const uwide length = fp->len;

			memcpy(data, fp->ptr, length);
			fp++;
			data += length;
		} while (--n);
	}
}
