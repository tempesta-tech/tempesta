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
#include "errors.h"
#include "buffers.h"

#define Debug_Buffers 1

#if Debug_Buffers
#define DPRINTF(...) printf("Buffers: " __VA_ARGS__)
#define DPUTS(...) puts("Buffers: " __VA_ARGS__)
#else
#define DPRINTF(...)
#define DPUTS(...)
#endif

/* ------------------------------------------------------- */
/* Input buffer (used in the parsers to handle fragments): */
/* ------------------------------------------------------- */

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

/* Get pointer to and length of the current fragment ("m"): */

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
	DPRINTF("Open at: %" PRIuPTR ", current: %" PRIuPTR " bytes...\n",
		offset, tail);
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

/* Close current parser iteration. There "m" is the length */
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
		current++;
		p->n -= p->tail;
		m = fp->len;
		p->current = current;
		p->tail = m;
		p->offset = 0;
		src = (const uchar *)fp->ptr;
		DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", m);
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
		*m_new = m - length;
		out->ptr = (uchar *) src;
		out->len = length;
		out->skb = NULL;
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
			p->n -= tail;
			m = fp->len;
			tail = m;
			src = (const uchar *)fp->ptr;
			DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", m);
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
			sp->len = copied;
			sp->skb = NULL;
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
	uwide tail;
	ufast k, code;
	const TfwStr *__restrict fp;
	uchar *__restrict dst = buffer_open(out, &k, 0);

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
		const TfwStr *const __restrict str = p->str;
		uwide current = p->current;

		tail = p->tail;
		fp = __TFW_STR_CH(str, current);
		if (unlikely(m == 0)) {
			fp++;
			current++;
			p->n -= tail;
			m = fp->len;
			tail = m;
			src = (const uchar *)fp->ptr;
			DPRINTF("Next fragment: %" PRIuPTR " bytes...\n", m);
		}
		p->n -= length;
		p->offset = 0;
		do {
			uwide fragment;

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
			do {
				uwide copied;

				if (unlikely(k == 0)) {
					dst = buffer_expand(out, &k);
					if (unlikely(dst == NULL)) {
						goto Bug2;
					}
				}
				copied = k;
				if (k >= fragment) {
					copied = fragment;
				}
				memcpy(dst, src, copied);
				dst += copied;
				src += copied;
				k -= copied;
				m -= copied;
				length -= copied;
				fragment -= copied;
			} while (fragment);
		} while (length);
 Save:
		p->current = current;
		p->tail = tail;
		*m_new = m;
	}
	code = 0;
 Emit:
	*rc = buffer_emit(out, k) || code;
	return src;
 Bug:
/* Partially rewind input buffer: */
	*m_new += length;
	code = Err_HTTP2_OutOfMemory;
	goto Emit;
 Bug2:
/* Partially rewind input buffer: */
	p->n += length;
	p->offset = fp->len - tail;
	code = Err_HTTP2_OutOfMemory;
	goto Save;
}

/* ------------------------------------------- */
/* Output buffer (used to store decoded stings */
/* in the parser or to store encoded strings   */
/* in the packet generators).		       */
/* ------------------------------------------- */

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
	p->last = NULL;
	p->first = NULL;
	p->current = NULL;
	p->offset = 0;
	p->tail = 0;
	p->count = 0;
	p->total = 0;
	p->def_align = align;
	p->align = align;
	p->pool = pool;
}

/* Open output buffer before decoding the new string. */
/* There "n" is the length of available space in the buffer: */

uchar *
buffer_open(HTTP2Output * __restrict p, ufast * __restrict n, ufast alignment)
{
	ufast tail = p->tail;
	uwide align;

	if (alignment == 0) {
		align = p->def_align;
	} else {
		align = ~alignment & (alignment - 1);
	}
	*n = tail;
	if (tail) {
		HTTP2Block *const __restrict last = p->last;
		ufast offset = p->offset;
		uchar *dst = last->data + offset;

		p->current = last;
		/* Calculate the distance to the next aligned block.          */
		/* Typecast to the signed integer was added here to eliminate */
		/* compiler warning about unary minus operator (which would   */
		/* be applied to the unsigned integer otherwise) - we know    */
		/* exactly what we do:                                        */
		ufast delta = (uwide) (-(wide) dst) & align;

		if (likely(delta <= tail)) {
			tail -= delta;
			if (tail >= align) {
				p->count = 1;
				if (delta) {
					dst += delta;
					p->tail = tail;
					p->offset = offset + delta;
				}
				DPRINTF
				    ("Open output buffer with %u unused bytes (offset = %u)...\n",
				     p->tail, p->offset);
				return dst;
			}
			/* Rewind alignment back: */
			tail += delta;
		}
		last->tail = tail;
		p->tail = 0;
	}
	DPUTS("Return empty output buffer...");
	return NULL;
}

#ifndef offsetof
#define offsetof(x, y) ((uwide) &((x *) 0)->y))
#endif

/* Add new block to the output buffer. Returns the NULL */
/* and zero length ("n") if unable to allocate memory: */

#define Page_Size 4096

uchar *
buffer_expand(HTTP2Output * __restrict p, ufast * __restrict n)
{
	HTTP2Block *const __restrict block = tfw_pool_alloc(p->pool, Page_Size);

	if (block) {
		uchar *__restrict dst = block->data;
		HTTP2Block *__restrict last = p->last;
		const uwide align = p->align;

		/* Calculate the distance to the next aligned block.          */
		/* Typecast to the signed integer was added here to eliminate */
		/* compiler warning about unary minus operator (which would   */
		/* be applied to the unsigned integer otherwise) - we know    */
		/* exactly what we do:                                        */
		const ufast delta = (uwide) (-(wide) dst) & align;
		const ufast length =
		    Page_Size - offsetof(HTTP2Block, data) - delta;
		dst += delta;
		block->next = NULL;
		block->n = Page_Size;
		block->tail = length;
		*n = length;
		p->last = block;
		if (last) {
			const ufast tail = p->tail;

			last->next = block;
			if (tail) {
				p->tail = length;
				p->count++;
				p->total += tail;
				DPRINTF
				    ("New fragment of %u bytes added to string...\n",
				     tail);
			} else {
				p->current = block;
				p->offset = delta;
				p->tail = length;
				p->count = 1;
				DPRINTF("New string started at offset %u...\n",
					delta);
			}
		} else {
			DPUTS("Initial block was allocated...");
			p->first = block;
			p->current = block;
			/* This is first block for of the new string,   */
			/* therefore we need to initialize offset here: */
			p->offset = delta;
			p->tail = length;
			p->count = 1;
		}
		DPRINTF("New offset = %u\n", p->offset);
		DPRINTF("New block with %u unused bytes was allocated...\n",
			p->tail);
		return dst;
	} else {
		DPUTS("Unable to allocate memory block...");
		*n = 0;
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

	DPRINTF("In emit, total length: %u, last delta: %u...\n", total, tail);
	DPRINTF("Offset = %u\n", offset);
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
			    current->n - offsetof(HTTP2Block,
						  data) - offset -
			    current->tail;
			fp->skb = NULL;
			fp->eolen = 0;
			fp->flags = 0;
			DPRINTF("Fragment: %u bytes...\n", (uint) fp->len);
			fp++;
			count -= 2;
			while (count) {
				current = current->next;
				fp->ptr = current->data;
				fp->len =
				    current->n - offsetof(HTTP2Block,
							  data) - current->tail;
				fp->skb = NULL;
				fp->eolen = 0;
				fp->flags = 0;
				DPRINTF("Fragment: %u bytes...\n",
					(uint) fp->len);
				fp++;
				count--;
			}
			current = current->next;
			fp->ptr = current->data;
			fp->len = tail;
			fp->skb = NULL;
			fp->eolen = 0;
			fp->flags = 0;
			DPRINTF("Fragment: %u bytes...\n", (uint) fp->len);
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
	uchar *__restrict dst = buffer_open(p, &k, 0);

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
buffer_str_to_array(uchar * __restrict data, const TfwStr * __restrict str)
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

/* Print TfwStr string: */

void
buffer_str_print(const TfwStr * __restrict str)
{
	ufast copied;
	char buf[1025];
	uwide length = str->len;

	if (unlikely(length == 0)) {
		return;
	}
	if (TFW_STR_PLAIN(str)) {
		const char *__restrict ptr = (const char *)str->ptr;

		do {
			copied = length;
			if (length >= sizeof(buf)) {
				copied = sizeof(buf) - 1;
			}
			memcpy(buf, ptr, copied);
			buf[copied] = 0;
			ptr += copied;
			length -= copied;
			printf("%s", buf);
		} while (length);
	} else {
		TfwStr *__restrict fp = (TfwStr *) str->ptr;
		char *__restrict bp = buf;
		ufast count = TFW_STR_CHUNKN(str);
		ufast space = sizeof(buf) - 1;

		do {
			const char *__restrict ptr = (const char *)str->ptr;
			uwide m = fp->len;

			fp++;
			do {
				if (space == 0) {
					*bp = 0;
					printf("%s", buf);
					space = sizeof(buf) - 1;
					bp = buf;
				}
				copied = m;
				if (m > space) {
					copied = space;
				}
				space -= copied;
				memcpy(bp, ptr, copied);
				ptr += copied;
				bp += copied;
				m -= copied;
			} while (m);
		} while (--count);
		if (bp != buf) {
			*bp = 0;
			printf("%s", buf);
		}
	}
}
