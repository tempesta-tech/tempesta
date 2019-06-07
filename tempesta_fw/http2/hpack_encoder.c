/**
 *		Tempesta FW
 *
 * HPACK (RFC-7541) encoders.
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

#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include "../pool.h"
#include "../str.h"
#include "../http.h"
#include "bits.h"
#include "buffers.h"
#include "huffman.h"
#include "hindex.h"
#include "errors.h"
#include "hpack_helpers.h"
#include "hpack.h"

#define Debug_HPack 1

#if Debug_HPack
#define DPRINTF(...) printf("HPack: " __VA_ARGS__)
#define DPUTS(...) puts("HPack: " __VA_ARGS__)
#else
#define DPRINTF(...)
#define DPUTS(...)
#endif

static unsigned char *
write_index(HTTP2Output * __restrict out,
	    unsigned char * __restrict dst,
	    unsigned int *__restrict k_new,
	    unsigned int index,
	    unsigned int max, unsigned int mask, unsigned int *__restrict rc)
{
	unsigned int k = *k_new;

	if (likely(index < max)) {
		index |= mask;
	} else {
		index -= max;
		CheckByte_goto(out, Bug);
		*dst++ = max | mask;
		k--;
		while (index > 0x7F) {
			CheckByte_goto(out, Bug);
			*dst++ = (index & 0x7F) | 0x80;
			k--;
			index >>= 7;
		}
	}
	CheckByte_goto(out, Bug);
	*dst++ = index;
	*k_new = k - 1;
	*rc = 0;
	return dst;
 Bug:
	*rc = Err_HTTP2_OutOfMemory;
	*k_new = 0;
	return NULL;
}

static unsigned char *
write_string(HTTP2Output * __restrict out,
	     unsigned char * __restrict dst,
	     unsigned int *__restrict k_new,
	     const HPackStr * __restrict x, unsigned int *__restrict rc)
{
	unsigned int k;

	if (x) {
		unsigned int n = x->len;

		if (x->arena == HPack_Arena_User) {
			const unsigned int m =
			    huffman_check_fragments(x->ptr, n);
			dst =
			    write_index(out, dst, k_new, m, 0x7F, (m < n) << 7,
					rc);
			if (rc == 0) {
				if (m < n) {
					return huffman_encode_fragments(out,
									dst,
									k_new,
									x->ptr,
									rc);
				} else {
					return buffer_put_string(out, dst,
								 k_new, x->ptr,
								 rc, NULL);
				}
			}
		} else {
			const unsigned int m = huffman_check(x->ptr, n);

			dst =
			    write_index(out, dst, k_new, m, 0x7F, (m < n) << 7,
					rc);
			if (rc == 0) {
				if (m < n) {
					return huffman_encode_plain(out, dst,
								    k_new,
								    x->ptr, m,
								    rc);
				} else {
					return buffer_put_raw(out, dst, k_new,
							      x->ptr, n, rc);
				}
			}
		}
	} else {
		k = *k_new;
		CheckByte_goto(out, Bug);
		*dst++ = 0;
		*k_new = k - 1;
		*rc = 0;
	}
	return dst;
 Bug:
	*rc = Err_HTTP2_OutOfMemory;
	return NULL;
}

unsigned int
hpack_encode(HPack * __restrict hp,
	     HTTP2Output * __restrict out,
	     const HTTP2Field * __restrict source, uintptr_t n)
{
	HTTP2Index *const __restrict ip = hp->dynamic;
	unsigned int rc;
	unsigned int k;
	unsigned char *__restrict dst = buffer_open(out, &k, 0);

	do {
		uintptr_t value_len;
		const TfwStr *name = &source->name;
		const TfwStr *value = &source->value;
		HPackStr nbuf;
		HPackStr vbuf;
		HPackStr *np = &nbuf;
		HPackStr *vp = &vbuf;
		unsigned int index;
		unsigned int flags;

		nbuf.ptr = (TfwStr *) name;
		nbuf.len = name->len;
		nbuf.arena = HPack_Arena_User;
		nbuf.count = 0;
		value_len = value->len;
		if (value_len) {
			vbuf.ptr = (TfwStr *) value;
			vbuf.len = value_len;
			vbuf.arena = HPack_Arena_User;
			vbuf.count = 0;
		} else {
			vp = NULL;
		}
		np = hpack_find_string(ip, np);
		vp = hpack_find_string(ip, vp);
		flags = 0;
		index = hpack_find_entry(ip, np, vp, &flags);
		if (value_len <= (ip->window >> 1)) {
			flags |= HPack_Flags_Add;
		}
		if (index) {
			if (flags & HPack_Flags_No_Value) {
				dst =
				    write_index(out, dst, &k, index, 0x7F, 0x80,
						&rc);
			} else {
				if (flags & HPack_Flags_Add) {
					dst =
					    write_index(out, dst, &k, index,
							0x3F, 0x40, &rc);
				} else {
					dst =
					    write_index(out, dst, &k, index,
							0xF, 0, &rc);
				}
				if (unlikely(rc)) {
					return rc;
				}
				dst = write_string(out, dst, &k, vp, &rc);
			}
		} else {
			unsigned char command = 0;

			if (flags & HPack_Flags_Add) {
				command = 0x40;
			}
			CheckByte(out);
			*dst++ = command;
			dst = write_string(out, dst, &k, np, &rc);
			if (unlikely(rc)) {
				return rc;
			}
			dst = write_string(out, dst, &k, vp, &rc);
		}
		if (unlikely(rc)) {
			return rc;
		}
		source = source->next;
	} while (--n);
	return buffer_emit(out, k);
}
