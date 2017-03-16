/**
 *		Tempesta FW
 *
 * HPACK static and dynamic tables for header fields.
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
#include <stdlib.h>
#include <stdio.h>
#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "errors.h"
#include "hpack.h"
#include "hindex.h"
#include "hstatic.h"

#define Debug_HIndex 1

#if Debug_HIndex
#define DPRINTF(...) printf("HIndex: " __VA_ARGS__)
#define DPUTS(...) puts("HIndex: " __VA_ARGS__)
#else
#define DPRINTF(...)
#define DPUTS(...)
#endif

static HPackEntry *
hpack_find_index(HTTP2Index * __restrict ip, ufast index)
{
	if (index <= HPACK_STATIC_ENTRIES) {
		DPUTS("Static table entry:");
		return hpack_static_table + index - 1;
	} else {
		index -= HPACK_STATIC_ENTRIES + 1;
		if (index < ip->n) {
			ufast current = ip->current;

			if (index <= current) {
				current -= index;
			} else {
				current += ip->length - index;
			}
			DPUTS("Dynamic table entry:");
			return ip->entries + current;
		} else {
			return NULL;
		}
	}
}

static void *
hpack_mem_allocate(uwide length)
{
	return malloc(length);
}

static void
hpack_mem_free(void *p)
{
	free(p);
}

static void
hpack_free_data(HPackStr * __restrict str)
{
	if (str->arena == HPack_Arena_Dynamic) {
		ufast count = str->count;

		if (count == 0) {
			hpack_mem_free(str->ptr);
		} else {
			str->count = count - 1;
		}
	}
}

static ufast
hpack_copy_data(HPackEntry * __restrict cp,
		const HPackStr * __restrict name,
		const HPackStr * __restrict value)
{
	uint8 arena = name->arena;

	if (arena == HPack_Arena_Static) {
		cp->name = *name;
	} else {
		const uwide length = name->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			cp->name.ptr = data;
			cp->name.len = length;
			cp->name.arena = HPack_Arena_Dynamic;
			cp->name.count = 0;
			if (arena == HPack_Arena_Dynamic) {
				memcpy(data, name->ptr, length);
			} else {
				buffer_str_to_array(data, name->ptr);
			}
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	}
	arena = value->arena;
	if (arena == HPack_Arena_Static) {
		cp->value = *value;
	} else {
		const uwide length = value->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			cp->value.ptr = data;
			cp->value.len = length;
			cp->value.arena = HPack_Arena_Dynamic;
			cp->value.count = 0;
			if (arena == HPack_Arena_Dynamic) {
				memcpy(data, name->ptr, length);
			} else {
				buffer_str_to_array(data, value->ptr);
			}
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	}
	return 0;
}

static ufast
hpack_add_and_prune(HTTP2Index * __restrict ip,
		    const HPackStr * __restrict name,
		    const HPackStr * __restrict value)
{
	const uwide name_len = name->len;
	const ufast delta = 32 + name_len + value->len;
	ufast count = ip->n;
	ufast current = ip->current + 1;
	ufast length = ip->length;
	const ufast window = ip->window;
	ufast size = ip->size + delta;
	HPackEntry *entries = ip->entries;

/* Check for integer overflow during calculation of the delta: */
	if (unlikely(delta < 32 || delta < name_len)) {
		goto Empty;
	}
/* Check for integer overflow during summation of */
/* the actual window size and delta: */
	if (size >= delta) {
		if (size > window) {
			if (delta <= window) {
				HPackEntry *__restrict cp;
				ufast early = current;

				if (current >= count) {
					early -= count;
				} else {
					early += length - count;
				}
				cp = entries + early;
				do {
					if (size > window) {
						size -=
						    32 + cp->name.len +
						    cp->value.len;
						hpack_free_data(&cp->value);
						hpack_free_data(&cp->name);
						early++;
						cp++;
						if (unlikely(early == length)) {
							early = 0;
							cp = entries;
						}
					} else {
						break;
					}
				} while (--count);
			} else {
				goto Empty;
			}
		}
 Save:
		if (unlikely(current == length)) {
			current = 0;
		}
		ip->n = ++count;
		ip->current = current;
		ip->size = size;
		if (unlikely(count > length)) {
			HPackEntry *const __restrict previous = entries;
			TfwPool *const __restrict pool = ip->pool;
			uwide block;
			ufast old = length;
			ufast log = 0;

			do {
				length += length;
				log++;
			} while (count > length);
			ip->length = length;
			block = length * (uwide) sizeof(HPackEntry);
			entries = tfw_pool_alloc(pool, block);
			ip->entries = entries;
			if (unlikely(entries == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			if (old) {
				const uwide wrap = old * sizeof(HPackEntry);

				block = (block >> log) - wrap;
				memcpy(entries, (uchar *) previous + wrap,
				       block);
				memcpy((uchar *) entries + block, previous,
				       wrap);
				tfw_pool_free(pool, previous, block);
			}

		}
		return hpack_copy_data(entries + current, name, value);
	} else if (likely(delta > window)) {
 Empty:
		if (count) {
			ip->n = 0;
			ip->current = 0;
			ip->size = 0;
		}
	} else {
		/* Handle rare case where we have an integer overflow */
		/* during summation of actual window size and delta, */
		/* but delta is less than maximal window size: */
		size = delta;
		goto Save;
	}
	return 0;
}

ufast
hpack_add(HTTP2Index * __restrict ip,
	  HTTP2Field * __restrict fp, ufast flags, HTTP2Output * __restrict out)
{
	if (flags & HPack_Flags_Add) {
		HPackStr name;
		HPackStr value;

		name.ptr = &fp->name;
		name.len = fp->name.len;
		name.arena = HPack_Arena_User;
		name.count = 0;
		value.ptr = &fp->value;
		value.len = fp->value.len;
		value.arena = HPack_Arena_User;
		value.count = 0;
		return hpack_add_and_prune(ip, &name, &value);
	}
#if HIndex_Debug
	else {
		DPUTS("Entry is not added to dictionary");
	}
#endif
	return 0;
}

ufast
hpack_add_index(HTTP2Index * __restrict ip,
		HTTP2Field * __restrict fp,
		ufast index, ufast flags, HTTP2Output * __restrict out)
{
	HPackEntry *const __restrict entry = hpack_find_index(ip, index);

	if (entry) {
		HPackStr *const __restrict name = &entry->name;
		HPackStr *__restrict value;
		HPackStr local_value;
		uint8 arena = name->arena;

		DPRINTF("           %s: %s\n",
			(char *)entry->name.ptr, (char *)entry->value.ptr);
		if (flags & HPack_Flags_Add && arena == HPack_Arena_Dynamic) {
			name->count++;
		}
		if (index <= HPACK_STATIC_ENTRIES ||
		    arena == HPack_Arena_Static) {
			fp->name.ptr = name->ptr;
			fp->name.len = name->len;
			fp->name.skb = NULL;
			fp->name.eolen = 0;
			fp->name.flags = 0;
		} else {
			ufast rc = buffer_put(out, name->ptr, name->len);

			if (rc == 0) {
				fp->name = out->str;
			} else {
				return rc;
			}
		}
		if (flags & HPack_Flags_No_Value) {
			value = &entry->value;
			arena = value->arena;
			if (flags & HPack_Flags_Add &&
			    arena == HPack_Arena_Dynamic) {
				value->count++;
			}
			if (index <= HPACK_STATIC_ENTRIES ||
			    arena == HPack_Arena_Static) {
				fp->value.ptr = value->ptr;
				fp->value.len = value->len;
				fp->value.skb = NULL;
				fp->value.eolen = 0;
				fp->value.flags = 0;
			} else {
				ufast rc =
				    buffer_put(out, value->ptr, value->len);
				if (rc == 0) {
					fp->value = out->str;
				} else {
					return rc;
				}
			}
		} else {
			local_value.ptr = &fp->value;
			local_value.len = fp->value.len;
			local_value.arena = HPack_Arena_User;
			local_value.count = 0;
			value = &local_value;
		}
		if (flags & HPack_Flags_Add) {
			return hpack_add_and_prune(ip, name, value);
		}
		return 0;
	} else {
		return Err_HPack_UnknownIndex;
	}
}

void
hpack_set_length(HTTP2Index * __restrict ip, ufast window)
{
	ufast count = ip->n;

	if (count) {
		ufast early = ip->current + 1;
		const ufast length = ip->length;
		ufast size = ip->size;
		HPackEntry *const entries = ip->entries;
		HPackEntry *__restrict cp;

		if (early >= count) {
			early -= count;
		} else {
			early += length - count;
		}
		cp = entries + early;
		do {
			if (size > window) {
				size -= 32 + cp->name.len + cp->value.len;
				hpack_free_data(&cp->value);
				hpack_free_data(&cp->name);
				early++;
				cp++;
				if (unlikely(early == length)) {
					early = 0;
					cp = entries;
				}
			} else {
				break;
			}
		} while (--count);
		ip->n = count;
		ip->size = size;
	}
	ip->window = window;
}

HTTP2Index *
hpack_new_index(ufast window, TfwPool * __restrict pool)
{
	HTTP2Index *const __restrict ip =
	    tfw_pool_alloc(pool, sizeof(HTTP2Index));
	if (ip) {
		ip->window = window;
		ip->size = 0;
		ip->n = 0;
		ip->current = 0;
		ip->length = 0;
		ip->entries = NULL;
		ip->pool = pool;
	}
	return ip;
}

void
hpack_free_index(HTTP2Index * __restrict ip)
{
	HPackEntry *const __restrict entries = ip->entries;
	TfwPool *const __restrict pool = ip->pool;

	if (entries) {
		tfw_pool_free(pool, entries, ip->length * sizeof(HPackEntry));
	}
	tfw_pool_free(pool, ip, sizeof(HTTP2Index));
}
