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

#define USE_KMALLOC 0

#include <stdint.h>
#if USE_KMALLOC
#include <linux/vmalloc.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "common.h"
#include "../pool.h"
#include "../str.h"
#include "bits.h"
#include "subs.h"
#include "hash.h"
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

static Hash *__restrict static_hash;
static Hash *__restrict static_names;
static Hash *__restrict static_pairs;

void
hpack_str_print(const HPackStr * __restrict str)
{
	if (str->arena == HPack_Arena_User) {
		buffer_str_print(str->ptr);
	} else {
		TfwStr text;

		text.ptr = str->ptr;
		text.skb = NULL;
		text.len = str->len;
		text.eolen = 0;
		text.flags = 0;
		buffer_str_print(&text);
	}
}

static void *
hpack_mem_allocate(uintptr_t length)
{
#if USE_KMALLOC
	return kmalloc(length, GFP_KERNEL);
#else
	return malloc(length);
#endif
}

static void
hpack_mem_free(void *p)
{
#if USE_KMALLOC
	kfree(p);
#else
	free(p);
#endif
}

static unsigned int
hpack_equal(const void *const xp, const void *const yp)
{
	const HPackStr *__restrict x = xp;
	const HPackStr *__restrict y = yp;
	const uintptr_t cx = x->len;
	const uintptr_t cy = y->len;

	if (cx == cy) {
		const TfwStr *__restrict fp;

		if (x->arena != HPack_Arena_User) {
			if (y->arena != HPack_Arena_User) {
				return memcmp(x->ptr, y->ptr, cx) == 0;
			}
		} else if (y->arena != HPack_Arena_User) {
			const HPackStr *__restrict t = x;

			x = y;
			y = t;
		} else {
			return buffer_str_cmp(x->ptr, y->ptr) == 0;
		}
		fp = y->ptr;
		if (TFW_STR_PLAIN(fp)) {
			return memcmp(x->ptr, fp->ptr, cx) == 0;
		} else {
			return buffer_str_cmp_plain(x->ptr, fp->ptr, cx) == 0;
		}
	}
	return 0;
}

static uintptr_t
hpack_hash(const void *const xp)
{
	const HPackStr *const __restrict x = xp;

	if (x->arena == HPack_Arena_User) {
		return buffer_str_hash(x->ptr);
	} else {
		return Byte_Hash_Chain(x->ptr, x->len, 0);
	}
}

static HPackStr *
hpack_hash_add(Hash * const __restrict ht,
	       HPackStr * __restrict p, Sub * const __restrict sub)
{
	HPackStr *__restrict prev = Hash_FindAdd(ht, p, p);

	if (prev) {
		if (p->arena != HPack_Arena_Static) {
			Sub_Free(sub, p);
			prev->count++;
		}
		return prev;
	} else if (p->arena == HPack_Arena_User) {
		const unsigned int length = p->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			const TfwStr *__restrict source = p->ptr;

			p->ptr = data;
			p->arena = HPack_Arena_Dynamic;
			buffer_str_to_array(data, source);
		} else {
			Sub_Free(sub, p);
			return NULL;
		}
	}
	return p;
}

static unsigned int
hpack_pair_equal(const void *const xp, const void *const yp)
{
	const HPackEntry *__restrict x = xp;
	const HPackEntry *__restrict y = yp;

	return x->name == y->name && x->value == y->value;
}

static uintptr_t
hpack_pair_hash(const void *const xp)
{
	const HPackEntry *const __restrict x = xp;

	return (uintptr_t) x->name ^ (uintptr_t) x->value;
}

static unsigned int
hpack_name_equal(const void *const xp, const void *const yp)
{
	return xp == yp;
}

static uintptr_t
hpack_name_hash(const void *const xp)
{
	return (uintptr_t) xp;
}

HPackStr *
hpack_find_string(HTTP2Index * __restrict ip, HPackStr * __restrict name)
{
	HPackStr *__restrict np = Hash_Find(static_hash, name);

	if (np == NULL) {
		np = Hash_Find(ip->hash, name);
		if (np == NULL) {
			return name;
		}
#if Debug_HIndex
		else {
			DPRINTF("In dynamic hash: \"");
		}
#endif
	}
#if Debug_HIndex
	else {
		DPRINTF("In static hash: \"");
	}
	hpack_str_print(np->ptr);
	puts("\"");
#endif
	return np;
}

#if Debug_HIndex

static void
DPRINT_ENTRY(unsigned int index,
	     HPackStr * const __restrict name,
	     HPackStr * const __restrict value)
{
	if (index <= HPACK_STATIC_ENTRIES) {
		DPUTS("Static entry:");
	} else {
		DPUTS("Dynamic entry:");
	}
	DPRINTF("   Index: %u\n", index);
	DPRINTF("   Name: \"");
	hpack_str_print(name);
	puts("\"");
	if (value) {
		DPRINTF("   Value: \"");
		hpack_str_print(value);
		puts("\"");
	}
}

#else

#define DPRINT_ENTRY(index, name, value);

#endif

unsigned int
hpack_find_entry(HTTP2Index * __restrict ip,
		 HPackStr * __restrict name,
		 HPackStr * __restrict value, unsigned int *__restrict flags)
{
	HPackEntry *__restrict entry;

	if (value->arena != HPack_Arena_User) {
		HPackEntry pattern;

		pattern.name = name;
		pattern.value = value;
		entry = Hash_Find(static_pairs, &pattern);
		if (entry) {
			unsigned int index;

			*flags |= HPack_Flags_No_Value;
 S1:
			index = (unsigned int)(entry - static_table) + 1;
			DPRINT_ENTRY(index, name, value);
			return index;
		}
		entry = Hash_Find(ip->pairs, &pattern);
		if (entry) {
			unsigned int shift;
			unsigned int index;

			*flags |= HPack_Flags_No_Value;
			if (value && value->arena != HPack_Arena_Static) {
				value->count++;
			}
 D1:
			if (name->arena != HPack_Arena_Static) {
				name->count++;
			}
			index = ip->current;
			shift = (unsigned int)(entry - ip->entries);
			if (shift < index) {
				index -= shift;
			} else {
				index += ip->length - shift;
			}
			index += HPACK_STATIC_ENTRIES;
			DPRINT_ENTRY(index, name, value);
			return index;
		}
	}
	if (name->arena != HPack_Arena_User) {
		entry = Hash_Find(static_names, name);
		if (entry) {
#if Debug_HIndex
			DPRINTF("Custom value: \"");
			hpack_str_print(value);
			puts("\"");
#endif
			goto S1;
		}
		entry = Hash_Find(ip->names, name);
		if (entry) {
#if Debug_HIndex
			DPRINTF("Custom value: \"");
			hpack_str_print(value);
			puts("\"");
#endif
			goto D1;
		}
	}
	return 0;
}

static HPackEntry *
hpack_find_index(HTTP2Index * __restrict ip, unsigned int index)
{
	if (index <= HPACK_STATIC_ENTRIES) {
		return static_table + index - 1;
	} else {
		index -= HPACK_STATIC_ENTRIES;
		if (index <= ip->n) {
			unsigned int current = ip->current;

			if (index <= current) {
				current -= index;
			} else {
				current += ip->length - index;
			}
			return ip->entries + current;
		} else {
			return NULL;
		}
	}
}

static void
hpack_free_entry(HTTP2Index * __restrict ip,
		 HPackEntry * __restrict cp,
		 HPackStr * __restrict np, HPackStr * __restrict vp)
{
	Sub *const __restrict sub = ip->sub;
	Hash *const __restrict ht = ip->hash;

	if (ht) {
		Hash *const __restrict hp = ip->pairs;
		Hash *const __restrict hn = ip->names;
		HPackEntry *__restrict rp = Hash_Find(hp, cp);

		if (rp == cp) {
			Hash_Delete(hp, cp);
		}
		rp = Hash_Find(hn, np);
		if (rp == cp) {
			Hash_Delete(hn, cp);
		}
	}
	if (np->arena != HPack_Arena_Static) {
		unsigned int count = np->count;

		if (count == 1) {
			if (ht) {
				DPUTS("Delete name from hash");
				Hash_Delete(ht, np);
			}
			hpack_mem_free(np->ptr);
			Sub_Free(sub, np);
		} else {
			np->count = count - 1;
		}
	}
	if (vp && vp->arena != HPack_Arena_Static) {
		unsigned int count = vp->count;

		if (count == 1) {
			if (ht) {
				DPUTS("Delete value from hash");
				Hash_Delete(ht, vp);
			}
			hpack_mem_free(vp->ptr);
			Sub_Free(sub, vp);
		} else {
			vp->count = count - 1;
		}
	}
}

static unsigned int
hpack_copy_data(HTTP2Index * __restrict ip,
		HPackEntry * __restrict cp,
		HPackStr * __restrict name, HPackStr * __restrict value)
{
	Hash *const __restrict ht = ip->hash;

	if (name->arena == HPack_Arena_User) {
		const uintptr_t length = name->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			HPackStr *__restrict np = Sub_Allocate(ip->sub);

			if (unlikely(np == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			DPUTS("New header name");
			np->ptr = data;
			np->len = length;
			np->arena = HPack_Arena_Dynamic;
			np->count = 1;
			buffer_str_to_array(data, name->ptr);
			name = np;
			if (ht) {
				Hash_Add(ht, np, np);
			}
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	}
	if (value && value->arena == HPack_Arena_User) {
		const uintptr_t length = value->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			HPackStr *__restrict vp = Sub_Allocate(ip->sub);

			if (unlikely(vp == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			DPUTS("New header value");
			vp->ptr = data;
			vp->len = length;
			vp->arena = HPack_Arena_Dynamic;
			vp->count = 1;
			buffer_str_to_array(data, value->ptr);
			value = vp;
			if (ht) {
				Hash_Add(ht, vp, vp);
			}
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	}
	cp->name = name;
	cp->value = value;
	if (ht) {
		Hash_Replace(ip->pairs, cp, cp);
		Hash_Replace(ip->names, name, cp);
	}
	return 0;
}

static unsigned int
hpack_add_and_prune(HTTP2Index * __restrict ip,
		    HPackStr * __restrict name, HPackStr * __restrict value)
{
	const uintptr_t name_len = name->len;
	const unsigned int delta = 32 + name_len + (value ? value->len : 0);
	unsigned int count = ip->n;
	unsigned int current = ip->current;
	unsigned int length = ip->length;
	unsigned int window, size, new_size;
	HPackEntry *entries = ip->entries;

/* Check for integer overflow occured during calculation of */
/* the delta:						    */
	if (unlikely(delta < name_len || delta < 32)) {
		DPUTS("Very big entry...");
		goto Empty;
	}
	size = ip->size;
	new_size = size + delta;
	window = ip->window;
/* Debug printfs: */
	DPRINTF("Window: %u, current dictionary size: %u\n", window, size);
	DPRINTF("New dictionary size: %u, delta: %u\n", new_size, delta);
/* The second condition "new_size < delta" was added here   */
/* to handle an integer overflow, which can occurred during */
/* summation of the actual window size with delta:	    */
	if (new_size > window || unlikely(new_size < delta)) {
		/* This condition also handles rare case where an integer  */
		/* overflow occurred during summation of the actual window */
		/* size with delta, but delta itself is less than or equal */
		/* to the current window size:                             */
		if (delta <= window) {
			HPackEntry *__restrict cp;
			unsigned int early = current;

			if (current >= count) {
				early -= count;
			} else {
				early += length - count;
			}
			window -= delta;
			DPRINTF("Current: %u, early entry: %u (%u entries)\n",
				current, early, count);
			DPRINTF("Maximum allowed size: %u\n", window);
			cp = entries + early;
			do {
				HPackStr *__restrict np = cp->name;
				HPackStr *__restrict vp = cp->value;

				size -= 32 + np->len;
				if (vp) {
					size -= vp->len;
				}
				DPRINTF("Drop index: %u\n", early);
				hpack_free_entry(ip, cp, np, vp);
				early++;
				cp++;
				count--;
				if (unlikely(early == length)) {
					early = 0;
					cp = entries;
				}
			} while (size > window);
			/* Calculated new size may be unreliable due to integer */
			/* overflow, therefore we need to re-calculate it:      */
			new_size = size + delta;
		} else {
 Empty:
			/* Cleaning of the entire dictionary: */
			DPUTS("Cleaning of the entire dictionary...");
			if (count) {
				HPackEntry *__restrict cp;

				if (current >= count) {
					current -= count;
				} else {
					current += length - count;
				}
				cp = entries + current;
				do {
					HPackStr *__restrict np = cp->name;
					HPackStr *__restrict vp = cp->value;

					DPRINTF("Drop index: %u\n", current);
					hpack_free_entry(ip, cp, np, vp);
					current++;
					cp++;
					if (unlikely(current == length)) {
						current = 0;
						cp = entries;
					}
				} while (--count);
				ip->n = 0;
				ip->current = 0;
				ip->size = 0;
			}
			return 0;
		}
	} else if (unlikely(count == length)) {
		HPackEntry *const __restrict previous = entries;
		TfwPool *const __restrict pool = ip->pool;
		uintptr_t block;

		DPUTS("Reallocation of the index structures...");
		if (length) {
			length += length;
		} else {
			length = 32;
		}
		DPRINTF("New index size: %u\n", length);
		block = length * (uintptr_t) sizeof(HPackEntry);
		entries = tfw_pool_alloc(pool, block);
		if (unlikely(entries == NULL)) {
			return Err_HTTP2_OutOfMemory;
		}
		ip->length = length;
		ip->entries = entries;
		if (count) {
			const uintptr_t wrap = current * sizeof(HPackEntry);

			block = (block >> 1) - wrap;
			if (block) {
				memcpy(entries, (uchar *) previous + wrap,
				       block);
			}
			if (wrap) {
				memcpy((uchar *) entries + block, previous,
				       wrap);
			}
			tfw_pool_free(pool, previous, block);
		}
		current = count;
		DPRINTF("Current entry after array expansion: %u\n", current);
	}
	ip->size = new_size;
	DPUTS("Put new item into dictionary...");
	entries += current;
	current++;
	ip->n = count + 1;
	if (unlikely(current == length)) {
		current = 0;
	}
	ip->current = current;
	DPRINTF("New current: %u\n", current);
	return hpack_copy_data(ip, entries, name, value);
}

void
hpack_set_length(HTTP2Index * __restrict ip, unsigned int window)
{
	unsigned int size = ip->size;

	if (size > window) {
		unsigned int count = ip->n;
		unsigned int early = ip->current;
		const unsigned int length = ip->length;
		HPackEntry *const entries = ip->entries;
		HPackEntry *__restrict cp;

		if (early >= count) {
			early -= count;
		} else {
			early += length - count;
		}
		DPRINTF("Current: %u, early entry: %u (%u entries)\n",
			ip->current, early, count);
		DPRINTF("Maximum allowed size: %u\n", window);
		cp = entries + early;
		do {
			HPackStr *__restrict np = cp->name;
			HPackStr *__restrict vp = cp->value;

			size -= 32 + np->len;
			if (vp) {
				size -= vp->len;
			}
			DPRINTF("Drop index: %u\n", early);
			hpack_free_entry(ip, cp, np, vp);
			early++;
			cp++;
			count--;
			if (unlikely(early == length)) {
				early = 0;
				cp = entries;
			}
		} while (size > window);
		ip->n = count;
		ip->size = size;
	}
	ip->window = window;
}

unsigned int
hpack_add(HTTP2Index * __restrict ip,
	  HTTP2Field * __restrict fp,
	  unsigned int flags, HTTP2Output * __restrict out)
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
#if Debug_HIndex
	else {
		DPUTS("Entry is not added to dictionary");
	}
#endif
	return 0;
}

unsigned int
hpack_add_index(HTTP2Index * __restrict ip,
		HTTP2Field * __restrict fp,
		unsigned int index,
		unsigned int flags, HTTP2Output * __restrict out)
{
	HPackEntry *const __restrict entry = hpack_find_index(ip, index);

	if (entry) {
		HPackStr *const __restrict name = entry->name;
		HPackStr *__restrict value;
		HPackStr local_value;
		uint8_t arena = name->arena;

		DPRINT_ENTRY(index, entry->name, entry->value);
		if (arena == HPack_Arena_Static) {
			fp->name.ptr = name->ptr;
			fp->name.skb = NULL;
			fp->name.len = name->len;
			fp->name.eolen = 0;
			fp->name.flags = 0;
		} else {
			unsigned int rc = buffer_put(out, name->ptr, name->len);

			if (rc == 0) {
				fp->name = out->str;
				if (flags & HPack_Flags_Add) {
					name->count++;
				}
			} else {
				return rc;
			}
		}
		/* Next assignment only to eliminate compiler warning: */
		value = NULL;
		if (flags & HPack_Flags_No_Value) {
			value = entry->value;
			if (value) {
				arena = value->arena;
				if (arena == HPack_Arena_Static) {
					fp->value.ptr = value->ptr;
					fp->value.skb = NULL;
					fp->value.len = value->len;
					fp->value.eolen = 0;
					fp->value.flags = 0;
				} else {
					unsigned int rc =
					    buffer_put(out, value->ptr,
						       value->len);
					if (rc == 0) {
						fp->value = out->str;
						if (flags & HPack_Flags_Add) {
							value->count++;
						}
					} else {
						return rc;
					}
				}
			}
		} else if (flags & HPack_Flags_Add) {
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
		DPRINTF("Unknown index: %u\n", index);
		return Err_HPack_UnknownIndex;
	}
}

HTTP2Index *
hpack_new_index(unsigned int window, unsigned char is_encoder,
		TfwPool * __restrict pool)
{
	HTTP2Index *const __restrict ip =
	    tfw_pool_alloc(pool, sizeof(HTTP2Index));
	if (ip) {
		Sub *__restrict sub;

		ip->window = window;
		ip->size = 0;
		ip->n = 0;
		ip->current = 0;
		ip->length = 0;
		ip->entries = NULL;
		ip->pool = pool;
		sub = Sub_New("hpack strings", sizeof(HPackStr), 32, 32, pool);
		if (unlikely(sub == NULL)) {
 B0:
			tfw_pool_free(pool, ip, sizeof(HTTP2Index));
			return NULL;
		}
		ip->sub = sub;
		ip->is_encoder = is_encoder;
		if (is_encoder) {
			Hash *const __restrict ht =
			    Hash_New("hpack-hash", 0, 32, 32,
				     hpack_hash,
				     hpack_equal, pool);
			Hash *__restrict hp;
			Hash *__restrict hn;

			if (unlikely(ht == NULL)) {
 B1:
				Sub_Delete(sub);
				goto B0;
			}
			hp = Hash_New("hpack-pairs", 0, 32, 32,
				      hpack_pair_hash, hpack_pair_equal, pool);
			if (unlikely(hp == NULL)) {
 B2:
				Hash_Free(ht);
				goto B1;
			}
			hn = Hash_New("hpack-names", 0, 32, 32,
				      hpack_name_hash, hpack_name_equal, pool);
			if (hn) {
				ip->hash = ht;
				ip->pairs = hp;
				ip->names = hn;
			} else {
				Hash_Free(hp);
				goto B2;
			}
		}
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
	if (ip->is_encoder) {
		Hash_Free(ip->names);
		Hash_Free(ip->pairs);
		Hash_Free(ip->hash);
	}
	Sub_Delete(ip->sub);
	tfw_pool_free(pool, ip, sizeof(HTTP2Index));
}

static TfwPool *__restrict global_pool;

void
hpack_index_init(TfwPool * __restrict pool)
{
	unsigned int i;
	Hash *const __restrict ht = Hash_New("static",
					     HPACK_STATIC_ENTRIES, 0, 16,
					     hpack_hash,
					     hpack_equal, pool);
	Hash *const __restrict hp = Hash_New("static-pairs",
					     HPACK_STATIC_ENTRIES, 0, 0,
					     hpack_pair_hash,
					     hpack_pair_equal, pool);
	Hash *const __restrict hn = Hash_New("static-names",
					     HPACK_STATIC_ENTRIES, 0, 0,
					     hpack_pair_hash,
					     hpack_pair_equal, pool);

	global_pool = pool;
	static_hash = ht;
	static_pairs = hp;
	static_names = hn;
	for (i = 0; i < HPACK_STATIC_ENTRIES; i++) {
		HPackStr *__restrict np = (HPackStr *) & static_data[i].name;
		HPackStr *__restrict vp = (HPackStr *) & static_data[i].value;

		if (vp->len == 0) {
			vp = NULL;
		}
		static_table[i].name = np;
		static_table[i].value = vp;
		np = hpack_hash_add(ht, np, NULL);
		if (vp) {
			vp = hpack_hash_add(ht, vp, NULL);
		}
		Hash_Add(hp, static_table + i, static_table + i);
		Hash_Add(hn, np, static_table + i);
	}
}

void
hpack_index_shutdown(void)
{
	Hash_Free(static_names);
	Hash_Free(static_pairs);
	Hash_Free(static_hash);
}
