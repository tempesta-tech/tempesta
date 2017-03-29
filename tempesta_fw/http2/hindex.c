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

static ufast
hpack_equal(const void *const xp, const void *const yp)
{
	const HPackStr *__restrict x = xp;
	const HPackStr *__restrict y = yp;
	const uwide cx = x->len;
	const uwide cy = y->len;

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

static uwide
hpack_hash(const void *const xp)
{
	const HPackStr *const __restrict x = xp;

	if (x->arena == HPack_Arena_User) {
		return buffer_str_hash(x->ptr);
	} else {
		return Byte_Hash_Chain(x->ptr, x->len, 0);
	}
}

static void *
hpack_mem_allocate(uwide length)
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

static HPackStr *
hpack_hash_add(Hash * const __restrict ht,
	       HPackStr * __restrict p, Sub * const __restrict sub)
{
	HPackStr *__restrict prev = Hash_FindAdd(ht, p, p);

	if (prev) {
		if (p->arena != HPack_Arena_Static) {
			Sub_Free(sub, p);
			p = prev;
			p->count++;
		} else {
			p = prev;
		}
	} else if (p->arena == HPack_Arena_User) {
		const ufast length = p->len;
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

static ufast
hpack_pair_equal(const void *const xp, const void *const yp)
{
	const HPackEntry *__restrict x = xp;
	const HPackEntry *__restrict y = yp;

	return x->name == y->name && x->value == y->value;
}

static uwide
hpack_pair_hash(const void *const xp)
{
	const HPackEntry *const __restrict x = xp;

	return (uwide) x->name ^ (uwide) x->value;
}

static ufast
hpack_name_equal(const void *const xp, const void *const yp)
{
	return xp == yp;
}

static uwide
hpack_name_hash(const void *const xp)
{
	return (uwide) xp;
}

static HPackEntry *
hpack_find_index(HTTP2Index * __restrict ip, ufast index)
{
	if (index <= HPACK_STATIC_ENTRIES) {
		DPUTS("Static table entry:");
		return static_table + index - 1;
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
		ufast count = np->count;

		if (count == 1) {
			if (ht) {
				Hash_Delete(ht, np);
			}
			hpack_mem_free(np->ptr);
		} else {
			np->count = count - 1;
		}
		Sub_Free(sub, np);
	}
	if (vp && vp->arena != HPack_Arena_Static) {
		ufast count = vp->count;

		if (count == 1) {
			if (ht) {
				Hash_Delete(ht, vp);
			}
			hpack_mem_free(vp->ptr);
		} else {
			vp->count = count - 1;
		}
		Sub_Free(sub, vp);
	}
}

static ufast
hpack_copy_data(HTTP2Index * __restrict ip,
		HPackEntry * __restrict cp,
		HPackStr * __restrict name, HPackStr * __restrict value)
{
	Hash *const __restrict ht = ip->hash;

	if (name->arena != HPack_Arena_User) {
		cp->name = name;
	} else {
		const uwide length = name->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			HPackStr *__restrict np = Sub_Allocate(ip->sub);

			if (unlikely(np == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			np->ptr = data;
			np->len = length;
			np->arena = HPack_Arena_Dynamic;
			np->count = 1;
			cp->name = np;
			buffer_str_to_array(data, name->ptr);
			name = np;
			if (ht) {
				Hash_Add(ht, np, np);
			}
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	}
	if (value == NULL || value->arena != HPack_Arena_User) {
		cp->value = value;
	} else {
		const uwide length = value->len;
		uchar *__restrict data = hpack_mem_allocate(length);

		if (data) {
			HPackStr *__restrict vp = Sub_Allocate(ip->sub);

			if (unlikely(vp == NULL)) {
				return Err_HTTP2_OutOfMemory;
			}
			vp->ptr = data;
			vp->len = length;
			vp->arena = HPack_Arena_Dynamic;
			vp->count = 1;
			cp->value = vp;
			buffer_str_to_array(data, name->ptr);
			value = vp;
			if (ht) {
				Hash_Add(ht, vp, vp);
			}
		} else {
			return Err_HTTP2_OutOfMemory;
		}
	}
	if (ht) {
		Hash_Replace(ip->pairs, cp, cp);
		Hash_Replace(ip->names, name, cp);
	}
	return 0;
}

static ufast
hpack_add_and_prune(HTTP2Index * __restrict ip,
		    HPackStr * __restrict name, HPackStr * __restrict value)
{
	const uwide name_len = name->len;
	const ufast delta = 32 + name_len + (value ? value->len : 0);
	ufast count = ip->n;
	ufast current = ip->current + 1;
	ufast length = ip->length;
	ufast window = ip->window;
	ufast size = ip->size;
	ufast new_size = size + delta;
	HPackEntry *entries = ip->entries;

/* Debug printfs: */
	DPRINTF("Name length: %" PRIuPTR " (arena = %u)\n",
		name_len, name->arena);
	DPRINTF("Value length: %" PRIuPTR " (arena = %d)\n",
		value ? value->len : 0, value ? (int)value->arena : -1);
	DPRINTF("Window: %u, current size: %u\n", window, size);
/* Check for integer overflow during calculation of the delta: */
	if (unlikely(delta < 32 || delta < name_len)) {
		goto Empty;
	}
/* Check for integer overflow during summation of */
/* the actual window size and delta: */
	if (new_size >= delta) {
		DPRINTF("New dictionary size: %u, delta: %u...\n", new_size,
			delta);
		if (new_size > window) {
 Save:
			if (delta <= window) {
				HPackEntry *__restrict cp;
				ufast early = current;

				if (current >= count) {
					early -= count;
				} else {
					early += length - count;
				}
				window -= delta;
				DPRINTF("Current: %u, early: %u, length: %u\n",
					current, early, length);
				DPRINTF("Maximum allowed size: %u\n", window);
				cp = entries + early;
				do {
					if (size > window) {
						HPackStr *__restrict np =
						    cp->name;
						HPackStr *__restrict vp =
						    cp->value;
						size -= 32 + np->len;
						if (vp) {
							size -= vp->len;
						}
						hpack_free_entry(ip, cp, np,
								 vp);
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
				new_size = size + delta;
			} else {
				goto Empty;
			}
		}
		if (unlikely(current == length)) {
			current = 0;
		}
		ip->n = ++count;
		ip->current = current;
		ip->size = new_size;
		if (unlikely(count > length)) {
			HPackEntry *const __restrict previous = entries;
			TfwPool *const __restrict pool = ip->pool;
			uwide block;
			ufast old = length;
			ufast log = 0;

			DPUTS("Reallocation of the index structures...");
			DPRINTF("New size: %u items...\n", count);
			if (length) {
				do {
					length += length;
					log++;
				} while (count > length);
			} else {
				length = Bit_UpPowerOfTwo(count);
				log = Bit_FastLog2(count);
			}
			DPRINTF("New length: %u, log: %u\n", length, log);
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
		DPUTS("Put new item into dictionary...");
		return hpack_copy_data(ip, entries + current, name, value);
	} else if (likely(delta > window)) {
 Empty:
		if (count) {
			HPackEntry *__restrict cp;
			ufast early = current;

			if (current >= count) {
				early -= count;
			} else {
				early += length - count;
			}
			cp = entries + early;
			do {
				HPackStr *__restrict np = cp->name;
				HPackStr *__restrict vp = cp->value;

				hpack_free_entry(ip, cp, np, vp);
				early++;
				cp++;
				if (unlikely(early == length)) {
					early = 0;
					cp = entries;
				}
			} while (--count);
			ip->n = 0;
			ip->current = 0;
			ip->size = 0;
		}
	} else {
		/* Handle rare case where we have an integer overflow */
		/* during summation of actual window size and delta,  */
		/* but delta itself is less than current window size: */
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
#if Debug_HIndex
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
		HPackStr *const __restrict name = entry->name;
		HPackStr *__restrict value;
		HPackStr local_value;
		uint8 arena = name->arena;

		DPRINTF("           %s: %s\n",
			(char *)entry->name->ptr, (char *)entry->value->ptr);
		if (flags & HPack_Flags_Add && arena == HPack_Arena_Dynamic) {
			name->count++;
		}
		if (arena == HPack_Arena_Static) {
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
			value = entry->value;
			if (value) {
				arena = value->arena;
				if (flags & HPack_Flags_Add &&
				    arena == HPack_Arena_Dynamic) {
					value->count++;
				}
				if (arena == HPack_Arena_Static) {
					fp->value.ptr = value->ptr;
					fp->value.len = value->len;
					fp->value.skb = NULL;
					fp->value.eolen = 0;
					fp->value.flags = 0;
				} else {
					ufast rc =
					    buffer_put(out, value->ptr,
						       value->len);
					if (rc == 0) {
						fp->value = out->str;
					} else {
						return rc;
					}
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

HPackStr *
hpack_find_string(HTTP2Index * __restrict ip, HPackStr * __restrict name)
{
	Hash *const __restrict ht = ip->hash;
	HPackStr *__restrict np = Hash_Find(ht, name);

	return np ? np : name;
}

ufast
hpack_find_entry(HTTP2Index * __restrict ip,
		 HPackStr * __restrict name,
		 HPackStr * __restrict value, ufast * __restrict flags)
{
	ufast current;
	ufast index;
	Hash *const __restrict hp = ip->pairs;
	Hash *const __restrict hn = ip->pairs;
	HPackEntry pattern;
	HPackEntry *__restrict entry;

	pattern.name = name;
	pattern.value = value;
	entry = Hash_Find(static_pairs, &pattern);
	if (entry) {
		*flags |= HPack_Flags_No_Value;
	} else if (likely(value != NULL)) {
		entry = Hash_Find(static_names, name);
	}
	if (entry) {
		return (ufast) (entry - static_table) + 1;
	}
	entry = Hash_Find(hp, &pattern);
	if (entry) {
		*flags |= HPack_Flags_No_Value;
	} else if (likely(value != NULL)) {
		entry = Hash_Find(hn, name);
		if (entry == NULL) {
			return 0;
		}
	} else {
		return 0;
	}
	index = (ufast) (entry - ip->entries);
	current = ip->current;
	if (index < current) {
		return current - index + HPACK_STATIC_ENTRIES;
	} else {
		current += ip->length - index;
		return current + HPACK_STATIC_ENTRIES;
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
				HPackStr *__restrict np = cp->name;
				HPackStr *__restrict vp = cp->value;

				size -= 32 + np->len;
				if (vp) {
					size -= vp->len;
				}
				hpack_free_entry(ip, cp, np, vp);
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
hpack_new_index(ufast window, byte is_encoder, TfwPool * __restrict pool)
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
		ip->sub =
		    Sub_New("hpack strings", sizeof(HPackStr), 32, 32, pool);
		if (is_encoder) {
			Hash *const __restrict ht =
			    Hash_New("hpack-hash", 0, 32, 32,
				     hpack_hash,
				     hpack_equal, pool);
			Hash *const __restrict hp =
			    Hash_New("hpack-pairs", 0, 32, 32,
				     hpack_pair_hash,
				     hpack_pair_equal, pool);
			Hash *const __restrict hn =
			    Hash_New("hpack-names", 0, 32, 32,
				     hpack_name_hash,
				     hpack_name_equal, pool);

			ip->hash = ht;
			ip->pairs = hp;
			ip->names = hn;
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
	tfw_pool_free(pool, ip, sizeof(HTTP2Index));
}

static TfwPool *__restrict global_pool;

void
hpack_index_init(TfwPool * __restrict pool)
{
	ufast i;
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
