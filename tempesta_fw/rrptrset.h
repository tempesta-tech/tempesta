/**
 *		Tempesta FW
 *
 * The TfwRrPtrSet is a set of pointers that can be rotated in a round-robin
 * manner. Each time you call get_rr() you get the next pointer in cycle.
 *
 * For example, it may be used to balance load uniformly over a set of servers.
 * You just put pointers to TfwServer objects to the TfwRrPtrSet and call
 * tfw_ptrset_get_rr() to get the next server.
 *
 * Generally it is optimized for the tfw_ptrset_get_rr() operation that may
 * be done concurrently on multiple CPUs without locking. No synchronization
 * with tfw_ptrset_add()/tfw_ptrset_del() is needed, although concurrent add/del
 * still require locking.
 *
 * The disadvantage is the slow asymptotic behavior: O(N) for add/del/test, so
 * generally the structure is applicable only for small sets of data.
 *
 * Also, tfw_ptrset_get_rr() uses atomic operations to provide consistency
 * across multiple CPUs. For a single CPU, it is possible to create a faster
 * alternative that doesn't involve slow atomic instructions.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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
#ifndef __TFW_PTRSET_H__
#define __TFW_PTRSET_H__

#include "lib.h"
#include "log.h"

typedef struct {
	atomic_t counter;
	short n;
	short max;
	void *ptrs[0];
} TfwRrPtrSet;

/**
 * Calculate total size of a set structure, including the array of pointers.
 */
#define tfw_ptrset_size(max) \
	(sizeof(TfwRrPtrSet) + ((max) * sizeof(void *)))

/**
 * Iterate over pointers in a set.
 *
 * Usage:
 *   typedef TFW_PTRSET_STRUCT(TfwAddr, 32) TfwMyAddrSet;
 *   size_t current_addr_idx;
 *   TfwAddr *current_addr;
 *   TfwMyAddrSet addresses;
 *
 *   tfw_ptrset_for_each(current_addr, current_addr_idx, addresses) {
 *           printk("%d\n", current_addr->family);
 *   }
 */
#define tfw_ptrset_for_each(ptr, i, s) \
	for ((i) = 0; ((i) < (s)->n && (ptr = (s)->ptrs[i])); ++(i))


/**
 * Sanity/debug runtime checks.
 * The function is completely eliminated by the compiler when DEBUG is not
 * defined, so it gives no overhead.
 */
static inline void
__tfw_ptrset_validate(const TfwRrPtrSet *s)
{
	IF_DEBUG {
		void *ptr1, *ptr2;
		int idx1, idx2;

		BUG_ON(!s);
		BUG_ON(s->max < 0);
		BUG_ON(s->max > 4096); /* Large value is likely garbage. */
		BUG_ON(s->n < 0 || s->n > s->max);

		tfw_ptrset_for_each(ptr1, idx1, s) {
			BUG_ON(!ptr1);
			tfw_ptrset_for_each(ptr2, idx2, s) {
				BUG_ON(ptr1 == ptr2 && idx1 != idx2);
			}
		}
	}
}

static inline int
__tfw_ptrset_find_idx(const TfwRrPtrSet *s, void *ptr)
{
	int i;

	__tfw_ptrset_validate(s);

	for (i = 0; i < s->max; ++i) {
		if (s->ptrs[i] == ptr)
			return i;
	}

	return -1;
}

static inline void
tfw_ptrset_init(TfwRrPtrSet *s, int max)
{
	memset(s, 0, tfw_ptrset_size(max));
	s->max = max;
	__tfw_ptrset_validate(s);
}

static inline int
tfw_ptrset_add(TfwRrPtrSet *s, void *ptr)
{
	if (__tfw_ptrset_find_idx(s, ptr) > 0) {
		TFW_ERR("Can't add ptr %p to set %p - duplicate ptr\n", ptr, s);
		return -1;
	}
	else if (s->n >= s->max) {
		TFW_ERR("Can't add ptr %p to set %p - set is full\n", ptr, s);
		return -1;
	}

	s->ptrs[s->n] = ptr;
	++s->n;

	return 0;
}

static inline int
tfw_ptrset_del(TfwRrPtrSet *s, void *ptr)
{
	int i;

	i = __tfw_ptrset_find_idx(s, ptr);
	if (i < 0) {
		TFW_ERR("Can't delete %p from set %p - not found\n", ptr, s);
		return -1;
	}

	s->ptrs[i] = s->ptrs[s->n - 1];
	s->ptrs[s->n] = NULL;
	--s->n;

	return 0;
}

static inline void *
tfw_ptrset_get_rr(TfwRrPtrSet *s)
{
	void *ret;
	short n;

	__tfw_ptrset_validate(s);

	do {
		n = s->n;
		if (unlikely(!n)) {
			TFW_ERR("Can't get ptr from the empty set: %p\n", s);
			return NULL;
		}
		ret = s->ptrs[(atomic_inc_return(&s->counter) & 0xFFFF) % n];
	} while (unlikely(!ret));

	return ret;
}

#endif /* __TFW_PTRSET_H__ */
