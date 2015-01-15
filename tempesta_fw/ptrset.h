/**
 *		Tempesta FW
 *
 * The TfwPtrSet is a generic set of pointers. Essentially, this is just a small
 * array of pointers, where all pointers are unique and you can add/delete
 * elements and iterate over them.
 *
 * The purpose of a TfwPtrSet is to store a small limited set of pointers to
 * distinct objects like a list of back-end servers for the Tempesta FW.
 *
 * Advantages over a linked list are:
 *  - No need for augmenting the target data structure with sturct list_head.
 *    This is useful when you want to make a list of objects in an external
 *    kernel module, but you don't want the main code to know about your module.
 *  - Lightweight operations.
 *    Although the asymptotic behavior is bad (O(N) for most operations), the
 *    code is good at constant factors, so the performance should be slightly
 *    better for small number of elements.
 *  - Some type checking.
 *    Say, you can define a TfwAddrSet type that contains pointers to TfwAddr
 *    objects, and your functions may take "TfwAddrSet *" now instead of generic
 *    "struct list_head *". That makes your code more obvious and readable.
 *  - An ability to pre-allocate the whole array statically that allows to avoid
 *    some boilerplate code for dynamic memory allocation and error handling.
 *  - Set-related operations out of the box: all pointers are unique, no NULLs
 *    allowed, etc. Again, no need for boilerplate code here.
 *
 * Disadvantages are:
 *  - Bad asymptotic behavior: add/delete take O(N).
 *  - Hard limit for a number of pointers in a set. No support for growing.
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

/**
 * Define a custom specific PtrSet structure.
 *
 * For example:
 *     typedef TFW_PTRSET_STRUCT(TfwAddr, 32) TfwMyAddrSet;
 * will define a type containing an array of 32 items of type "TfwAddr *".
 *
 * The fixed maximum number of 32 elements is not always handy.
 * If you want dynamic allocation, you may specify @static_max_ptrs = 0:
 *     typedef TFW_PTRSET_STRUCT(TfwAddr, 0) TfwMyAddrSet;
 * That creates a structure with zero-length array in the tail, so you will be
 * responsible for memory allocation. Use __tfw_ptrset_max() to calculate size
 * and __tfw_ptrset_init() to initialize the structure after allocation.
 */
#define TFW_PTRSET_STRUCT(ptr_type, static_max_ptrs) \
struct {					\
	atomic_t counter;			\
	short n;				\
	short max;				\
	ptr_type *ptrs[static_max_ptrs];	\
}

/**
 * Get the maximum number of pointers in a set. Calculate it at compile time for
 * fixed-length arrays, or use TfwPtrSet->max for variable-length arrays.
 * That is a little bit faster and allows you to allocate sets statically
 * without explicit initialization (all the fields are zero'ed which is valid).
 */
#define __tfw_ptrset_max(s) \
	(ARRAY_SIZE((s)->ptrs) ? ARRAY_SIZE((s)->ptrs) : (s)->max)

/**
 * Calculate total size of a set structure, including the array of pointers.
 */
#define tfw_ptrset_size(max) \
	(sizeof(TfwPtrSet) + ((max) * sizeof(void *)))

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
 * The TfwPtrSet is a dummy generic structure that contains fields common for
 * all custom structures (defined manually or with TFW_PTRSET_STRUCT()).
 * We just cast everything to the TfwPtrSet. That allows us to use inline
 * functions instead of macros and thus the make code much cleaner.
 */
typedef TFW_PTRSET_STRUCT(void, 0) TfwPtrSet;

/**
 * Since we go generic, and cast everything to TfwPtrSet, we loose even basic
 * static checks, so here we define a couple of macros to simulate them.
 * This one checks that a custom structure is compatible with TfwPtrSet by
 * detecting the "ptrs" field. That is enough to catch the majority of errors.
 */
#define __tfw_ptrset_cast(s)	\
({				\
	BUILD_BUG_ON(offsetof(typeof(*(s)), ptrs) != offsetof(TfwPtrSet, ptrs)); \
	((TfwPtrSet *)s);	\
})

/**
 * Check that @ptr is compatible with the set of pointers @s.
 * Also check for NULL because nothing is not a valid element of a set.
 */
#define __tfw_ptrset_checkptr(s, ptr)	\
({					\
	(void)((s)->ptrs[0] == (ptr));	\
	BUG_ON(!ptr);			\
	ptr;				\
})

/* Common operations for a set. */

#define tfw_ptrset_is_empty(s) \
 	(!__tfw_ptrset_cast(s)->n)

#define tfw_ptrset_init(s) \
 	__tfw_ptrset_init(__tfw_ptrset_cast(s), ARRAY_SIZE((s)->ptrs))

#define tfw_ptrset_init_dyn(s, max_ptrs) \
 	__tfw_ptrset_init(__tfw_ptrset_cast(s), (max_ptrs))

#define tfw_ptrset_purge(s) \
	__tfw_ptrset_init(__tfw_ptrset_cast(s), __tfw_ptrset_max(s))

#define tfw_ptrset_add(s, ptr) \
	__tfw_ptrset_add(__tfw_ptrset_cast(s), \
			 __tfw_ptrset_checkptr(s, ptr), \
			 __tfw_ptrset_max(s))

#define tfw_ptrset_del(s, ptr) \
	__tfw_ptrset_del(__tfw_ptrset_cast(s), \
			 __tfw_ptrset_checkptr(s, ptr), \
			 __tfw_ptrset_max(s))

#define tfw_ptrset_test(s, ptr) \
	(0 < __tfw_ptrset_find_idx(__tfw_ptrset_case(s), \
				   __tfw_ptrset_checkptr(s, ptr), \
				   __tfw_ptrest_max(s)))

/**
 * Sanity/debug runtime checks.
 * The function is completely eliminated by the compiler when DEBUG is not
 * defined, so it gives no overhead.
 */
static inline void
__tfw_ptrset_validate(const TfwPtrSet *s, int max)
{
	IF_DEBUG {
		void *ptr1, *ptr2;
		int idx1, idx2;

		BUG_ON(!s);
		BUG_ON(max > 4096); /* Large value is likely garbage. */
		BUG_ON(max <= 0);   /* Can't be zero unlike TfwPtrSet->max. */
		BUG_ON(s->n < 0 || s->n > max);
		BUG_ON(s->max < 0 || s->max > 4096);

		tfw_ptrset_for_each(ptr1, idx1, s) {
			BUG_ON(!ptr1);
			tfw_ptrset_for_each(ptr2, idx2, s) {
				BUG_ON(ptr1 == ptr2 && idx1 != idx2);
			}
		}
	}
}

static inline int
__tfw_ptrset_find_idx(const TfwPtrSet *s, const void *ptr, int max)
{
	int i;

	__tfw_ptrset_validate(s, max);

	for (i = 0; i < max; ++i) {
		if (s->ptrs[i] == ptr)
			return i;
	}

	return -1;
}

static inline void
__tfw_ptrset_init(TfwPtrSet *s, int max)
{
	memset(s->ptrs, 0, tfw_ptrset_size(max));
	s->max = max;
	__tfw_ptrset_validate(s, max);
}

static inline int
__tfw_ptrset_add(TfwPtrSet *s, void *ptr, int max)
{
	if (__tfw_ptrset_find_idx(s, ptr, max) > 0) {
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
__tfw_ptrset_del(TfwPtrSet *s, const void *ptr, int max)
{
	int i;

	i = __tfw_ptrset_find_idx(s, ptr, max);
	if (i < 0) {
		TFW_ERR("Can't delete ptr %p from set %p - not found\n", ptr,
			s);
		return -1;
	}

	s->ptrs[i] = s->ptrs[s->n - 1];
	s->ptrs[s->n] = NULL;
	--s->n;

	return 0;
}

/**
 * Return pointers from the @s in the round-robin manner.
 *
 * On each call you get the next pointer in the set, and so on in cycle.
 *
 * The order of pointers is not guaranteed since tfw_ptrset_del() changes it.
 * Not very fair, but still good unless you delete elements often.
 *
 * No synchronization with add/delete/purge operations is needed (lock-free).
 *
 * Safe for use on multiple CPUs because of the atomic operations.
 * BUG: atomic_t contains signed int which is overflown.
 *      Perhaps we should use a regular unsigned int instead of atomic_t here?
 *      That fixes the bug, and also makes the code faster, but less fair.
 */
#define tfw_ptrset_get_rr(s) \
	__tfw_ptrset_get_rr(__tfw_ptrset_cast(s), __tfw_ptrset_max(s))

static inline void *
__tfw_ptrset_get_rr(TfwPtrSet *s, int max)
{
	unsigned int n, counter;
	void *ret;

	__tfw_ptrset_validate(s, max);

	do {
		n = s->n;
		if (unlikely(!n)) {
			TFW_ERR("Can't get pointer from the empty set: %p\n",
				s);
			return NULL;
		}

		counter = atomic_inc_return(&s->counter);
		ret = s->ptrs[counter % n];
	} while (unlikely(!ret));

	return ret;
}

#endif /* __TFW_PTRSET_H__ */
