/**
 *		Tempesta FW
 *
 * The TfwPtrSet is a generic set of pointers (implemented as plain array).
 *
 * The following operations are defined on the set:
 *  -
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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

#define TFW_PTRSET_STRUCT(ptr_type, static_max_ptrs) \
struct {					\
	atomic_t counter;			\
	short n;				\
	short max;				\
	ptr_type *ptrs[static_max_ptrs];	\
}

typedef TFW_PTRSET_STRUCT(void, 0) TfwPtrSet;

#define __tfw_ptrset_cast(s) 	\
({				\
	BUILD_BUG_ON(offsetof(typeof(*(s)), ptrs) != offsetof(TfwPtrSet, ptrs)); \
	((TfwPtrSet *)(s)); 	\
})

#define __tfw_ptrset_max(s) \
	(ARRAY_SIZE((s)->ptrs) ? ARRAY_SIZE((s)->ptrs) : (s)->max)

#define __tfw_ptrset_size(max) \
	(sizeof(TfwPtrSet) + ((max) * sizeof(void *)))

#define tfw_ptrset_for_each(ptr, i, s) \
	for ((i) = 0; ((i) < (s)->n && (ptr = (s)->ptrs[i])); ++(i))

#define tfw_ptrset_is_empty(s) (!(s)->n)

#define tfw_ptrset_add(s, ptr) \
	__tfw_ptrset_add(__tfw_ptrset_cast(s), ptr, __tfw_ptrset_max(s))

#define tfw_ptrset_del(s, ptr) \
	__tfw_ptrset_del(__tfw_ptrset_cast(s), ptr, __tfw_ptrset_max(s))

#define tfw_ptrset_purge(s) \
	__tfw_ptrset_init(__tfw_ptrset_cast(s), __tfw_ptrset_max(s))

#define tfw_ptrset_get_rr(s) \
	__tfw_ptrset_get_rr(__tfw_ptrset_cast(s), __tfw_ptrset_max(s))


static inline void
__tfw_ptrset_validate(const TfwPtrSet *s, int max)
{
	IF_DEBUG {
		void *ptr1, *ptr2;
		int idx1, idx2;

		BUG_ON(!s);
		BUG_ON(max <= 0);
		BUG_ON(s->n < 0 || s->n > max);

		tfw_ptrset_for_each(ptr1, idx1, s) {
			BUG_ON(!ptr1);
			tfw_ptrset_for_each(ptr2, idx2, s) {
				BUG_ON(ptr1 == ptr2 && idx1 != idx2);
			}
		}
	}
}

static inline void
__tfw_ptrset_init(TfwPtrSet *s, int max)
{
	memset(s->ptrs, 0, __tfw_ptrset_size(max));
	s->max = max;
	__tfw_ptrset_validate(s, max);
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

static inline int
__tfw_ptrset_add(TfwPtrSet *s, void *ptr, int max)
{
	BUG_ON(!ptr);

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

	BUG_ON(!ptr);

	i = __tfw_ptrset_find_idx(s, ptr, max);

	if (i < 0) {
		TFW_ERR("Can't delete ptr %p from set %p - not found\n", ptr, s);
		return -1;
	}

	s->ptrs[i] = s->ptrs[s->n - 1];
	s->ptrs[s->n] = NULL;
	--s->n;

	return 0;
}

static inline void *
__tfw_ptrset_get_rr(TfwPtrSet *s, int max)
{
	unsigned int n, counter;
	void *ret;

	__tfw_ptrset_validate(s, max);

	do {
		n = s->n;
		if (unlikely(!n)) {
			TFW_ERR("Can't get pointer from the empty set: %p\n", s);
			return NULL;
		}

		counter = atomic_inc_return(&s->counter);
		ret = s->ptrs[counter % n];
	} while (unlikely(!ret));

	return ret;
}





#endif /* __TFW_PTRSET_H__ */
