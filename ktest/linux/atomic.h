/**
 *	Tempesta kernel emulation unit testing framework.
 *
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
#ifndef __ATOMIC_H__
#define __ATOMIC_H__

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	long counter;
} atomic64_t;

#define atomic64_set(v, i)	((v)->counter = (i))
#define atomic64_read(v)	(*(volatile long *)&(v)->counter)

static inline int
atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return __atomic_compare_exchange_n(&v->counter, &old, new, false,
					   __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static inline int
atomic64_cmpxchg(atomic64_t *v, long old, long new)
{
	return __atomic_compare_exchange_n(&v->counter, &old, new, false,
					   __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static inline void
atomic64_add(long i, atomic64_t *v)
{
	__atomic_fetch_add(&v->counter, i, __ATOMIC_SEQ_CST);
}

#endif /* __ATOMIC_H__ */
