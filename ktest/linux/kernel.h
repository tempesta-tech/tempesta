/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <stdio.h>

#include "compiler.h"

#ifndef ENOMEM /* if one is undefinded, then we're good */
#define ENOENT			2
#define ENOMEM			12
#define EINVAL			22
#define ENOSPC			28
#define EDOM			33
#endif

#define ARRAY_SIZE(x)   	(sizeof(x) / sizeof(*(x)))

#define pr_err(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)
#define net_warn_ratelimited(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define net_err_ratelimited(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)

/* asm/cache.h */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES 64
#endif

#define SMP_CACHE_BYTES L1_CACHE_BYTES
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define __aligned(a)	__attribute__((__aligned__(a)))
#define __page_aligned_data	__attribute__((__aligned__(4096)))
#define CRYPTO_MINALIGN_ATTR __attribute__ ((__aligned__(L1_CACHE_BYTES)))

#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

#define __min(t1, t2, min1, min2, x, y) ({		\
	t1 min1 = (x);					\
	t2 min2 = (y);					\
	(void) (&min1 == &min2);			\
	min1 < min2 ? min1 : min2; })

#define min(x, y)					\
	__min(typeof(x), typeof(y),			\
	      __UNIQUE_ID(min1_), __UNIQUE_ID(min2_),	\
	      x, y)

#define __max(t1, t2, max1, max2, x, y) ({		\
	t1 max1 = (x);					\
	t2 max2 = (y);					\
	(void) (&max1 == &max2);			\
	max1 > max2 ? max1 : max2; })

#define max(x, y)							\
	__max(typeof(x), typeof(y), (max1_), (max2_), x, y)

#define min_t(type, x, y)						\
	__min(type, type, (min1_), (min2_), x, y)

#define max_t(type, x, y)						\
	__max(type, type, (min1_), (min2_), x, y)


struct module { /* dummy strut */ };

#define __init

struct list_head {
	struct list_head *next, *prev;
};

/**
 * Constants instead of the real random bytes make the debugging simpler.
 * Don't use zero as cryptography may check for non-zero values.
 */
void
get_random_bytes_arch(void *buf, int nbytes)
{
	memset(buf, 0xAA, nbytes);
}

#endif /* __KERNEL_H__ */
