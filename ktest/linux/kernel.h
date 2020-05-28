/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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

#include <linux/errno.h>
#include <stdio.h>

#include "bug.h"
#include "compiler.h"

#define ARRAY_SIZE(x)   	(sizeof(x) / sizeof(*(x)))

#define KERN_INFO		""
#define KERN_WARNING		""
#define KERN_ERR		""

#define printk			printf
#define pr_err(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)
#define net_warn_ratelimited(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#define net_err_ratelimited(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)

/* asm/cache.h */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES		64
#endif

#define SMP_CACHE_BYTES		L1_CACHE_BYTES
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define __aligned(a)	__attribute__((__aligned__(a)))
#define __page_aligned_data	__attribute__((__aligned__(4096)))
#define CRYPTO_MINALIGN_ATTR __attribute__ ((__aligned__(L1_CACHE_BYTES)))

#define offsetof(TYPE, MEMBER)	((size_t)&((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

#define __min(t1, t2, min1, min2, x, y) ({				\
	t1 min1 = (x);							\
	t2 min2 = (y);							\
	(void) (&min1 == &min2);					\
	min1 < min2 ? min1 : min2; })

#define min(x, y)							\
	__min(typeof(x), typeof(y),					\
	      __UNIQUE_ID(min1_), __UNIQUE_ID(min2_),			\
	      x, y)

#define __max(t1, t2, max1, max2, x, y) ({				\
	t1 max1 = (x);							\
	t2 max2 = (y);							\
	(void) (&max1 == &max2);					\
	max1 > max2 ? max1 : max2; })

#define max(x, y)							\
	__max(typeof(x), typeof(y), (max1_), (max2_), x, y)

#define min_t(type, x, y)						\
	__min(type, type, (min1_), (min2_), x, y)

#define max_t(type, x, y)						\
	__max(type, type, (min1_), (min2_), x, y)

struct module { /* dummy strut */ };

#define request_module(...)

#define __init

struct list_head {
	struct list_head *next, *prev;
};

static inline void
get_random_bytes_arch(void *buf, int nbytes)
{
#ifdef NO_RANDOM
	memset(buf, 0xAA, nbytes);
#else
	int failures = 0;
	unsigned long long *pl;

	while (nbytes > sizeof(long)) {
		pl = (unsigned long long *)((char *)buf + nbytes - sizeof(long));

		if (__builtin_ia32_rdrand64_step(pl)) {
			nbytes -= sizeof(long);
		} else {
			BUG_ON(failures++ > 10);
		}
	}
	if (nbytes) {
		unsigned long long l;
		for (failures = 0; !__builtin_ia32_rdrand64_step(&l); )
			BUG_ON(failures++ > 10);
		memcpy(buf, &l, nbytes);
	}
#endif
}

#define DUMP_PREFIX_OFFSET	0

static inline void
print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
	       int rowsize, int groupsize, const void *buf, size_t len,
	       bool ascii)
{
	int i;
	const unsigned char *c = (unsigned char *)buf;

	fflush(NULL);
	printf(prefix_str);

	for (i = 0; i < len; ++i) {
		if (i && !(i % 16))
			printf("\n%s", prefix_str);
		printf("%.2x ", c[i]);
	}
	printf("\n");

	fflush(NULL);
}

#define IRQ_STACK_SIZE		(PAGE_SIZE << 2)

static inline unsigned long
task_stack_page(void)
{
	unsigned long r;

	asm volatile("movq %%rsp, %0\n": "=r"(r) ::);

	return r;
}

#define might_sleep()
#define current
#define irq_stack_ptr		task_stack_page()

#define EXPORT_SYMBOL(...)

#endif /* __KERNEL_H__ */
