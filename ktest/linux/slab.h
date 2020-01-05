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
#ifndef __SLAB_H__
#define __SLAB_H__

#include <stdlib.h>
#include <string.h>

#include "atomic.h"
#include "compiler.h"
#include "kernel.h"
#include "percpu.h"
#include "spinlock.h"
#include "threads.h"

#define NUMA_NO_NODE	0

/* asm/page.h */
#define PAGE_SIZE	4096UL

typedef enum {
	GFP_KERNEL = 0,
	GFP_ATOMIC = 0,
	__GFP_ZERO = 1,
} gfp_t;

/* Tempesta FW specific API. */
#ifndef pg_skb_alloc
#define pg_skb_alloc(size, ...)		malloc(size)
#endif

static inline void *
kmalloc(size_t size, gfp_t gf_flags)
{
	void *p = malloc(size);
	if (p && (gf_flags & __GFP_ZERO))
		memset(p, 0, size);
	return p;
}

/**
 * Emulates buddy system allocating higher order page buddies by aligned
 * addresses.
 */
static inline unsigned long
__get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	void *ptr;
	size_t n = PAGE_SIZE << order;

	if (posix_memalign(&ptr, n, n))
		return 0;
	if (gfp_mask & __GFP_ZERO)
		memset(ptr, 0, n);

	return (unsigned long)ptr;
}

#define kzalloc(size, ...)		calloc(1, size)

#define kfree(p)			free(p)
#define free_pages(p, order)		free((void *)p)

#define get_order(n)	( ((n) < 4096) ? 0				\
			  : ((n) < 8192) ? 1				\
			    : ((n) < 16384) ? 2				\
			      : ((n) < 32768) ? 3			\
			        : ((n) < 65536) ? 4			\
				  : ((n) < 131072) ? 5			\
				    : ((n) < 262144) ? 6 : (abort(), 7) )

#endif /* __SLAB_H__ */
