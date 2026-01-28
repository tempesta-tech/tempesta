/**
 *		Tempesta FW
 *
 * Memory pool.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, Inc.
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
#ifndef __TFW_POOL_H__
#define __TFW_POOL_H__

#include <linux/cache.h>
#include <asm/page.h>
#include "log.h"

#define TFW_POOL_ZERO	0x1

#define TFW_POOL_CHUNK_SZ(p)	(PAGE_SIZE << (p)->order)
#define TFW_POOL_CHUNK_BASE(c)	((unsigned long)(c) & PAGE_MASK)
#define TFW_POOL_CHUNK_END(p)	((void *)TFW_POOL_CHUNK_BASE((p)->curr) + (p)->off)
#define TFW_POOL_CHUNK_ROOM(p)	(TFW_POOL_CHUNK_SZ((p)) - (p)->off)
#define TFW_POOL_ALIGN_SZ(n)	(((n) + 7) & ~7UL)
#define TFW_POOL_ALIGN_PTR(p)	((void *)TFW_POOL_ALIGN_SZ((unsigned long)p))

/**
 * Memory pool chunk descriptor.
 *
 * @next	- pointer to next memory chunk;
 * @order	- order of number of pages in the chunk;
 * @off		- current chunk offset;
 */
typedef struct tfw_pool_chunk_t {
	struct tfw_pool_chunk_t	*next;
	unsigned int		order;
	unsigned int		off;
} TfwPoolChunk;

/**
 * Memory pool descriptor.
 *
 * @curr	- current chunk to allocate memory from;
 * @owner	- owner for memory accounting;
 * @order,@off	- cached members of @curr;
 */
typedef struct {
	TfwPoolChunk	*curr;
	void		*owner;
	unsigned int	order;
	unsigned int	off;
} TfwPool;

#define tfw_pool_new(struct_name, owner, mask)				\
({									\
 	struct_name *s = NULL;						\
	TfwPool *p = __tfw_pool_new(sizeof(struct_name), owner);	\
	if (likely(p)) {						\
 		s = tfw_pool_alloc(p, sizeof(struct_name));		\
 		BUG_ON(!s);						\
		if (mask & TFW_POOL_ZERO)				\
			memset(s, 0, sizeof(struct_name));		\
 		s->pool = p;						\
 	} else {							\
		T_ERR("Can't alloc new " #struct_name);			\
 	}								\
 	s;								\
 })

int tfw_pool_init(void);
void tfw_pool_exit(void);
TfwPool *__tfw_pool_new(size_t n, void *owner);
void *__tfw_pool_alloc_page(TfwPool *p, size_t n, bool align);
void tfw_pool_free(TfwPool *p, void *ptr, size_t n);
void tfw_pool_clean(TfwPool *p);
void tfw_pool_clean_single(TfwPool *p, void *ptr);
void tfw_pool_destroy(TfwPool *p);
void *__tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n,
			 bool copy);

static inline void *
tfw_pool_alloc_np(TfwPool *p, size_t n, bool *np)
{
	void *a;
	unsigned int off;

	off = TFW_POOL_ALIGN_SZ(p->off) + n;

	if (unlikely(off > TFW_POOL_CHUNK_SZ(p))) {
		*np = true;
		return __tfw_pool_alloc_page(p, n, /* align */ true);
	}

	*np = false;
	a = TFW_POOL_ALIGN_PTR(TFW_POOL_CHUNK_END(p));
	p->off = off;

	return a;
}

static inline void *
tfw_pool_alloc(TfwPool *p, size_t n)
{
	bool dummy;

	return tfw_pool_alloc_np(p, n, &dummy);
}

static inline void *
tfw_pool_alloc_not_align_np(TfwPool *p, size_t n, bool *np)
{
	void *a;

	if (unlikely(p->off + n > TFW_POOL_CHUNK_SZ(p))) {
		*np = true;
		return __tfw_pool_alloc_page(p, n, /* align */ false);
	}

	*np = false;
	a = TFW_POOL_CHUNK_END(p);
	p->off += n;

	return a;
}

static inline void *
tfw_pool_alloc_not_align(TfwPool *p, size_t n)
{
	bool dummy;

	return tfw_pool_alloc_not_align_np(p, n, &dummy);
}

static inline void *
tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n)
{
	return __tfw_pool_realloc(p, ptr, old_n, new_n, true);
}

static inline void *
tfw_pool_realloc_no_copy(TfwPool *p, void *ptr, size_t old_n, size_t new_n)
{
	return __tfw_pool_realloc(p, ptr, old_n, new_n, false);
}

#endif /* __TFW_POOL_H__ */
