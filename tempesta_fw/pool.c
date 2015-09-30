/**
 *		Tempesta FW
 *
 * Memory pool.
 *
 * Pools are used per message (e.g. HTTP request or response).
 * Since Tempesta handles a message only on one CPU, then the pool should not
 * bother about concurrency.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include <linux/gfp.h>

#include "pool.h"

#define TFW_POOL_CHUNK_SZ(c)	(PAGE_SIZE << (c)->order)
#define TFW_POOL_CHUNK_BASE(c)	((unsigned long)(c) & PAGE_MASK)
#define TFW_POOL_CHUNK_END(c)	(TFW_POOL_CHUNK_BASE(c) + (c)->off)
#define TFW_POOL_ALIGN_SZ(n)	(((n) + 7) & ~7UL)
#define TFW_POOL_HEAD_OFF	(TFW_POOL_ALIGN_SZ(sizeof(TfwPool))	\
				 + TFW_POOL_ALIGN_SZ(sizeof(TfwPoolChunk)))
#define TFW_POOL_PGCACHE_SZ	512

static DEFINE_PER_CPU(unsigned int, pg_next);
static DEFINE_PER_CPU(unsigned long [TFW_POOL_PGCACHE_SZ], pg_cache);

/*
 * Per-CPU page cache.
 *
 * The buddy allocator does relatively heavy things, so the cache makes
 * memory allocations faster.
 *
 * It caches small number of pages and return free pages to buddy allocator,
 * which are out of the space.
 * Multi-page chunks can be coalesced with buddies, so that we'll be able to
 * satisfy large realloc (i.e. if the we called from realloc(), then it's
 * likely that the next request will be of doubled size and we typically grow
 * through buddies coalescing). So we never cache multi-pages.
 */
static unsigned long
tfw_pool_alloc_pages(unsigned int order)
{
	unsigned int *pgn;
	unsigned long pg_res;

	preempt_disable();

	pgn = this_cpu_ptr(&pg_next);

	if (likely(*pgn && !order)) {
		--*pgn;
		pg_res = this_cpu_read(pg_cache[*pgn]);

		preempt_enable();

		return pg_res;
	}
	preempt_enable();

	return __get_free_pages(GFP_ATOMIC, order);
}

static void
tfw_pool_free_pages(unsigned long addr, unsigned int order)
{
	unsigned int *pgn;

	preempt_disable();

	pgn = this_cpu_ptr(&pg_next);

	if (likely(*pgn < TFW_POOL_PGCACHE_SZ && !order)) {
		*this_cpu_ptr(&pg_cache[*pgn]) = addr;
		++*pgn;

		preempt_enable();

		return;
	}
	preempt_enable();

	free_pages(addr, order);
}

static inline TfwPoolChunk *
tfw_pool_chunk_first(TfwPool *p)
{
	return (TfwPoolChunk *)TFW_POOL_ALIGN_SZ((unsigned long)(p + 1));
}

void *
tfw_pool_alloc(TfwPool *p, size_t n)
{
	void *a;
	TfwPoolChunk *c = p->curr;

	n = TFW_POOL_ALIGN_SZ(n);

	if (unlikely(c->off + n > TFW_POOL_CHUNK_SZ(c))) {
		unsigned int off = TFW_POOL_ALIGN_SZ(sizeof(*c)) + n;
		unsigned int order = get_order(off);

		c = (TfwPoolChunk *)tfw_pool_alloc_pages(order);
		if (!c)
			return NULL;

		c->next = p->curr;
		c->order = order;
		c->off = off;
		p->curr = c;

		return (void *)TFW_POOL_ALIGN_SZ((unsigned long)(c + 1));
	}

	a = (char *)TFW_POOL_CHUNK_END(c);
	c->off += n;

	return a;
}
EXPORT_SYMBOL(tfw_pool_alloc);

void *
tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n)
{
	void *a;
	TfwPoolChunk *c = p->curr;

	BUG_ON(new_n < old_n);

	old_n = TFW_POOL_ALIGN_SZ(old_n);
	new_n = TFW_POOL_ALIGN_SZ(new_n);

	if ((char *)ptr + old_n == (char *)TFW_POOL_CHUNK_END(c)
	    && c->off + new_n <= TFW_POOL_CHUNK_SZ(c))
	{
		c->off += new_n - old_n;
		return ptr;
	}


	a = tfw_pool_alloc(p, new_n);
	if (likely(a))
		memcpy(a, ptr, old_n);

	return a;
}
EXPORT_SYMBOL(tfw_pool_realloc);

/**
 * It's good to call the function against just allocated chunk in stack-manner.
 * Consequent free calls can empty the whole pool but the first chunk with
 * the pool header.
 */
void
tfw_pool_free(TfwPool *p, void *ptr, size_t n)
{
	TfwPoolChunk *c = p->curr;

	n = TFW_POOL_ALIGN_SZ(n);
	/* Stack-like usage is expected. */
	if (likely((char *)ptr + n == (char *)TFW_POOL_CHUNK_END(c)))
		c->off -= n;

	/* Free empty chunk which doesn't contain the pool header. */
	if (unlikely(c != tfw_pool_chunk_first(p)
		     && c->off == TFW_POOL_ALIGN_SZ(sizeof(*c))))
	{
		p->curr = c->next;
		tfw_pool_free_pages(TFW_POOL_CHUNK_BASE(c), c->order);
	}
}
EXPORT_SYMBOL(tfw_pool_free);

/**
 * Allocate bit more pages than we need.
 */
TfwPool *
__tfw_pool_new(size_t n)
{
	TfwPool *p;
	TfwPoolChunk *c;
	unsigned int order;

	order = get_order(TFW_POOL_ALIGN_SZ(n) + TFW_POOL_HEAD_OFF);

	p = (TfwPool *)tfw_pool_alloc_pages(order);
	if (!p)
		return NULL;

	c = tfw_pool_chunk_first(p);
	c->next = NULL;
	c->order = order;
	c->off = TFW_POOL_ALIGN_SZ((char *)(c + 1) - (char *)p);

	p->curr = c;

	return p;
}
EXPORT_SYMBOL(__tfw_pool_new);

void
tfw_pool_destroy(TfwPool *p)
{
	TfwPoolChunk *c, *next, *first = tfw_pool_chunk_first(p);

	for (c = p->curr; c != first; c = next) {
		next = c->next;
		tfw_pool_free_pages(TFW_POOL_CHUNK_BASE(c), c->order);
	}
	tfw_pool_free_pages((unsigned long)p, first->order);
}
EXPORT_SYMBOL(tfw_pool_destroy);
