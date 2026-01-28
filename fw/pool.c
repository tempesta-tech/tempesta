/**
 *		Tempesta FW
 *
 * Stack-like region-based memory manager.
 *
 * Pools are used per message (e.g. HTTP request or response).
 * Since Tempesta handles a message only on one CPU, then the pool should not
 * bother about concurrency.
 *
 * The allocator is pure Tempesta specific which is perfect for current
 * workload (i.e. should be reviewed when new usage patterns appear):
 * 1. the typical allocation sequence is:
 *    (a) HTTP message is allocated on the same page as the pool itself;
 *    (b) TfwHttpHdrTbl follows the message descriptor;
 *    (c) many TfwStr's for each HTTP field;
 * 2. TfwHttpHdrTbl can be rarely reallocated - since it's followed by TfwStr
 *    allocations we always lose it's memory. The table grows exponentially
 *    minimizing number of reallocations and Frang controls number and size
 *    of the reallocations;
 * 3. TfwStr grows while we're reading it, so this is last allocation when we
 *    reallocate it - the operation is pretty fast for current allocation.
 *    Duplicate HTTP headers are likely introduces heavy reallocations like
 *    (2) with losing memory - they're also rare;
 * 4. sometimes we need temporal buffers to do something - the buffers should
 *    be immediately freed to keep stack-like memory management.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#include <linux/mm.h>
#include <linux/error-injection.h>

#include "lib/str.h"
#include "lib/fault_injection_alloc.h"
#include "fw/client.h"
#include "pool.h"

#define TFW_POOL_HEAD_OFF	(TFW_POOL_ALIGN_SZ(sizeof(TfwPool))	\
				 + TFW_POOL_ALIGN_SZ(sizeof(TfwPoolChunk)))
#define TFW_POOL_PGCACHE_SZ	512

static DEFINE_PER_CPU(unsigned int, pg_next);
static unsigned long __percpu (*pg_cache)[TFW_POOL_PGCACHE_SZ];

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
tfw_pool_alloc_pages(TfwClient *cli, unsigned int order)
{
	unsigned long pg_res = 0;
	unsigned int *pgn;
	gfp_t flags;

	local_bh_disable();

	pgn = this_cpu_ptr(&pg_next);

	if (likely(*pgn && !order)) {
		--*pgn;
		pg_res = ((unsigned long *)this_cpu_ptr(pg_cache))[*pgn];
	}
	local_bh_enable();

	if (!pg_res) {
		flags = order > 0 ? GFP_ATOMIC | __GFP_COMP : GFP_ATOMIC;
		pg_res = __get_free_pages(flags, order);
	}
	if (likely(pg_res) && cli)
		tfw_client_adjust_mem(cli, PAGE_SIZE << order);

	return pg_res;

}
ALLOW_ERROR_INJECTION(tfw_pool_alloc_pages, NULL);

static void
tfw_pool_free_pages(TfwClient *cli, unsigned long addr, unsigned int order)
{
	unsigned int *pgn;
	int refcnt;

	local_bh_disable();

	pgn = this_cpu_ptr(&pg_next);
	refcnt = page_count(virt_to_page(addr));

	if (cli)
		tfw_client_adjust_mem(cli, -(PAGE_SIZE << order));

	if (likely(*pgn < TFW_POOL_PGCACHE_SZ && !order && refcnt == 1)) {
		((unsigned long *)this_cpu_ptr(pg_cache))[*pgn] = addr;
		++*pgn;

		local_bh_enable();

		return;
	}
	local_bh_enable();

	put_page(compound_head(virt_to_page(addr)));
}

void *
__tfw_pool_alloc_page(TfwPool *p, size_t n, bool align)
{
	TfwPoolChunk *c, *curr = p->curr;
	unsigned int desc_size = align
		? TFW_POOL_ALIGN_SZ(sizeof(TfwPoolChunk))
		: sizeof(TfwPoolChunk);
	unsigned int off = desc_size + n;
	unsigned int order = get_order(off);

	c = (TfwPoolChunk *)tfw_pool_alloc_pages(p->owner, order);
	if (!c)
		return NULL;
	c->next = curr;
	c->order = order;

	curr->off = p->off;

	p->order = order;
	p->off = off;
	p->curr = c;

	return align
		? (void *)TFW_POOL_ALIGN_SZ((unsigned long)(c + 1))
		: (void *)(c + 1);
}

void *
__tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n, bool copy)
{
	void *a;

	BUG_ON(new_n < old_n);

	if ((char *)ptr + old_n == TFW_POOL_CHUNK_END(p)
	    && p->off - old_n + new_n <= TFW_POOL_CHUNK_SZ(p))
	{
		p->off += new_n - old_n;
		return ptr;
	}

	a = tfw_pool_alloc(p, new_n);
	if (copy && a)
		memcpy_fast(a, ptr, old_n);

	return a;
}

/**
 * It's good to call the function against just allocated chunk in stack-manner.
 * Consequent free calls can empty the whole pool but the first chunk with
 * the pool header.
 */
void
tfw_pool_free(TfwPool *p, void *ptr, size_t n)
{
	n = TFW_POOL_ALIGN_SZ(n);

	/* Stack-like usage is expected. */
	if (unlikely((char *)ptr + n != TFW_POOL_CHUNK_END(p)))
		return;

	p->off -= n;

	/* Free empty chunk which doesn't contain the pool header. */
	if (unlikely(p->off == TFW_POOL_ALIGN_SZ(sizeof(TfwPoolChunk)))) {
		TfwPoolChunk *next = p->curr->next;

		tfw_pool_free_pages(p->owner, TFW_POOL_CHUNK_BASE(p->curr),
				    p->order);
		p->curr = next;
		p->order = next->order;
		p->off = next->off;
	}
}

/**
 * Delete single chunk that holds @ptr.
 */
void
tfw_pool_clean_single(TfwPool *pool, void *ptr)
{
	TfwPoolChunk *c, *next, *prev = pool->curr;

	BUG_ON(!pool);
	BUG_ON(!ptr);

	for (c = pool->curr->next; c; c = next) {
		if (!(next = c->next))
			break;

		if ((char *)ptr >= (char *)TFW_POOL_CHUNK_BASE(c)
		    && (char *)ptr < (char *)TFW_POOL_CHUNK_BASE(c) + c->off)
		{
			tfw_pool_free_pages(pool->owner, TFW_POOL_CHUNK_BASE(c),
					    c->order);
			prev->next = next;
			return;
		}
		prev = c;
	}
}

/**
 * Delete all chunks between the first (i.e. current in use) and the last one
 * (which is the holder of @TfwPool itself). This is a garbage collection
 * procedure, which is applicable only for cases when pool is used for one
 * dynamically resizable (via @__tfw_pool_realloc()) instance.
 */
void
tfw_pool_clean(TfwPool *pool)
{
	TfwPoolChunk *c, *next;

	BUG_ON(!pool);

	for (c = pool->curr->next; c; c = next) {
		if (!(next = c->next))
			break;

		tfw_pool_free_pages(pool->owner, TFW_POOL_CHUNK_BASE(c),
				    c->order);
		pool->curr->next = next;
	}
}

/**
 * Allocate bit more pages than we need.
 */
TfwPool *
__tfw_pool_new(size_t n, void *owner)
{
	TfwClient *cli = (TfwClient *)owner;
	TfwPool *p;
	TfwPoolChunk *c;
	unsigned int order;

	order = get_order(TFW_POOL_ALIGN_SZ(n) + TFW_POOL_HEAD_OFF);

	c = (TfwPoolChunk *)tfw_pool_alloc_pages(cli, order);
	if (unlikely(!c))
		return NULL;

	if (cli)
		tfw_client_get(cli);

	p = (TfwPool *)((char *)c + TFW_POOL_ALIGN_SZ(sizeof(*c)));

	c->next = NULL;
	p->order = c->order = order;
	p->owner = owner;
	p->off = c->off = TFW_POOL_HEAD_OFF;
	p->curr = c;

	return p;
}

void
tfw_pool_destroy(TfwPool *p)
{
	TfwPoolChunk *c, *next;
	TfwClient *cli;

	if (!p)
		return;

	cli = p->owner;
	for (c = p->curr; c; c = next) {
		next = c->next;
		tfw_pool_free_pages(p->owner, TFW_POOL_CHUNK_BASE(c),
				    c->order);
	}
	if (cli)
		tfw_client_put(cli);
}

int
tfw_pool_init(void)
{
	pg_cache = tfw_alloc_percpu(unsigned long [TFW_POOL_PGCACHE_SZ]);
	if (pg_cache == NULL)
		return -ENOMEM;
	return 0;
}

void
tfw_pool_exit(void)
{
	int i;

	for_each_online_cpu(i) {
		unsigned int pgn = per_cpu(pg_next, i);
		unsigned long *pgc = (unsigned long *)per_cpu_ptr(pg_cache, i);
		while (pgn--)
			free_page(pgc[pgn]);
	}

	free_percpu(pg_cache);
}

