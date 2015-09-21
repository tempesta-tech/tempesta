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
#include <linux/list.h>

#include "pool.h"

#define TFW_POOL_CHUNK_SIZE(p)	(PAGE_SIZE << (p)->order)

/**
 * Allocate bit more pages than we need.
 */
TfwPool *
__tfw_pool_new(size_t n)
{
	unsigned int order = (n + sizeof(TfwPool) + sizeof(TfwPoolChunk)) >> PAGE_SHIFT;
	TfwPool *p;
	TfwPoolChunk *chunk;

	p = (TfwPool *)__get_free_pages(GFP_ATOMIC, order);
	if (!p)
		return NULL;

	INIT_LIST_HEAD(&p->chunks);

	chunk = (TfwPoolChunk *)(p + 1);
	chunk->base = (unsigned char *)p;
	chunk->order = order;
	chunk->off = sizeof(*p) + sizeof(*chunk);
	INIT_LIST_HEAD(&chunk->list);
	list_add(&chunk->list, &p->chunks);

	return p;
}
EXPORT_SYMBOL(__tfw_pool_new);

void *
tfw_pool_alloc(TfwPool *p, size_t n)
{
	void *a;
	TfwPoolChunk *chunk;

	chunk = list_entry(p->chunks.next, TfwPoolChunk, list);

	/* TODO properly increase the pool size. */
	if (unlikely(chunk->off + n >= TFW_POOL_CHUNK_SIZE(chunk))) {
		unsigned int order = (n + sizeof(TfwPoolChunk)) >> PAGE_SHIFT;
		chunk = (TfwPoolChunk *)__get_free_pages(GFP_ATOMIC, order);
		if (!chunk)
			return NULL;

		chunk->base = (unsigned char *)chunk;
		chunk->order = order;
		chunk->off = sizeof(*chunk);
		INIT_LIST_HEAD(&chunk->list);
		list_add(&chunk->list, &p->chunks);
	}

	a = chunk->base + chunk->off;
	chunk->off += n;

	return a;
}
EXPORT_SYMBOL(tfw_pool_alloc);

void *
tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n)
{
	unsigned char *tmp_ptr = ptr;
	void *a;
	TfwPoolChunk *chunk;

	list_for_each_entry(chunk, &p->chunks, list) {
		if (chunk->base <= tmp_ptr &&
		    tmp_ptr < chunk->base + TFW_POOL_CHUNK_SIZE(chunk)) {
			break;
		}
	}

	BUG_ON(new_n < old_n);

	if (ptr + old_n == chunk->base + chunk->off &&
	    chunk->off + new_n - old_n < TFW_POOL_CHUNK_SIZE(chunk)) {
		chunk->off += new_n - old_n;
		return ptr;
	}

	a = tfw_pool_alloc(p, new_n);
	if (likely(a))
		memcpy(a, ptr, old_n);

	return a;
}
EXPORT_SYMBOL(tfw_pool_realloc);

void
tfw_pool_free(TfwPool *p)
{
	TfwPoolChunk *chunk;

	list_for_each_entry(chunk, &p->chunks, list) {
		free_pages((unsigned long)chunk, chunk->order);
	}
}
EXPORT_SYMBOL(tfw_pool_free);
