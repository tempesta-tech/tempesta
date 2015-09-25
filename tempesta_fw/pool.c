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

#define TFW_POOL_CHUNK_SIZE(p)	(PAGE_SIZE << (p)->order)

/**
 * Allocate bit more pages than we need.
 */
TfwPool *
__tfw_pool_new(size_t n)
{
	TfwPool *p;
	TfwPoolChunk *chunk;
	unsigned int order = get_order(n + sizeof(*p) + sizeof(*chunk));

	p = (TfwPool *)__get_free_pages(GFP_ATOMIC, order);
	if (!p)
		return NULL;

	chunk = (TfwPoolChunk *)(p + 1);
	chunk->base = (unsigned char *)p;
	chunk->order = order;
	chunk->off = sizeof(*p) + sizeof(*chunk);
	chunk->next = NULL;
	p->head = chunk;

	return p;
}
EXPORT_SYMBOL(__tfw_pool_new);

TfwPoolChunk *
__tfw_find_chunk(TfwPool *p, void *ptr)
{
	unsigned char *tmp_ptr = ptr;
	TfwPoolChunk *chunk;

	chunk = p->head;
	while (chunk != NULL) {
		if (chunk->base <= tmp_ptr &&
		    tmp_ptr < chunk->base + TFW_POOL_CHUNK_SIZE(chunk)) {
			break;
		}
		chunk = chunk->next;
	}

	return chunk;
}

void *
tfw_pool_alloc(TfwPool *p, size_t n)
{
	void *a;
	TfwPoolChunk *chunk;

	chunk = p->head;
	if (unlikely(chunk->off + n >= TFW_POOL_CHUNK_SIZE(chunk))) {
		unsigned int order = get_order(n + sizeof(TfwPoolChunk));
		chunk = (TfwPoolChunk *)__get_free_pages(GFP_ATOMIC, order);
		if (!chunk)
			return NULL;

		chunk->base = (unsigned char *)chunk;
		chunk->order = order;
		chunk->off = sizeof(*chunk);
		chunk->next = p->head;
		p->head = chunk;
	}

	a = chunk->base + chunk->off;
	chunk->off += n;

	return a;
}
EXPORT_SYMBOL(tfw_pool_alloc);

void *
tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n)
{
	void *a;
	TfwPoolChunk *chunk;

	BUG_ON(new_n < old_n);

	chunk = __tfw_find_chunk(p, ptr);
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
tfw_pool_try_free(TfwPool *p, void *ptr, size_t n)
{
	TfwPoolChunk *chunk;

	chunk = __tfw_find_chunk(p, ptr);
	if (ptr + n == chunk->base + chunk->off) {
		chunk->off -= n;
	}
}
EXPORT_SYMBOL(tfw_pool_try_free);

void
tfw_pool_destroy(TfwPool *p)
{
	TfwPoolChunk *chunk, *next;

	chunk = p->head;
	while (chunk != NULL) {
		next = chunk->next;
		free_pages((unsigned long)chunk, chunk->order);
		chunk = next;
	}
}
EXPORT_SYMBOL(tfw_pool_destroy);
