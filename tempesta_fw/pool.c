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

#include "pool.h"

#define TFW_POOL_SIZE(p)	(PAGE_SIZE << (p)->order)

/**
 * Allocate bit more pages than we need.
 */
TfwPool *
__tfw_pool_new(size_t n)
{
	unsigned int order = (n + sizeof(TfwPool)) >> PAGE_SHIFT;
	TfwPool *p;

	p = (TfwPool *)__get_free_pages(GFP_ATOMIC, order);
	if (!p)
		return NULL;
	p->base = (unsigned char *)p;
	p->order = order;
	p->off = sizeof(*p);

	return p;
}
EXPORT_SYMBOL(__tfw_pool_new);

void *
tfw_pool_alloc(TfwPool *p, size_t n)
{
	void *a;

	/* TODO properly increase the pool size. */
	if (unlikely(p->off + n >= TFW_POOL_SIZE(p))) {
		TFW_ERR("%s: insufficient space in pool %p\n", __func__, p);
		return NULL;
	}

	a = p->base + p->off;
	p->off += n;

	return a;
}
EXPORT_SYMBOL(tfw_pool_alloc);

void *
tfw_pool_realloc(TfwPool *p, void *ptr, size_t old_n, size_t new_n)
{
	unsigned char *p_tmp = ptr;
	void *a;

	BUG_ON(new_n < old_n);

	if (p_tmp + old_n == p->base + p->off) {
		/*
		 * Quick path: there were no other allocations since previous
		 * alloc().
		 */
		if (unlikely(p->off + new_n - old_n >= TFW_POOL_SIZE(p))) {
			TFW_ERR("%s: insufficient space in pool %p\n", __func__, p);
			return NULL;
		}
		p->off += new_n - old_n;
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
	free_pages((unsigned long)p, p->order);
}
EXPORT_SYMBOL(tfw_pool_free);
