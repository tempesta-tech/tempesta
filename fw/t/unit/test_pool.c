/**
 *		Tempesta FW
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

#include "test.h"
#include "pool.h"

TEST(pool, alignment)
{
	TfwPool *p;
	void *a, *b, *c, *d;
	bool np;

	/* this should give us a single page minus the 40 byte pool headers */
	p = __tfw_pool_new(1001, NULL);
	EXPECT_NOT_NULL(p);
	EXPECT_TRUE(TFW_POOL_CHUNK_SZ(p) == PAGE_SIZE);

	a = tfw_pool_alloc_not_align(p, 1);
	b = tfw_pool_alloc(p, 1);
	c = tfw_pool_alloc_not_align(p, 1);

	EXPECT_TRUE(b == a + 8); /* 'b' must be aligned */
	EXPECT_ZERO((unsigned long)b & 7);
	EXPECT_TRUE(c == b + 1); /* 'c' must be tightly packed */

	/* 'd' should still fit into the same page */
	d = tfw_pool_alloc_not_align_np(p, PAGE_SIZE - (40 + 10), &np);
	EXPECT_TRUE(d == c + 1);
	EXPECT_FALSE(np);

	/* ... but the following doesn't fit anymore */
	d = tfw_pool_alloc_not_align_np(p, 1, &np);
	EXPECT_NOT_NULL(d);
	EXPECT_TRUE(np);
}

TEST(pool, realloc)
{
	TfwPool *p;
	void *a, *b, *c, *d;

	p = __tfw_pool_new(1001, NULL);
	EXPECT_NOT_NULL(p);
	EXPECT_TRUE(TFW_POOL_CHUNK_SZ(p) == PAGE_SIZE);

	a = tfw_pool_alloc_not_align(p, 1);
	b = tfw_pool_alloc_not_align(p, 7);
	c = tfw_pool_realloc(p, a, 1, 17);

	EXPECT_TRUE(c != a);
	EXPECT_TRUE(c == b + 7);

	/* allocate more memory */
	d = tfw_pool_realloc(p, c, 17, PAGE_SIZE - 300);
	EXPECT_TRUE(d == c);

	/* allocate enough memory to use the entire chunk */
	d = tfw_pool_realloc(p, c, PAGE_SIZE - 300, PAGE_SIZE - 48);
	EXPECT_TRUE(d == c);

	/* the pool chunk must be exhausted now */
	d = tfw_pool_realloc(p, c, PAGE_SIZE - 48, PAGE_SIZE - 47);
	EXPECT_TRUE(d != c);
}

TEST(pool, clean_single)
{
	TfwPool *p;
	void *root, *curr, *first_ptr, *last_ptr;
	struct tfw_pool_chunk_t	*head, *tail;

	p = __tfw_pool_new(1001, NULL);
	EXPECT_NOT_NULL(p);
	EXPECT_TRUE(TFW_POOL_CHUNK_SZ(p) == PAGE_SIZE);

	/* Save chunk that holds Pool's descriptor. */
	root = tfw_pool_alloc_not_align(p, 10);
	tail = p->curr;
	EXPECT_NULL(p->curr->next);

	/* Alloc new chunk */
	tfw_pool_alloc_not_align(p, PAGE_SIZE * 4);
	/* Get first address in the current chunk */
	first_ptr = (void*)TFW_POOL_CHUNK_BASE(p->curr);
	EXPECT_NOT_NULL(p->curr->next);

	/* Alloc new chunk */
	tfw_pool_alloc_not_align(p, PAGE_SIZE * 4);
	/* Get last address in the current chunk */
	last_ptr = (void*)(TFW_POOL_CHUNK_BASE(p->curr) + p->off - 1);
	EXPECT_NOT_NULL(p->curr->next->next);

	/*
	 * Alloc new chunk. This chunk must never deleted, this is head of the
	 * pool.
	 */
	curr = tfw_pool_alloc_not_align(p, PAGE_SIZE * 4);
	head = p->curr;
	EXPECT_NOT_NULL(p->curr->next->next->next);

	/* Delete chunk by first adress. */
	tfw_pool_clean_single(p, first_ptr);
	EXPECT_NULL(p->curr->next->next->next);
	EXPECT_NOT_NULL(p->curr->next->next);

	/* Delete chunk by last adress. */
	tfw_pool_clean_single(p, last_ptr);
	EXPECT_NULL(p->curr->next->next);
	EXPECT_NOT_NULL(p->curr->next);

	/* Now we have two chunks: head and tail. Try to delete both of them. */
	tfw_pool_clean_single(p, root);
	/* Must not delete root of the pool. */
	EXPECT_NOT_NULL(p->curr->next);

	/* Try delete current chunk. */
	tfw_pool_clean_single(p, curr);
	/* Must not delete current chunk of the pool. */
	EXPECT_NOT_NULL(p->curr->next);

	/* Check that head and tail chunks are valid. */
	EXPECT_EQ(head, p->curr);
	EXPECT_EQ(tail, p->curr->next);
}

TEST(pool, clean)
{
	TfwPool *p;
	struct tfw_pool_chunk_t	*head, *tail;

	p = __tfw_pool_new(1001, NULL);
	EXPECT_NOT_NULL(p);
	EXPECT_TRUE(TFW_POOL_CHUNK_SZ(p) == PAGE_SIZE);

	/* Chunk that holds Pool's descriptor. */
	tfw_pool_alloc_not_align(p, 10);
	tail = p->curr;
	EXPECT_NULL(p->curr->next);

	/* Alloc new chunk */
	tfw_pool_alloc_not_align(p, PAGE_SIZE * 4);
	EXPECT_NOT_NULL(p->curr->next);

	/* Alloc new chunk */
	tfw_pool_alloc_not_align(p, PAGE_SIZE * 4);
	EXPECT_NOT_NULL(p->curr->next->next);

	/*
	 * Alloc new chunk. This chunk must never deleted, this is head of the
	 * pool.
	 */
	tfw_pool_alloc_not_align(p, PAGE_SIZE * 4);
	head = p->curr;
	EXPECT_NOT_NULL(p->curr->next->next->next);

	/* Delete all chunks except head and tail. */
	tfw_pool_clean(p);

	/* Check that head and tail chunks are valid. */
	EXPECT_EQ(head, p->curr);
	EXPECT_EQ(tail, p->curr->next);
	/* Only head and tail must exist. */
	EXPECT_NULL(p->curr->next->next);

}

TEST_SUITE(pool)
{
	TEST_RUN(pool, alignment);
	TEST_RUN(pool, realloc);
	TEST_RUN(pool, clean_single);
	TEST_RUN(pool, clean);
}
