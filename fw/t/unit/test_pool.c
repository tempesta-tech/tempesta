/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2021 Tempesta Technologies, Inc.
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

	/* this should give us a single page minus the 32 byte pool headers */
	p = __tfw_pool_new(1001);
	EXPECT_NOT_NULL(p);
	EXPECT_TRUE(TFW_POOL_CHUNK_SZ(p) == PAGE_SIZE);

	a = tfw_pool_alloc_not_align(p, 1);
	b = tfw_pool_alloc(p, 1);
	c = tfw_pool_alloc_not_align(p, 1);

	EXPECT_TRUE(b == a + 8); /* 'b' must be aligned */
	EXPECT_ZERO((unsigned long)b & 7);
	EXPECT_TRUE(c == b + 1); /* 'c' must be tightly packed */

	/* 'd' should still fit into the same page */
	d = tfw_pool_alloc_not_align_np(p, PAGE_SIZE - (32 + 10), &np);
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

	p = __tfw_pool_new(1001);
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
	d = tfw_pool_realloc(p, c, PAGE_SIZE - 300, PAGE_SIZE - 40);
	EXPECT_TRUE(d == c);

	/* the pool chunk must be exhausted now */
	d = tfw_pool_realloc(p, c, PAGE_SIZE - 40, PAGE_SIZE - 39);
	EXPECT_TRUE(d != c);
}

TEST_SUITE(pool)
{
	TEST_RUN(pool, alignment);
	TEST_RUN(pool, realloc);
}
