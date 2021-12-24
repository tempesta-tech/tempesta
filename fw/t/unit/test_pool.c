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
	void *a, *b, *c;

	p = __tfw_pool_new(1001);
	EXPECT_NOT_NULL(p);

	a = tfw_pool_alloc_not_align(p, 1);
	b = tfw_pool_alloc(p, 1);
	c = tfw_pool_alloc_not_align(p, 1);

	EXPECT_TRUE(b == a + 8); /* 'b' must be aligned */
	EXPECT_ZERO((unsigned long)b & 7);
	EXPECT_TRUE(c == b + 1); /* 'c' must be tightly packed */
}

TEST(pool, realloc)
{
	TfwPool *p;
	void *a, *b, *c;

	p = __tfw_pool_new(1001);
	EXPECT_NOT_NULL(p);

	a = tfw_pool_alloc_not_align(p, 1);
	b = tfw_pool_alloc_not_align(p, 7);
	c = tfw_pool_realloc(p, a, 1, 17);

	EXPECT_TRUE(c != a);
	EXPECT_TRUE(c >= b + 7);
}

TEST_SUITE(pool)
{
	TEST_RUN(pool, alignment);
	TEST_RUN(pool, realloc);
}
