/**
 *		Tempesta FW
 *
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/skbuff.h>

#include "lib/str.h"
#include "test.h"

static unsigned char a[512], b[512];

static void
run_tests_set(void (*test_fn)(size_t off, size_t n))
{
	test_fn(0, 0);
	test_fn(0, 1);
	test_fn(1, 0);
	test_fn(1, 1);
	test_fn(1, 2);
	test_fn(2, 2);
	test_fn(0, 2);
	test_fn(3, 3);
	test_fn(3, 4);
	test_fn(1, 4);
	test_fn(3, 5);
	test_fn(1, 5);
	test_fn(3, 7);
	test_fn(1, 7);
	test_fn(1, 8);
	test_fn(0, 8);
	test_fn(3, 8);
	test_fn(0, 9);
	test_fn(3, 11);
	test_fn(2, 13);
	test_fn(0, 16);
	test_fn(2, 16);
	test_fn(3, 17);
	test_fn(7, 19);
	test_fn(16, 30);
	test_fn(0, 32);
	test_fn(1, 32);
	test_fn(11, 32);
	test_fn(16, 32);
	test_fn(8, 37);
	test_fn(16, 48);
	test_fn(29, 49);
	test_fn(17, 50);
	test_fn(1, 63);
	test_fn(0, 64);
	test_fn(4, 64);
	test_fn(47, 64);
	test_fn(41, 65);
	test_fn(50, 79);
	test_fn(7, 100);
	test_fn(29, 127);
	test_fn(7, 128);
	test_fn(8, 250);
	test_fn(11, 383);
}

static void
__memcpy_test(size_t off, size_t n)
{
	unsigned int i;

	memset((void *)a, 0, sizeof(a));
	for (i = 0; i < sizeof(b); ++i)
		b[i] = (i & 0xff) ? : 0xa;

	memcpy_fast((void *)&a[off], (void *)&b[off], n);

	for (i = 0; i < sizeof(a); ++i)
		EXPECT_FALSE((i >= off && i < off + n
			      && a[i] != ((i & 0xff) ? : 0xa))
			     || ((i < off || i >= off + n) && a[i]));
}

static void
__memcmp_test(size_t off, size_t n)
{
	int i, r0, r1;

	for (i = 0; i < sizeof(a); ++i) {
		a[i] = (i & 0xff) ? : 0xa;
		b[i] = (i & 0xff) ? : 0xa;
	}

	/* Test for equal. */
	r0 = memcmp_fast((const void *)&a[off], (const void *)&b[off], n);
	r1 = !!memcmp((const void *)&a[off], (const void *)&b[off], n);
	EXPECT_EQ(r0, r1);

	/* Test for different data. */
	++a[off + n++];
	n += off ? : 1;
	r0 = memcmp_fast((const void *)&a[off], (const void *)&b[off], n);
	r1 = !!memcmp((const void *)&a[off], (const void *)&b[off], n);
	EXPECT_EQ(r0, r1);
}

static void
__bzero_test(size_t off, size_t n)
{
	unsigned int i;

	for (i = 0; i < sizeof(a); ++i)
		a[i] = (i & 0xff) ? : 0xa;

	bzero_fast((void *)&a[off], n);

	for (i = 0; i < sizeof(a); ++i)
		EXPECT_FALSE((i >= off && i < off + n && a[i])
			     || ((i < off || i >= off + n)
				 && a[i] != ((i & 0xff) ? : 0xa)));
}

TEST(memcpy, memcpy_fast)
{
	run_tests_set(__memcpy_test);
}

TEST(memcmp, memcmp_fast)
{
	run_tests_set(__memcmp_test);
}

TEST(memset, bzero_fast)
{
	run_tests_set(__bzero_test);
}

TEST_SUITE(mem_fast)
{
	TEST_RUN(memcpy, memcpy_fast);
	TEST_RUN(memcmp, memcmp_fast);
	TEST_RUN(memset, bzero_fast);
}
