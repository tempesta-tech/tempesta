/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
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

#include "lib/128bit.h"
#include "test.h"

TEST(128bit, div)
{
	u128 v;

	/* exact division */
	v = 100;
	EXPECT_EQ(u128_div_u32(v, 10), 10);

	v = (u128)U64_MAX;
	EXPECT_EQ(u128_div_u32(v, 2), U64_MAX / 2);

	v = ((u128)(1) << 80);
	EXPECT_EQ(u128_div_u32(v, 16), ((u128)(1) << 76));

	v = 15555555555555532;
	EXPECT_EQ(u128_div_u32(v, 10), 1555555555555553);
}

TEST(128bit, sqrt)
{
	u128 v;

	/* 0 */
	v = 0;
	EXPECT_EQ(u128_sqrt(v), 0);

	/* 1 */
	v = 1;
	EXPECT_EQ(u128_sqrt(v), 1);

	/* 2..3 -> 1 */
	v = 3;
	EXPECT_EQ(u128_sqrt(v), 1);

	/* 4 -> 2 */
	v = 4;
	EXPECT_EQ(u128_sqrt(v), 2);

	/* 111 -> 10 */
	v = 111;
	EXPECT_EQ(u128_sqrt(v), 10);

	/* U64_MAX */
	v = U64_MAX;
	EXPECT_EQ(u128_sqrt(v), U32_MAX);

	v = (u128)(~0);
	EXPECT_EQ(u128_sqrt(v), U64_MAX);
}

TEST_SUITE(128bit)
{
	TEST_RUN(128bit, div);
	TEST_RUN(128bit, sqrt);
}
