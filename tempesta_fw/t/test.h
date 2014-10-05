/**
 *		Tempesta FW
 *
 * A basic set of macros for writing unit tests that run in the kernel space.
 *
 * This is a bit awkward approach for unit testing, but it allows to start
 * writing tests quickly with minimal effort (spent for mocking the kernel API).
 * Later on we may decide to move them into user-space. These macros try to
 * imitate the GoogleTest API. That should facilitate the future migration.
 *
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
#ifndef __TFW_TEST_H__
#define __TFW_TEST_H__

int run_all_tests(void);
void register_test_failure(void);

#define TEST(unit, assertion)  static void test__ ##unit ##__ ##assertion(void)
#define RUN_TEST(unit, assertion) test__ ##unit ##__ ##assertion()

#define TEST_SUITE(name) void test_suite__##name(void)
#define RUN_TEST_SUITE(name) \
do { \
	printk("RUN_SUITE(%s)\n", #name); \
	test_suite__##name(); \
} while (0)

#define __FAIL(...) 					\
do {							\
	printk("FAIL:\n");				\
	printk("  %s():%d\n  ", __func__, __LINE__); 	\
	printk(__VA_ARGS__);				\
	printk("\n");					\
	register_test_failure();			\
} while (0)

#define FAIL() __FAIL("FAIL()");

#define EXPECT_TRUE(cond) 		\
do { 					\
	bool _test_val = (cond); 	\
	if (_test_val)			\
		break;			\
	__FAIL("EXPECT_TRUE(%s) => %d", #cond, _test_val); \
} while (0)

#define EXPECT_FALSE(cond)		\
do {					\
	bool _test_val = (cond);	\
	if (!_test_val)			\
		break;			\
	__FAIL("EXPECT_FALSE(%s) => %d", #cond, _test_val); \
} while (0)

#define __EXPECT_CMP(name, expr1, expr2, cmp_expr)	\
do {							\
	unsigned long _val1 = (expr1);			\
	unsigned long _val2 = (expr2);			\
	if (cmp_expr)					\
		break;					\
	__FAIL("%s(%s, %s) => (%#lx, %#lx)",		\
	          name, #expr1, #expr2, _val1, _val2);	\
} while (0)


#define EXPECT_EQ(expr1, expr2) \
	__EXPECT_CMP("EXPECT_EQ", expr1, expr2, _val1 == _val2)

#define EXPECT_NE(expr1, expr2) \
	__EXPECT_CMP("EXPECT_NE", expr1, expr2, _val1 != _val2)

#define EXPECT_LT(expr1, expr2) \
	__EXPECT_CMP("EXPECT_LT", expr1, expr2, _val1 < _val2)

#define EXPECT_LE(expr1, expr2) \
	__EXPECT_CMP("EXPECT_LE", expr1, expr2, _val1 <= _val2)

#define EXPECT_GT(expr1, expr2) \
	__EXPECT_CMP("EXPECT_GT", expr1, expr2, _val1 > _val2)

#define EXPECT_GE(expr1, expr2) \
	__EXPECT_CMP("EXPECT_GE", expr1, expr2, _val1 >= val2)


#endif /* __TFW_TEST_H__ */
