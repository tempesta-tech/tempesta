/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/bug.h>
#include <linux/kernel.h>

#include "str.h"
#include "test.h"
#include "tfw_str_helper.h"

TEST(tfw_strcpy, zero_src)
{
	TfwStr s1 = {
		.len = 0,
		.ptr = NULL
	};
	TfwStr s2 = {
		.len = 3,
		.ptr = "abc"
	};

	/* @dest->ptr is static memory, but must not crash. */
	EXPECT_ZERO(tfw_strcpy(&s2, &s1));
	EXPECT_ZERO(s2.len);
}

TEST(tfw_strcpy, zero_dst)
{
	TfwStr s1 = {
		.len = 0,
		.ptr = NULL
	};
	TfwStr s2 = {
		.len = 3,
		.ptr = "abc"
	};

	/* @dest->ptr is static memory, but must not crash. */
	EXPECT_ZERO(!tfw_strcpy(&s1, &s2));
}

TEST(tfw_strcpy, both_plain)
{
	char buf1[4] = { 0 }, buf2[4] = "abc";
	TfwStr s1 = {
		.len = 4,
		.ptr = buf1
	};
	TfwStr s2 = {
		.len = 4,
		.ptr = buf2
	};

	EXPECT_ZERO(tfw_strcpy(&s1, &s2));
	EXPECT_STR_EQ(s1.ptr, "abc");
}

TEST(tfw_strcpy, src_compound)
{
	char buf1[32] = { 0 };
	TfwStr s1 = {
		.len = 32,
		.ptr = buf1
	};
	TFW_STR(s2, "abcdefghijklmnop");

	EXPECT_ZERO(tfw_strcpy(&s1, s2));
	EXPECT_STR_EQ(s1.ptr, "abcdefghijklmnop");
}

TEST(tfw_strcpy, dst_compound)
{
	char buf[32] = { [0 ... 30] = 'a', 0 };
	TfwStr s2 = {
		.len = sizeof("abcdefghijklmnop") - 1,
		.ptr = "abcdefghijklmnop"
	};
	TFW_STR(s1, buf);

	EXPECT_ZERO(tfw_strcpy(s1, &s2));
	EXPECT_TRUE(tfw_str_eq_cstr(s1, "abcdefghijklmnop",
				    sizeof("abcdefghijklmnop") - 1, 0));
}

TEST(tfw_strcpy, both_compound)
{
	char buf[32] = { [0 ... 30] = 'a', 0 };
	TFW_STR(s1, buf);
	TfwStr s2 = {
		.ptr = (TfwStr []){
			{ .ptr = "ab",	.len = 2 },
			{ .ptr = "cde",	.len = 3 },
			{ .ptr = "f",	.len = 1 },
			{ .ptr = "g",	.len = 1 },
			{ .ptr = "h",	.len = 1 },
			{ .ptr = "ijklmno", .len = 7 },
			{ .ptr = "p", .len = 1 }
		},
		.len = sizeof("abcdefghijklmnop") - 1,
		.flags = 7 << TFW_STR_CN_SHIFT
	};

	EXPECT_ZERO(tfw_strcpy(s1, &s2));
	EXPECT_TRUE(tfw_str_eq_cstr(s1, "abcdefghijklmnop",
				    sizeof("abcdefghijklmnop") - 1, 0));
}

TEST(tfw_strcat, plain)
{
	int chunks;
	TFW_STR(s1, "abcdefghijklmnop");
	TfwStr s2 = {
		.len = sizeof("0123456789") - 1,
		.ptr = "0123456789"
	};

	chunks = TFW_STR_CHUNKN(s1);

	EXPECT_ZERO(tfw_strcat(str_pool, s1, &s2));
	EXPECT_TRUE(TFW_STR_CHUNKN(s1) == chunks + 1);
	EXPECT_TRUE(tfw_str_eq_cstr(s1, "abcdefghijklmnop0123456789",
				    sizeof("abcdefghijklmnop0123456789") - 1,
				    0));
}

TEST(tfw_strcat, compound)
{
	int chunks1, chunks2;
	TFW_STR(s1, "abcdefghijklmnop");
	TFW_STR(s2, "0123456789");

	chunks1 = TFW_STR_CHUNKN(s1);
	chunks2 = TFW_STR_CHUNKN(s2);

	EXPECT_ZERO(tfw_strcat(str_pool, s1, s2));
	EXPECT_TRUE(TFW_STR_CHUNKN(s1) == chunks1 + chunks2);
	EXPECT_TRUE(tfw_str_eq_cstr(s1, "abcdefghijklmnop0123456789",
				    sizeof("abcdefghijklmnop0123456789") - 1,
				    0));
}

TEST(tfw_stricmpspn, returns_true_only_for_equal_tfw_strs)
{
	TFW_STR(s1, "abcdefghijklmnopqrst");
	TFW_STR(s2, "ABcDefGHIJKLmnopqrst");
	TFW_STR(s3, "abcdefghi");
	TFW_STR(s4, "abcdefghijklmnopqrst_the_tail");

	EXPECT_TRUE(tfw_stricmpspn(s1, s2, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(s1, s3, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(s1, s3, 'f') == 0);
	EXPECT_FALSE(tfw_stricmpspn(s1, s4, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(s1, s4, 't') == 0);
}

TEST(tfw_stricmpspn, handles_plain_and_compound_strs)
{
	TfwStr s1 = {
		.len	= sizeof("abcdefghijklmnopqrst") - 1,
		.ptr	= "abcdefghijklmnopqrst"
	};
	TFW_STR(s2, "abcdefghijklmnopqrst");
	TFW_STR(s3, "abcdefghi");
	TFW_STR(s4, "abcdefghijklmnopqrst_the_tail");

	EXPECT_TRUE(tfw_stricmpspn(&s1, s2, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, s3, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(&s1, s3, 'f') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, s3, 'z') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, s4, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(&s1, s4, 't') == 0);
}

TEST(tfw_stricmpspn, handles_empty_strs)
{
	TfwStr s1 = {
		.len	= 0,
		.ptr	= "garbage"
	};
	TfwStr s2 = {
		.len	= 0,
		.ptr	= "trash"
	};
	TFW_STR(s3, "abcdefghijklmnopqrst");

	EXPECT_TRUE(tfw_stricmpspn(&s1, &s2, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s2, 'a') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, s3, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, s3, 'a') == 0);
}

TEST(tfw_stricmpspn, handles_different_size_strs)
{
	TfwStr s1 = {
		.ptr = (TfwStr []){
			{ .ptr = "ab", .len = sizeof("ab") - 1 },
			{ .ptr = "cdefghijklmnopqrst",
			  .len = sizeof("cdefghijklmnopqrst") - 1 }
		},
		.len = sizeof("abcdefghijklmnopqrst") - 1,
		.flags = 2 << TFW_STR_CN_SHIFT
	};
	TfwStr s2 = {
		.ptr = (TfwStr []){
			{ .ptr = "abcdefg", .len = sizeof("abcdefg") - 1 },
			{ .ptr = "hi", .len = sizeof("hi") - 1 },
			{ .ptr = "jklmnopqrst",
			  .len = sizeof("jklmnopqrst") - 1 }
		},
		.len = sizeof("abcdefghijklmnopqrst") - 1,
		.flags = 3 << TFW_STR_CN_SHIFT
	};

	EXPECT_ZERO(tfw_stricmpspn(&s1, &s2, 0));
	EXPECT_ZERO(tfw_stricmpspn(&s1, &s2, 'r'));
}

TEST(tfw_str_eq_cstr, returns_true_only_for_equal_strs)
{
	const char *cstr = "foo123 barbaz";
	int len = strlen(cstr);

	TFW_STR(match, "foo123 barbaz");
	TFW_STR(diff1, "aoo123 barbaz");
	TFW_STR(diff2, "foo123 barbaa");
	TFW_STR(diff3, "Foo123 barbaz");
	TFW_STR(crop,  "foo123 barba");
	TFW_STR(extra, "foo123 barbazz");

	EXPECT_TRUE(tfw_str_eq_cstr(match, cstr, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(diff1, cstr, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(diff2, cstr, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(diff3, cstr, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(crop,  cstr, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(extra, cstr, len, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, handles_plain_str)
{
	const char *cstr1 = "foo";
	const char *cstr2 = "bar baz";
	size_t len1 = strlen(cstr1);
	size_t len2 = strlen(cstr2);
	TfwStr *s1 = make_plain_str(cstr1);
	TfwStr *s2 = make_plain_str(cstr2);

	EXPECT_TRUE(tfw_str_eq_cstr(s1, cstr1, len1, TFW_STR_EQ_DEFAULT));
	EXPECT_TRUE(tfw_str_eq_cstr(s2, cstr2, len2, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(s1, cstr2, len2, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(s2, cstr1, len1, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, handles_unterminated_strs)
{
	const char *cstr = "foobarbaz [SOME GARBAGE]";
	int cstr_len = 9;
	TfwStr s = {
		.len = cstr_len,
		.ptr = (void *)"foobarbaz [ANOTHER GARBAGE]"
	};
	EXPECT_TRUE(tfw_str_eq_cstr(&s, cstr, cstr_len, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, handles_empty_strs)
{
	TfwStr s1 = {
		.len = 0,
		.ptr = (void *)"garbage"
	};
	TfwStr s2 = {
		.len = 0,
		.ptr = NULL
	};
	TfwStr chunks[] = { s1, s2 };
	TfwStr s3 = {
		.len = 0,
		.ptr = &chunks
	};
	TfwStr s_ne = {
		.len = 3,
		.ptr = (void *)"foo"
	};
	const char *cstr = "";
	const char *cstr_ne = "bar";
	size_t len = strlen(cstr_ne);

	TFW_STR_CHUNKN_INIT(&s3);

	EXPECT_TRUE(tfw_str_eq_cstr(&s1, cstr, 0, TFW_STR_EQ_DEFAULT));
	EXPECT_TRUE(tfw_str_eq_cstr(&s2, cstr, 0, TFW_STR_EQ_DEFAULT));
	EXPECT_TRUE(tfw_str_eq_cstr(&s3, cstr, 0, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s_ne, cstr, 0, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s1, cstr_ne, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s2, cstr_ne, len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s3, cstr_ne, len, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, supports_casei)
{
	TFW_STR(s, "FooBarBaz 123");
	const char *cstr1 = "FooBarBaz 123";
	const char *cstr2 = "fooBarBaz 123";
	const char *cstr3 = "FooBarBaZ 123";
	size_t len1 = strlen(cstr1);
	size_t len2 = strlen(cstr2);
	size_t len3 = strlen(cstr3);

	EXPECT_TRUE(tfw_str_eq_cstr(s, cstr1, len1, TFW_STR_EQ_CASEI));
	EXPECT_TRUE(tfw_str_eq_cstr(s, cstr2, len2, TFW_STR_EQ_CASEI));
	EXPECT_TRUE(tfw_str_eq_cstr(s, cstr3, len3, TFW_STR_EQ_CASEI));
	EXPECT_FALSE(tfw_str_eq_cstr(s, cstr2, len2, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(s, cstr3, len3, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, supports_prefix)
{
	TFW_STR(s, "/foo/bar/baz.test");
	const char *p1 = "/foo/bar/baz.test";
	const char *p2 = "/foo/bar/baz.tes";
	const char *p3 = "/foo/bar/baz";
	const char *p4 = "/foo/bar/";
	const char *p5 = "/foo";
	const char *p6 = "/";
	const char *p7 = "";
	const char *extra = "/foo/bar/baz.test1";
	const char *p1_ci = "/foo/bar/baz.tesT";
	const char *p5_ci = "/Foo";

	EXPECT_TRUE(tfw_str_eq_cstr(s, p1, strlen(p1), TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p2, strlen(p2), TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p3, strlen(p3), TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p4, strlen(p4), TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p5, strlen(p5), TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p6, strlen(p6), TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p7, strlen(p7), TFW_STR_EQ_PREFIX));

	EXPECT_FALSE(tfw_str_eq_cstr(s, extra, strlen(extra),
		     TFW_STR_EQ_PREFIX));
	EXPECT_FALSE(tfw_str_eq_cstr(s, p1_ci, strlen(p1_ci),
		     TFW_STR_EQ_PREFIX));
	EXPECT_FALSE(tfw_str_eq_cstr(s, p5_ci, strlen(p5_ci),
		     TFW_STR_EQ_PREFIX));

	EXPECT_TRUE(tfw_str_eq_cstr(s, p1_ci, strlen(p1_ci),
		    TFW_STR_EQ_PREFIX_CASEI));
	EXPECT_TRUE(tfw_str_eq_cstr(s, p5_ci, strlen(p5_ci),
		    TFW_STR_EQ_PREFIX_CASEI));
}

TEST(tfw_str_eq_cstr_off, supports_suffix)
{
	TFW_STR(s, "/foo/bar/baz.test");
	const char *p1 = "/foo/bar/baz.test";
	const char *p2 = "foo/bar/baz.test";
	const char *p3 = "bar/baz.test";
	const char *p4 = "/baz.test";
	const char *p5 = ".test";
	const char *f1 = "/bar/foo/baz.test";
	const char *f2 = "/foo/bar/";
	const char *extra = "/bar/foo/baz.test100";
	const char *i1 = "/foo/bar/baz.tesT";
	const char *i2 = ".TeSt";

#define X_EXPECT_TRUE(s, p, flags)					\
do {									\
	int plen = strlen(p);						\
	EXPECT_TRUE(tfw_str_eq_cstr_off(s, s->len - plen, p, plen, flags)); \
} while(0)
#define X_EXPECT_FALSE(s, p, flags)					\
do {									\
	int plen = strlen(p);						\
	EXPECT_FALSE(tfw_str_eq_cstr_off(s, s->len - plen, p, plen, flags)); \
} while(0)

	X_EXPECT_TRUE(s, p1, TFW_STR_EQ_DEFAULT);
	X_EXPECT_TRUE(s, p2, TFW_STR_EQ_DEFAULT);
	X_EXPECT_TRUE(s, p3, TFW_STR_EQ_DEFAULT);
	X_EXPECT_TRUE(s, p4, TFW_STR_EQ_DEFAULT);
	X_EXPECT_TRUE(s, p5, TFW_STR_EQ_DEFAULT);

	X_EXPECT_FALSE(s, f1, TFW_STR_EQ_DEFAULT);
	X_EXPECT_FALSE(s, f2, TFW_STR_EQ_DEFAULT);

	X_EXPECT_FALSE(s, extra, TFW_STR_EQ_DEFAULT);
	X_EXPECT_FALSE(s, i1, TFW_STR_EQ_DEFAULT);
	X_EXPECT_FALSE(s, i2, TFW_STR_EQ_DEFAULT);

	X_EXPECT_TRUE(s, i1, TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI);
	X_EXPECT_TRUE(s, i2, TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI);

#undef X_EXPECT_TRUE
#undef X_EXPECT_FALSE
}

static const char *foxstr = "The quick brown fox jumps over the lazy dog";

TEST(tfw_str_eq_cstr_pos, plain)
{
	TfwStr *fox = make_plain_str(foxstr), *c, *end;
	long i, offset = 0, foxlen = fox->len;

	TFW_STR_FOR_EACH_CHUNK(c, fox, end) {
		for (i = 0; i < c->len; i++) {
			EXPECT_TRUE(tfw_str_eq_cstr_pos(fox,
							c->ptr + i,
							foxstr + offset,
							foxlen - offset,
							TFW_STR_EQ_CASEI));
			EXPECT_FALSE(tfw_str_eq_cstr_pos(fox,
							 c->ptr + i,
							 "1234567890",
							 10,
							 TFW_STR_EQ_CASEI));
			++offset;
		}
	}

	EXPECT_FALSE(tfw_str_eq_cstr_pos(fox,
					 (const char *)1,
					 foxstr,
					 foxlen,
					 TFW_STR_EQ_CASEI));

}

TEST(tfw_str_eq_cstr_off, plain)
{
	TfwStr *fox = make_plain_str(foxstr);
	long offset = 0, foxlen = fox->len;

	for (offset = 0; offset < fox->len; ++offset) {
		EXPECT_TRUE(tfw_str_eq_cstr_off(fox, offset,
						foxstr + offset,
						foxlen - offset,
						TFW_STR_EQ_CASEI));
		EXPECT_FALSE(tfw_str_eq_cstr_off(fox, offset,
						 "1234567890", 10,
						 TFW_STR_EQ_CASEI));
	}

	EXPECT_TRUE(tfw_str_eq_cstr_off(fox, 0,
					foxstr, foxlen, TFW_STR_EQ_CASEI));

	EXPECT_FALSE(tfw_str_eq_cstr_off(fox, foxlen + 1,
					 foxstr, foxlen, TFW_STR_EQ_CASEI));
	EXPECT_FALSE(tfw_str_eq_cstr_off(fox, -1,
					 foxstr, foxlen, TFW_STR_EQ_CASEI));

}

TEST(tfw_str_eq_cstr_pos, compound)
{
	TfwStr *fox = make_compound_str(foxstr), *c, *end;
	long i, offset = 0, foxlen = fox->len;

	TFW_STR_FOR_EACH_CHUNK(c, fox, end) {
		for (i = 0; i < c->len; i++) {
			EXPECT_TRUE(tfw_str_eq_cstr_pos(fox,
							c->ptr + i,
							foxstr + offset,
							foxlen - offset,
							TFW_STR_EQ_CASEI));
			EXPECT_FALSE(tfw_str_eq_cstr_pos(fox,
							 c->ptr + i,
							 "1234567890",
							 10,
							 TFW_STR_EQ_CASEI));
			++offset;
		}
	}

	EXPECT_FALSE(tfw_str_eq_cstr_pos(fox,
					 (const char *)1,
					 foxstr,
					 foxlen,
					 TFW_STR_EQ_CASEI));
}

TEST(tfw_str_eq_cstr_off, compound)
{
	TfwStr *fox = make_compound_str(foxstr);
	long offset = 0, foxlen = fox->len;

	for (offset = 0; offset < fox->len; ++offset) {
		EXPECT_TRUE(tfw_str_eq_cstr_off(fox, offset,
						foxstr + offset,
						foxlen - offset,
						TFW_STR_EQ_CASEI));
		EXPECT_FALSE(tfw_str_eq_cstr_off(fox, offset,
						 "1234567890", 10,
						 TFW_STR_EQ_CASEI));
	}

	EXPECT_TRUE(tfw_str_eq_cstr_off(fox, 0,
					foxstr, foxlen, TFW_STR_EQ_CASEI));

	EXPECT_FALSE(tfw_str_eq_cstr_off(fox, foxlen + 1,
					 foxstr, foxlen, TFW_STR_EQ_CASEI));
	EXPECT_FALSE(tfw_str_eq_cstr_off(fox, -1,
					 foxstr, foxlen, TFW_STR_EQ_CASEI));

}

TEST_SUITE(tfw_str)
{
	TEST_SETUP(create_str_pool);
	TEST_TEARDOWN(free_all_str);

	TEST_RUN(tfw_strcpy, zero_src);
	TEST_RUN(tfw_strcpy, zero_dst);
	TEST_RUN(tfw_strcpy, both_plain);
	TEST_RUN(tfw_strcpy, src_compound);
	TEST_RUN(tfw_strcpy, dst_compound);
	TEST_RUN(tfw_strcpy, both_compound);

	TEST_RUN(tfw_strcat, plain);
	TEST_RUN(tfw_strcat, compound);

	TEST_RUN(tfw_stricmpspn, returns_true_only_for_equal_tfw_strs);
	TEST_RUN(tfw_stricmpspn, handles_plain_and_compound_strs);
	TEST_RUN(tfw_stricmpspn, handles_empty_strs);
	TEST_RUN(tfw_stricmpspn, handles_different_size_strs);

	TEST_RUN(tfw_str_eq_cstr, returns_true_only_for_equal_strs);
	TEST_RUN(tfw_str_eq_cstr, handles_plain_str);
	TEST_RUN(tfw_str_eq_cstr, handles_unterminated_strs);
	TEST_RUN(tfw_str_eq_cstr, handles_empty_strs);
	TEST_RUN(tfw_str_eq_cstr, supports_casei);
	TEST_RUN(tfw_str_eq_cstr, supports_prefix);
	TEST_RUN(tfw_str_eq_cstr_off, supports_suffix);

	TEST_RUN(tfw_str_eq_cstr_pos, plain);
	TEST_RUN(tfw_str_eq_cstr_off, plain);
	TEST_RUN(tfw_str_eq_cstr_pos, compound);
	TEST_RUN(tfw_str_eq_cstr_off, compound);
}
