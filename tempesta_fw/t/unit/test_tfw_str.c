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
	TfwStr s1 = { 0 };
	TfwStr s2 = TFW_STR_FROM("abc");
	
	/* @dest->ptr is static memory, but must not crash. */
	EXPECT_ZERO(tfw_strcpy(&s2, &s1));
	EXPECT_ZERO(s2.len);
}

TEST(tfw_strcpy, zero_dst)
{
	TfwStr s1 = { 0	};
	TfwStr s2 = TFW_STR_FROM("abc");

	/* @dest->ptr is static memory, but must not crash. */
	EXPECT_ZERO(!tfw_strcpy(&s1, &s2));
}

TEST(tfw_strcpy, both_plain)
{
	char buf1[4] = { 0 }, buf2[4] = "abc";
	DEFINE_TFW_STR(s1, buf1);
	DEFINE_TFW_STR(s2, buf2);

	EXPECT_ZERO(tfw_strcpy(&s1, &s2));
	EXPECT_STR_EQ(s1.data, "abc");
}

TEST(tfw_strcpy, src_compound)
{
	char buf1[32] = { 0 };
	DEFINE_TFW_STR(s1, buf1);
	DEFINE_TFW_STR(s2, "abcdefghijklmnop");

	EXPECT_ZERO(tfw_strcpy(&s1, &s2));
	EXPECT_STR_EQ(s1.data, "abcdefghijklmnop");
}

TEST(tfw_strcpy, dst_compound)
{
	char buf[32] = { [0 ... 30] = 'a', 0 };
	DEFINE_TFW_STR(s1, buf);
	DEFINE_TFW_STR(s2, "abcdefghijklmnop");

	EXPECT_ZERO(tfw_strcpy(&s1, &s2));
	EXPECT_TRUE(tfw_str_eq_cstr(&s1, "abcdefghijklmnop",
				    sizeof("abcdefghijklmnop") - 1, 0));
}

TEST(tfw_strcpy, both_compound)
{
	char buf[32] = { [0 ... 30] = 'a', 0 };
	DEFINE_TFW_STR(s1, buf);
	TfwStr s2 = {
		.chunks = (TfwStr []){
			TFW_STR_FROM("ab"),
			TFW_STR_FROM("cde"),
			TFW_STR_FROM("f"),
			TFW_STR_FROM("g"),
			TFW_STR_FROM("h"),
			TFW_STR_FROM("ijklmno"),
			TFW_STR_FROM("p")
		},
		.len = sizeof("abcdefghijklmnop") - 1,
		.chunknum = 7
	};

	EXPECT_ZERO(tfw_strcpy(&s1, &s2));
	EXPECT_TRUE(tfw_str_eq_cstr(&s1, "abcdefghijklmnop",
				    sizeof("abcdefghijklmnop") - 1, 0));
}

TEST(tfw_strcat, plain)
{
	int chunkscnt;
	DEFINE_TFW_STR(s1, "abcdefghijklmnop");
	DEFINE_TFW_STR(s2, "0123456789");

	chunkscnt = TFW_STR_CHUNKN(&s1);
	EXPECT_ZERO(tfw_strcat(str_pool, &s1, &s2));
	EXPECT_TRUE(TFW_STR_CHUNKN(&s1) == chunkscnt + 1);
	EXPECT_TRUE(tfw_str_eq_cstr(&s1, "abcdefghijklmnop0123456789",
				    sizeof("abcdefghijklmnop0123456789") - 1,
				    0));
}

TEST(tfw_strcat, compound)
{
	int chunks1, chunks2;
	TfwStr *s1 = make_compound_str2("abc", "defgh");
	TfwStr *s2 = make_compound_str2("01234", "56789");

	chunks1 = TFW_STR_CHUNKN(s1);
	chunks2 = TFW_STR_CHUNKN(s2);
	EXPECT_ZERO(tfw_strcat(str_pool, s1, s2));
	EXPECT_TRUE(TFW_STR_CHUNKN(s1) == chunks1 + chunks2);
	EXPECT_TRUE(tfw_str_eq_cstr(s1, "abcdefgh0123456789",
				    sizeof("abcdefgh0123456789") - 1,
				    0));
}

TEST(tfw_stricmpspn, returns_true_only_for_equal_tfw_strs)
{
	DEFINE_TFW_STR(s1, "abcdefghijklmnopqrst");
	DEFINE_TFW_STR(s2, "ABcDefGHIJKLmnopqrst");
	DEFINE_TFW_STR(s3, "abcdefghi");
	DEFINE_TFW_STR(s4, "abcdefghijklmnopqrst_the_tail");

	EXPECT_TRUE(tfw_stricmpspn(&s1, &s2, 1) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s3, 1) == 0);
	EXPECT_TRUE(tfw_stricmpspn(&s1, &s3, 'f') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s4, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(&s1, &s4, 't') == 0);
}

TEST(tfw_stricmpspn, handles_plain_and_compound_strs)
{
	DEFINE_TFW_STR(s1, "abcdefghijklmnopqrst");
	DEFINE_TFW_STR(s2, "abcdefghijklmnopqrst");
	DEFINE_TFW_STR(s3, "abcdefghi");
	DEFINE_TFW_STR(s4, "abcdefghijklmnopqrst_the_tail");

	EXPECT_TRUE(tfw_stricmpspn(&s1, &s2, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s3, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(&s1, &s3, 'f') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s3, 'z') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s4, 0) == 0);
	EXPECT_TRUE(tfw_stricmpspn(&s1, &s4, 't') == 0);
}

TEST(tfw_stricmpspn, handles_empty_strs)
{
	DEFINE_TFW_STR(s1, "garbage");
	DEFINE_TFW_STR(s2, "trash");
	DEFINE_TFW_STR(s3, "abcdefghijklmnopqrst");

	EXPECT_TRUE(tfw_stricmpspn(&s1, &s2, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s2, 'a') == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s3, 0) == 0);
	EXPECT_FALSE(tfw_stricmpspn(&s1, &s3, 'a') == 0);
}

TEST(tfw_stricmpspn, handles_different_size_strs)
{
	TfwStr s1 = {
		.chunks = (TfwStr []){
			TFW_STR_FROM("ab"),
			TFW_STR_FROM("cdefghijklmnopqrst"),
			TFW_STR_FROM("cdefghijklmnopqrst")
		},
		.len = sizeof("abcdefghijklmnopqrst") - 1,
		.chunknum = 3
	};
	TfwStr s2 = {
		.chunks = (TfwStr []){
			TFW_STR_FROM("abcdefg"),
			TFW_STR_FROM("hi"),
			TFW_STR_FROM("jklmnopqrst")
		},
		.len = sizeof("abcdefghijklmnopqrst") - 1,
		.chunknum = 3
	};

	EXPECT_ZERO(tfw_stricmpspn(&s1, &s2, 0));
	EXPECT_ZERO(tfw_stricmpspn(&s1, &s2, 0));
}

TEST(tfw_str_eq_cstr, returns_true_only_for_equal_strs)
{
	const char *cstr = "foo123 barbaz";
	int len = strlen(cstr);
	DEFINE_TFW_STR(match, "foo123 barbaz");
	TFW_STR(diff1, "aoo123 barbaz");
	TFW_STR(diff2, "foo123 barbaa");
	TFW_STR(diff3, "Foo123 barbaz");
	TFW_STR(crop,  "foo123 barba");
	TFW_STR(extra, "foo123 barbazz");

	EXPECT_TRUE(tfw_str_eq_cstr(&match, cstr, len, TFW_STR_EQ_DEFAULT));
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
	TfwStr s = TFW_STR_FROM("foobarbaz [ANOTHER GARBAGE]");

	EXPECT_TRUE(tfw_str_eq_cstr(&s, cstr, cstr_len, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, handles_empty_strs)
{
	TfwStr s1 = TFW_STR_FROM("garbage");
	TfwStr s2 = { 0	};
	TfwStr chunks[] = { s1, s2 };
	TfwStr s3 = {
		.chunks = chunks,
		.chunknum = ARRAY_SIZE(chunks)
	};
	TfwStr s = TFW_STR_FROM("");
	TfwStr s_ne = TFW_STR_FROM("foo");
	TfwStr s_ne2 = TFW_STR_FROM("bar");

	EXPECT_TRUE(tfw_str_eq_cstr(&s1, s.data, s.len, TFW_STR_EQ_DEFAULT));
	EXPECT_TRUE(tfw_str_eq_cstr(&s2, s.data, s.len, TFW_STR_EQ_DEFAULT));
	EXPECT_TRUE(tfw_str_eq_cstr(&s3, s.data, s.len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s_ne, s.data, s.len,
				     TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s1, s_ne2.data, s_ne2.len,
				     TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s2, s_ne2.data, s_ne2.len,
				     TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s3, s_ne2.data, s_ne2.len,
				     TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, supports_casei)
{
	DEFINE_TFW_STR(s, "FooBarBaz 123");
	DEFINE_TFW_STR(c1, "FooBarBaz 123");
	DEFINE_TFW_STR(c2, "fooBarBaz 123");
	DEFINE_TFW_STR(c3, "FooBarBaZ 123");

	EXPECT_TRUE(tfw_str_eq_cstr(&s, c1.data, c1.len, TFW_STR_EQ_CASEI));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, c2.data, c2.len, TFW_STR_EQ_CASEI));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, c3.data, c3.len, TFW_STR_EQ_CASEI));
	EXPECT_FALSE(tfw_str_eq_cstr(&s, c2.data, c2.len, TFW_STR_EQ_DEFAULT));
	EXPECT_FALSE(tfw_str_eq_cstr(&s, c3.data, c3.len, TFW_STR_EQ_DEFAULT));
}

TEST(tfw_str_eq_cstr, supports_prefix)
{
	const TfwStr s  = TFW_STR_FROM("/foo/bar/baz.test");
	const TfwStr p1 = TFW_STR_FROM("/foo/bar/baz.test");
	const TfwStr p2 = TFW_STR_FROM("/foo/bar/baz.tes");
	const TfwStr p3 = TFW_STR_FROM("/foo/bar/baz");
	const TfwStr p4 = TFW_STR_FROM("/foo/bar/");
	const TfwStr p5 = TFW_STR_FROM("/foo");
	const TfwStr p6 = TFW_STR_FROM("/");
	const TfwStr p7 = TFW_STR_FROM("");
	const TfwStr extra = TFW_STR_FROM("/foo/bar/baz.test/extra");
	const TfwStr p1_ci = TFW_STR_FROM("/foo/bar/");
	const TfwStr p5_ci = TFW_STR_FROM("/foo/bar/");
	const TfwStr p6_ci = TFW_STR_FROM("/foo/bar/p6_ci");

	EXPECT_TRUE(tfw_str_eq_cstr(&s, p1.data, p1.len, TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p2.data, p2.len, TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p3.data, p3.len, TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p4.data, p4.len, TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p5.data, p5.len, TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p6.data, p6.len, TFW_STR_EQ_PREFIX));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p7.data, p7.len, TFW_STR_EQ_PREFIX));

	EXPECT_FALSE(tfw_str_eq_cstr(&s, extra.data, extra.len,
		     TFW_STR_EQ_PREFIX));
	EXPECT_FALSE(tfw_str_eq_cstr(&s, p6_ci.data, p6_ci.len,
		     TFW_STR_EQ_PREFIX));
	EXPECT_FALSE(tfw_str_eq_cstr(&s, p6_ci.data, p6_ci.len,
		     TFW_STR_EQ_PREFIX));

	EXPECT_TRUE(tfw_str_eq_cstr(&s, p1_ci.data, p1_ci.len,
		    TFW_STR_EQ_PREFIX_CASEI));
	EXPECT_TRUE(tfw_str_eq_cstr(&s, p5_ci.data, p5_ci.len,
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

	X_EXPECT_FALSE(s, i1, TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI);
	X_EXPECT_FALSE(s, i2, TFW_STR_EQ_DEFAULT | TFW_STR_EQ_CASEI);

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
							c->data + i,
							foxstr + offset,
							foxlen - offset,
							TFW_STR_EQ_CASEI));
			EXPECT_FALSE(tfw_str_eq_cstr_pos(fox,
							 c->data + i,
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
	long i, offset = 0, foxlen = fox->len;

	for (i = 0; i < fox->len; i++) {
		EXPECT_TRUE(tfw_str_eq_cstr_off(fox, fox->len + i,
						foxstr + offset,
						foxlen - offset,
						TFW_STR_EQ_CASEI));
		EXPECT_FALSE(tfw_str_eq_cstr_off(fox, fox->len + i,
						 "1234567890", 10,
						 TFW_STR_EQ_CASEI));
		++offset;
	}

	EXPECT_TRUE(tfw_str_eq_cstr_off(fox, foxlen,
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
							c->data + i,
							foxstr + offset,
							foxlen - offset,
							TFW_STR_EQ_CASEI));
			EXPECT_FALSE(tfw_str_eq_cstr_pos(fox,
							 c->data + i,
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
	long i, offset = 0, foxlen = fox->len;

	for (i = 0; i < fox->len; i++) {
		EXPECT_TRUE(tfw_str_eq_cstr_off(fox, fox->len + i,
						foxstr + offset,
						foxlen - offset,
						TFW_STR_EQ_CASEI));
		EXPECT_FALSE(tfw_str_eq_cstr_off(fox, fox->len + i,
						 "1234567890", 10,
						 TFW_STR_EQ_CASEI));
		++offset;
	}

	EXPECT_TRUE(tfw_str_eq_cstr_off(fox, foxlen,
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
