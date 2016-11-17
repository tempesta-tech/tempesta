/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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

#include "htype.h"
#include "str.h"
#include "test.h"
#include "tfw_str_helper.h"

TEST(cstr, tolower)
{
	EXPECT_TRUE(TFW_LC('A') == tolower('A'));
	EXPECT_TRUE(TFW_LC('Z') == tolower('Z'));
	EXPECT_TRUE(TFW_LC('a') == tolower('a'));
	EXPECT_TRUE(TFW_LC('z') == tolower('z'));
	EXPECT_TRUE(TFW_LC('0') == tolower('0'));
	EXPECT_TRUE(TFW_LC('9') == tolower('9'));
	EXPECT_TRUE(TFW_LC('/') == tolower('/'));
	EXPECT_TRUE(TFW_LC('@') == tolower('@'));
	EXPECT_TRUE(TFW_LC('[') == tolower('['));
	EXPECT_TRUE(TFW_LC('`') == tolower('`'));
	EXPECT_TRUE(TFW_LC('{') == tolower('{'));
	EXPECT_TRUE(TFW_LC('\r') == tolower('\r'));
	EXPECT_TRUE(TFW_LC(0) == tolower(0));
	EXPECT_TRUE(TFW_LC(127) == tolower(127));
	/* tolower() somehow treats 200 as upper case character. */
	EXPECT_TRUE(TFW_LC(200) != tolower(200));
	EXPECT_TRUE(TFW_LC(255) == tolower(255));
}

#define ACCEPT_URI	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"			\
			"aabcdefghijklmnopqrstuvwxyz"			\
			"!#$%&'*+-._();:@=,/?[]~0123456789"

#define __test_match(s)							\
do {									\
	EXPECT_TRUE(tfw_match_uri(s, sizeof(s) - 1) == strspn(s, ACCEPT_URI)); \
} while (0)

TEST(cstr, simd_match)
{
	__test_match("");
	__test_match(" ");
	__test_match("^");
	__test_match("a");
	__test_match("ab");
	__test_match("{a");
	__test_match("abc");
	__test_match("a}b");
	__test_match("abcd");
	__test_match("abc}");
	__test_match("abcde");
	__test_match("\"abce");
	__test_match("heLLo_24!");
	__test_match("0123456789ab{c}def");
	__test_match("!#$%&'*+-._();^abcde");
	__test_match("0123456789abcdefghIjkl|\\Pmdsfdfew34////");
	__test_match("0123456789abcdefghIjkl@?Pmdsfdfew34//^//");
	__test_match("0123456789_0123456789_0123456789_0123456789_|abcdef");
	__test_match("0123456789_0123456789_^0123456789_0123456789_abcdef");
	__test_match("0123456789_0123456789_0123456789_0123456789_abcdef^");
	__test_match("mozilla!5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		     "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11");
	__test_match("mozilla!5.0_(windows_nt_6.1!_wow64)_applewebkit!535.^11_"
		     "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11");
	__test_match("mozilla!5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		     "(khtml._like_gecko)_chrome!17.^0.963.56_safari!535.11");
	__test_match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		     "cccccccccccccccccccccccccccccccc"
		     "dddddddddddddddddddddddddddddddd");
	__test_match("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		     "ccccccccccccccc^cccccccccccccccc"
		     "dddddddddddddddddddddddddddddddd"
		     "0123456|95");
	__test_match("aaaaaaaaaaaa^aaaaaaaaaaaaaaaaaaa"
		     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		     "cccccccccccccccccccccccccccccccc"
		     "dddddddddddddddddddddddddddddddd"
		     "0123456|95");
}

static inline void *
c_strtolower(unsigned char *dest, const unsigned char *src, size_t len)
{
	int i;

	for (i = 0; i < len; ++i)
		dest[i] = tolower(src[i]);

	return dest;
}

#define __test_tolower(s)						\
do {									\
	size_t n = sizeof(s) - 1;					\
	unsigned char *dst1, *dst2;					\
	dst1 = kmalloc(n * 2, GFP_ATOMIC);				\
	BUG_ON(!dst1);							\
	dst2 = dst1 + n;						\
	dst1 = tfw_strtolower(dst1, s, n);				\
	dst2 = c_strtolower(dst2, s, n);				\
	EXPECT_TRUE(!strncmp(dst1, dst2, n));				\
} while (0)

TEST(cstr, simd_strtolower)
{
	__test_tolower("");
	__test_tolower(" ");
	__test_tolower("a");
	__test_tolower("A");
	__test_tolower("ab");
	__test_tolower("AB");
	__test_tolower("/!");
	__test_tolower("{a");
	__test_tolower("abc");
	__test_tolower("ABC");
	__test_tolower("a}b");
	__test_tolower("abcd");
	__test_tolower("ABCD");
	__test_tolower("ABCd");
	__test_tolower("abc}");
	__test_tolower("abcde");
	__test_tolower("ABCDE");
	__test_tolower("AbCdE");
	__test_tolower("\"abce");
	__test_tolower("AbCdEm");
	__test_tolower("AbCdEmN");
	__test_tolower("heLLo_24!");
	__test_tolower("!#$%&'*+-._();^abcDe");
	__test_tolower("0123456789abcDefghIjkl|@?\\PmdSfdfew34//^//");
	__test_tolower("0123456789_0123456789_0123456789_0123456789_abcdef^");
	__test_tolower("MOZILLa!5.0_(wIndOws_nt_6.1!_WOW64)_APPLEwebkit!535.11_"
		      "(khtml._liKE_GECKO)_CHROme!17.^0.963.56_safari!535.11");
	__test_tolower("aaAAAAAAAAAAAAaaaaaAAAAAAAAaaaaa"
		       "ABC");
	__test_tolower("aaAAAAAAAAAAAAaaaaaAAAAAAAAaaaaa"
		       "0123456|ABC");
	__test_tolower("aaAAAAAAAAAAAAaaaaaAAAAAAAAaaaaa"
		       "BBBBBBBBBbbbbbbbbBBBBBBBBBBBBBBB"
		       "ABC");
	__test_tolower("aaAAAAAAAAAAAAaaaaaAAAAAAAAaaaaa"
		       "BBBBBBBBBbbbbbbbbBBBBBBBBBBBBBBB"
		       "0123456|ABC");
	__test_tolower("aaAAAAAAAAAAAAaaaaaAAAAAAAAaaaaa"
		       "BBBBBBBBBbbbbbbbbBBBBBBBBBBBBBBB"
		       "CcccccccCcccccc^CcccccCccccccccc"
		       "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
		       "0123456|95");
}

#define __test_strcmp(s1, s2)						\
do {									\
	size_t n = min(sizeof(s1), sizeof(s2)) - 1;			\
	EXPECT_TRUE(!tfw_stricmp(s1, s2, n) == !strncasecmp(s1, s2, n)); \
	EXPECT_TRUE(!tfw_stricmp_2lc(s1, s2, n) == !strncasecmp(s1, s2, n)); \
} while (0)

TEST(cstr, simd_stricmp)
{
	/* Second string is always in lower case to fit *_2lc() requirement. */
	__test_strcmp("", "");
	__test_strcmp("", "a");
	__test_strcmp("/!", "");
	__test_strcmp("/!", "abc");
	__test_strcmp("ABC", "abc");
	__test_strcmp("ABC ", "abc@");
	__test_strcmp("ABC@", "abc`");
	__test_strcmp("ABCR", "abc2");
	__test_strcmp("ABC[", "abc{");
	__test_strcmp("ABC{", "abc[");
	__test_strcmp("AbCdE", "abcde");
	__test_strcmp("AbCdEm", "abcde");
	__test_strcmp("AbCdE", "axcde");
	__test_strcmp("/img/arrow-up.png", "/img/arrow-up.png");
	__test_strcmp("0123456789abcdefghijklmno", "0123456789abcdefghijklmno");
	__test_strcmp("0123456789abcdefghijkLmno", "0123456789abcdefghijkLmn0");
	__test_strcmp("0123456789_0123456789_0123456789_zxfghert", "012345678");
	__test_strcmp("0123456789_0123456789_0123456789_zxfghert", "0_zxfghrt");
	__test_strcmp("0123456789_0123456789_0123456789_zX",
		      "0123456789_0123456789_0123456789_zx");
	__test_strcmp("0123456789_0123456789_0123456789_z;",
		      "0123456789_0123456789_0123456789_z[");
	__test_strcmp("0123456789_0123456789_0123456789_zXfGhERT",
		      "0123456789_0123456789_0123456789_zxfghert");
	__test_strcmp("0123456789_0123456789_0123456789_zXfGhERT",
		      "0123456789_0123456789_0123456789t_zxfghert");
	__test_strcmp("MOZILLA!5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		      "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11",
		      "mozilla!5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		      "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11");
	__test_strcmp("mozilla!5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		      "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11",
		      "Internet Explorer!5.0_(windows_nt_6.1!_wow64)_applewebk"
		      "it!535.11_(khtml._like_gecko)_chrome!17.0.963.56_safari"
		      "!535.11");
	__test_strcmp("mozilla@5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		      "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11",
		      "MOZILLA`5.0_(windows_nt_6.1!_wow64)_applewebkit!535.11_"
		      "(khtml._like_gecko)_chrome!17.0.963.56_safari!535.11");
	__test_strcmp("aaaaaaaaaaaa^aaaaaaaaaaaaaaaaaaa"
		      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		      "cccccccccccccccccccccccccccccccc"
		      "dddddddddddddddddddddddddddddddd"
		      "0123456|95",
		      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		      "cccccccccccccccccccccccccccccccc"
		      "dddddddddddddddddddddddddddddddd"
		      "0123456|95");
	__test_strcmp("aaaaaaaaAAAAAAAAAAAAAAAAAAAAAAAA"
		      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		      "CCCCCCCCCCCCCCCCCCCCCccccccccccc"
		      "dddddddddddddddddddddddddddddddd"
		      "0123456|95",
		      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		      "cccccccccccccccccccccccccccccccc"
		      "dddddddddddddddddddddddddddddddd"
		      "0123456|95");

}

TEST(cstr, ultoa)
{
	char buf[TFW_ULTOA_BUF_SIZ + 1] = {0};

	EXPECT_TRUE(tfw_ultoa(0, buf, TFW_ULTOA_BUF_SIZ) == 1);
	EXPECT_ZERO(tfw_stricmp(buf, "0", 2));

	memset(buf, 0, TFW_ULTOA_BUF_SIZ + 1);
	EXPECT_TRUE(tfw_ultoa(5, buf, TFW_ULTOA_BUF_SIZ) == 1);
	EXPECT_ZERO(tfw_stricmp(buf, "5", 2));

	memset(buf, 0, TFW_ULTOA_BUF_SIZ + 1);
	EXPECT_TRUE(tfw_ultoa(58743, buf, TFW_ULTOA_BUF_SIZ) == 5);
	EXPECT_ZERO(tfw_stricmp(buf, "58743", 6));

	memset(buf, 0, TFW_ULTOA_BUF_SIZ + 1);
	EXPECT_TRUE(tfw_ultoa(0xaabbccff, buf, TFW_ULTOA_BUF_SIZ) == 10);
	EXPECT_ZERO(tfw_stricmp(buf, "2864434431", 11));

	memset(buf, 0, TFW_ULTOA_BUF_SIZ + 1);
	EXPECT_TRUE(tfw_ultoa(18446744073709551615UL,
			      buf, TFW_ULTOA_BUF_SIZ) == 20);
	EXPECT_ZERO(tfw_stricmp(buf, "18446744073709551615", 21));

	EXPECT_ZERO(tfw_ultoa(589, buf, 2));
}

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

	TEST_RUN(cstr, tolower);
	TEST_RUN(cstr, simd_match);
	TEST_RUN(cstr, simd_strtolower);
	TEST_RUN(cstr, simd_stricmp);

	TEST_RUN(cstr, ultoa);

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
