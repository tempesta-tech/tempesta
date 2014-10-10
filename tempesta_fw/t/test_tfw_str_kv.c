/**
 *		Tempesta FW
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

#include "test.h"
#include "str.h"
#include "pool.h"

/* These should always pass on all functions. */
static const char *data_norm = "Cache-Control: max-age=3600, public";
static const char *data_spc1 = "Cache-Control:max-age=3600, public";
static const char *data_spc2 = "Cache-Control   :max-age=3600, public";
static const char *data_spc3 = "Cache-Control\r  : \t\n max-age=3600, public";
static const char *data_keycase = "Cache-controL: max-age=3600, public";

/* These should always fail. */
static const char *data_keydiff  = "Cache-Cootrol: max-age=3600, public";
static const char *data_sepdiff  = "Cache-Control= max-age=3600, public";
static const char *data_sepempty = "Cache-Control max-age=3600, public";
static const char *data_sepdup   = "Cache-Control:: max-age=3600, public";
static const char *data_vardiff  = "Cache-Control: max-age=3601, public";
static const char *data_keyshort = "Cache-Contro: max-age=3600, public";
static const char *data_keylong  = "Cache-Controll: max-age=3600, public";
static const char *data_valshort = "Cache-Control: max-age=3600, publi";

/* These depend on prefix mode and case sensitivity. */
static const char *data_valcase = "Cache-Control: Max-Age=3600, publiC";
static const char *data_varlong  = "Cache-Control: max-age=3600, publicc";

/* Corresponding TfwStr objects (generated in runtime). */
static const TfwStr *str_keycase;
static const TfwStr *str_keydiff;
static const TfwStr *str_keylong;
static const TfwStr *str_keyshort;
static const TfwStr *str_norm;
static const TfwStr *str_sepdiff;
static const TfwStr *str_sepdup;
static const TfwStr *str_sepempty;
static const TfwStr *str_spc1;
static const TfwStr *str_spc2;
static const TfwStr *str_spc3;
static const TfwStr *str_valcase;
static const TfwStr *str_valshort;
static const TfwStr *str_vardiff;
static const TfwStr *str_varlong;

/*
 * key/sep/val strings for comparison with the data defined above.
 *
 * Note that there are only correct values in the C strings:
 * We are assuming that comparison is symmetrical, so we can use one-to-many
 * instead of many-to-many approach. We can keep only one set of key/sep/val
 * strings and compare it against many TfwStrs and thus reduce the code size.
 */
static const char key[] = "Cache-Control";
static const char sep = ':';
static const char val[] = "max-age=3600, public";
static const int key_len = sizeof(key) - 1;
static const int val_len = sizeof(val) - 1;

static TfwPool *str_pool;

static TfwStr *
alloc_str(void)
{
	TfwStr *s = tfw_pool_alloc(str_pool, sizeof(*s));
	memset(s, 0, sizeof(*s));

	return s;
}

static unsigned long
hash_djb2(const char *str)
{
	unsigned long hash = 5381;
	int c;
	while ((c = *str++))
		hash = ((hash << 5) + hash) + c; /* hash*33 + c */
	return hash;
}

static const TfwStr *
make_tfw_str(const char *data)
{
	TfwStr *s, *c1, *c2, *c3, *c4;
	int len, len1, len2, len3, len4;
	unsigned long hash = hash_djb2(data);

	s = alloc_str();
	c1 = tfw_str_add_compound(str_pool, s);
	c2 = tfw_str_add_compound(str_pool, s);
	c3 = tfw_str_add_compound(str_pool, s);
	c4 = tfw_str_add_compound(str_pool, s);

	/* Each string is sliced to 4 chunks of different length.
	 * That is done to test different ways of spreading the key/val data
	 * across the chunks. */
	len = strlen(data);
	len1 = hash & 0xF;
	len2 = (hash >> 8)  & 0x1;
	len3 = ((hash >> 16) & 0xF) | 0x7;
	len4 = len - len1 - len2 - len3;
	BUG_ON(len4 < 0);

	s->len = 5; /* 4 + one empty chunk created by alloc_str() */
	c1->len = len1;
	c2->len = len2;
	c3->len = len3;
	c4->len = len4;
	c1->ptr = (void *)data;
	c2->ptr = (void *)data + len1;
	c3->ptr = (void *)data + len1 + len2;
	c4->ptr = (void *)data + len1 + len2 + len3;

	return s;
}

#define MAKE_TFW_STR(name) str_##name = make_tfw_str(data_##name)

static void
make_tfw_strs(void)
{
	str_pool = __tfw_pool_new(1);

	MAKE_TFW_STR(keycase);
	MAKE_TFW_STR(keydiff);
	MAKE_TFW_STR(keylong);
	MAKE_TFW_STR(keyshort);
	MAKE_TFW_STR(norm);
	MAKE_TFW_STR(sepdiff);
	MAKE_TFW_STR(sepdup);
	MAKE_TFW_STR(sepempty);
	MAKE_TFW_STR(spc1);
	MAKE_TFW_STR(spc2);
	MAKE_TFW_STR(spc3);
	MAKE_TFW_STR(valcase);
	MAKE_TFW_STR(valshort);
	MAKE_TFW_STR(vardiff);
	MAKE_TFW_STR(varlong);
}

static void
release_tfw_strs(void)
{
	tfw_pool_free(str_pool);
	str_pool = NULL;
}

/**
 * Common assertions that should be held for any kv-related function.
 */
#define TEST_STR_KV_COMMON(fn) \
({ \
	EXPECT_TRUE(fn(str_norm, key, key_len, sep, val, val_len)); \
	EXPECT_TRUE(fn(str_spc1, key, key_len, sep, val, val_len)); \
	EXPECT_TRUE(fn(str_spc2, key, key_len, sep, val, val_len)); \
	EXPECT_TRUE(fn(str_spc3, key, key_len, sep, val, val_len)); \
	EXPECT_TRUE(fn(str_keycase, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_keydiff, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_sepdiff, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_sepempty, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_sepdup, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_vardiff, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_keyshort, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_keylong, key, key_len, sep, val, val_len)); \
	EXPECT_FALSE(fn(str_valshort, key, key_len, sep, val, val_len)); \
})

TEST(tfw_str_kv, common_checks)
{
	TEST_STR_KV_COMMON(tfw_str_eq_kv);
	TEST_STR_KV_COMMON(tfw_str_eq_kv_ci);
	TEST_STR_KV_COMMON(tfw_str_subjoins_kv);
	TEST_STR_KV_COMMON(tfw_str_subjoins_kv_ci);
}

TEST(tfw_str_eq_kv_ci, ignores_value_case)
{
	bool cs_match, ci_match;

	cs_match = tfw_str_eq_kv(str_valcase, key, key_len, sep, val, val_len);
	ci_match = tfw_str_eq_kv_ci(str_valcase, key, key_len, sep, val,
	                            val_len);

	EXPECT_FALSE(cs_match);
	EXPECT_TRUE(ci_match);
}

TEST(tfw_str_subioins_kv, treats_val_as_prefix)
{
	bool eq_match, sj_match;

	eq_match = tfw_str_eq_kv(str_varlong, key, key_len, sep, val, val_len);
	sj_match = tfw_str_subjoins_kv(str_varlong, key, key_len, sep, val,
	                               val_len);

	EXPECT_FALSE(eq_match);
	EXPECT_TRUE(sj_match);
}

TEST(tfw_str_subjoins_kv_ci, ignores_value_case)
{
	bool cs_match, ci_match;

	cs_match = tfw_str_eq_kv(str_valcase, key, key_len, sep, val, val_len);
	ci_match = tfw_str_subjoins_kv_ci(str_valcase, key, key_len, sep, val,
	                                  val_len);

	EXPECT_FALSE(cs_match);
	EXPECT_TRUE(ci_match);
}


TEST_SUITE(tfw_str_kv)
{
	make_tfw_strs();

	TEST_RUN(tfw_str_kv, common_checks);
	TEST_RUN(tfw_str_eq_kv_ci, ignores_value_case);
	TEST_RUN(tfw_str_subioins_kv, treats_val_as_prefix);
	TEST_RUN(tfw_str_subjoins_kv_ci, ignores_value_case);

	release_tfw_strs();
}
