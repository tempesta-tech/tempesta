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

#include "cfg.h"
#include "test.h"

static int
parse_cfg(const char *cfg_text, TfwCfgSpec specs[])
{
	TfwCfgMod dummy_mod = {
		.name = "dummy_test_mod",
		.specs = specs
	};
	struct list_head dummy_mod_list;

	INIT_LIST_HEAD(&dummy_mod_list);
	list_add(&dummy_mod.list, &dummy_mod_list);

	return tfw_cfg_parse_mods_cfg(cfg_text, &dummy_mod_list);
}

static int
incr_counter(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);
	return 0;
}

static int
decr_counter(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	--(*counter);
	return 0;
}

TEST(cfg_parser, invokes_specified_handler)
{
	int counter1 = 0;
	int counter2 = 0;

	TfwCfgSpec specs[] = {
		{ "incr1", NULL, incr_counter, &counter1, .allow_repeat = true },
		{ "incr2", NULL, incr_counter, &counter2, .allow_repeat = true },
		{ "decr1", NULL, decr_counter, &counter1, .allow_repeat = true },
		{ "decr2", NULL, decr_counter, &counter2, .allow_repeat = true },
		{}
	};
	const char *cfg_text =
		"incr1; incr1; incr1;"
		"decr1; decr1;"
		"decr2; decr2; decr2;"
		"incr2; incr2;";

	int r = parse_cfg(cfg_text, specs);

	EXPECT_OK(r);
	EXPECT_EQ(counter1,  1);
	EXPECT_EQ(counter2, -1);
}

/* Helpers and input data for TEST(cfg_parser, puts_vals_to_entry). */

static char *opts_cfg_text =
	"option1;					\r\n"
	"option2 value;					\r\n"
	"option3 attr = val ;				\r\n"
	"option4  foo bar baz  attr1=val1 attr2=val2;	\r\n";

static int
check_option1(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	bool *is_called = cs->dest;
	(*is_called) = true;

	EXPECT_STR_EQ(e->name, "option1");

	EXPECT_EQ(e->val_n, 0);
	EXPECT_NULL(e->vals[0]);

	EXPECT_EQ(e->attr_n, 0);
	EXPECT_NULL(e->attrs[0].key);
	EXPECT_NULL(e->attrs[0].val);

	return 0;
}

static int
check_option2(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	bool *is_called = cs->dest;
	(*is_called) = true;

	EXPECT_STR_EQ(e->name, "option2");

	EXPECT_EQ(e->val_n, 1);
	EXPECT_STR_EQ(e->vals[0], "value");

	EXPECT_EQ(e->attr_n, 0);
	EXPECT_NULL(e->attrs[0].key);
	EXPECT_NULL(e->attrs[0].val);

	return 0;
}

static int
check_option3(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	bool *is_called = cs->dest;
	(*is_called) = true;

	EXPECT_STR_EQ(e->name, "option3");

	EXPECT_EQ(e->val_n, 0);
	EXPECT_NULL(e->vals[0]);

	EXPECT_EQ(e->attr_n, 1);
	EXPECT_STR_EQ(e->attrs[0].key, "attr");
	EXPECT_STR_EQ(e->attrs[0].val, "val");

	return 0;
}

static int
check_option4(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	bool *is_called = cs->dest;
	(*is_called) = true;

	EXPECT_STR_EQ(e->name, "option4");

	EXPECT_EQ(e->val_n, 3);
	EXPECT_STR_EQ(e->vals[0], "foo");
	EXPECT_STR_EQ(e->vals[1], "bar");
	EXPECT_STR_EQ(e->vals[2], "baz");
	EXPECT_NULL(e->vals[3]);

	EXPECT_EQ(e->attr_n, 2);
	EXPECT_STR_EQ(e->attrs[0].key, "attr1");
	EXPECT_STR_EQ(e->attrs[0].val, "val1");
	EXPECT_STR_EQ(e->attrs[1].key, "attr2");
	EXPECT_STR_EQ(e->attrs[1].val, "val2");
	EXPECT_NULL(e->attrs[2].key);
	EXPECT_NULL(e->attrs[2].val);

	return 0;
}

TEST(cfg_parser, puts_vals_to_entry)
{
	bool option1_is_checked = false;
	bool option2_is_checked = false;
	bool option3_is_checked = false;
	bool option4_is_checked = false;

	TfwCfgSpec specs[] = {
		{ "option1", NULL, check_option1, &option1_is_checked },
		{ "option2", NULL, check_option2, &option2_is_checked },
		{ "option3", NULL, check_option3, &option3_is_checked },
		{ "option4", NULL, check_option4, &option4_is_checked },
		{}
	};

	int r = parse_cfg(opts_cfg_text, specs);

	EXPECT_OK(r);
	EXPECT_TRUE(option1_is_checked);
	EXPECT_TRUE(option2_is_checked);
	EXPECT_TRUE(option3_is_checked);
	EXPECT_TRUE(option4_is_checked);
}

typedef struct {
	int len;
	char *data;
} StrPtr;

TEST(cfg_parser, allows_recursion_to_subsections)
{
	int counter1 = 0;
	int counter2 = 0;
	int counter3 = 0;

	TfwCfgSpec section1_specs[] = {
		{ "incr", NULL, incr_counter, &counter1, .allow_repeat = true },
		{ "decr", NULL, decr_counter, &counter1, .allow_repeat = true },
		{}
	};
	TfwCfgSpec section2_specs[] = {
		{ "incr", NULL, incr_counter, &counter2, .allow_repeat = true },
		{ "decr", NULL, decr_counter, &counter2, .allow_repeat = true },
		{}
	};
	TfwCfgSpec root_specs[] = {
		{ "section1", NULL, tfw_cfg_parse_children, section1_specs },
		{ "section2", NULL, tfw_cfg_parse_children, section2_specs },
		{ "incr", NULL, incr_counter, &counter3, .allow_repeat = true },
		{ "decr", NULL, decr_counter, &counter3, .allow_repeat = true },
		{}
	};

	const char *cfg_text =
		"section1 {			"
		"	incr;			"
		"	decr;			"
		"	incr;			"
		"}				"
		"section2 {			"
		"	incr;			"
		"	incr;			"
		"	decr;			"
		"	incr;			"
		"}				"
		"incr;				"
		"incr;				"
		"incr;				"
		"decr;				"
		"incr;				";


	int r = parse_cfg(cfg_text, root_specs);

	EXPECT_OK(r);
	EXPECT_EQ(counter1, 1);
	EXPECT_EQ(counter2, 2);
	EXPECT_EQ(counter3, 3);
}

TEST(tfw_cfg_set_int, recognizes_dec_hex_bin_bases)
{
	int r, dec1, dec2, dec3, dec4, hex1, hex2, hex3, hex4, bin1, bin2, bin3;

	const char *cfg_text =
		"dec1 000;			"
		"dec2 +1234567890;		"
		"dec3 -1234567890;		"
		"dec4 000024;			"
		"hex1 0x0;			"
		"hex2 0xDEAD;			"
		"hex3 0x00123;			"
		"hex4 0X01a;			"
		"bin1 0b0;			"
		"bin2 0b00111101;		"
		"bin3 0B100;			";

	TfwCfgSpec specs[] = {
		{ "dec1", NULL, tfw_cfg_set_int, &dec1 },
		{ "dec2", NULL, tfw_cfg_set_int, &dec2 },
		{ "dec3", NULL, tfw_cfg_set_int, &dec3 },
		{ "dec4", NULL, tfw_cfg_set_int, &dec4 },
		{ "hex1", NULL, tfw_cfg_set_int, &hex1 },
		{ "hex2", NULL, tfw_cfg_set_int, &hex2 },
		{ "hex3", NULL, tfw_cfg_set_int, &hex3 },
		{ "hex4", NULL, tfw_cfg_set_int, &hex4 },
		{ "bin1", NULL, tfw_cfg_set_int, &bin1 },
		{ "bin2", NULL, tfw_cfg_set_int, &bin2 },
		{ "bin3", NULL, tfw_cfg_set_int, &bin3 },
		{}
	};

	r = parse_cfg(cfg_text, specs);

	EXPECT_OK(r);
	EXPECT_EQ(dec1, 0);
	EXPECT_EQ(dec2, 1234567890);
	EXPECT_EQ(dec3, -1234567890);
	EXPECT_EQ(dec4, 24);
	EXPECT_EQ(hex1, 0x0);
	EXPECT_EQ(hex2, 0xDEAD);
	EXPECT_EQ(hex3, 0x00123);
	EXPECT_EQ(hex4, 0x01a);
	EXPECT_EQ(bin1, 0);
	EXPECT_EQ(bin2, 0x3D);
	EXPECT_EQ(bin3, 0x4);
}

TEST(tfw_cfg_set_bool, recognizes_truthy_falsy_values)
{
	int r;
	bool b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12;

	const char *cfg_text =
		"option1  true;			"
		"option2  false;		"
		"option3  on;			"
		"option4  off;			"
		"option5  yes;			"
		"option6  no;			"
		"option7  enable;		"
		"option8  disable;		"
		"option9  1;			"
		"option10 0;			"
		"option11 TrUe;			"
		"option12 FalsE;		";

	TfwCfgSpec specs[] = {
		{ "option1", NULL, tfw_cfg_set_bool, &b1 },
		{ "option2", NULL, tfw_cfg_set_bool, &b2 },
		{ "option3", NULL, tfw_cfg_set_bool, &b3 },
		{ "option4", NULL, tfw_cfg_set_bool, &b4 },
		{ "option5", NULL, tfw_cfg_set_bool, &b5 },
		{ "option6", NULL, tfw_cfg_set_bool, &b6 },
		{ "option7", NULL, tfw_cfg_set_bool, &b7 },
		{ "option8", NULL, tfw_cfg_set_bool, &b8 },
		{ "option9", NULL, tfw_cfg_set_bool, &b9 },
		{ "option10", NULL, tfw_cfg_set_bool, &b10 },
		{ "option11", NULL, tfw_cfg_set_bool, &b11 },
		{ "option12", NULL, tfw_cfg_set_bool, &b12 },
		{}
	};

	r = parse_cfg(cfg_text, specs);

	EXPECT_OK(r);
	EXPECT_TRUE(b1);
	EXPECT_TRUE(b3);
	EXPECT_TRUE(b5);
	EXPECT_TRUE(b7);
	EXPECT_TRUE(b9);
	EXPECT_TRUE(b11);
	EXPECT_FALSE(b2);
	EXPECT_FALSE(b4);
	EXPECT_FALSE(b6);
	EXPECT_FALSE(b8);
	EXPECT_FALSE(b10);
	EXPECT_FALSE(b12);
}

TEST_SUITE(cfg)
{
	TEST_RUN(cfg_parser, invokes_specified_handler);
	TEST_RUN(cfg_parser, puts_vals_to_entry);
	TEST_RUN(cfg_parser, allows_recursion_to_subsections);
	TEST_RUN(tfw_cfg_set_int, recognizes_dec_hex_bin_bases);
	TEST_RUN(tfw_cfg_set_bool, recognizes_truthy_falsy_values);
}
