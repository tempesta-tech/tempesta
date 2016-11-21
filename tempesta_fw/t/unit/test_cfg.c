/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies.
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

#include "cfg.h"
#include "test.h"
#ifdef EXPORT_SYMBOL
#undef EXPORT_SYMBOL
#define EXPORT_SYMBOL(func)
#endif
#include "cfg.c"
/*
 * ------------------------------------------------------------------------
 *	Generic helpers common for all tests.
 * ------------------------------------------------------------------------
 */

/**
 * The internal functions are imported to simplify testing.
 * We don't want to inject a real Tempesta FW module via public API because
 * our specs may interfere with already existing modules.
 * Instead, we create a dummy TfwCfgMod and pass it to them as if it was real.
 */

LIST_HEAD(test_mod_list);
TfwCfgMod test_dummy_mod = { .name = "test_dummy_mod" };

static int
do_parse_cfg(const char *cfg_text, TfwCfgSpec specs[])
{
	BUG_ON(!list_empty(&test_mod_list));
	test_dummy_mod.specs = specs;
	list_add(&test_dummy_mod.list, &test_mod_list);
	return tfw_cfg_start_mods(cfg_text, &test_mod_list);
}

static void
do_cleanup_cfg(void)
{
	BUG_ON(list_empty(&test_mod_list));
	tfw_cfg_stop_mods(&test_mod_list);
	list_del(&test_dummy_mod.list);
}

static int
parse_cfg(const char *cfg_text, TfwCfgSpec specs[])
{
	int r = do_parse_cfg(cfg_text, specs);
	do_cleanup_cfg();
	return r;
}

/**
 * Dummy TfwCfgSpec->handler callbacks for testing.
 * They simply modify TfwCfgSpec->dest as an integer, so we know that they were
 * called during the parsing process.
 */

static int
cb_incr_ctr(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);
	return 0;
}

static int
cb_decr_ctr(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	--(*counter);
	return 0;
}

static int
cb_incr_ctr_err(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);
	return -1;
}

/**
 * The TfwCfgSpec->cleanup dummy callback.
 * Note that spec_ext is changed instead of dest to allow using it together
 * with the handler callbacks above.
 */
static void
cleanup_incr_ctr(TfwCfgSpec *cs)
{
	int *counter = cs->spec_ext;
	++(*counter);
}

/*
 * ------------------------------------------------------------------------
 *	parser tests
 * ------------------------------------------------------------------------
 */

TEST(cfg_parser, invokes_specified_handler)
{
	int ctr = 0;

	TfwCfgSpec specs[] = {
		{ "foo", NULL, cb_incr_ctr, &ctr },
		{ 0 }
	};

	parse_cfg("foo;", specs);
	EXPECT_EQ(ctr, 1);
}

TEST(cfg_parser, allows_repeating_entries)
{
	int ctr1 = 0;
	int ctr2 = 0;

	TfwCfgSpec specs[] = {
		{ "incr1", NULL, cb_incr_ctr, &ctr1, .allow_repeat = true },
		{ "incr2", NULL, cb_incr_ctr, &ctr2, .allow_repeat = true },
		{ "decr1", NULL, cb_decr_ctr, &ctr1, .allow_repeat = true },
		{ "decr2", NULL, cb_decr_ctr, &ctr2, .allow_repeat = true },
		{ 0 }
	};
	const char *cfg_text =
		"incr1; incr1; incr1;"
		"decr1; decr1;"
		"decr2; decr2; decr2;"
		"incr2; incr2;";

	int r = parse_cfg(cfg_text, specs);

	EXPECT_OK(r);
	EXPECT_EQ(ctr1,  1);
	EXPECT_EQ(ctr2, -1);
}

TEST(cfg_parser, allows_optional_entries)
{
	int r;
	int counter = 0;

	TfwCfgSpec specs_opt[] = {
		{ "incr1", NULL, cb_incr_ctr, &counter },
		{ "incr2", NULL, cb_incr_ctr, &counter, .allow_none = true },
		{ "incr3", NULL, cb_incr_ctr, &counter },
		{ 0 }
	};
	TfwCfgSpec specs_noopt[] = {
		{ "incr1", NULL, cb_incr_ctr, &counter },
		{ "incr2", NULL, cb_incr_ctr, &counter },
		{ "incr3", NULL, cb_incr_ctr, &counter },
		{ 0 }
	};
	const char *cfg_text = "incr1; incr3;";

	r = parse_cfg(cfg_text, specs_opt);
	EXPECT_OK(r);
	EXPECT_EQ(counter, 2);

	r = parse_cfg(cfg_text, specs_noopt);
	EXPECT_ERROR(r);
}


static char *opts_cfg_text =
	"option1;					\r\n"
	"option2 value;					\r\n"
	"option3 attr = val ;				\r\n"
	"option4  foo bar baz  attr1=val1 attr2=val2;	\r\n";

static int
cb_option1(TfwCfgSpec *cs, TfwCfgEntry *e)
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
cb_option2(TfwCfgSpec *cs, TfwCfgEntry *e)
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
cb_option3(TfwCfgSpec *cs, TfwCfgEntry *e)
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
cb_option4(TfwCfgSpec *cs, TfwCfgEntry *e)
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

TEST(cfg_parser, puts_parsed_vals_to_entry)
{
	bool option1_is_checked = false;
	bool option2_is_checked = false;
	bool option3_is_checked = false;
	bool option4_is_checked = false;

	TfwCfgSpec specs[] = {
		{ "option1", NULL, cb_option1, &option1_is_checked },
		{ "option2", NULL, cb_option2, &option2_is_checked },
		{ "option3", NULL, cb_option3, &option3_is_checked },
		{ "option4", NULL, cb_option4, &option4_is_checked },
		{ 0 }
	};

	int r = parse_cfg(opts_cfg_text, specs);

	EXPECT_OK(r);
	EXPECT_TRUE(option1_is_checked);
	EXPECT_TRUE(option2_is_checked);
	EXPECT_TRUE(option3_is_checked);
	EXPECT_TRUE(option4_is_checked);
}

static int
cb_cmntws(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);

	EXPECT_STR_EQ(e->name, "cmntws");
	EXPECT_EQ(e->val_n, 3);
	EXPECT_STR_EQ(e->vals[0], "foo");
	EXPECT_STR_EQ(e->vals[1], "bar");
	EXPECT_STR_EQ(e->vals[2], "baz");

	return 0;
}

TEST(cfg_parser, eats_comments_and_whitespace)
{
	int ctr = 0;
	TfwCfgSpec specs[] = {
		{ "cmntws", NULL, cb_cmntws, &ctr, .allow_repeat = true },
		{ 0 }
	};
	const char *cfg_text =
		"# this is a comment				\n"
		"cmntws foo bar baz;				\n"
		"	cmntws    foo    bar\n \t baz 		\n"
		" #another comment				\n"
		" 	\r\n ; \r\n";

	int r = parse_cfg(cfg_text, specs);
	EXPECT_OK(r);
	EXPECT_EQ(ctr, 2);
}

static int
cb_qtdstr(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);

	EXPECT_EQ(e->val_n, 1);
	EXPECT_STR_EQ(e->name, "qtdstr");
	EXPECT_STR_EQ(e->vals[0], " foo \t\r\n bar \"#\" baz \\");

	return 0;
}

TEST(cfg_parser, handles_quoted_strings)
{
	int ctr = 0;
	TfwCfgSpec specs[] = {
		{ "qtdstr", NULL, cb_qtdstr, &ctr, .allow_repeat = true },
		{ 0 }
	};
	const char *cfg_text =
		"qtdstr  \" foo \t\r\n bar \\\"#\\\" baz \\\\\";	\n"
		"	qtdstr					\n"
		"	\" foo \t\r\n bar \\\"#\\\" baz \\\\\"		\n"
		"	;						\n";

	int r = parse_cfg(cfg_text, specs);
	EXPECT_OK(r);
	EXPECT_EQ(ctr, 2);
}

static int
cb_escaped(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);

	EXPECT_EQ(e->val_n, 1);
	EXPECT_STR_EQ(e->name, "escaped");
	EXPECT_STR_EQ(e->vals[0], " \r\n#\";\\");

	return 0;
}

TEST(cfg_parser, handles_escaped_special_characters)
{
	int ctr = 0;

	TfwCfgSpec specs[] = {
		{ "escaped", NULL, cb_escaped, &ctr },
		{ 0 }
	};

	/* The leaning toothpick syndrome here: have to escape backslahes and
	 * quotes both in C and the configuration language. */
	int r = parse_cfg("escaped  \\ \\\r\\\n\\#\\\"\\;\\\\;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(ctr, 1);
}

static int
cb_deflt_used(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);

	EXPECT_STR_EQ(e->name, "deflt_used");

	EXPECT_EQ(e->val_n, 2);
	EXPECT_STR_EQ(e->vals[0], "val1");
	EXPECT_STR_EQ(e->vals[1], "val2");

	EXPECT_EQ(e->attr_n, 2);
	EXPECT_STR_EQ(e->attrs[0].key, "k1");
	EXPECT_STR_EQ(e->attrs[0].val, "v1");
	EXPECT_STR_EQ(e->attrs[1].key, "k2");
	EXPECT_STR_EQ(e->attrs[1].val, "v2");

	return 0;
}

static int
cb_deflt_unused(TfwCfgSpec *cs, TfwCfgEntry *e)
{
	int *counter = cs->dest;
	++(*counter);

	EXPECT_EQ(e->val_n, 1);
	EXPECT_STR_EQ(e->name, "deflt_unused");
	EXPECT_STR_EQ(e->vals[0], "the value from cfg_text");

	return 0;
}

TEST(cfg_parser, simulates_default_values)
{
	int ctrs[3] = { 0 };

	TfwCfgSpec specs[] = {
		{
			"deflt_used", "val1 val2 k1=v1  k2 = v2",
			cb_deflt_used,
			&ctrs[0]
		},
		{
			"deflt_unused", "this default value is not used",
			cb_deflt_unused,
			&ctrs[1]
		},
		{
			"completely_optional",
			NULL,
			cb_incr_ctr,
			&ctrs[2],
			.allow_none = true
		},
		{ 0 }
	};
	const char *cfg_text = "deflt_unused \"the value from cfg_text\";";

	int r = parse_cfg(cfg_text, specs);
	EXPECT_OK(r);
	EXPECT_EQ(ctrs[0], 1);
	EXPECT_EQ(ctrs[1], 1);
	EXPECT_EQ(ctrs[2], 0);
}

TEST(cfg_parser, invokes_cleanup_callback)
{
	int call_ctrs[5] = { 0 };
	int cleanup_ctrs[5] = { 0 };
	int r;

	TfwCfgSpec specs[] = {
		{
			"single", NULL,
			cb_incr_ctr,
			&call_ctrs[0],
			&cleanup_ctrs[0],
			.cleanup = cleanup_incr_ctr
		},
		{
			"repeat", NULL,
			cb_incr_ctr,
			&call_ctrs[1],
			&cleanup_ctrs[1],
			.cleanup = cleanup_incr_ctr,
			.allow_repeat = true
		},
		{
			"deflt", "the default value",
			cb_incr_ctr,
			&call_ctrs[2],
			&cleanup_ctrs[2],
			.cleanup = cleanup_incr_ctr
		},
		{
			"none", NULL,
			cb_incr_ctr,
			&call_ctrs[3],
			&cleanup_ctrs[3],
			.cleanup = cleanup_incr_ctr,
			.allow_none = true
		},
		{
			"err", NULL,
			cb_incr_ctr_err,
			&call_ctrs[4],
			&cleanup_ctrs[4],
			.cleanup = cleanup_incr_ctr,
			.allow_none = true
		},
		{ 0 }
	};


	r = parse_cfg("single; repeat; repeat; repeat;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(call_ctrs[0], 1);
	EXPECT_EQ(call_ctrs[1], 3);
	EXPECT_EQ(call_ctrs[2], 1);
	EXPECT_EQ(call_ctrs[3], 0);
	EXPECT_EQ(call_ctrs[4], 0);
	EXPECT_EQ(cleanup_ctrs[0], 1);
	EXPECT_EQ(cleanup_ctrs[1], 1);
	EXPECT_EQ(cleanup_ctrs[2], 1);
	EXPECT_EQ(cleanup_ctrs[3], 0);
	EXPECT_EQ(cleanup_ctrs[4], 0);

	/* Now try to inject 'err' in the middle of the config.
	 * The parser should terminate at that point, and the cleanup callback
	 * should be called for all previously touched specs (including the
	 * 'err'). That also means that the 'deflt' remains untouched. */
	memset(call_ctrs, 0, sizeof(call_ctrs));
	memset(cleanup_ctrs, 0, sizeof(call_ctrs));
	r = parse_cfg("single; repeat; repeat; err; repeat;", specs);
	EXPECT_ERROR(r);
	EXPECT_EQ(call_ctrs[0], 1);
	EXPECT_EQ(call_ctrs[1], 2);
	EXPECT_EQ(call_ctrs[2], 0);
	EXPECT_EQ(call_ctrs[3], 0);
	EXPECT_EQ(call_ctrs[4], 1);
	EXPECT_EQ(cleanup_ctrs[0], 1);
	EXPECT_EQ(cleanup_ctrs[1], 1);
	EXPECT_EQ(cleanup_ctrs[2], 0);
	EXPECT_EQ(cleanup_ctrs[3], 0);
	EXPECT_EQ(cleanup_ctrs[4], 1);
}

/*
 * ------------------------------------------------------------------------
 *	tests for generic TfwCfgSpec->handler callbacks
 * ------------------------------------------------------------------------
 */

TEST(tfw_cfg_set_bool, treats_noval_as_true_flag)
{
	/* char is used instead of bool because for bool the value 42 is
	 * substituted with 1 automatically. */
	char flag1_cfgtext = 42;
	char flag2_none = 42;
	char flag3_def_true  = 42;
	char flag4_def_false = 42;

	TfwCfgSpec specs[] = {
		{
			"flag1", NULL,
			tfw_cfg_set_bool,
			&flag1_cfgtext
		},
		{
			"flag2", NULL,
			tfw_cfg_set_bool,
			&flag2_none,
			.allow_none = true
		},
		{
			"flag3", "true",
			tfw_cfg_set_bool,
			&flag3_def_true
		},
		{
			"flag4", "false",
			tfw_cfg_set_bool,
			&flag4_def_false
		},
		{ 0 }
	};

	int r = parse_cfg("flag1;", specs);

	EXPECT_OK(r);
	EXPECT_EQ(flag1_cfgtext, true);    /* parsed from cfg */
	EXPECT_EQ(flag2_none, 42);	   /* untouched */
	EXPECT_EQ(flag3_def_true, true);   /* default value is used */
	EXPECT_EQ(flag4_def_false, false); /* default value is used */

	BUILD_BUG_ON(sizeof(char) != sizeof(bool));
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
		{ 0 }
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

TEST(tfw_cfg_set_int, sets_dest_value)
{
	int val = 0;
	TfwCfgSpec specs[] = {
		{ "val", NULL, tfw_cfg_set_int, &val },
		{ 0 }
	};

	parse_cfg("val 42;", specs);

	EXPECT_EQ(val, 42);
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
		{ 0 }
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

TEST(tfw_cfg_set_int, checks_ext_restrictions)
{
	int r, val;
	TfwCfgSpec specs[] = {
		{
			"val", NULL,
			tfw_cfg_set_int,
			&val,
			&(TfwCfgSpecInt) {
				.multiple_of = 2,
				.range = { 10, 20 }
			}
		},
		{ 0 }
	};

	/* Should pass only even numbers within range 10 to 20 (inclusive). */

	r = parse_cfg("val -16;", specs);
	EXPECT_ERROR(r);

	r = parse_cfg("val 0;", specs);
	EXPECT_ERROR(r);

	r = parse_cfg("val 2;", specs);
	EXPECT_ERROR(r);

	r = parse_cfg("val 9;", specs);
	EXPECT_ERROR(r);

	r = parse_cfg("val 10;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, 10);

	r = parse_cfg("val 15;", specs);
	EXPECT_ERROR(r);

	r = parse_cfg("val 16;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, 16);

	r = parse_cfg("val 20;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, 20);

	r = parse_cfg("val 21;", specs);
	EXPECT_ERROR(r);

	r = parse_cfg("val 65536;", specs);
	EXPECT_ERROR(r);
}

TEST(tfw_cfg_set_int, maps_enum_keywords)
{
	int r, val;
	TfwCfgEnum val_mappings[] = {
		{ "off", -1 },
		{ "auto", 42 },
		{ 0 }
	};
	TfwCfgSpec specs[] = {
		{
			"val", NULL,
			tfw_cfg_set_int,
			&val,
			&(TfwCfgSpecInt) {
				.enums = val_mappings
			}
		},
		{ 0 }
	};

	r = parse_cfg("val 222;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, 222);

	r = parse_cfg("val off;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, -1);

	r = parse_cfg("val auto;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, 42);

	r = parse_cfg("val -1;", specs);
	EXPECT_OK(r);
	EXPECT_EQ(val, -1);
}

TEST(tfw_cfg_set_str, sets_dest_str)
{
	int r;
	const char *str1 = NULL;
	const char *str2 = NULL;
	const char *str3 = NULL;
	const char *str4 = NULL;
	TfwCfgSpec specs[] = {
		{ "str1", NULL, tfw_cfg_set_str, &str1 },
		{ "str2", NULL, tfw_cfg_set_str, &str2 },
		{ "str3", NULL, tfw_cfg_set_str, &str3 },
		{ "str4", NULL, tfw_cfg_set_str, &str4 },
		{ 0 }
	};
	const char *cfg_text =
		"str1 foo;			"
		"str2 foo\\ bar\\ baz;		"
		"str3 \"foo bar baz\";		"
		"str4 \"\";			";

	r = do_parse_cfg(cfg_text, specs);
	EXPECT_OK(r);

	EXPECT_NOT_NULL(str1);
	EXPECT_NOT_NULL(str2);
	EXPECT_NOT_NULL(str3);
	EXPECT_NOT_NULL(str4);
	EXPECT_STR_EQ(str1, "foo");
	EXPECT_STR_EQ(str2, "foo bar baz");
	EXPECT_STR_EQ(str3, "foo bar baz");
	EXPECT_STR_EQ(str4, "");

	do_cleanup_cfg();
}

TEST(tfw_cfg_set_str, sets_dest_str_empty_string)
{
	int r;
	const char *str = NULL;
	TfwCfgSpec specs[] = {
		{ "str", NULL, tfw_cfg_set_str, &str },
		{ 0 }
	};

	r = do_parse_cfg("str;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();

	r = do_parse_cfg("str ;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();

	r = do_parse_cfg("str \"\";", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "");
	do_cleanup_cfg();
}

TEST(tfw_cfg_set_str, checks_strlen)
{
	int r;
	const char *str = NULL;
	TfwCfgSpec specs[] = {
		{
			"str", NULL,
			tfw_cfg_set_str,
			&str,
			&(TfwCfgSpecStr) {
				.len_range = { 2, 8 }
			}
		},
		{ 0 }
	};

	r = do_parse_cfg("str 1;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();

	r = do_parse_cfg("str 12;", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "12");
	do_cleanup_cfg();

	r = do_parse_cfg("str 123;", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "123");
	do_cleanup_cfg();

	r = do_parse_cfg("str \"12345\";", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "12345");
	do_cleanup_cfg();

	r = do_parse_cfg("str 12345678;", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "12345678");
	do_cleanup_cfg();

	r = do_parse_cfg("str 123456789;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();
}

TEST(tfw_cfg_set_str, checks_character_set)
{
	int r;
	const char *str = NULL;
	TfwCfgSpec specs[] = {
		{
			"hex", NULL,
			tfw_cfg_set_str,
			&str,
			&(TfwCfgSpecStr) {
				.cset = "1234567890abcdefABCDEF"
			}
		},
		{ 0 }
	};

	r = do_parse_cfg("hex \"\";", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "");
	do_cleanup_cfg();

	r = do_parse_cfg("hex a;", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "a");
	do_cleanup_cfg();

	r = do_parse_cfg("hex 412dfBA;", specs);
	EXPECT_OK(r);
	EXPECT_STR_EQ(str, "412dfBA");
	do_cleanup_cfg();

	r = do_parse_cfg("hex 4z2;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();

	r = do_parse_cfg("hex abc!;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();

	r = do_parse_cfg("hex -42;", specs);
	EXPECT_ERROR(r);
	do_cleanup_cfg();
}

TEST(tfw_cfg_handle_children, parses_nested_entries_recursively)
{
	int counter1 = 0;
	int counter2 = 0;
	int counter3 = 0;

	TfwCfgSpec section1_specs[] = {
		{ "incr", NULL, cb_incr_ctr, &counter1, .allow_repeat = true },
		{ "decr", NULL, cb_decr_ctr, &counter1, .allow_repeat = true },
		{ 0 }
	};
	TfwCfgSpec section2_specs[] = {
		{ "incr", NULL, cb_incr_ctr, &counter2, .allow_repeat = true },
		{ "decr", NULL, cb_decr_ctr, &counter2, .allow_repeat = true },
		{ 0 }
	};
	TfwCfgSpec root_specs[] = {
		{ "section1", NULL, tfw_cfg_handle_children, section1_specs },
		{ "section2", NULL, tfw_cfg_handle_children, section2_specs },
		{ "incr", NULL, cb_incr_ctr, &counter3, .allow_repeat = true },
		{ "decr", NULL, cb_decr_ctr, &counter3, .allow_repeat = true },
		{ 0 }
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

TEST(tfw_cfg_handle_children, propagates_cleanup_to_nested_specs)
{
	int call_ctr = 0;
	int cleanup_ctr = 0;

	TfwCfgSpec nested_specs[] = {
		{
			"entry", NULL,
			cb_incr_ctr,
			&call_ctr,
			&cleanup_ctr,
			.cleanup = cleanup_incr_ctr,
			.allow_repeat = true
		},
		{ 0 }
	};
	TfwCfgSpec root_specs[] = {
		{
			"section", NULL,
			tfw_cfg_handle_children,
			nested_specs,
			.allow_repeat = true
		},
		{ 0 }
	};
	const char *cfg_text =
		"section {		\n"
		"	entry;		\n"
		"	entry;		\n"
		"	entry;		\n"
		"}			\n"
		"section {		\n"
		"	entry;		\n"
		"	entry;		\n"
		"}			\n"
		"section {		\n"
		"}			\n";

	int r = parse_cfg(cfg_text, root_specs);

	EXPECT_OK(r);
	EXPECT_EQ(call_ctr, 5);
	EXPECT_EQ(cleanup_ctr, 1);
}

TEST_SUITE(cfg)
{
	TEST_RUN(cfg_parser, invokes_specified_handler);
	TEST_RUN(cfg_parser, allows_repeating_entries);
	TEST_RUN(cfg_parser, allows_optional_entries);
	TEST_RUN(cfg_parser, puts_parsed_vals_to_entry);
	TEST_RUN(cfg_parser, eats_comments_and_whitespace);
	TEST_RUN(cfg_parser, handles_quoted_strings);
	TEST_RUN(cfg_parser, handles_escaped_special_characters);
	TEST_RUN(cfg_parser, simulates_default_values);
	TEST_RUN(cfg_parser, invokes_cleanup_callback);

	TEST_RUN(tfw_cfg_set_bool, treats_noval_as_true_flag);
	TEST_RUN(tfw_cfg_set_bool, recognizes_truthy_falsy_values);
	TEST_RUN(tfw_cfg_set_int, sets_dest_value);
	TEST_RUN(tfw_cfg_set_int, recognizes_dec_hex_bin_bases);
	TEST_RUN(tfw_cfg_set_int, checks_ext_restrictions);
	TEST_RUN(tfw_cfg_set_int, maps_enum_keywords);
	TEST_RUN(tfw_cfg_set_str, sets_dest_str);
	TEST_RUN(tfw_cfg_set_str, sets_dest_str_empty_string);
	TEST_RUN(tfw_cfg_set_str, checks_strlen);
	TEST_RUN(tfw_cfg_set_str, checks_character_set);
	TEST_RUN(tfw_cfg_handle_children, parses_nested_entries_recursively);
	TEST_RUN(tfw_cfg_handle_children, propagates_cleanup_to_nested_specs);
}
