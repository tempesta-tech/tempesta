/**
 *		Tempesta FW
 *
 * The parser and TfwCfgNode are tested together because:
 *  1. The parser produces TfwCfgNode which is accessible only through its
 *     methods. You have to call them anyway in parser tests, so if you add
 *     up separate node tests, you end up with a lot of duplicate logic.
 *  2. It is hard to construct a tree of TfwCfgNode objects manually,
 *     it would require a lot of relatively low-level operations to do that.
 *
 * So we are creating trees with parser and then querying them using the
 * TfwCfgNode methods. Of course, we get worse isolation and test granularity
 * as a drawback.
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

#include "cfg_parser.h"
#include "test.h"

TEST(cfg_parser, recognizes_dec_hex_bin_bases)
{
	int dec1, dec2, dec3, dec4, hex1, hex2, hex3, hex4, bin1, bin2, bin3;
	int inv1 = 1, inv2 = 1, inv3 = 1, inv4 = 1, inv5 = 1;
	int r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11;
	int err1, err2, err3, err4, err5;

	r1 = tfw_cfg_parse_int("000", &dec1);
	r2 = tfw_cfg_parse_int("+1234567890", &dec2);
	r3 = tfw_cfg_parse_int("-1234567890", &dec3);
	r4 = tfw_cfg_parse_int("000024", &dec4);
	r5 = tfw_cfg_parse_int("0x0", &hex1);
	r6 = tfw_cfg_parse_int("0xDEAD", &hex2);
	r7 = tfw_cfg_parse_int("0x00123", &hex3);
	r8 = tfw_cfg_parse_int("0X01a", &hex4);
	r9  = tfw_cfg_parse_int("0b0", &bin1);
	r10 = tfw_cfg_parse_int("0b00111101", &bin2);
	r11 = tfw_cfg_parse_int("0B100", &bin3);

	err1 = tfw_cfg_parse_int("0z123", &inv1);
	err2 = tfw_cfg_parse_int("0xG", &inv2);
	err3 = tfw_cfg_parse_int("-0x12", &inv3);
	err4 = tfw_cfg_parse_int("1 2 3", &inv4);
	err5 = tfw_cfg_parse_int("", &inv5);

	EXPECT_OK(r1);
	EXPECT_OK(r2);
	EXPECT_OK(r3);
	EXPECT_OK(r4);
	EXPECT_OK(r5);
	EXPECT_OK(r6);
	EXPECT_OK(r7);
	EXPECT_OK(r8);
	EXPECT_OK(r9);
	EXPECT_OK(r10);
	EXPECT_OK(r11);

	EXPECT_ERROR(err1);
	EXPECT_ERROR(err2);
	EXPECT_ERROR(err3);
	EXPECT_ERROR(err4);

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

	EXPECT_EQ(inv1, 0);
	EXPECT_EQ(inv2, 0);
	EXPECT_EQ(inv3, 0);
	EXPECT_EQ(inv4, 0);
	EXPECT_EQ(inv5, 0);
}

TEST(cfg_parser, recognizes_truthy_falsy_values)
{
	int r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
	int err1, err2, err3;
	bool t1, t2, t3, t4, t5, t6, f1, f2, f3, f4, f5, f6;
	bool e1, e2, e3;

	r1 = tfw_cfg_parse_bool("true",  &t1);
	r2 = tfw_cfg_parse_bool("false", &f1);

	r3 = tfw_cfg_parse_bool("on",  &t2);
	r4 = tfw_cfg_parse_bool("off", &f2);

	r5 = tfw_cfg_parse_bool("yes", &t3);
	r6 = tfw_cfg_parse_bool("no",  &f3);

	r7 = tfw_cfg_parse_bool("enable",  &t4);
	r8 = tfw_cfg_parse_bool("disable", &f4);

	r9  = tfw_cfg_parse_bool("1", &t5);
	r10 = tfw_cfg_parse_bool("0", &f5);

	r11 = tfw_cfg_parse_bool("TrUe",  &t6);
	r12 = tfw_cfg_parse_bool("FalsE", &f6);

	err1 = tfw_cfg_parse_bool("42", &e1);
	err2 = tfw_cfg_parse_bool("foo", &e2);
	err3 = tfw_cfg_parse_bool("", &e3);

	EXPECT_OK(r1);
	EXPECT_OK(r2);
	EXPECT_OK(r3);
	EXPECT_OK(r4);
	EXPECT_OK(r5);
	EXPECT_OK(r6);
	EXPECT_OK(r7);
	EXPECT_OK(r8);
	EXPECT_OK(r9);
	EXPECT_OK(r10);
	EXPECT_OK(r11);
	EXPECT_OK(r12);
	EXPECT_ERROR(err1);
	EXPECT_ERROR(err2);
	EXPECT_ERROR(err3);

	EXPECT_TRUE(t1);
	EXPECT_TRUE(t2);
	EXPECT_TRUE(t3);
	EXPECT_TRUE(t4);
	EXPECT_TRUE(t5);
	EXPECT_TRUE(t6);
	EXPECT_FALSE(f1);
	EXPECT_FALSE(f2);
	EXPECT_FALSE(f3);
	EXPECT_FALSE(f4);
	EXPECT_FALSE(f5);
	EXPECT_FALSE(f6);
	EXPECT_FALSE(e1);
	EXPECT_FALSE(e2);
	EXPECT_FALSE(e3);
}

TEST(cfg_parser, recognizes_ipv4_ipv6_formats)
{
	const char *s1 = "127.0.0.1";
	const char *s2 = "127.0.0.1:8081";
	const char *s3 = ":8080";
	const char *s4 = "[::1]:1234";
	const char *s5 = "[::0]:5678";

	TfwAddr e1 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	TfwAddr e2 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.v4.sin_port = htons(8081)
	};
	TfwAddr e3 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_ANY),
		.v4.sin_port = htons(8080)
	};
	TfwAddr e4 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.v6.sin6_port = htons(1234)
	};
	TfwAddr e5 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_ANY_INIT,
		.v6.sin6_port = htons(5678)
	};
	TfwAddr a1, a2, a3, a4, a5;
	int r1, r2, r3, r4, r5;

	r1 = tfw_cfg_parse_addr(s1, &a1);
	r2 = tfw_cfg_parse_addr(s2, &a2);
	r3 = tfw_cfg_parse_addr(s3, &a3);
	r4 = tfw_cfg_parse_addr(s4, &a4);
	r5 = tfw_cfg_parse_addr(s5, &a5);

	EXPECT_OK(r1);
	EXPECT_OK(r2);
	EXPECT_OK(r3);
	EXPECT_OK(r4);
	EXPECT_OK(r5);
	EXPECT_TRUE(tfw_addr_eq(&a1, &e1));
	EXPECT_TRUE(tfw_addr_eq(&a2, &e2));
	EXPECT_TRUE(tfw_addr_eq(&a3, &e3));
	EXPECT_TRUE(tfw_addr_eq(&a4, &e4));
	EXPECT_TRUE(tfw_addr_eq(&a5, &e5));
}

TEST(cfg_parser, handles_simple_node_value)
{
	const char *s1 = "node_name string_value;";
	const char *s2 = "node_name 42;";
	const char *s3 = "node_name true;";

	/* Expected/got. */
	const char *v1e = "string_value";
	const char *v1g;
	int v2e = 42;
	int v2g;
	bool v3e = true;
	bool v3g;

	TfwCfgNode *n1, *n2, *n3;

	n1 = tfw_cfg_parse_single_node(s1);
	n2 = tfw_cfg_parse_single_node(s2);
	n3 = tfw_cfg_parse_single_node(s3);

	TFW_CFG_NVAL(n1, str, v1g);
	TFW_CFG_NVAL(n2, int, v2g);
	TFW_CFG_NVAL(n3, bool, v3g);

	//EXPECT_STR_EQ(v1e, v1g);
	(void)v1e;
	EXPECT_EQ(v2e, v2g);
	EXPECT_EQ(v3e, v3g);

	tfw_cfg_node_free(n1);
	tfw_cfg_node_free(n2);
	tfw_cfg_node_free(n3);
}

TEST(cfg_parser, handles_value_list)
{
	TfwAddr e1 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_ANY),
		.v4.sin_port = htons(80)
	};
	TfwAddr e2 = {
		.v6.sin6_family = AF_INET6,
		.v6.sin6_addr = IN6ADDR_ANY_INIT,
		.v6.sin6_port = htons(80)
	};
	TfwAddr e3 = {
		.v4.sin_family = AF_INET,
		.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.v4.sin_port = htons(8081)
	};
	const TfwAddr *g1, *g2, *g3;
	TfwCfgNode *n;

	const char *s = "backends :80 [::0]:80 127.0.0.1:8081;";

	n = tfw_cfg_parse_single_node(s);

	TFW_CFG_NVAL_GET(n, 1, addr, g2);
	TFW_CFG_NVAL_GET(n, 0, addr, g1);
	TFW_CFG_NVAL_GET(n, 2, addr, g3);

	EXPECT_TRUE(tfw_addr_eq(&e1, g1));
	EXPECT_TRUE(tfw_addr_eq(&e2, g2));
	EXPECT_TRUE(tfw_addr_eq(&e3, g3));

	tfw_cfg_node_free(n);
}

TEST(cfg_parser, handles_node_attributes)
{
	const char *attr1_val;
	bool attr2_val;
	int attr3_val;

	TfwCfgNode *n;
	const char *s = "node_name attr1=val1 attr2=true attr3=42;";

	n = tfw_cfg_parse_single_node(s);

	TFW_CFG_NATTR_GET(n, "attr1", str, attr1_val);
	TFW_CFG_NATTR_GET(n, "attr2", bool, attr2_val);
	TFW_CFG_NATTR_GET(n, "AtTr3", int, attr3_val);

	EXPECT_STR_EQ("val1", attr1_val);
	EXPECT_EQ(true, attr2_val);
	EXPECT_EQ(42, attr3_val);

	tfw_cfg_node_free(n);
}

TEST(cfg_parser, handles_nested_nodes)
{
	const char *s =
		"section {			"
		"	name1 1;		"
		"	name2 2;		"
		"	name3 3;		"
		"				"
		"	subsection {		"
		"		sub1 1;		"
		"		sub2 2;		"
		"		sub3 3;		"
		"	}			"
		"}				"
		"				";

	TfwCfgNode *section, *subsection;
	TfwCfgNode *n1, *n2, *n3, *nn1, *nn2, *nn3;
	int n1v, n2v, n3v, nn1v, nn2v, nn3v;

	section = tfw_cfg_parse_single_node(s);
	subsection = tfw_cfg_nchild_get(section, "subsection");

	n1 = tfw_cfg_nchild_get(section, "name1");
	n2 = tfw_cfg_nchild_get(section, "name2");
	n3 = tfw_cfg_nchild_get(section, "name3");
	nn1 = tfw_cfg_nchild_get(subsection, "sub1");
	nn2 = tfw_cfg_nchild_get(subsection, "sub2");
	nn3 = tfw_cfg_nchild_get(subsection, "sub3");

	TFW_CFG_NVAL(n1, int, n1v);
	TFW_CFG_NVAL(n2, int, n2v);
	TFW_CFG_NVAL(n3, int, n3v);
	TFW_CFG_NVAL(nn1, int, nn1v);
	TFW_CFG_NVAL(nn2, int, nn2v);
	TFW_CFG_NVAL(nn3, int, nn3v);

	EXPECT_EQ(n1v, 1);
	EXPECT_EQ(n2v, 2);
	EXPECT_EQ(n3v, 3);
	EXPECT_EQ(nn1v, 1);
	EXPECT_EQ(nn2v, 2);
	EXPECT_EQ(nn3v, 3);

	tfw_cfg_node_free(section);
}

TEST(cfg_parser, handles_mixed_vals_attrs_children)
{
	TfwCfgNode *server, *child2;
	const char *name, *addr, *mode, *child2_val;
	const char *s =
		"server example.com 10.1.1.1 mode=reverse_proxy {	"
		"	child1 1;					"
		"	child2 2;					"
		"}";

	server = tfw_cfg_parse_single_node(s);
	child2 = tfw_cfg_nchild_get(server, "child2");

	TFW_CFG_NVAL_GET(server, 0, str, name);
	TFW_CFG_NVAL_GET(server, 1, str, addr);
	TFW_CFG_NATTR_GET(server, "mode", str, mode);
	TFW_CFG_NVAL(child2, str, child2_val);

	EXPECT_STR_EQ(name, "example.com");
	EXPECT_STR_EQ(addr, "10.1.1.1");
	EXPECT_STR_EQ(mode, "reverse_proxy");
	EXPECT_STR_EQ(child2_val, "2");

	tfw_cfg_node_free(server);
}

TEST(cfg_parser, reads_all_nodes_from_input)
{
	TfwCfgNode *root, *section, *subsection;
	TfwCfgNode *n1, *n2, *n3, *n4, *n5;
	int v1, v2, v3, v4, v5;

	const char *s =
		"name1 1;		"
		"			"
		"section {		"
		"	name2 2;	"
		"	name3 3;	"
		"			"
		"	subsection {	"
		"		name4 4;"
		"	}		"
		"			"
		"}			"
		"			"
		"name5 5;		"
		"			";

	root = tfw_cfg_parse(s);
	section = tfw_cfg_nchild_get(root, "section");
	subsection = tfw_cfg_nchild_get(section, "subsection");

	n1 = tfw_cfg_nchild_get(root, "name1");
	n2 = tfw_cfg_nchild_get(section, "name2");
	n3 = tfw_cfg_nchild_get(section, "name3");
	n4 = tfw_cfg_nchild_get(subsection, "name4");
	n5 = tfw_cfg_nchild_get(root, "name5");

	TFW_CFG_NVAL(n1, int, v1);
	TFW_CFG_NVAL(n2, int, v2);
	TFW_CFG_NVAL(n3, int, v3);
	TFW_CFG_NVAL(n4, int, v4);
	TFW_CFG_NVAL(n5, int, v5);

	EXPECT_EQ(v1, 1);
	EXPECT_EQ(v2, 2);
	EXPECT_EQ(v3, 3);
	EXPECT_EQ(v4, 4);
	EXPECT_EQ(v5, 5);

	tfw_cfg_node_free(root);
}


TEST(tfw_cfg_node_descend, retrieves_nested_nodes)
{
	TfwCfgNode *root, *target;
	const char *val;

	const char *s =
		"level1 {"
		"	some_garbage;			"
		"	level2 {			"
		"		level3 {		"
		"			target value;	"
		"			target false;	"
		"		}			"
		" 		level3 {		"
		"			garbage value;	"
		"		}			"
		"	}				"
		"}";


	root = tfw_cfg_parse(s);
	target = tfw_cfg_node_descend(root, "level1.level2.level3.target");

	TFW_CFG_NVAL(target, str, val);

	EXPECT_STR_EQ(val, "value");

	tfw_cfg_node_free(root);
}

TEST(tfw_cfg_node_descend, reaches_child_in_duplicate_parents)
{
	TfwCfgNode *root, *child3;

	const char *s =
		"section {			"
		"	child1 value1;		"
		"	child2 value2;		"
		"}"
		""
		"section {"
		"	child3 value3;		"
		"	child4 value4;		"
		"}				"
		"";

	root = tfw_cfg_parse(s);
	child3 = tfw_cfg_node_descend(root, "section.child3");

	EXPECT_NOT_NULL(child3);

	tfw_cfg_node_free(root);
}

TEST(TFW_CFG_GET, may_retreive_either_val_attr_child)
{
	TfwCfgNode *root, *sub2_node, *flag2_node;
	bool flag1, flag2, flag3;
	bool is_sub;

	const char *s =
		"section1 {				"
		"	flag1 on;			"
		"}					"
		"					"
		"section2 {				"
		"	subsection2 is_sub=yes {	"
		"		flag2 yes;		"
		"		flag2 no;		"
		"	}				"
		"}					"
		"					"
		"flag3 enable;			"
		"";

	root = tfw_cfg_parse(s);

	TFW_CFG_GET(root, "section1.flag1", val, 0, bool, flag1);
	TFW_CFG_GET(root, "section2.subsection2.flag2", val, 0, bool, flag2);
	TFW_CFG_GET(root, "flag3", val, 0, bool, flag3);
	TFW_CFG_GET(root, "section2.subsection2", attr, "is_sub", bool, is_sub);

	EXPECT_TRUE(flag1);
	EXPECT_TRUE(flag2);
	EXPECT_TRUE(flag3);
	EXPECT_TRUE(is_sub);

	TFW_CFG_GET(root, "section2", child, "subsection2", node, sub2_node);
	flag2 = false;
	TFW_CFG_GET(sub2_node, "flag2", val, 0, bool, flag2);
	EXPECT_TRUE(flag2);

	TFW_CFG_GET(sub2_node, "", child, "flag2", node, flag2_node);
	flag2 = false;
	TFW_CFG_GET(flag2_node, "", val, 0, bool, flag2);
	EXPECT_TRUE(flag2);

	tfw_cfg_node_free(root);
}

TEST(TFW_CFG_NCHILD_EACH, iterates_over_children_nodes)
{
	const char *s =
		"n1 {					"
		"	n1_1 foo;			"
		"	n1_2 bar;			"
		"	n1_3 baz;			"
		"}					"
		"					"
		"n2;					"
		"					"
		"n3 {					"
		"	n3_1 {				"
		"		n3_1_1 value1;		"
		"		n3_1_2 value2;		"
		"	}				"
		"					"
		"	n3_2 {				"
		"		n3_2_1 value3;		"
		"		n3_2_2 value4;		"
		"	}				"
		"}					"
		"					";

	TfwCfgNode *root, *l1_node, *l2_node, *l3_node;
	const char *val;
	int l1_cnt = 0;
	int l2_cnt = 0;
	int l3_cnt = 0;

	root = tfw_cfg_parse(s);


	TFW_CFG_NCHILD_EACH(root, l1_node) {
		++l1_cnt;

		TFW_CFG_NCHILD_EACH(l1_node, l2_node) {
			++l2_cnt;

			TFW_CFG_NCHILD_EACH(l2_node, l3_node) {
				++l3_cnt;

				/* Selectively check some values. */
				if (l1_cnt == 3 && l2_cnt == 1 && l3_cnt == 1) {
					TFW_CFG_NVAL(l2_node, str, val);
					EXPECT_STR_EQ(val, "value1");
				}

				if (l1_cnt == 3 && l2_cnt == 2 && l3_cnt == 2) {
					TFW_CFG_NVAL(l2_node, str, val);
					EXPECT_STR_EQ(val, "value4");
				}
			}
		}
	}

	EXPECT_EQ(l1_cnt, 3);
	EXPECT_EQ(l2_cnt, 5);
	EXPECT_EQ(l3_cnt, 4);

	tfw_cfg_node_free(root);
}

TEST_SUITE(cfg_parser)
{
	TEST_RUN(cfg_parser, recognizes_dec_hex_bin_bases);
	TEST_RUN(cfg_parser, recognizes_truthy_falsy_values);
	TEST_RUN(cfg_parser, recognizes_ipv4_ipv6_formats);
	TEST_RUN(cfg_parser, handles_simple_node_value);
	TEST_RUN(cfg_parser, handles_value_list);
	TEST_RUN(cfg_parser, handles_node_attributes);
	TEST_RUN(cfg_parser, handles_nested_nodes);
	TEST_RUN(cfg_parser, handles_mixed_vals_attrs_children);
	TEST_RUN(cfg_parser, reads_all_nodes_from_input);
	TEST_RUN(tfw_cfg_node_descend, retrieves_nested_nodes);
	TEST_RUN(tfw_cfg_node_descend, reaches_child_in_duplicate_parents);
	TEST_RUN(TFW_CFG_GET, may_retreive_either_val_attr_child);
	TEST_RUN(TFW_CFG_NCHILD_EACH, iterates_over_children_nodes);
}
