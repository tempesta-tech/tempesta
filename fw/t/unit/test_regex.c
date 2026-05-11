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
#include "test.h"
#include "regex.h"

struct regex_map_t {
	unsigned short	regex_idx;
	TfwStr		str;
};

static bool
__match_regex(struct regex_map_t *map, int idx, TfwStr *pattern)
{
	char cstr[2] = {};

	memcpy(cstr, &map[idx].regex_idx, sizeof(unsigned short));
	pr_err("match regex_id = %d\n", map[idx].regex_idx);
	return tfw_match_regex(cstr, pattern);
}

TEST(regex, match_regex)
{
#define SET_REGEXP(no, regexp_str)					\
		{.regex_idx = 0, .str = TFW_STR_STRING(regexp_str)}

	static TfwStr source = TFW_STR_STRING("few words about) LiNux_kernel");
	static TfwStr source_no_spc = TFW_STR_STRING("fewwordsabout)");
	static TfwStr source_fail = TFW_STR_STRING("fqwrdsabut)linx");
	static TfwStr source_rep = TFW_STR_STRING("wwwww");
	static TfwStr source_id = TFW_STR_STRING("myID_7711");

	struct regex_map_t map[] = {
		SET_REGEXP(0, "/words/"),
		SET_REGEXP(1, "/words about/"),
		SET_REGEXP(2, "/wards/"),
		SET_REGEXP(3, "/linux/"),
		SET_REGEXP(4, "/linux/i"),
		SET_REGEXP(5, "/^words/"),
		SET_REGEXP(6, "/^few/"),
		SET_REGEXP(7, "/kernel$/"),
		SET_REGEXP(8, "/\\bwords\\b/"),
		SET_REGEXP(9, "/(wards|few|words|about|linux)/"),
		SET_REGEXP(10, "/w{3,5}/"),
		SET_REGEXP(11, "/[A-Za-z]_[0-9]+/")

	};

	for (int i = 0; i < ARRAY_SIZE(map); i++) {
		unsigned short idx = 0;

		kernel_fpu_end();
		EXPECT_ZERO(tfw_write_regex(map[i].str.data, &idx));
		kernel_fpu_begin();

		map[i].regex_idx = idx;
	}

	kernel_fpu_end();
	tfw_regex_start();
	kernel_fpu_begin();

	EXPECT_TRUE(__match_regex(map, 0, &source));
	EXPECT_TRUE(__match_regex(map, 0, &source_no_spc));
	EXPECT_TRUE(__match_regex(map, 1, &source));
	EXPECT_FALSE(__match_regex(map, 1, &source_no_spc));
	EXPECT_FALSE(__match_regex(map, 2, &source));
	EXPECT_FALSE(__match_regex(map, 3, &source));
	EXPECT_TRUE(__match_regex(map, 4, &source));
	EXPECT_FALSE(__match_regex(map, 5, &source));
	EXPECT_TRUE(__match_regex(map, 6, &source));
	EXPECT_TRUE(__match_regex(map, 7, &source));
	EXPECT_TRUE(__match_regex(map, 8, &source));
	EXPECT_FALSE(__match_regex(map, 8, &source_no_spc));
	EXPECT_TRUE(__match_regex(map, 9, &source));
	EXPECT_TRUE(__match_regex(map, 9, &source_no_spc));
	EXPECT_FALSE(__match_regex(map, 9, &source_fail));
	EXPECT_TRUE(__match_regex(map, 10, &source_rep));
	EXPECT_FALSE(__match_regex(map, 10, &source_no_spc));
	EXPECT_TRUE(__match_regex(map, 11, &source_id));
	EXPECT_FALSE(__match_regex(map, 11, &source));
}

TEST_SUITE(regex)
{
	TEST_RUN(regex, match_regex);
}
