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

#include <linux/module.h>
#include "test.h"

int test_fail_counter;
test_fixture_fn_t test_setup_fn;
test_fixture_fn_t test_teardown_fn;

void
test_register_failure(void)
{
	++test_fail_counter;
}

void
test_set_setup_fn(test_fixture_fn_t fn)
{
	BUG_ON(fn && test_setup_fn);
	test_setup_fn = fn;
}

void
test_set_teardown_fn(test_fixture_fn_t fn)
{
	BUG_ON(fn && test_teardown_fn);
	test_teardown_fn = fn;
}

void
test_call_setup_fn(void)
{
	if (test_setup_fn)
		test_setup_fn();
}

void
test_call_teardown_fn(void)
{
	if (test_teardown_fn)
		test_teardown_fn();
}

TEST_SUITE(tfw_str);
TEST_SUITE(http_match);
TEST_SUITE(hash);
TEST_SUITE(cfg);

int
test_run_all(void)
{
	test_fail_counter = 0;

	TEST_SUITE_RUN(tfw_str);
	TEST_SUITE_RUN(http_match);
	TEST_SUITE_RUN(hash);
	TEST_SUITE_RUN(cfg);

	return test_fail_counter;
}
