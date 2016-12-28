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
#include <asm/fpu/api.h>
#include <linux/module.h>
#include "test.h"

#include "apm.c"
#include "vhost.c"

int test_fail_counter;
test_fixture_fn_t test_setup_fn;
test_fixture_fn_t test_teardown_fn;

/* TODO: run tests with logging disabled, and re-run the failed test
 *       with enabled logs.
 *
 * The problem with logging is that it is hard to find a real error
 * message among all logs generated during a test run.
 * That happens because:
 *  - Some tests intentionally make calls with invalid input data.
 *    The code generates TFW_ERR() messages indistinguishable from
 *    real errors.
 *  - Overall, there is a lot of debugging output, and usually you
 *    don't need it unless the test is failed.
 *
 * The proposed solution is to register our own Tempesta FW logger and
 * suppress all messages until a test is failed. When a failure happens,
 * we can re-run the failed test and print all the log messages, and
 * thus avoid all this noise in the test log.
 *
 * Currently the Tempesta FW logger module interface is not established
 * yet, so here is just a BUG() that terminates the the testing process.
 * It doesn't prevent flooding, but at least it makes interesting
 * messages appear at the end of the log where they can be found easily.
 */
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

TEST_SUITE(cfg);
TEST_SUITE(tfw_str);
TEST_SUITE(http_parser);
TEST_SUITE(http_sticky);
TEST_SUITE(http_match);
TEST_SUITE(hash);
TEST_SUITE(addr);
TEST_SUITE(sched_rr);
TEST_SUITE(sched_hash);
TEST_SUITE(sched_http);

int
test_run_all(void)
{
	test_fail_counter = 0;

	/* Run sleeping tests first. */
	TEST_SUITE_RUN(cfg);

	kernel_fpu_begin();
	tfw_str_init_const();

	/*
	 * Preemption is diabled by kernel_fpu_begin(), so
	 * the tests can not sleep.
	 */
	TEST_SUITE_RUN(tfw_str);
	TEST_SUITE_RUN(http_parser);
	TEST_SUITE_RUN(http_match);
	TEST_SUITE_RUN(http_sticky);
	TEST_SUITE_RUN(hash);
	TEST_SUITE_RUN(addr);
	TEST_SUITE_RUN(sched_rr);
	TEST_SUITE_RUN(sched_hash);
	TEST_SUITE_RUN(sched_http);

	kernel_fpu_end();

	return test_fail_counter;
}
