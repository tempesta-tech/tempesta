/**
 *		Tempesta FW
 *
 * Copyright (C) 2018 Tempesta Technologies, Inc.
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
#include <linux/types.h>
#include <asm/fpu/api.h>
#include <linux/bug.h>
#include <linux/kernel.h>

#include "kallsyms_helper.h"
#include "test.h"
#include "ttls.h"

#define DEFINE_TLS_TEST(name)						\
TEST(tls, name)								\
{									\
	int verbose = 1; /* Use 1 for verbose mode. */			\
	int (*tfn)(int) = get_sym_ptr("ttls_" #name "_self_test");	\
	if (!tfn) {							\
		TEST_FAIL("Cannot find ttls self test for %s", #name);	\
		return;							\
	}								\
	kernel_fpu_begin();						\
	EXPECT_ZERO(tfn(verbose));					\
	kernel_fpu_end();						\
}

DEFINE_TLS_TEST(ecp);
DEFINE_TLS_TEST(mpi);
DEFINE_TLS_TEST(rsa);
DEFINE_TLS_TEST(x509);

TEST_SUITE(tls)
{
	TEST_RUN(tls, ecp);
	TEST_RUN(tls, mpi);
	TEST_RUN(tls, rsa);
	TEST_RUN(tls, x509);
}
