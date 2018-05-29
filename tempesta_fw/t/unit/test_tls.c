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

DEFINE_TLS_TEST(aes);
DEFINE_TLS_TEST(arc4);
DEFINE_TLS_TEST(base64);
DEFINE_TLS_TEST(camellia);
DEFINE_TLS_TEST(ccm);
DEFINE_TLS_TEST(cmac);
DEFINE_TLS_TEST(ctr_drbg);
DEFINE_TLS_TEST(des);
DEFINE_TLS_TEST(dhm);
DEFINE_TLS_TEST(ecjpake);
DEFINE_TLS_TEST(ecp);
DEFINE_TLS_TEST(entropy);
DEFINE_TLS_TEST(gcm);
DEFINE_TLS_TEST(hmac_drbg);
DEFINE_TLS_TEST(md2);
DEFINE_TLS_TEST(md4);
DEFINE_TLS_TEST(md5);
DEFINE_TLS_TEST(mpi);
DEFINE_TLS_TEST(pkcs5);
DEFINE_TLS_TEST(ripemd160);
DEFINE_TLS_TEST(rsa);
DEFINE_TLS_TEST(sha1);
DEFINE_TLS_TEST(sha256);
DEFINE_TLS_TEST(sha512);
DEFINE_TLS_TEST(x509);
DEFINE_TLS_TEST(xtea);

TEST_SUITE(tls)
{
	TEST_RUN(tls, aes);
	TEST_RUN(tls, arc4);
	TEST_RUN(tls, base64);
	TEST_RUN(tls, camellia);
	TEST_RUN(tls, ccm);
	TEST_RUN(tls, cmac);
	TEST_RUN(tls, ctr_drbg);
	TEST_RUN(tls, des);
	TEST_RUN(tls, dhm);
	TEST_RUN(tls, ecjpake);
	TEST_RUN(tls, ecp);
	TEST_RUN(tls, entropy);
	TEST_RUN(tls, gcm);
	TEST_RUN(tls, hmac_drbg);
	TEST_RUN(tls, md2);
	TEST_RUN(tls, md4);
	TEST_RUN(tls, md5);
	TEST_RUN(tls, mpi);
	TEST_RUN(tls, pkcs5);
	TEST_RUN(tls, ripemd160);
	TEST_RUN(tls, rsa);
	TEST_RUN(tls, sha1);
	TEST_RUN(tls, sha256);
	TEST_RUN(tls, sha512);
	TEST_RUN(tls, x509);
	TEST_RUN(tls, xtea);
}
