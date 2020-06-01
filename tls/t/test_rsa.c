/**
 *		Tempesta TLS RSA signature unit test
 *
 * Copyright (C) 2018-2020 Tempesta Technologies, Inc.
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
#define RSA_TEST
#include "ttls_mocks.h"
/* mpool.c requires ECP and DHM routines. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../ecp.c"
#include "../mpool.c"
#include "../rsa.c"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP256_G = {};
const TlsEcpGrp SECP384_G = {};
const TlsEcpGrp CURVE25519_G = {};

/*
 * Example RSA-1024 keypair, for test purposes.
 */
#define KEY_LEN	128
#define PT_LEN  (256 / 8) /* SHA256 size, 32 bytes */

#define RSA_N								   \
	"\x92\x92\x75\x84\x53\x06\x3D\x80\x3D\xD6\x03\xD5\xE7\x77\xD7\x88" \
	"\x8E\xD1\xD5\xBF\x35\x78\x61\x90\xFA\x2F\x23\xEB\xC0\x84\x8A\xEA" \
	"\xDD\xA9\x2C\xA6\xC3\xD8\x0B\x32\xC4\xD1\x09\xBE\x0F\x36\xD6\xAE" \
	"\x71\x30\xB9\xCE\xD7\xAC\xDF\x54\xCF\xC7\x55\x5A\xC1\x4E\xEB\xAB" \
	"\x93\xA8\x98\x13\xFB\xF3\xC4\xF8\x06\x6D\x2D\x80\x0F\x7C\x38\xA8" \
	"\x1A\xE3\x19\x42\x91\x74\x03\xFF\x49\x46\xB0\xA8\x3D\x3D\x3E\x05" \
	"\xEE\x57\xC6\xF5\xF5\x60\x6F\xB5\xD4\xBC\x6C\xD3\x4E\xE0\x80\x1A" \
	"\x5E\x94\xBB\x77\xB0\x75\x07\x23\x3A\x0B\xC7\xBA\xC8\xF9\x0F\x79"

#define RSA_E	"\x01\x00\x01"

#define RSA_D								   \
	"\x24\xBF\x61\x85\x46\x87\x86\xFD\xD3\x03\x08\x3D\x25\xE6\x4E\xFC" \
	"\x66\xCA\x47\x2B\xC4\x4D\x25\x31\x02\xF8\xB4\xA9\xD3\xBF\xA7\x50" \
	"\x91\x38\x6C\x00\x77\x93\x7F\xE3\x3F\xA3\x25\x2D\x28\x85\x58\x37" \
	"\xAE\x1B\x48\x4A\x8A\x9A\x45\xF7\xEE\x8C\x0C\x63\x4F\x99\xE8\xCD" \
	"\xDF\x79\xC5\xCE\x07\xEE\x72\xC7\xF1\x23\x14\x21\x98\x16\x42\x34" \
	"\xCA\xBB\x72\x4C\xF7\x8B\x81\x73\xB9\xF8\x80\xFC\x86\x32\x24\x07" \
	"\xAF\x1F\xED\xFD\xDE\x2B\xEB\x67\x4C\xA1\x5F\x3E\x81\xA1\x52\x1E" \
	"\x07\x15\x13\xA1\xE8\x5B\x5D\xFA\x03\x1F\x21\xEC\xAE\x91\xA3\x4D"

#define RSA_P								   \
	"\xC3\x6D\x0E\xB7\xFC\xD2\x85\x22\x3C\xFB\x5A\xAB\xA5\xBD\xA3\xD8" \
	"\x2C\x01\xCA\xD1\x9E\xA4\x84\xA8\x7E\xA4\x37\x76\x37\xE7\x55\x00" \
	"\xFC\xB2\x00\x5C\x5C\x7D\xD6\xEC\x4A\xC0\x23\xCD\xA2\x85\xD7\x96" \
	"\xC3\xD9\xE7\x5E\x1E\xFC\x42\x48\x8B\xB4\xF1\xD1\x3A\xC3\x0A\x57"

#define RSA_Q								   \
	"\xC0\x00\xDF\x51\xA7\xC7\x7A\xE8\xD7\xC7\x37\x0C\x1F\xF5\x5B\x69" \
	"\xE2\x11\xC2\xB9\xE5\xDB\x1E\xD0\xBF\x61\xD0\xD9\x89\x96\x20\xF4" \
	"\x91\x0E\x41\x68\x38\x7E\x3C\x30\xAA\x1E\x00\xC3\x39\xA7\x95\x08" \
	"\x84\x52\xDD\x96\xA9\xA5\xEA\x5D\x9D\xCA\x68\xDA\x63\x60\x32\xAF"

#define RSA_PT								   \
	"\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF\x11\x22\x33\x0A" \
	"\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD\x84\xF7\x55\xF0\x40\x88\x3C\x96"

static void
rsa_sign(void)
{
	TlsMpiPool *mp;
	TlsRSACtx *rsa;
	unsigned char hash[PT_LEN], sig[KEY_LEN];

	EXPECT_FALSE(!(mp = ttls_mpi_pool_create(TTLS_MPOOL_ORDER, GFP_KERNEL)));
	EXPECT_FALSE(!(rsa = ttls_mpool_alloc_data(mp, sizeof(TlsRSACtx))));
	memset(rsa, 0, sizeof(TlsRSACtx));
	ttls_rsa_init(rsa, TTLS_RSA_PKCS_V15, 0);

	EXPECT_ZERO(ttls_rsa_import_raw(rsa, RSA_N, 128, RSA_P, 64, RSA_Q, 64,
					RSA_D, 128, RSA_E, 3));

	EXPECT_ZERO(ttls_rsa_check_pubkey(rsa));

	/* Run-time (softirq) logic. */
	kernel_fpu_begin();

	memcpy(hash, RSA_PT, PT_LEN);
	EXPECT_ZERO(ttls_rsa_pkcs1_sign(rsa, TTLS_MD_SHA256, hash, PT_LEN, sig));
	EXPECT_ZERO(ttls_rsa_pkcs1_verify(rsa, TTLS_MD_SHA256, PT_LEN, hash,
					  sig));

	kernel_fpu_end();

	ttls_rsa_free(rsa);
	ttls_mpi_pool_free(rsa);
}

int
main(int argc, char *argv[])
{
	/*
	 * The test works in process context, so cfg_pool is used
	 * for all the MPI computations.
	 */
	BUG_ON(ttls_mpool_init());

	rsa_sign();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
