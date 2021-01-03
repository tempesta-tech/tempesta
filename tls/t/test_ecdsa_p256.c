/**
 *		Tempesta TLS ECDSA/secp256r1 signature unit test
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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
#include "ttls_mocks.h"
/* mpool.c requires ECP and DHM routines. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../asn1.c"
#include "../ec_p256.c"
#include "../ecp.c"
#include "../pk.c"
#include "../mpool.c"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP384_G = {};
const TlsEcpGrp CURVE25519_G = {};

#define EC_Qx								   \
	"\xB8\x81\xE6\x91\x1E\xAD\xA2\x23\x61\xC5\x48\x7D\x77\xC6\xD2\x49" \
	"\xDD\x38\xFF\xF8\xF7\x5E\xC2\x8D\x08\xFA\x02\x5B\x8C\xD4\xCE\x5B"

#define EC_Qy								   \
	"\x80\xDF\x24\x74\xAB\x78\x97\x59\xF4\x09\x6A\x6C\xFD\xD4\x26\xD5" \
	"\x32\x6D\x6B\xC3\xEA\x6F\xB5\x02\x2B\x1E\x7A\xB6\x79\x43\x62\x6A"

#define EC_d								   \
	"\xC7\x1C\xBC\x8A\xCA\x38\xF7\xC9\x97\xF9\x3A\x6C\xBD\xFD\xCF\x7F" \
	"\x4C\x9D\x32\xAA\x35\x1F\x49\xDB\xF4\x7D\x72\xD6\x64\x2F\x06\xDC"

/**
 * Check that a point is valid as a public key.
 *
 * This function only checks the point is non-zero, has valid coordinates and
 * lies on the curve, but not that it is indeed a multiple of G. This is
 * additional check is more expensive, isn't required by standards, and
 * shouldn't be necessary if the group used has a small cofactor. In particular,
 * it is useless for the NIST groups which all have a cofactor of 1.
 *
 * Uses bare components rather than an TlsEcpKeypair structure in order to ease
 * use with other structures such as TlsECDHCtx of TlsEcpKeypair.
 */
static void
ecp256_check_pubkey(const TlsEcpGrp *grp, const TlsEcpPoint *pt)
{
	unsigned long RHS[G_LIMBS * 2], YY[G_LIMBS * 2], A[G_LIMBS];

	/* Must use affine coordinates */
	BUG_ON(ttls_mpi_cmp_int(&pt->Z, 1));

	if (grp->id == TTLS_ECP_DP_CURVE25519) {
		/*
		 * Check validity of a public key for Montgomery curves with
		 * x-only schemes. [Curve25519 p. 5] Just check X is the correct
		 * number of bytes.
		 */
		BUG_ON(ttls_mpi_size(&pt->X) > (grp->bits + 7) / 8);
	}

	/*
	 * Check that an affine point is valid as a public key,
	 * short Weierstrass curves (SEC1 3.2.3.1).
	 *
	 * pt coordinates must be normalized for our checks.
	 */
	BUG_ON(mpi_cmp_x86_64_4(MPI_P(&pt->X), MPI_P(&G.P)) >= 0
	       || mpi_cmp_x86_64_4(MPI_P(&pt->Y), MPI_P(&G.P)) >= 0);

	/*
	 * YY = Y^2
	 * RHS = X (X^2 + A) + B = X^3 + A X + B
	 */
	mpi_sqr_mod_p256_x86_64_4(YY, MPI_P(&pt->Y));
	mpi_sqr_mod_p256_x86_64_4(RHS, MPI_P(&pt->X));

	/* Special case for A = -3 */
	ecp256_lset(A, 3);
	mpi_sub_mod_p256_x86_64_4(RHS, RHS, A);
	mpi_mul_mod_p256_x86_64_4(RHS, RHS, MPI_P(&pt->X));
	mpi_add_mod_p256_x86_64(RHS, RHS, MPI_P(&G.B));

	BUG_ON(mpi_cmp_x86_64_4(YY, RHS));
}

static void
ecdsa_sign(void)
{
	TlsMpiPool *mp;
	TlsEcpKeypair *ctx;
	size_t slen;
	char hash[32] = {1}, sig[80] = {0};

	EXPECT_FALSE(!(mp = ttls_mpi_pool_create(0, GFP_KERNEL)));

	EXPECT_FALSE(!(ctx = ttls_mpool_alloc_data(mp, sizeof(*ctx))));

	EXPECT_FALSE(!(ctx->grp = ttls_ecp_group_lookup(TTLS_ECP_DP_SECP256R1)));

	ttls_mpi_read_binary(&ctx->Q.X, EC_Qx, 32);
	ttls_mpi_read_binary(&ctx->Q.Y, EC_Qy, 32);
	ttls_mpi_lset(&ctx->Q.Z, 1);
	ttls_mpi_read_binary(&ctx->d, EC_d, 32);

	EXPECT_ZERO(ctx->grp->ecdsa_sign(&ctx->d, hash, 32, sig, &slen));
	EXPECT_EQ(slen, 71);
	EXPECT_ZERO(memcmp(sig, "\x30\x45\x02\x20\x38\x01\x4C\x60", 8));
	EXPECT_ZERO(memcmp(sig + 24, "\x90\xBB\x5B\x07\x91\xAE\x8F\x5D", 8));
	EXPECT_ZERO(memcmp(sig + 64, "\x09\xA2\x46\xFC\xF7\x14\x2D\x00", 8));
	EXPECT_ZERO(memcmp(sig + 72, "\x00\x00\x00\x00\x00\x00\x00\x00", 8));

	ecp256_check_pubkey(ctx->grp, &ctx->Q);
	EXPECT_ZERO(ecdsa_verify_wrap(ctx, TTLS_MD_SHA256, hash, 32, sig, slen));

	ttls_mpi_pool_free(ctx);
}

int
main(int argc, char *argv[])
{
	BUG_ON(ttls_mpool_init());

	ecdsa_sign();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
