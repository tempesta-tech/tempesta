/**
 *		Tempesta TLS ECDSA signature unit test
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
#include "../asn1parse.c"
#include "../asn1write.c"
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../ecp.c"
#include "../ecp_curves.c"
#include "../ecdsa.c"
#include "../mpool.c"

#define EC_Qx								   \
	"\xB8\x81\xE6\x91\x1E\xAD\xA2\x23\x61\xC5\x48\x7D\x77\xC6\xD2\x49" \
	"\xDD\x38\xFF\xF8\xF7\x5E\xC2\x8D\x08\xFA\x02\x5B\x8C\xD4\xCE\x5B"

#define EC_Qy								   \
	"\x80\xDF\x24\x74\xAB\x78\x97\x59\xF4\x09\x6A\x6C\xFD\xD4\x26\xD5" \
	"\x32\x6D\x6B\xC3\xEA\x6F\xB5\x02\x2B\x1E\x7A\xB6\x79\x43\x62\x6A"

#define EC_d								   \
	"\xC7\x1C\xBC\x8A\xCA\x38\xF7\xC9\x97\xF9\x3A\x6C\xBD\xFD\xCF\x7F" \
	"\x4C\x9D\x32\xAA\x35\x1F\x49\xDB\xF4\x7D\x72\xD6\x64\x2F\x06\xDC"

static void
ecdsa_sign(void)
{
	TlsMpiPool *mp;
	TlsEcpKeypair *ctx;
	size_t slen;
	char hash[32] = {1}, sig[80] = {0};

	EXPECT_FALSE(!(mp = ttls_mpi_pool_alloc(TTLS_MPOOL_ORDER, GFP_KERNEL)));

	EXPECT_FALSE(!(ctx = ttls_mpool_alloc_data(mp, sizeof(*ctx))));

	EXPECT_ZERO(ttls_ecp_group_load(&ctx->grp, TTLS_ECP_DP_SECP256R1));
	/* See __mpi_profile_load_ec() for Secp256r1. */
	EXPECT_ZERO(ecp_precompute_comb(&ctx->grp, ctx->grp.T, &ctx->grp.G,
					5, (ctx->grp.nbits + 4) / 5));

	EXPECT_ZERO(ttls_mpi_read_binary(&ctx->Q.X, EC_Qx, 32));
	EXPECT_ZERO(ttls_mpi_read_binary(&ctx->Q.Y, EC_Qy, 32));
	EXPECT_ZERO(ttls_mpi_lset(&ctx->Q.Z, 1));
	EXPECT_ZERO(ttls_mpi_read_binary(&ctx->d, EC_d, 32));

	EXPECT_ZERO(ttls_ecdsa_write_signature(ctx, hash, 32, sig, &slen));
	EXPECT_EQ(slen, 71);
	EXPECT_ZERO(memcmp(sig, "\x30\x45\x02\x20\x38\x01\x4C\x60", 8));
	EXPECT_ZERO(memcmp(sig + 24, "\x90\xBB\x5B\x07\x91\xAE\x8F\x5D", 8));
	EXPECT_ZERO(memcmp(sig + 64, "\x09\xA2\x46\xFC\xF7\x14\x2D\x00", 8));
	EXPECT_ZERO(memcmp(sig + 72, "\x00\x00\x00\x00\x00\x00\x00\x00", 8));
	EXPECT_ZERO(ttls_ecdsa_read_signature(ctx, hash, 32, sig, slen));

	ttls_mpi_pool_free(ctx);
}

int
main(int argc, char *argv[])
{
	/*
	 * The test works in process context, so cfg_pool is used
	 * for all the MPI computations.
	 */
	BUG_ON(ttls_mpool_init());

	ecdsa_sign();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
