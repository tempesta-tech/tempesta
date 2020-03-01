/**
 *		Tempesta TLS ECP unit test
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
#include "ttls_mocks.h"
/* mpool.c requires DHM routines. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../ecp_curves.c"
#include "../ecp.c"
#include "../mpool.c"

static void
ecp_mul(void)
{
	int i;
	TlsEcpGrp *grp;
	TlsEcpPoint *R, *P;
	TlsMpi *m;
	TlsMpiPool *mp;
	/* Exponents especially adapted for secp256r1, 32 bytes in size. */
	const char *exponents[] = {
		/* one */
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x01",

		/* N - 1 */
		"\xFF\xFF\xFF\xFF\x00\x00\x00\x00"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84"
		"\xF3\xB9\xCA\xC2\xFC\x63\x25\x50"

		/* random */
		"\x5E\xA6\xF3\x89\xA3\x8B\x8B\xC8"
		"\x1E\x76\x77\x53\xB1\x5A\xA5\x56"
		"\x9E\x17\x82\xE3\x0A\xBE\x7D\x25"
		"\x31\x28\xD2\xB4\xB1\xC9\x6B\x14",

		/* one and zeros */
		"\x40\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00",

		/* all ones */
		"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",

		/* 101010... */
		"\x55\x55\x55\x55\x55\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x55\x55\x55",
	};

	/* ttls_mpool() treats the pool as "handshake" pool. */
	EXPECT_FALSE(!(mp = ttls_mpi_pool_create(TTLS_MPOOL_ORDER, GFP_KERNEL)));

	EXPECT_FALSE(!(R = ttls_mpool_alloc_data(mp, sizeof(*R))));
	ttls_ecp_point_init(R);

	EXPECT_FALSE(!(P = ttls_mpool_alloc_data(mp, sizeof(*P))));
	ttls_ecp_point_init(P);

	EXPECT_FALSE(!(m = ttls_mpool_alloc_data(mp, sizeof(*m) + 4 * CIL)));
	ttls_mpi_init_next(m, 4);

	/* Use group from the MPI profile for Secp256r1 PK operations. */
	grp = MPI_POOL_TAIL_PTR(&cs_mp_ecdhe_secp256.mp);
	EXPECT_FALSE(!grp);
	EXPECT_EQ(grp->id, TTLS_ECP_DP_SECP256R1);
	EXPECT_EQ(grp->bits, 256);
	EXPECT_EQ(grp->P.used, 4);
	EXPECT_EQ(grp->P.limbs, 4);
	EXPECT_EQ(grp->P.s, 1);
	EXPECT_EQ(MPI_P(&grp->P)[0], 0xffffffffffffffff);
	EXPECT_EQ(MPI_P(&grp->P)[1], 0xffffffff);
	EXPECT_EQ(MPI_P(&grp->P)[2], 0);
	EXPECT_EQ(MPI_P(&grp->P)[3], 0xffffffff00000001);
	EXPECT_EQ(grp->A.used, 0);
	EXPECT_EQ(grp->A.limbs, 0);
	EXPECT_EQ(grp->A.s, 0);
	EXPECT_EQ(grp->B.used, 4);
	EXPECT_EQ(grp->B.limbs, 4);
	EXPECT_EQ(grp->B.s, 1);
	EXPECT_EQ(MPI_P(&grp->B)[0], 0x3bce3c3e27d2604b);
	EXPECT_EQ(MPI_P(&grp->B)[1], 0x651d06b0cc53b0f6);
	EXPECT_EQ(MPI_P(&grp->B)[2], 0xb3ebbd55769886bc);
	EXPECT_EQ(MPI_P(&grp->B)[3], 0x5ac635d8aa3a93e7);
	EXPECT_EQ(grp->N.used, 4);
	EXPECT_EQ(grp->N.limbs, 4);
	EXPECT_EQ(grp->N.s, 1);
	EXPECT_EQ(MPI_P(&grp->N)[0], 0xf3b9cac2fc632551);
	EXPECT_EQ(MPI_P(&grp->N)[1], 0xbce6faada7179e84);
	EXPECT_EQ(MPI_P(&grp->N)[2], 0xffffffffffffffff);
	EXPECT_EQ(MPI_P(&grp->N)[3], 0xffffffff00000000);
	EXPECT_EQ(grp->G.X.used, 4);
	EXPECT_EQ(grp->G.X.limbs, 4);
	EXPECT_EQ(grp->G.X.s, 1);
	EXPECT_EQ(MPI_P(&grp->G.X)[0], 0xf4a13945d898c296);
	EXPECT_EQ(MPI_P(&grp->G.X)[1], 0x77037d812deb33a0);
	EXPECT_EQ(MPI_P(&grp->G.X)[2], 0xf8bce6e563a440f2);
	EXPECT_EQ(MPI_P(&grp->G.X)[3], 0x6b17d1f2e12c4247);
	EXPECT_EQ(grp->G.Y.used, 4);
	EXPECT_EQ(grp->G.Y.limbs, 4);
	EXPECT_EQ(grp->G.Y.s, 1);
	EXPECT_EQ(MPI_P(&grp->G.Y)[0], 0xcbb6406837bf51f5);
	EXPECT_EQ(MPI_P(&grp->G.Y)[1], 0x2bce33576b315ece);
	EXPECT_EQ(MPI_P(&grp->G.Y)[2], 0x8ee7eb4a7c0f9e16);
	EXPECT_EQ(MPI_P(&grp->G.Y)[3], 0x4fe342e2fe1a7f9b);
	EXPECT_EQ(grp->G.Z.used, 1);
	EXPECT_EQ(grp->G.Z.limbs, grp->bits / BIL);
	EXPECT_EQ(grp->G.Z.s, 1);
	EXPECT_EQ(MPI_P(&grp->G.Z)[0], 1);

	/*
	 * ECP test #1 (constant op_count, base point G).
	 */
	/* Do a dummy multiplication first to trigger precomputation */
	ttls_mpi_lset(m, 2);
	EXPECT_ZERO(ttls_ecp_mul(grp, P, m, &grp->G, false));
	ttls_mpi_pool_cleanup_ctx(0, true);

	for (i = 0; i < ARRAY_SIZE(exponents); i++) {
		ttls_mpi_read_binary(m, exponents[i], 32);
		EXPECT_ZERO(ttls_ecp_mul(grp, R, m, &grp->G, false));
		/*
		 * ECP test #2 (constant op_count, other point).
		 * We computed P = 2G last time, use it.
		 */
		EXPECT_ZERO(ttls_ecp_mul(grp, R, m, P, false));

		ttls_mpi_pool_cleanup_ctx(0, false);
	}

	ttls_mpi_pool_free(R);
}

/* Leave the code to make mod_p384() test. */
#if 0
static void
ecp_mod256(void)
{
	TlsMpi *X;

	TlsEcpGrp *grp = MPI_POOL_TAIL_PTR(&cs_mp_ecdhe_secp256.mp);

	X = ttls_mpi_alloc_stack_init(8);
	ttls_mpi_lset(X, 0);

	X->used = 8;
	MPI_P(X)[0] = 1;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 1);
	EXPECT_TRUE(MPI_P(X)[0] == 1);
	EXPECT_TRUE(MPI_P(X)[1] == 0);
	EXPECT_TRUE(MPI_P(X)[2] == 0);
	EXPECT_TRUE(MPI_P(X)[4] == 0);

	X->used = 5;
	MPI_P(X)[0] = 1;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0;
	MPI_P(X)[4] = 1;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 2);
	EXPECT_TRUE(MPI_P(X)[1] == 0xffffffff00000000);
	EXPECT_TRUE(MPI_P(X)[2] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[3] == 0xfffffffe);

	X->used = 8;
	MPI_P(X)[0] = 0x0000000100000002;
	MPI_P(X)[1] = 0x0000000300000004;
	MPI_P(X)[2] = 0x0000000500000006;
	MPI_P(X)[3] = 0x0000000700000008;
	MPI_P(X)[4] = 0x000000090000000a;
	MPI_P(X)[5] = 0x0000000b0000000c;
	MPI_P(X)[6] = 0x0000000d0000000e;
	MPI_P(X)[7] = 0x0000000f00000011;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0xffffffdaffffffde);
	EXPECT_TRUE(MPI_P(X)[1] == 0x1fffffffed);
	EXPECT_TRUE(MPI_P(X)[2] == 0x3900000038);
	EXPECT_TRUE(MPI_P(X)[3] == 0x0c00000053);

	X->used = 8;
	MPI_P(X)[0] = 0x81049834a729f046;
	MPI_P(X)[1] = 0x8e8ccd3064d562a6;
	MPI_P(X)[2] = 0x9571db50f3374ad4;
	MPI_P(X)[3] = 0x9ce41a936065fb64;
	MPI_P(X)[4] = 0xc123e496517641f8;
	MPI_P(X)[5] = 0x77fc879a14c43d96;
	MPI_P(X)[6] = 0xa10f6b7f64496e90;
	MPI_P(X)[7] = 0x106c3d3c1c31371c;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0x24f66bf9203d7e0e);
	EXPECT_TRUE(MPI_P(X)[1] == 0xc521c13a23e947ff);
	EXPECT_TRUE(MPI_P(X)[2] == 0x939e9894443213e3);
	EXPECT_TRUE(MPI_P(X)[3] == 0x8d8574ff64476023);

	X->used = 8;
	MPI_P(X)[0] = 0xffffffffffffffff;
	MPI_P(X)[1] = 0xffffffffffffffff;
	MPI_P(X)[2] = 0xffffffffffffffff;
	MPI_P(X)[3] = 0xffffffffffffffff;
	MPI_P(X)[4] = 0xffffffff;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0xffffffffffffffff;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0x200000004);
	EXPECT_TRUE(MPI_P(X)[1] == 0xfffffffb00000000);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffdfffffffc);
	EXPECT_TRUE(MPI_P(X)[3] == 0x4fffffff9);

	X->used = 4;
	MPI_P(X)[0] = 0xaaaaaaaaaaaaaaaa;
	MPI_P(X)[1] = 0x5555555555555555;
	MPI_P(X)[2] = 0x7777777777777777;
	MPI_P(X)[3] = 0xffffffffffffffff;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0xaaaaaaaaaaaaaaab);
	EXPECT_TRUE(MPI_P(X)[1] == 0x5555555455555555);
	EXPECT_TRUE(MPI_P(X)[2] == 0x7777777777777777);
	EXPECT_TRUE(MPI_P(X)[3] == 0xfffffffe);

	X->used = 4;
	MPI_P(X)[0] = 0xffffffff00000001;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0xffffffff;
	MPI_P(X)[3] = 0xffffffffffffffff;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0xffffffff00000002);
	EXPECT_TRUE(MPI_P(X)[1] == 0xffffffff00000000);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffe);
	EXPECT_TRUE(MPI_P(X)[3] == 0xfffffffe);

	X->used = 8;
	MPI_P(X)[0] = 0;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0;
	MPI_P(X)[4] = 0xffffffffffffffff;
	MPI_P(X)[5] = 0xffffffffffffffff;
	MPI_P(X)[6] = 0xffffffffffffffff;
	MPI_P(X)[7] = 0xffffffffffffffff;
	ecp_modp(X, grp);
	EXPECT_EQ(X->used, 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0x2);
	EXPECT_TRUE(MPI_P(X)[1] == 0xfffffffcffffffff);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[3] == 0x3fffffffe);

	ttls_mpi_pool_free(X);
}
#endif

int
main(int argc, char *argv[])
{
	BUG_ON(ttls_mpool_init());

	ecp_mul();
	//ecp_mod256();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
