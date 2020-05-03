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
#include "util.h"
/* mpool.c requires DHM routines. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../ecp_curves.c"
#include "../ecp.c"
#include "../mpool.c"

#ifdef DEBUG
/*
 * Use another version of ttls_mpi_dump() to print MPIs suitable for
 * copy & paste as values into the C code.
 */
static void __attribute__((unused))
__mpi_dump(const TlsMpi *m, const char *prefix)
{
	int i;

	printf("  %s:", prefix);
	for (i = 0; i < m->used; ++i)
		printf(" %#lx", MPI_P(m)[i]);
	printf("\n");
}

static void __attribute__((unused))
__ecp_dump(const TlsEcpPoint *p, const char *prefix)
{
	printf("DUMP %s:\n", prefix);
	__mpi_dump(&p->X, "X");
	__mpi_dump(&p->Y, "Y");
	__mpi_dump(&p->Z, "Z");
}
#endif

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
	EXPECT_EQ(grp->B.limbs, 4);
	EXPECT_EQ(grp->B.s, 1);
	EXPECT_MPI(&grp->B, 4, 0x3bce3c3e27d2604bUL, 0x651d06b0cc53b0f6UL,
			       0xb3ebbd55769886bcUL, 0x5ac635d8aa3a93e7);
	EXPECT_EQ(grp->N.limbs, 4);
	EXPECT_EQ(grp->N.s, 1);
	EXPECT_MPI(&grp->N, 4, 0xf3b9cac2fc632551UL, 0xbce6faada7179e84UL,
			       0xffffffffffffffffUL, 0xffffffff00000000UL);
	EXPECT_EQ(grp->G.X.limbs, 4);
	EXPECT_EQ(grp->G.X.s, 1);
	EXPECT_MPI(&grp->G.X, 4, 0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
				 0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL);
	EXPECT_EQ(grp->G.Y.limbs, 4);
	EXPECT_EQ(grp->G.Y.s, 1);
	EXPECT_MPI(&grp->G.Y, 4, 0xcbb6406837bf51f5UL, 0x2bce33576b315eceUL,
				 0x8ee7eb4a7c0f9e16UL, 0x4fe342e2fe1a7f9bUL);
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

int
main(int argc, char *argv[])
{
	BUG_ON(ttls_mpool_init());

	ecp_mul();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
