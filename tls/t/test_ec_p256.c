/**
 *		Tempesta TLS EC NIST secp256r1 (prime256v1) unit test
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
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c" /* mpool.c requires DHM routines. */
#include "../asn1.c"
#include "../ec_p256.c"
#include "../ecp.c"
#include "../mpool.c"
#include "util.h"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP384_G = {};
const TlsEcpGrp CURVE25519_G = {};

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
		printf(" %#lxUL,", MPI_P(m)[i]);
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
ecp_base_math(void)
{
	int i;
	TlsMpi *A, *B, *T1, *T2, *X1, *X2;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(T1 = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(T2 = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(X1 = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(X2 = ttls_mpi_alloc_stack_init(8)));

	ecp256_mpi_lset(A, LONG_MAX);
	ecp256_mpi_lset(B, INT_MAX);
	for (i = 0; i < 1000; ++i) {
		/* 2 * B * 2 * A^2 = B * (2 * A)^2 */
		ecp256_sqr_mod(T1, A);
		ttls_mpi_shift_l(T1, T1, 1);
		ecp256_mod_add(T1);
		ecp256_mul_mod(X1, T1, B);
		ttls_mpi_shift_l(X1, X1, 1);
		ecp256_mod_add(X1);

		ttls_mpi_shift_l(T2, A, 1);
		ecp256_mod_add(T2);
		ecp256_sqr_mod(T2, T2);
		ecp256_mul_mod(X2, T2, B);

		EXPECT_ZERO(ttls_mpi_cmp_mpi(X1, X2));

		/* (2 * A^2)^2 * 2 = ((2 * A)^2)^2 / 2 */
		ecp256_sqr_mod(X1, T1);
		ttls_mpi_shift_l(X1, X1, 1);
		ecp256_mod_add(X1);

		ecp256_sqr_mod(X2, T2);
		mpi_div2_x86_64_4(MPI_P(X2), MPI_P(X2));

		EXPECT_ZERO(ttls_mpi_cmp_mpi(X1, X2));

		ecp256_mul_mod(A, A, T1);
		ecp256_mul_mod(B, B, T2);
	}

	ttls_mpi_pool_cleanup_ctx(0, false);
}

static void
ecp_multi_dbl(void)
{
	int i;
	TlsMpi *tmp, *t[8];
	TlsEcpPoint *r1, *r2;
	static const struct {
		unsigned long x[G_LIMBS];
		unsigned long y[G_LIMBS];
		unsigned long z[G_LIMBS];
		TlsEcpPoint p;
	} __attribute__((packed)) P = {
		.x = { 0xa60b48fc47669978UL, 0xc08969e277f21b35UL,
		       0x8a52380304b51ac3UL, 0x7cf27b188d034f7eUL },
		.y = { 0x9e04b79d227873d1UL, 0xba7dade63ce98229UL,
		       0x293d9ac69f7430dbUL, 0x7775510db8ed040UL },
		.z = { 1, 0, 0, 0 },
		.p = {
			.X = {
				.s	= 1,
				.used	= G_LIMBS,
				.limbs	= G_LIMBS,
				._off	= -3 * (short)(G_LIMBS * CIL)
			},
			.Y = {
				.s	= 1,
				.used	= G_LIMBS,
				.limbs	= G_LIMBS,
				._off	= -2 * (short)(G_LIMBS * CIL)
					  - (short)sizeof(TlsMpi)
			},
			.Z = {
				.s	= 1,
				.used	= 1,
				.limbs	= G_LIMBS,
				._off	= -1 * (short)(G_LIMBS * CIL)
					  - 2 * (short)sizeof(TlsMpi)
			}
		}
	};

	ttls_ecp_point_tmp_alloc_init(r1, G_LIMBS, G_LIMBS, G_LIMBS);
	ttls_mpi_alloc(&r1->X, G_LIMBS);
	ttls_mpi_alloc(&r1->Y, G_LIMBS);
	ttls_mpi_alloc(&r1->Z, G_LIMBS);

	ttls_ecp_point_tmp_alloc_init(r2, G_LIMBS, G_LIMBS, G_LIMBS);
	ttls_mpi_alloc(&r2->X, G_LIMBS);
	ttls_mpi_alloc(&r2->Y, G_LIMBS);
	ttls_mpi_alloc(&r2->Z, G_LIMBS);

	tmp = ttls_mpool_alloc_stack((sizeof(TlsMpi) + G_LIMBS * 2 * CIL) * 8);
	for (i = 0, t[0] = tmp; i < 8; i++) {
		TlsMpi *tt = ttls_mpi_init_next(t[i], G_LIMBS * 2);
		if (i < 7)
			t[i + 1] = tt;
	}

	ecp256_double_jac_n(r1, &P.p, t);

	ecp256_mpi_copy(&r2->X, &P.p.X);
	ecp256_mpi_copy(&r2->Y, &P.p.Y);
	ecp256_mpi_copy(&r2->Z, &P.p.Z);
	for (i = 0; i < D; i++)
		ecp256_double_jac(r2, r2);

	EXPECT_ZERO(ttls_mpi_cmp_mpi(&r1->X, &r2->X));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(&r1->Y, &r2->Y));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(&r1->Z, &r2->Z));

	ttls_mpi_pool_cleanup_ctx((unsigned long)tmp, false);
}

static void
ecp_mul(void)
{
	int i;
	const TlsEcpGrp *grp;
	TlsEcpPoint *R, *P;
	TlsMpi *m;
	TlsMpiPool *mp;
	unsigned long pXY[G_LIMBS * 2];
	/* Exponents especially adapted for secp256r1, 32 bytes in size. */
	struct {
		const char	*m;
		unsigned long	Xg[4];
		unsigned long	Yg[4];
		unsigned long	Xp[4];
		unsigned long	Yp[4];
	} mc[] = {
		{ /* one */
			"\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x01",
			{ 0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
			  0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL },
			{ 0xcbb6406837bf51f5UL, 0x2bce33576b315eceUL,
			  0x8ee7eb4a7c0f9e16UL, 0x4fe342e2fe1a7f9bUL },
			{ 0xa60b48fc47669978UL, 0xc08969e277f21b35UL,
			  0x8a52380304b51ac3UL, 0x7cf27b188d034f7eUL },
			{ 0x9e04b79d227873d1UL, 0xba7dade63ce98229UL,
			  0x293d9ac69f7430dbUL, 0x7775510db8ed040UL }
		},
		{ /* N - 1 */
			"\xFF\xFF\xFF\xFF\x00\x00\x00\x00"
			"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
			"\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84"
			"\xF3\xB9\xCA\xC2\xFC\x63\x25\x50",
			{ 0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
			  0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL },
			{ 0x3449bf97c840ae0aUL, 0xd431cca994cea131UL,
			  0x711814b583f061e9UL, 0xb01cbd1c01e58065UL },
			{ 0xa60b48fc47669978UL, 0xc08969e277f21b35UL,
			  0x8a52380304b51ac3UL, 0x7cf27b188d034f7eUL },
			{ 0x61fb4862dd878c2eUL, 0x4582521ac3167dd6UL,
			  0xd6c26539608bcf24UL, 0xf888aaee24712fc0UL }
		},
		{ /* random */
			"\x5E\xA6\xF3\x89\xA3\x8B\x8B\xC8"
			"\x1E\x76\x77\x53\xB1\x5A\xA5\x56"
			"\x9E\x17\x82\xE3\x0A\xBE\x7D\x25"
			"\x31\x28\xD2\xB4\xB1\xC9\x6B\x14",
			{ 0x9c7f30f30319e045UL, 0x92ab9c5645d8586cUL,
			  0xfd36a1cfd4888860UL, 0x43f16b56ef44340UL },
			{ 0x2f359cffb23dcee8UL, 0xb6f6cdc219e18f1UL,
			  0x9b77e16b67d8b77aUL, 0xa06bbcc42fdf583bUL },
			{ 0xb58dc5314d2bce6dUL, 0x2184c1245ba4a26fUL,
			  0x9a974f76c97508c2UL, 0xa84080d38a36f131UL },
			{ 0x994cb221c43c8388UL, 0x662818239061933UL,
			  0xedad077efcc307daUL, 0x8273d22c4f8eff78UL }
		},
		{ /* one and zeros */
			"\x40\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00"
			"\x00\x00\x00\x00\x00\x00\x00\x00",
			{ 0x8d93ca698eb99805UL, 0xad086d4ce99a11e3UL,
			  0xb0c2bf930bf33a68UL, 0x1ee7fc202708cfeUL },
			{ 0x9fd5f4e10eeccafUL, 0x811836ea35be799bUL,
			  0x124be02ef3455711UL, 0x9655cef01b024882UL },
			{ 0xb52dec8f375f2b54UL, 0x4efe3560e3e92350UL,
			  0x5066e911891524bcUL, 0x77b20a912e6b2313UL },
			{ 0xcaa801fcd6cc67ffUL, 0xdf623da1e850e0f1UL,
			  0xf7b10bfcdd038a72UL, 0xa3dc291825cea3f7UL }
		},
		{ /* all ones */
			"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
			"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
			"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
			"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
			{ 0xad946b700aa2613aUL, 0xada3f05e4cf412f2UL,
			  0xcbe299ec2cc9cc2dUL, 0xc1d17269e46e387aUL },
			{ 0x5f5fb84162909dbbUL, 0x9d111f69129c24dbUL,
			  0xf49957d54ff79811UL, 0xedb7744f370c13a4UL },
			{ 0x11f665299feb7b34UL, 0x36ee523e0b590bf5UL,
			  0xf48246ce0a1422aaUL, 0x19f3f57b530c7fdcUL },
			{ 0xd83a044fc38674c4UL, 0x3c0142705daadbbbUL,
			  0xd2b0d93bd5053e99UL, 0x2b6adb6b9b89332fUL }
		},
		{ /* 101010... */
			"\x55\x55\x55\x55\x55\x55\x55\x55"
			"\x55\x55\x55\x55\x55\x55\x55\x55"
			"\x55\x55\x55\x55\x55\x55\x55\x55"
			"\x55\x55\x55\x55\x55\x55\x55\x55",
			{ 0xa447b7d3d762ab34UL, 0x9caf56d458682fcUL,
			  0xfe7acf2842ed9870UL, 0x57e977f6db7e33c3UL },
			{ 0x68e5f59cc471c2ecUL, 0x346dfa84dec4db4dUL,
			  0xf5414065640ffb5bUL, 0xc5ab3770ba573bdfUL },
			{ 0x91ae8f5db486b7dbUL, 0x795dda3b90bb5b07UL,
			  0x12426320ee53a94cUL, 0x38014c603c89da97UL },
			{ 0x738cbc8294706c96UL, 0xac834bcd61541b90UL,
			  0x6566f66590f89ea2UL, 0x25e3aa368ede37b9UL }
		}
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
	grp = &SECP256_G;
	EXPECT_FALSE(!grp);
	EXPECT_EQ(grp->id, TTLS_ECP_DP_SECP256R1);
	EXPECT_EQ(grp->bits, 256);
	EXPECT_EQ(G.P.used, 4);
	EXPECT_EQ(G.P.limbs, 4);
	EXPECT_EQ(G.P.s, 1);
	EXPECT_MPI(&G.P, 4, 0xffffffffffffffffUL, 0xffffffffUL,
			    0, 0xffffffff00000001UL);
	EXPECT_EQ(G.B.limbs, 4);
	EXPECT_EQ(G.B.s, 1);
	EXPECT_MPI(&G.B, 4, 0x3bce3c3e27d2604bUL, 0x651d06b0cc53b0f6UL,
			    0xb3ebbd55769886bcUL, 0x5ac635d8aa3a93e7);
	EXPECT_EQ(G.N.limbs, 4);
	EXPECT_EQ(G.N.s, 1);
	EXPECT_MPI(&G.N, 4, 0xf3b9cac2fc632551UL, 0xbce6faada7179e84UL,
			    0xffffffffffffffffUL, 0xffffffff00000000UL);
	EXPECT_EQ(G.G.X.limbs, 4);
	EXPECT_EQ(G.G.X.s, 1);
	EXPECT_MPI(&G.G.X, 4, 0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
			      0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL);
	EXPECT_EQ(G.G.Y.limbs, 4);
	EXPECT_EQ(G.G.Y.s, 1);
	EXPECT_MPI(&G.G.Y, 4, 0xcbb6406837bf51f5UL, 0x2bce33576b315eceUL,
			      0x8ee7eb4a7c0f9e16UL, 0x4fe342e2fe1a7f9bUL);
	EXPECT_EQ(G.G.Z.used, 1);
	EXPECT_EQ(G.G.Z.limbs, grp->bits / BIL);
	EXPECT_EQ(G.G.Z.s, 1);
	EXPECT_EQ(MPI_P(&G.G.Z)[0], 1);

	/*
	 * ECP test #1 (constant op_count, base point G).
	 */
	/* Do a dummy multiplication first to trigger precomputation */
	ecp256_mpi_lset(m, 2);
	EXPECT_ZERO(ecp256_mul_comb_g(P, m));
	EXPECT_MPI(&P->X, 4, 0xa60b48fc47669978UL, 0xc08969e277f21b35UL,
			     0x8a52380304b51ac3UL, 0x7cf27b188d034f7eUL);
	EXPECT_MPI(&P->Y, 4, 0x9e04b79d227873d1UL, 0xba7dade63ce98229UL,
			     0x293d9ac69f7430dbUL, 0x7775510db8ed040UL);
	EXPECT_MPI(&P->Z, 1, 1);
	ttls_mpi_pool_cleanup_ctx(0, true);

	for (i = 0; i < ARRAY_SIZE(mc); i++) {
		ttls_mpi_read_binary(m, mc[i].m, 32);

		EXPECT_ZERO(ecp256_mul_comb_g(R, m));
		EXPECT_MPI(&R->X, 4, mc[i].Xg[0], mc[i].Xg[1],
				     mc[i].Xg[2], mc[i].Xg[3]);
		EXPECT_MPI(&R->Y, 4, mc[i].Yg[0], mc[i].Yg[1],
				     mc[i].Yg[2], mc[i].Yg[3]);
		EXPECT_MPI(&R->Z, 1, 1);

		/*
		 * ECP test #2 (constant op_count, other point).
		 * We computed P = 2G last time, use it.
		 */
		memcpy(pXY, MPI_P(&P->X), G_LIMBS * CIL);
		memcpy(&pXY[G_LIMBS], MPI_P(&P->Y), G_LIMBS * CIL);
		EXPECT_ZERO(grp->mul(R, m, pXY));
		EXPECT_MPI(&R->X, 4, mc[i].Xp[0], mc[i].Xp[1],
				     mc[i].Xp[2], mc[i].Xp[3]);
		EXPECT_MPI(&R->Y, 4, mc[i].Yp[0], mc[i].Yp[1],
				     mc[i].Yp[2], mc[i].Yp[3]);
		EXPECT_MPI(&R->Z, 1, 1);

		ttls_mpi_pool_cleanup_ctx(0, false);
	}

	ttls_mpi_pool_free(R);
}

static void
ecp_inv(void)
{
	TlsMpi *A, *X;

	A = ttls_mpi_alloc_stack_init(4);
	X = ttls_mpi_alloc_stack_init(8);

	ttls_mpi_copy(A, &G.P);
	ttls_mpi_sub_int(A, A, 1);
	ecp256_inv_mod(X, A, &G.P);
	EXPECT_MPI(X, 4, 0xfffffffffffffffeUL, 0xffffffffUL,
			 0UL, 0xffffffff00000001UL);

	ttls_mpi_copy(A, &G.N);
	ttls_mpi_sub_int(A, A, 1);
	ecp256_inv_mod(X, A, &G.N);
	EXPECT_MPI(X, 4, 0xf3b9cac2fc632550UL, 0xbce6faada7179e84UL,
			 0xffffffffffffffffUL, 0xffffffff00000000UL);

	ecp256_mpi_lset(A, 1);
	ecp256_inv_mod(X, A, &G.P);
	EXPECT_MPI(X, 1, 1);

	ecp256_inv_mod(X, A, &G.N);
	EXPECT_MPI(X, 1, 1);

	ttls_mpi_add_int(A, A, LONG_MAX);
	ecp256_inv_mod(X, A, &G.P);
	EXPECT_MPI(X, 4, 0x200000000UL, 0UL, 0xfffffffe00000002UL, 0x1UL);

	ecp256_inv_mod(X, A, &G.N);
	EXPECT_MPI(X, 4, 0x52483a7dde617e67UL, 0xd7bb2ccbb87235cbUL,
			 0xbda218b7dc01789dUL, 0x99a39155425de748UL);

	ttls_mpi_add_int(A, A, LONG_MAX);
	ecp256_inv_mod(X, A, &G.P);
	EXPECT_MPI(X, 4, 0xfffffffffffffffdUL, 0x1fffffffdUL,
			 0xfffffffeUL, 0xffffffff00000000UL);

	ecp256_inv_mod(X, A, &G.N);
	EXPECT_MPI(X, 4, 0x59e3e70f9bf9a3e6UL, 0xfac1e065553149e5UL,
			 0x2791bfd535e466eUL, 0x1d702a231af70e26UL);

	ttls_mpi_add_int(A, A, LONG_MAX);
	ttls_mpi_add_int(A, A, LONG_MAX);
	ecp256_inv_mod(X, A, &G.P);
	EXPECT_MPI(X, 4, 0x9954071d2477fa15UL, 0xec6ab5536da55163UL,
			 0x4847238cafc4d9cfUL, 0x65fe0aab50b5ec75UL);

	ecp256_inv_mod(X, A, &G.N);
	EXPECT_MPI(X, 4, 0xd11600bf3e0b05dbUL, 0x5e27c81f75e59425UL,
			 0xb6deccbfe7ee2dcfUL, 0xc6f83f8273959285UL);

	ttls_mpi_shift_l(A, A, 100);
	ecp256_inv_mod(X, A, &G.P);
	EXPECT_MPI(X, 4, 0x4918e0ed10e2af6UL, 0x3752de692b5ec74fUL,
			 0x1f8c9445bdada17bUL, 0x86da5515b2baeb5cUL);

	ecp256_inv_mod(X, A, &G.N);
	EXPECT_MPI(X, 4, 0xeac6e35f6e2e6ac1UL, 0xff76efdf47c1a0a9UL,
			 0x152a4e13984f9845UL, 0x510a62612850ec16UL);

	ttls_mpi_pool_cleanup_ctx((unsigned long)A, false);
}

int
main(int argc, char *argv[])
{
	BUG_ON(ttls_mpool_init());

	ecp_base_math();
	ecp_multi_dbl();
	ecp_mul();
	ecp_inv();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
