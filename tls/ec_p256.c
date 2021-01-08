/**
 *		Tempesta TLS
 *
 * Elliptic curve NIST secp256r1 (prime256v1) over GF(p) in short Weierstrass
 * form, y^2 = x^3 - 3*x + b.
 *
 * References:
 *
 * 1. SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *
 * 2. GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 *
 * 3. FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 *
 * 4. RFC 8422 for the related TLS structures and constants
 *
 * 5. J.W.Bos, P.L.Montgomery, "Montgomery Arithmetic from a Software
 *    Perspective", 2017.
 *
 * 6. Coron, Jean-S'ebastien. Resistance against differential power analysis
 *    for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *    Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *    <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 *
 * 7. M.Hedabou, P.Pinel, L.Beneteau, "A comb method to render ECC resistant
 *    against Side Channel Attacks", 2004.
 *
 * 8. Jacobian coordinates for short Weierstrass curves,
 *    http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
 *
 * 9. S.Gueron, V.Krasnov, "Fast prime field elliptic-curve cryptography with
 *    256-bit primes", 2014.
 *
 * 10. NIST: Mathematical routines for the NIST prime elliptic curves, 2010.
 *
 * #8 #1335: There are faster point multiplication methods using point halving
 * and or multi-base representations for m * P and m * G, see more in:
 *
 * 11. I.Abdulwahed et al, "An Algorithm to Enhance Elliptic Curves Scalar
 *     Multiplication Combining MBNR with Point Halving", 2010.
 *
 * 12. G.N.Purohit et al, "Elliptic Curve Point Multiplication Using MBNR and
 *     Point Halving", 2011.
 *
 * 13. J.Taverne et al, "Software implementation of binary elliptic curves:
 *     impact of the carry-less multiplier on scalar multiplication", 2011.
 *
 * 14. m0m1 algorithm in J.-M.Robert et al, "Efficient Fixed Base Exponentiation
 *     and Scalar Multiplication based on a Multiplicative Splitting Exponent
 *     Recoding", 2019.
 *
 * Some baseline is described in
 * [15] A.Krizhanovsky, I.Koveshnikov, "Performance study of kernel TLS
 * handshakes", Netdev 0x14, 2020,
 *
 * Copyright (C) 2020-2021 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "lib/str.h"
#include "asn1.h"
#include "bignum_asm.h"
#include "ecp.h"
#include "mpool.h"

/*
 * We can not use too large windows (W and G_W): 1 additional bit in the window
 * doubles precomputation time for m * P or memory for m * G, but number of
 * iterations on D and G_D decreases much slowly.
 */
#define G_BITS		256
#define G_LIMBS		(G_BITS / BIL)
#define G_W		7			/* m * G window bits */
#define G_W_SZ		(1U << (G_W - 1))	/* m * G window size */
#define G_D		((G_BITS + G_W - 1) / G_W)
#define W		5			/* m * P window bits */
#define W_SZ		(1U << (W - 1))		/* m * P window size */
#define D		((G_BITS + W - 1) / W)

static const struct {
	unsigned long	secp256r1_p[G_LIMBS];
	unsigned long	secp256r1_b[G_LIMBS];
	unsigned long	secp256r1_n[G_LIMBS];
	unsigned long	secp256r1_gx[G_LIMBS];
	unsigned long	secp256r1_gy[G_LIMBS];
	unsigned long	secp256r1_gz[G_LIMBS];

	TlsMpi		P;
	TlsMpi		B;
	TlsMpi		N;
	TlsMpi		__align_placeholder;
	TlsEcpPoint	G;
} ____cacheline_aligned __attribute__((packed)) G = {
	/*
	 * Domain parameters for secp256r1 (prime256v1) - generalized Mersenne primes.
	 */
	.secp256r1_p = {
		0xffffffffffffffffUL, 0xffffffffUL, 0UL, 0xffffffff00000001UL
	},
	.secp256r1_b = {
		0x3bce3c3e27d2604bUL, 0x651d06b0cc53b0f6UL,
		0xb3ebbd55769886bcUL, 0x5ac635d8aa3a93e7UL
	},
	.secp256r1_n = {
		0xf3b9cac2fc632551UL, 0xbce6faada7179e84UL,
		0xffffffffffffffffUL, 0xffffffff00000000UL
	},
	.secp256r1_gx = {
		0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
		0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL
	},
	.secp256r1_gy = {
		0xcbb6406837bf51f5UL, 0x2bce33576b315eceUL,
		0x8ee7eb4a7c0f9e16UL, 0x4fe342e2fe1a7f9bUL
	},
	.secp256r1_gz = {
		1, 0, 0, 0
	},
	.P = {
		.s	= 1,
		.used	= G_LIMBS,
		.limbs	= G_LIMBS,
		._off	= -6 * (short)(G_LIMBS * CIL)
	},
	.B = {
		.s	= 1,
		.used	= G_LIMBS,
		.limbs	= G_LIMBS,
		._off	= -5 * (short)(G_LIMBS * CIL) - (short)sizeof(TlsMpi)
	},
	.N = {
		.s	= 1,
		.used	= G_LIMBS,
		.limbs	= G_LIMBS,
		._off	= -4 * (short)(G_LIMBS * CIL) - 2 * (short)sizeof(TlsMpi)
	},
	.__align_placeholder = {},
	.G = {
		.X = {
			.s	= 1,
			.used	= G_LIMBS,
			.limbs	= G_LIMBS,
			._off	= -3 * (short)(G_LIMBS * CIL)
				  - 4 * (short)sizeof(TlsMpi)
		},
		.Y = {
			.s	= 1,
			.used	= G_LIMBS,
			.limbs	= G_LIMBS,
			._off	= -2 * (short)(G_LIMBS * CIL)
				  - 5 * (short)sizeof(TlsMpi)
		},
		.Z = {
			.s	= 1,
			.used	= 1,
			.limbs	= G_LIMBS,
			._off	= -1 * (short)(G_LIMBS * CIL)
				  - 6 * (short)sizeof(TlsMpi)
		}
	}
};

static const unsigned long P_INV_TBL[12][4] ____cacheline_aligned = {
	{ 0xdafffffff3000000UL, 0xd40000006dffffffUL,
	  0x5500000000ffffffUL, 0x38ffffffad000000UL },
	{ 0xe3ffffff9800000UL, 0xfd3ffffffcc00000UL,
	  0xf50000000d3fffffUL, 0x80000006bfffffUL },
	{ 0x20000001cfffffUL, 0x1c00000fe600000UL,
	  0xff4fffffff100000UL, 0xfeefffff01800000UL },
	{ 0xffbc0000001c0000UL, 0xffec00000073ffffUL,
	  0x6fffffffdbffffUL, 0x33ffffffa80000UL },
	{ 0xcfffffff70000UL, 0xfff8000000070000UL,
	  0xfffb0000000fffffUL, 0x5ffffffffffffUL },
	{ 0x1800000017fffUL, 0x1c000fffdc000UL,
	  0xfffe000000004000UL, 0xfffebfff00028000UL },
	{ 0xffffb00000005000UL, 0x100000005fffUL,
	  0x6fffffffc000UL, 0x1fffffffc000UL },
	{ 0x7fffffff800UL, 0xfffff40000001400UL,
	  0x40000000fffUL, 0xbfffffff800UL },
	{ 0x300000000ffUL, 0x100fffffe00UL,
	  0xfffffd0000000200UL, 0xfffffeff00000300UL },
	{ 0xffffffc000000080UL, 0x400000003fUL,
	  0x3fffffffc0UL, 0x0UL },
	{ 0x0UL, 0xfffffff000000020UL,
	  0x100000000fUL, 0xffffffff0UL },
	{ 0x400000000UL, 0x0UL,
	  0xfffffffc00000004UL, 0x3UL }
};
static const unsigned long N_INV_TBL[12][4] ____cacheline_aligned = {
	{ 0xd3dd171618a3b717UL, 0x3fff681d9923f61UL,
	  0x6efa45ccec548683UL, 0xbe928d6f19f723f8UL },
	{ 0xb78c9deaa307dad7UL, 0xc808b9c007d0b5d5UL,
	  0xcd7cbc7306439253UL, 0xe23c5a7044f2b547UL },
	{ 0x5f5ddcdb262b9bb2UL, 0x1641c8ba4f5b1641UL,
	  0xd528811b72891fUL, 0x49bdc6e77c520a7UL },
	{ 0xd6810951c480022bUL, 0xc4b5ee11ad2ad8d0UL,
	  0xc5ddc1af11e1c923UL, 0x5e269249a7c46302UL },
	{ 0xfa2ae5335fb419bdUL, 0x43a48bed3d62277bUL,
	  0xf758ce8517f6bc78UL, 0x1b68892c42fdb4f5UL },
	{ 0x80d8ed17f512edf8UL, 0x1b9010e227a474UL,
	  0x12b4e566c6c6b007UL, 0x8e95a0de2e641f96UL },
	{ 0x14d2e6919fd355d3UL, 0x699bb05e43f692c5UL,
	  0xc95eaa2fab3d0d1cUL, 0x1046413f02733be4UL },
	{ 0xc1c6158bd8367238UL, 0xa32a55bee13d72caUL,
	  0x1b77eaa9301d001fUL, 0xf2f479842620e3ffUL },
	{ 0xb61cee7d744e7aa0UL, 0x855e124ad943df2UL,
	  0xf8b6041e607725d4UL, 0xd06633a905c1e8a7UL },
	{ 0x728a0e536f91deacUL, 0xf8e1e329a7d18c44UL,
	  0xfbd3fbe8d1574a5UL, 0x3f9dfb312293c261UL },
	{ 0xfca78ace2bcb4d5cUL, 0xc8383b74e7dca67fUL,
	  0x82639ce9ea3c688dUL, 0x8c9440874ab8edc5UL },
	{ 0xb0d6aa38c05fd77dUL, 0xf28f5ee9c9cccd11UL,
	  0x7b44316fb802f13bUL, 0x334722ab84bbce90UL }
};

typedef struct {
	unsigned long	x[G_LIMBS];
	unsigned long	y[G_LIMBS];
} __attribute__((packed)) __attribute__((aligned(G_LIMBS * CIL))) EcpXY;

typedef struct {
	unsigned long	x[G_LIMBS];
	unsigned long	y[G_LIMBS];
	unsigned long	z[G_LIMBS];
} __attribute__((packed)) __attribute__((aligned(G_LIMBS * CIL))) Ecp256Point;

/*
 * Static precomputed table for the group generator.
 *
 * GPUs have a large amount of global memory, so we can use giant table
 * for ECDSA point multiplication making signing almost as fast as GPU I/O.
 */
static const EcpXY combT_G[G_D + 1][G_W_SZ] __page_aligned_data = {
	#include "ecp256_G.autogen.h" /* Generated by t/tgen_ec256.c */
};
static DEFINE_PER_CPU(Ecp256Point, combT[W_SZ]);

/**
 * Copy single coordinate of a point.
 */
static void
ecp256_copy(unsigned long *__restrict dst, const unsigned long *__restrict src)
{
	memcpy(dst, src, G_LIMBS * CIL);
}

/**
 * Compare single coordinates of 2 points.
 */
static bool
ecp256_eq(const unsigned long *a, const unsigned long *b)
{
	return !memcmp(a, b, G_LIMBS * CIL);
}

static void
ecp256_mpi_write(TlsMpi *__restrict x, unsigned long *__restrict a)
{
	x->s = 1;
	MPI_P(x)[0] = a[0];
	MPI_P(x)[1] = a[1];
	MPI_P(x)[2] = a[2];
	MPI_P(x)[3] = a[3];

	x->used = G_LIMBS;
	if (a[3])
		return;
	x->used--;
	if (a[2])
		return;
	x->used--;
	if (a[1])
		return;
	x->used--;
	if (a[0])
		return;
	x->used--;
}

static void
ecp256_mpi_read(unsigned long *__restrict a, const TlsMpi *__restrict x)
{
	ecp256_copy(a, MPI_P(x));
}

static void
ecp256_lset(unsigned long *x, long z)
{
	x[0] = z;
	x[1] = 0;
	x[2] = 0;
	x[3] = 0;
}

static bool
ecp256_mpi_eq_0(const unsigned long x[G_LIMBS])
{
	return !x[0] && !x[1] && !x[2] && !x[3];
}

/**
 * Set coordinate Z to 1 in Montgomery form.
 * Precomputed from ecp256_to_mont() call over {1, 0, 0, 0}.
 */
static void
ecp256_set_mont_1(Ecp256Point *p)
{
	p->z[0] = 0x1UL;
	p->z[1] = 0xffffffff00000000UL;
	p->z[2] = 0xffffffffffffffffUL;
	p->z[3] = 0xfffffffe;
}

/**
 * Safe conditional assignment X = Y if @assign is 1.
 *
 * This function avoids leaking any information about whether the assignment was
 * done or not (the above code may leak information through branch prediction
 * and/or memory access patterns analysis). Leaking information about the
 * respective sizes of X and Y is ok however.
 */
static void
ecp256_safe_cond_assign(unsigned long *x, unsigned long *y, unsigned char assign)
{
	static const unsigned long l_masks[2] = {0, 0xffffffffffffffffUL};

	unsigned long l_mask = l_masks[assign];

	x[0] ^= (x[0] ^ y[0]) & l_mask;
	x[1] ^= (x[1] ^ y[1]) & l_mask;
	x[2] ^= (x[2] ^ y[2]) & l_mask;
	x[3] ^= (x[3] ^ y[3]) & l_mask;
}

static void
ecp256_mul_int(TlsMpi *X, const TlsMpi *A, long b)
{
	BUG_ON(X->limbs < G_LIMBS + 1);
	BUG_ON(A->used < 4 && MPI_P(A)[3]);
	BUG_ON(A->used < 3 && MPI_P(A)[2]);
	BUG_ON(A->used < 2 && MPI_P(A)[1]);

	if (unlikely(!b)) {
		X->s = 1;
		X->used = 1;
		ecp256_lset(MPI_P(X), 0);
		return;
	}

	if (b > 0) {
		X->s = A->s;
	} else {
		X->s = -A->s;
		b = -b;
	}

	mpi_mul_int_x86_64_4(MPI_P(X), MPI_P(A), b);

	mpi_fixup_used(X, G_LIMBS + 1);
	if (X->used == 1 && !MPI_P(X)[0])
		X->s = 1;
}

/**
 * ecp256_inv_mod() works with negative MPIs, so we need the wrapper yet.
 */
static void
ecp256_mul(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	BUG_ON(X->limbs < G_LIMBS * 2);
	BUG_ON(A->used < 4 && MPI_P(A)[3]);
	BUG_ON(A->used < 3 && MPI_P(A)[2]);
	BUG_ON(A->used < 2 && MPI_P(A)[1]);
	BUG_ON(B->used < 4 && MPI_P(B)[3]);
	BUG_ON(B->used < 3 && MPI_P(B)[2]);
	BUG_ON(B->used < 2 && MPI_P(B)[1]);

	mpi_mul_x86_64_4(MPI_P(X), MPI_P(A), MPI_P(B));
	mpi_fixup_used(X, G_LIMBS * 2);
	X->s = A->s * B->s;
}

/**
 * Modular inverse X = A^-1 mod N.
 *
 * We use modified version of the algorithm by Bernstein and Yang,
 * "Fast constant-time gcd computation and modular inversion", 2019.
 * Our version isn't constant time, but much faster: there are 170 in average
 * less 64-bit division steps and in average 3 less big integer matrices
 * multiplications. Moreover, we multiply the matrices as they elements grow
 * closer to 256 bits, so in most cases we get even less number of matrices
 * multiplications (the math prototype test for the optimized matrices
 * multiplication is about 8 times faster that the original divide and conquer
 * algorithm from the paper). The division steps also optimized for tail
 * zeroes.
 *
 * It's worth mentionung that the Little Fermat theorem approach used in
 * OpenSSL and WolfSSL takes about 255 256-bit integer modular squares and
 * 12-13 modular multiplications. Our approach uses:
 * - 72 64-256-bit multiplications in average
 * - 36 256-bit multiplications in average
 * - 4 modular reductions in worse case.
 *
 * @X must be at least G_LIMBS * 2 in size.
 *
 * TODO #1064 [5] we can not use the inversion with numbers in Montgormery
 * representation as is, so need to multiply on R^3 or perform double
 * reduction or use inversion for normal numbers only.
 */
static void
ecp256_inv_mod(TlsMpi *X, const TlsMpi *I, const TlsMpi *N)
{
	int delta = 1, g0, i, m, n;
	/* Tau matrices */
	long *f, *g, fi, gi;
	TlsMpi *F, *P, *A, *B, *U[3], *V[3], *Q[3], *R[3];
	static size_t sz = sizeof(TlsMpi) * 16 + (G_LIMBS * 18 + 14) * CIL;

	F = ttls_mpool_alloc_stack(sz);
	bzero_fast(F, sz);
	P = ttls_mpi_init_next(F, G_LIMBS + 1);
	A = ttls_mpi_init_next(P, G_LIMBS + 1);
	B = ttls_mpi_init_next(A, G_LIMBS * 2);
	U[0] = ttls_mpi_init_next(B, G_LIMBS * 2);
	U[1] = ttls_mpi_init_next(U[0], G_LIMBS + 1);
	U[2] = ttls_mpi_init_next(U[1], G_LIMBS + 1);
	V[0] = ttls_mpi_init_next(U[2], G_LIMBS + 1);
	V[1] = ttls_mpi_init_next(V[0], G_LIMBS + 1);
	V[2] = ttls_mpi_init_next(V[1], G_LIMBS + 1);
	Q[0] = ttls_mpi_init_next(V[2], G_LIMBS + 1);
	Q[1] = ttls_mpi_init_next(Q[0], G_LIMBS + 1);
	Q[2] = ttls_mpi_init_next(Q[1], G_LIMBS + 1);
	R[0] = ttls_mpi_init_next(Q[2], G_LIMBS + 1);
	R[1] = ttls_mpi_init_next(R[0], G_LIMBS + 1);
	R[2] = ttls_mpi_init_next(R[1], G_LIMBS + 1);
	ttls_mpi_init_next(R[2], G_LIMBS + 1);

	ecp256_mpi_write(F, MPI_P(N));
	ecp256_mpi_write(P, MPI_P(I));
	f = MPI_P(F);
	g = MPI_P(P);

	for (m = 2, n = 12; n > 0; ) {
		/* Divsion steps. */
		long tmp0, tmp1, tmp2, u = 1, v = 0, q = 0, r = 1;

		fi = (F->s * f[0]) & ((1UL << 62) - 1);
		gi = (P->s * g[0]) & ((1UL << 62) - 1);

		for (i = 0; i < 62; ) {
			if (!gi) {
				delta += 62 - i;
				u <<= 62 - i;
				v <<= 62 - i;
				break;
			}
			if ((tmp0 = __ffs(gi))) {
				tmp0 = min_t(long, tmp0, 62 - i);
				delta += tmp0;
				gi >>= tmp0;
				u <<= tmp0;
				v <<= tmp0;
				i += tmp0;
				continue;
			}
			if (delta > 0) {
				delta = -delta;
				tmp0 = -fi;
				tmp1 = -u;
				tmp2 = -v;
				fi = gi;
				u = q;
				v = r;
				gi = tmp0;
				q = tmp1;
				r = tmp2;
			}
			delta++;
			g0 = gi & 1;
			/* f := g only if g is odd, so f is always odd */
			gi = (gi >> 1) + (g0 * fi >> 1) + g0;
			q = q + g0 * u;
			r = r + g0 * v;
			u <<= 1;
			v <<= 1;
			i++;
		}

		if (U[m]->used && U[m]->used < G_LIMBS && V[m]->used < G_LIMBS
		    && Q[m]->used < G_LIMBS && R[m]->used < G_LIMBS)
		{
			/*
			 * TODO #1064 use faster multiplication
			 * Revert back to divide & conquer strategy?
			 * We can use nice 128-bit integers then.
			 */
			ecp256_mul_int(A, V[m], u);
			ecp256_mul_int(B, R[m], v);
			ttls_mpi_add_mpi(A, A, B);

			ecp256_mul_int(R[m], R[m], r);
			ecp256_mul_int(B, V[m], q);
			ttls_mpi_add_mpi(R[m], R[m], B);

			ttls_mpi_copy(V[m], A);

			ecp256_mul_int(A, U[m], u);
			ecp256_mul_int(B, Q[m], v);
			ttls_mpi_add_mpi(A, A, B);

			ecp256_mul_int(Q[m], Q[m], r);
			ecp256_mul_int(B, U[m], q);
			ttls_mpi_add_mpi(Q[m], Q[m], B);

			ttls_mpi_copy(U[m], A);
		} else {
			m -= !!U[m]->used;
			ttls_mpi_lset(U[m], u);
			ttls_mpi_lset(V[m], v);
			ttls_mpi_lset(Q[m], q);
			ttls_mpi_lset(R[m], r);
		}

		n--;
		if (!gi && ttls_mpi_eq_0(P))
			break;

		/*
		 * F and P can be negative after the multiplication:
		 *   F, P = (F * u + P * v) >> 62, (F * q + P * r) >> 62
		 */
		ecp256_mul_int(A, F, q);
		ecp256_mul_int(F, F, u);
		ecp256_mul_int(B, P, v);
		ttls_mpi_add_mpi(F, F, B);
		BUG_ON(F->limbs > F->used && MPI_P(F)[F->used]);
		ttls_mpi_shift_r(F, 62);
		BUG_ON(F->limbs > F->used && MPI_P(F)[F->used]);
		ecp256_mul_int(P, P, r);
		ttls_mpi_add_mpi(P, P, A);
		ttls_mpi_shift_r(P, 62);
	}
	BUG_ON(gi);

	/* Finally, multiply up to 3 256-bit Tau matrices using MODULus. */
	if (N == &G.N) {
		if (m == 2) {
			ttls_mpi_copy(X, V[m]);
		} else {
			ecp256_mul(X, U[m], V[m + 1]);
			ecp256_mul(B, V[m], R[m + 1]);
			ttls_mpi_add_mpi(X, X, B);
			ttls_mpi_mod_mpi(X, X, &G.N);

			if (m == 0) {
				ecp256_mul(B, U[m], U[m + 1]);
				ecp256_mul(A, V[m], Q[m + 1]);
				ttls_mpi_add_mpi(B, B, A);
				ttls_mpi_mod_mpi(B, B, &G.N);

				ecp256_mul(B, B, V[m + 2]);
				ecp256_mul(X, X, R[m + 2]);
				ttls_mpi_add_mpi(X, X, B);
				ttls_mpi_mod_mpi(X, X, &G.N);
			}
		}
		memcpy_fast(MPI_P(A), N_INV_TBL[n], G_LIMBS * CIL);
		mpi_fixup_used(A, G_LIMBS);
		A->s = X->s * F->s;
		ecp256_mul(X, X, A);
		ttls_mpi_mod_mpi(X, X, &G.N);
	} else {
		if (m == 2) {
			ttls_mpi_copy(X, V[m]);
		} else {
			ecp256_mul(X, U[m], V[m + 1]);
			ecp256_mul(B, V[m], R[m + 1]);
			ttls_mpi_add_mpi(X, X, B);
			bzero_fast(&MPI_P(X)[X->used], (X->limbs - X->used) * CIL);
			ecp_mod_p256_x86_64(MPI_P(X));
			mpi_fixup_used(X, G_LIMBS);

			if (m == 0) {
				ecp256_mul(B, U[m], U[m + 1]);
				ecp256_mul(A, V[m], Q[m + 1]);
				ttls_mpi_add_mpi(B, B, A);
				bzero_fast(&MPI_P(B)[B->used],
					   (B->limbs - B->used) * CIL);
				ecp_mod_p256_x86_64(MPI_P(B));
				mpi_fixup_used(B, G_LIMBS);

				ecp256_mul(B, B, V[m + 2]);
				ecp256_mul(X, X, R[m + 2]);
				ttls_mpi_add_mpi(X, X, B);
				bzero_fast(&MPI_P(X)[X->used],
					   (X->limbs - X->used) * CIL);
				ecp_mod_p256_x86_64(MPI_P(X));
				mpi_fixup_used(X, G_LIMBS);
			}
		}
		mpi_mul_x86_64_4(MPI_P(X), MPI_P(X), P_INV_TBL[n]);
		mpi_fixup_used(X, G_LIMBS * 2);
		ecp_mod_p256_x86_64(MPI_P(X));
		mpi_fixup_used(X, G_LIMBS);
		X->s = X->s * F->s;
		if (X->s < 0)
			ttls_mpi_add_mpi(X, X, &G.P);
		X->s = 1;
	}

	ttls_mpi_pool_cleanup_ctx((unsigned long)F, false);
}

/*
 * Normalize jacobian coordinates so that Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static void
ecp256_normalize_jac(Ecp256Point *r, bool norm_mont)
{
	unsigned long zzi[8], x[8] = {}, y[8] = {};
	DECLARE_MPI_AUTO(zi, 8);

	ecp256_mpi_write(&zi, r->z);
	ecp256_copy(x, r->x);
	ecp256_copy(y, r->y);

	if (norm_mont) {
		mpi_from_mont_p256_x86_64(MPI_P(&zi));
		mpi_from_mont_p256_x86_64(x);
		mpi_from_mont_p256_x86_64(y);
	}

	/* X = X / Z^2  mod p */
	ecp256_inv_mod(&zi, &zi, &G.P);
	mpi_sqr_mod_p256_x86_64_4(zzi, MPI_P(&zi));
	mpi_mul_mod_p256_x86_64_4(x, x, zzi);
	ecp256_copy(r->x, x);

	/* Y = Y / Z^3  mod p */
	mpi_mul_mod_p256_x86_64_4(y, y, zzi);
	mpi_mul_mod_p256_x86_64_4(y, y, MPI_P(&zi));
	ecp256_copy(r->y, y);

	/* Z = 1 */
	ecp256_lset(r->z, 1);
}

/**
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid.
 */
static void
ecp256_safe_invert_jac(Ecp256Point *q, unsigned char inv)
{
	unsigned char nonzero = !ecp256_mpi_eq_0(q->y);
	unsigned long mqy[4];

	/* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
	mpi_sub_mod_p256_x86_64(mqy, G.secp256r1_p, q->y);

	ecp256_safe_cond_assign(q->y, mqy, inv & nonzero);
}

/**
 * Point doubling R = 2 P, Jacobian coordinates [8, "dbl-1998-cmo-2"].
 *
 * Cost: 4M + 4S + 10A
 */
static void
ecp256_double_jac(Ecp256Point *r, const Ecp256Point *p)
{
	unsigned long m[4], s[8], t[8], u[8];

	/* M = 3(X + Z^2)(X - Z^2) */
	mpi_sqr_mont_mod_p256_x86_64(s, p->z);
	mpi_add_mod_p256_x86_64(t, p->x, s);
	mpi_sub_mod_p256_x86_64(u, p->x, s);
	mpi_mul_mont_mod_p256_x86_64(s, t, u);
	mpi_tpl_mod_p256_x86_64(m, s);

	/* S = 4 * X * Y^2 = X * (2 * Y)^2 */
	mpi_shift_l1_mod_p256_x86_64(t, p->y);
	mpi_sqr_mont_mod_p256_x86_64(t, t);
	mpi_mul_mont_mod_p256_x86_64(s, p->x, t);

	/* U = 8 * Y^4 = ((2 * Y)^2)^2 / 2 */
	mpi_sqr_mont_mod_p256_x86_64(u, t);
	mpi_div2_x86_64_4(u, u);

	/* T = M^2 - 2 * S */
	mpi_sqr_mont_mod_p256_x86_64(t, m);
	mpi_sub_mod_p256_x86_64(t, t, s);
	mpi_sub_mod_p256_x86_64(t, t, s);

	/* S = M(S - T) - U */
	mpi_sub_mod_p256_x86_64(s, s, t);
	mpi_mul_mont_mod_p256_x86_64(s, s, m);
	mpi_sub_mod_p256_x86_64(s, s, u);

	/* U = 2 * Y * Z */
	mpi_mul_mont_mod_p256_x86_64(u, p->y, p->z);
	mpi_shift_l1_mod_p256_x86_64(u, u);

	ecp256_copy(r->x, t);
	ecp256_copy(r->y, s);
	ecp256_copy(r->z, u);
}

/**
 * Repeated point doubling in Jacobian coordinates (GECC 3.23).
 */
static void
ecp256_double_jac_n(Ecp256Point *r, const Ecp256Point *p)
{
	int i;
	unsigned long x[8], y[4], z[8], a[8], b[8], w[8], t[4], y2[8];

	ecp256_copy(x, p->x);
	ecp256_copy(z, p->z);

	/* Y = 2 * Y */
	mpi_shift_l1_mod_p256_x86_64(y, p->y);
	/* W = Z^4 */
	mpi_sqr_mont_mod_p256_x86_64(w, z);
	mpi_sqr_mont_mod_p256_x86_64(w, w);

	for (i = 0; i < D; ++i) {
		/* A = 3 * (X^2 - W) */
		mpi_sqr_mont_mod_p256_x86_64(a, x);
		mpi_sub_mod_p256_x86_64(a, a, w);
		mpi_tpl_mod_p256_x86_64(a, a);
		/* B = X * Y^2 */
		mpi_sqr_mont_mod_p256_x86_64(y2, y);
		mpi_mul_mont_mod_p256_x86_64(b, y2, x);
		/* X = A^2 - 2 * B */
		mpi_sqr_mont_mod_p256_x86_64(x, a);
		mpi_shift_l1_mod_p256_x86_64(t, b);
		mpi_sub_mod_p256_x86_64(x, x, t);
		/* Z = Z * Y */
		mpi_mul_mont_mod_p256_x86_64(z, z, y);
		/* W = W * Y^4 */
		mpi_sqr_mont_mod_p256_x86_64(y2, y2);
		if (likely(i != D - 1))
			mpi_mul_mont_mod_p256_x86_64(w, w, y2);
		/* Y = 2 * A * (B - X) - Y^4 */
		mpi_sub_mod_p256_x86_64(b, b, x);
		mpi_mul_mont_mod_p256_x86_64(a, a, b);
		mpi_shift_l1_mod_p256_x86_64(y, a);
		mpi_sub_mod_p256_x86_64(y, y, y2);
	}

	mpi_div2_x86_64_4(r->y, y);
	memcpy_fast(r->x, x, 4 * CIL);
	memcpy_fast(r->z, z, 4 * CIL);
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * TODO #1064: the implementation uses formula [8, "madd-2008-g"] and I'm not
 * sure if it's the most efficient one - [9] refernces another formula.
 * Explore "New Point Addition Formulae for ECC Applications" by Meloni 2007.
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Cost: 1A := 8M + 3S (same as Chudnovsky-Affine time, GECC 3.2.2).
 */
static void
ecp256_add_mixed(Ecp256Point *R, const Ecp256Point *P, const Ecp256Point *Q)
{
	unsigned long t1[8], t2[8], t3[8], t4[8], x[8], z[8];

	mpi_sqr_mod_p256_x86_64_4(t1, P->z);
	mpi_mul_mod_p256_x86_64_4(t2, t1, P->z);
	mpi_mul_mod_p256_x86_64_4(t1, t1, Q->x);
	mpi_mul_mod_p256_x86_64_4(t2, t2, Q->y);
	mpi_sub_mod_p256_x86_64(t1, t1, P->x);
	mpi_sub_mod_p256_x86_64(t2, t2, P->y);

	mpi_mul_mod_p256_x86_64_4(z, P->z, t1);

	mpi_sqr_mod_p256_x86_64_4(t3, t1);
	mpi_mul_mod_p256_x86_64_4(t4, t3, t1);
	mpi_mul_mod_p256_x86_64_4(t3, t3, P->x);
	mpi_shift_l1_mod_p256_x86_64(t1, t3);
	mpi_sqr_mod_p256_x86_64_4(x, t2);
	mpi_sub_mod_p256_x86_64(x, x, t1);
	mpi_sub_mod_p256_x86_64(x, x, t4);
	mpi_sub_mod_p256_x86_64(t3, t3, x);
	mpi_mul_mod_p256_x86_64_4(t3, t3, t2);
	mpi_mul_mod_p256_x86_64_4(t4, t4, P->y);

	mpi_sub_mod_p256_x86_64(R->y, t3, t4);

	memcpy_fast(R->x, x, 4 * CIL);
	memcpy_fast(R->z, z, 4 * CIL);
}

/**
 * Addition R = P + Q in Jacobian coordinates using add-1998-cmo-2 from [8].
 * Cost: 12M + 4S + 6add + 1dbl.
 *
 * OpenSSL and WolfSSL use the same formula, but the former one avoids extra
 * subtraction to handle almost impossible case of equal points (see
 * ecp_nistz256_point_add()), so we do the same.
 */
static void
ecp256_add_jac(Ecp256Point *r, const Ecp256Point *p, const Ecp256Point *q)
{
	unsigned long t1[8], t2[8], t3[8], t4[8], u1[8], s1[8], h[8], tr[8];
	bool p_inf = ecp256_mpi_eq_0(p->z), q_inf = ecp256_mpi_eq_0(q->z);

	mpi_sqr_mont_mod_p256_x86_64(t1, p->z);
	mpi_sqr_mont_mod_p256_x86_64(t2, q->z);
	mpi_mul_mont_mod_p256_x86_64(t3, t1, q->x);	/* U2 = X2 * Z1^2 */
	mpi_mul_mont_mod_p256_x86_64(u1, t2, p->x);	/* U1 = X1 * Z2^2 */
	mpi_sub_mod_p256_x86_64(h, t3, u1);		/* H = U2 - U1 */

	mpi_mul_mont_mod_p256_x86_64(s1, t2, q->z);
	mpi_mul_mont_mod_p256_x86_64(t4, t1, p->z);
	mpi_mul_mont_mod_p256_x86_64(s1, s1, p->y);	/* S1 = Y1 * Z2^3 */
	mpi_mul_mont_mod_p256_x86_64(t4, t4, q->y);	/* S2 = Y2 * Z1^3 */
	mpi_sub_mod_p256_x86_64(tr, t4, s1);		/* R = S2 - S1 */

#ifdef TLS_CONST_TIME
	if (unlikely(!p_inf & !q_inf & ecp256_eq(u1, t3) & ecp256_eq(s1, t4)))
#else
	if (unlikely(!p_inf && !q_inf && ecp256_eq(u1, t3) && ecp256_eq(s1, t4)))
#endif
	{
		ecp256_double_jac(r, p);
		return;
	}

	mpi_mul_mont_mod_p256_x86_64(t1, h, p->z);
	mpi_mul_mont_mod_p256_x86_64(t1, t1, q->z);	/* Z3 = H * Z1 * Z2 */

	mpi_sqr_mont_mod_p256_x86_64(t2, h);		/* H^2 */
	mpi_mul_mont_mod_p256_x86_64(h, h, t2);		/* H^3 */
	mpi_mul_mont_mod_p256_x86_64(t2, t2, u1);		/* U1 * H^2 */
	mpi_sqr_mont_mod_p256_x86_64(t3, tr);		/* R^2 */
	mpi_shift_l1_mod_p256_x86_64(t4, t2);		/* 2 * U1 * H^2 */

	/* X3 = R^2 - H^3 - 2 * U1 * H^2 */
	mpi_sub_mod_p256_x86_64(t3, t3, h);
	mpi_sub_mod_p256_x86_64(t3, t3, t4);

	/* Y3 = (U1 * H^2 - X3) * R - S1 * H^3 */
	mpi_sub_mod_p256_x86_64(t2, t2, t3);
	mpi_mul_mont_mod_p256_x86_64(t2, t2, tr);
	mpi_mul_mont_mod_p256_x86_64(s1, s1, h);
	mpi_sub_mod_p256_x86_64(t2, t2, s1);

	ecp256_copy(r->x, t3);
	ecp256_copy(r->y, t2);
	ecp256_copy(r->z, t1);
}

/*
 * Recode the secret scalar `m` that will be used with our comb method.
 *
 * Basically, we use the same comb algorithm modification as mbed TLS.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries, but saves on the size of
 * the precomputed table.
 *
 * Summary of the comb method and its modifications:
 *
 * - The goal is to compute m*P for some w*d-bit integer m.
 *
 * - The basic comb method splits m into the w-bit integers
 *   x[0] .. x[d-1] where x[i] consists of the bits in m whose
 *   index has residue i modulo d, and computes m * P as
 *   S[x[0]] + 2 * S[x[1]] + .. + 2^(d-1) S[x[d-1]], where
 *   S[i_{w-1} .. i_0] := i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + i_0 P.
 *
 * - If it happens that, say, x[i+1]=0 (=> S[x[i+1]]=0), one can replace the sum by
 *   .. + 2^{i-1} S[x[i-1]] - 2^i S[x[i]] + 2^{i+1} S[x[i]] + 2^{i+2} S[x[i+2]] ..,
 *   thereby successively converting it into a form where all summands
 *   are nonzero, at the cost of negative summands. This is the basic idea of [3].
 *
 * - More generally, even if x[i+1] != 0, we can first transform the sum as
 *   .. - 2^i S[x[i]] + 2^{i+1} ( S[x[i]] + S[x[i+1]] ) + 2^{i+2} S[x[i+2]] ..,
 *   and then replace S[x[i]] + S[x[i+1]] = S[x[i] ^ x[i+1]] + 2 S[x[i] & x[i+1]].
 *   Performing and iterating this procedure for those x[i] that are even
 *   (keeping track of carry), we can transform the original sum into one of the
 *   form S[x'[0]] +- 2 S[x'[1]] +- .. +- 2^{d-1} S[x'[d-1]] + 2^d S[x'[d]]
 *   with all x'[i] odd. It is therefore only necessary to know S at odd indices,
 *   which is why we are only computing half of it in the first place in
 *   ecp256_precompute_comb() and accessing it with index abs(i) / 2 in
 *   ecp256_select_comb().
 *
 * - For the sake of compactness, only the seven low-order bits of x[i]
 *   are used to represent its absolute value (K_i in the paper), and the msb
 *   of x[i] encodes the sign (s_i in the paper): it is set if and only if
 *   if s_i == -1;
 *
 * Note that the function has no branches except the bitlength, so it's constant
 * time and DPA-resistant. Reference: "A New Attack with Side Channel Leakage
 * During Exponent Recoding Computations" by Sakai & Sakurai, 2004.
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void
ecp256_comb_fixed(unsigned char *__restrict x, size_t d, unsigned char w,
		  const unsigned long *__restrict m)
{
	size_t i, j, b;
	unsigned char c, cc, adjust;

	bzero_fast(x, d + 1);

	/* First get the classical comb values (except for x_d = 0) */
	for (i = 0; i < d; i++)
		for (j = 0; j < w; j++) {
			b = i + d * j;
			if (unlikely(b >= 256))
				break;
			x[i] |= ((m[b >> BSHIFT] >> (b & BMASK)) & 1) << j;
		}

	/* Now make sure x_1 .. x_d are odd */
	for (c = 0, i = 1; i <= d; i++) {
		/* Add carry and update it */
		cc = x[i] & c;
		x[i] = x[i] ^ c;
		c = cc;

		/* Adjust if needed, avoiding branches */
		adjust = 1 - (x[i] & 1);
		c |= x[i] & (x[i - 1] * adjust);
		x[i] = x[i] ^ (x[i - 1] * adjust);
		x[i - 1] |= adjust << 7;
	}
}

/**
 * Multiply a number by Montogmery normalizer mod p256.
 * Borrowed from WolfSSL sp_256_mod_mul_norm_4().
 */
static void
ecp256_to_mont(unsigned long *__restrict r, const unsigned long *__restrict a)
{
	long t[8], a32[8], o;

	a32[0] = a[0] & 0xffffffff;
	a32[1] = a[0] >> 32;
	a32[2] = a[1] & 0xffffffff;
	a32[3] = a[1] >> 32;
	a32[4] = a[2] & 0xffffffff;
	a32[5] = a[2] >> 32;
	a32[6] = a[3] & 0xffffffff;
	a32[7] = a[3] >> 32;

	/*  1  1  0 -1 -1 -1 -1  0 */
	t[0] = 0 + a32[0] + a32[1] - a32[3] - a32[4] - a32[5] - a32[6];
	/*  0  1  1  0 -1 -1 -1 -1 */
	t[1] = 0 + a32[1] + a32[2] - a32[4] - a32[5] - a32[6] - a32[7];
	/*  0  0  1  1  0 -1 -1 -1 */
	t[2] = 0 + a32[2] + a32[3] - a32[5] - a32[6] - a32[7];
	/* -1 -1  0  2  2  1  0 -1 */
	t[3] = 0 - a32[0] - a32[1] + 2 * a32[3] + 2 * a32[4] + a32[5] - a32[7];
	/*  0 -1 -1  0  2  2  1  0 */
	t[4] = 0 - a32[1] - a32[2] + 2 * a32[4] + 2 * a32[5] + a32[6];
	/*  0  0 -1 -1  0  2  2  1 */
	t[5] = 0 - a32[2] - a32[3] + 2 * a32[5] + 2 * a32[6] + a32[7];
	/* -1 -1  0  0  0  1  3  2 */
	t[6] = 0 - a32[0] - a32[1] + a32[5] + 3 * a32[6] + 2 * a32[7];
	/*  1  0 -1 -1 -1 -1  0  3 */
	t[7] = 0 + a32[0] - a32[2] - a32[3] - a32[4] - a32[5] + 3 * a32[7];

	t[1] += t[0] >> 32; t[0] &= 0xffffffff;
	t[2] += t[1] >> 32; t[1] &= 0xffffffff;
	t[3] += t[2] >> 32; t[2] &= 0xffffffff;
	t[4] += t[3] >> 32; t[3] &= 0xffffffff;
	t[5] += t[4] >> 32; t[4] &= 0xffffffff;
	t[6] += t[5] >> 32; t[5] &= 0xffffffff;
	t[7] += t[6] >> 32; t[6] &= 0xffffffff;

	o = t[7] >> 32; t[7] &= 0xffffffff;

	t[0] += o;
	t[3] -= o;
	t[6] -= o;
	t[7] += o;
	t[1] += t[0] >> 32; t[0] &= 0xffffffff;
	t[2] += t[1] >> 32; t[1] &= 0xffffffff;
	t[3] += t[2] >> 32; t[2] &= 0xffffffff;
	t[4] += t[3] >> 32; t[3] &= 0xffffffff;
	t[5] += t[4] >> 32; t[4] &= 0xffffffff;
	t[6] += t[5] >> 32; t[5] &= 0xffffffff;
	t[7] += t[6] >> 32; t[6] &= 0xffffffff;

	r[0] = (t[1] << 32) | t[0];
	r[1] = (t[3] << 32) | t[2];
	r[2] = (t[5] << 32) | t[4];
	r[3] = (t[7] << 32) | t[6];
}

/*
 * Precompute points for the comb method
 *
 * If i = i_{w-1} ... i_1 is the binary representation of i, then
 * T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
 *
 * T must be able to hold 2^{w - 1} elements
 *
 * Cost: ~ 2^{w-1} * (12*M + 9*S) + 2*2^{w-1}*(6*M + S) + 2*I
 * For w=4,S=0.8M this gives about 262*M + 2*I.
 */
static void
ecp256_precompute_comb(const unsigned long *pXY)
{
	int i, j;
	Ecp256Point *T = *this_cpu_ptr(&combT);

	/* Set T[0] = P and multiply it by Montogmery normalizer mod P256. */
	ecp256_to_mont(T->x, pXY);
	ecp256_to_mont(T->y, pXY + G_LIMBS);
	ecp256_set_mont_1(T);

	/* Set T[2^{i-1}] = 2^{di} P for i = 1 .. w-1 */
	for (i = 1; i < W_SZ; i <<= 1)
		ecp256_double_jac_n(&T[i], &T[i >> 1]);

	/*
	 * Compute the remaining ones using the minimal number of additions
	 * Be careful to update T[2^l] only after using it!
	 */
	for (i = 1; i < W_SZ; i <<= 1)
		for (j = i - 1; j >= 0; j--)
			ecp256_add_jac(&T[i + j], &T[j], &T[i]);
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 */
static void
ecp256_select_comb(Ecp256Point *r, const Ecp256Point T[], unsigned char i)
{
	static const unsigned long l_masks[2] = {0, 0xffffffffffffffffUL};
	unsigned char ii, j;

	/* Ignore the "sign" bit and scale down */
	ii =  (i & 0x7Fu) >> 1;

	/* Read the whole table to thwart cache-based timing attacks */
	for (j = 0; j < W_SZ; j++) {
		const unsigned long mask = l_masks[j == ii];

		r->x[0] ^= (r->x[0] ^ T[j].x[0]) & mask;
		r->x[1] ^= (r->x[1] ^ T[j].x[1]) & mask;
		r->x[2] ^= (r->x[2] ^ T[j].x[2]) & mask;
		r->x[3] ^= (r->x[3] ^ T[j].x[3]) & mask;

		r->y[0] ^= (r->y[0] ^ T[j].y[0]) & mask;
		r->y[1] ^= (r->y[1] ^ T[j].y[1]) & mask;
		r->y[2] ^= (r->y[2] ^ T[j].y[2]) & mask;
		r->y[3] ^= (r->y[3] ^ T[j].y[3]) & mask;

		r->z[0] ^= (r->z[0] ^ T[j].z[0]) & mask;
		r->z[1] ^= (r->z[1] ^ T[j].z[1]) & mask;
		r->z[2] ^= (r->z[2] ^ T[j].z[2]) & mask;
		r->z[3] ^= (r->z[3] ^ T[j].z[3]) & mask;
	}

	/* Safely invert result if i is "negative" */
	ecp256_safe_invert_jac(r, i >> 7);
}

static void
ecp256_select_comb_g(Ecp256Point *r, const EcpXY T[], unsigned char i)
{
	static const unsigned long l_masks[2] = {0, 0xffffffffffffffffUL};
	unsigned char ii, j;

	/* Ignore the "sign" bit and scale down */
	ii =  (i & 0x7Fu) >> 1;

	/* Read the whole table to thwart cache-based timing attacks */
	for (j = 0; j < G_W_SZ; j++) {
		const unsigned long mask = l_masks[j == ii];

		r->x[0] ^= (r->x[0] ^ T[j].x[0]) & mask;
		r->x[1] ^= (r->x[1] ^ T[j].x[1]) & mask;
		r->x[2] ^= (r->x[2] ^ T[j].x[2]) & mask;
		r->x[3] ^= (r->x[3] ^ T[j].x[3]) & mask;

		r->y[0] ^= (r->y[0] ^ T[j].y[0]) & mask;
		r->y[1] ^= (r->y[1] ^ T[j].y[1]) & mask;
		r->y[2] ^= (r->y[2] ^ T[j].y[2]) & mask;
		r->y[3] ^= (r->y[3] ^ T[j].y[3]) & mask;
	}

	/* Safely invert result if i is "negative" */
	ecp256_safe_invert_jac(r, i >> 7);
}


/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 *
 * For w=4,D=4S+4M,A=8M+3S,S=0.8M this gives about 1126*M, which with the
 * cost of ecp256_precompute_comb() gives ~1392+ 3*I, which is ~900-1000*M
 * better than the number for Jacobian cure shapes with 3*I in
 * "Analysis and optimization of elliptic-curve single-scalar multiplication",
 * by Bernstein & Lange, 2007.
 */
static void
ecp256_mul_comb_core(Ecp256Point *r, const unsigned char x[])
{
	const Ecp256Point *t = *this_cpu_ptr(&combT);
	Ecp256Point txi;
	size_t i = D;

	/*
	 * We operate with precomputed table which is significantly smaller
	 * than L1d cache - for secp256 and w=5:
	 *
	 *	(sizeof(ECP)=(2 * 32)) * (1 << (w - 1)) = 1024
	 *
	 * just 16 cache lines, which is 32 times smaller than L1d cache size.
	 * Also there is no preemption and point doubling and addition
	 * aren't memory hungry, so once being read T resides in L1d cache and
	 * we can address it directly without sacrificing safety against SCAs.
	 * Even in hyperthreading mode and keeping L1d cache associativity in
	 * mind, the probablity for the cache miss is too small to recover the
	 * secret bits.
	 *
	 * TODO #1064: 5. AVX2 - 4 points in parallel in OpenSSL,
	 * see ecp_nistz256_avx2_mul_g().
	 */
	ecp256_select_comb(r, t, x[i]);

	while (i--) {
		unsigned char ii = (x[i] & 0x7Fu) >> 1;

		/*
		 * TODO #1064 use merged doubling-addition formula.
		 *
		 * "New Composite Operations and Precomputation Schemefor
		 * Elliptic Curve Cryptosystems over Prime Fields" by Longa,
		 * 2008.
		 */

		ecp256_double_jac(r, r);

		memcpy(&txi, &t[ii], sizeof(txi));

		ecp256_safe_invert_jac(&txi, x[i] >> 7);

		ecp256_add_jac(r, r, &txi);
	}
}

/*
 * Multiplication R = m * P using the comb method.
 *
 * It seems integer sub-decomposition, introduced in "Point Multiplication using
 * Integer Sub-Decompositionfor Elliptic Curve Cryptography" by Ajeena et all,
 * makes the computation 50% faster, but relatively complex transformation of
 * `m` is required.
 *
 * In order to prevent timing attacks, this function executes the exact same
 * sequence of (base field) operations for any valid m. It avoids any if-branch
 * or array index depending on the value of m.
 *
 * If @rng is true, the functions randomizes intermediate results in order to
 * prevent potential timing attacks targeting these results.
 * TODO #1064: double SCA protection?
 *
 * TODO #1064: why wNAF isn't used? Is comb the most efficient method?
 * It seems WolfSSL's sp_256_ecc_mulmod_win_add_sub_avx2_4() also uses comb,
 * but with d=43 (w=6).
 * OpenSSL's ecp_nistz256_windowed_mul() use Booth windowed method.
 * It seems the both OpenSSL and WolfSSL don't use coordinates randomization.
 */
static void
ecp256_mul_comb(TlsEcpPoint *R, const TlsMpi *m, const unsigned long *P)
{
	/*
	 * Minimize the number of multiplications, that is to minimize
	 * (S = 0.8*M, I = 100*M):
	 *
	 *  18 * 2^(w-1) + 14 * (w-1) + 18 * d + 300
	 *
	 * The function values for different w:
	 *
	 * 1 -> 4926, 2 -> 2654, 3 -> 1948, 4 -> 1638, 5 -> 1580, 6 -> 1720.
	 *
	 * TODO #1064 at the moment we have S = 0.9*M and very expensive I,
	 * so recheck the optimal w value after the optimizations.
	 */
	unsigned long M[4], mm[4];
	unsigned char k[D + 1];
	Ecp256Point r;
	unsigned char m_is_odd = MPI_P(m)[0] & 1;

	ecp256_precompute_comb(P);

	/*
	 * Make sure M is odd (M = m or M = N - m, since N is odd)
	 * using the fact that m * P = - (N - m) * P
	 */
	ecp256_mpi_read(M, m);
	mpi_sub_mod_p256_x86_64(mm, G.secp256r1_n, MPI_P(m));
	ecp256_safe_cond_assign(M, mm, !m_is_odd);

	/* Go for comb multiplication, R = M * P */
	ecp256_comb_fixed(k, D, W, M);
	ecp256_mul_comb_core(&r, k);

	/* Now get m * P from M * P and normalize it. */
	ecp256_safe_invert_jac(&r, !m_is_odd);
	ecp256_normalize_jac(&r, true);

	ecp256_mpi_write(&R->X, r.x);
	ecp256_mpi_write(&R->Y, r.y);
	ecp256_mpi_write(&R->Z, r.z);
}

/**
 * Fixed-base comb method with V=d extended precomputed tables (GECC 3.45, 3.47).
 */
static void
ecp256_mul_comb_core_g(Ecp256Point *r, const unsigned char k[])
{
	Ecp256Point txi;
	size_t i = G_D - 1;
	unsigned char ii;
	unsigned long t1[8], t2[8], t3[8], t4[8], x[8], y[8], z[8];

	/*
	 * Start with a non-zero point and randomize its coordinates.
	 *
	 * TODO #1064: revert ecp_randomize_jac() - it's only 1S + 3M + R
	 * (R is for random, very fast).
	 */
	ecp256_select_comb_g(r, combT_G[G_D], k[G_D]);

	/*
	 * Do shorter computations for the first iteration with
	 * Z coordinate equal 1.
	 */
	ii = (k[i] & 0x7Fu) >> 1;

	/* Copy X and Y in one shot. */
	memcpy(&txi, &combT_G[i][ii], G_LIMBS * CIL * 2);
	ecp256_set_mont_1(&txi);
	ecp256_safe_invert_jac(&txi, k[i] >> 7);

	/* ecp256_add_mixed() for P->Z == 1 */
	// TODO #1064 ecp256_add_mixed(r, r, &txi);  P = r  Q = txi
	mpi_sub_mod_p256_x86_64(t1, txi.x, r->x);
	mpi_sub_mod_p256_x86_64(t2, txi.y, r->y);
	memcpy(z, t1, G_LIMBS * CIL);
	mpi_sqr_mont_mod_p256_x86_64(t3, t1);
	mpi_mul_mont_mod_p256_x86_64(t4, t3, t1);
	mpi_mul_mont_mod_p256_x86_64(t3, t3, r->x);
	mpi_shift_l1_mod_p256_x86_64(t1, t3);
	mpi_sqr_mont_mod_p256_x86_64(x, t2);
	mpi_sub_mod_p256_x86_64(x, x, t1);
	mpi_sub_mod_p256_x86_64(x, x, t4);
	mpi_sub_mod_p256_x86_64(t3, t3, x);
	mpi_mul_mont_mod_p256_x86_64(t3, t3, t2);
	mpi_mul_mont_mod_p256_x86_64(t4, t4, r->y);
	mpi_sub_mod_p256_x86_64(y, t3, t4);

	while (i--) {
		ii = (k[i] & 0x7Fu) >> 1;
		memcpy(&txi, &combT_G[i][ii], G_LIMBS * CIL * 2);

		ecp256_safe_invert_jac(&txi, k[i] >> 7);

		// TODO #1064 ecp256_add_mixed(r, r, &txi);
		mpi_sqr_mont_mod_p256_x86_64(t1, z);
		mpi_mul_mont_mod_p256_x86_64(t2, t1, z);
		mpi_mul_mont_mod_p256_x86_64(t1, t1, txi.x);
		mpi_mul_mont_mod_p256_x86_64(t2, t2, txi.y);
		mpi_sub_mod_p256_x86_64(t1, t1, x);
		mpi_sub_mod_p256_x86_64(t2, t2, y);
		mpi_mul_mont_mod_p256_x86_64(z, z, t1);
		mpi_sqr_mont_mod_p256_x86_64(t3, t1);
		mpi_mul_mont_mod_p256_x86_64(t4, t3, t1);
		mpi_mul_mont_mod_p256_x86_64(t3, t3, x);
		mpi_shift_l1_mod_p256_x86_64(t1, t3);
		mpi_sqr_mont_mod_p256_x86_64(x, t2);
		mpi_sub_mod_p256_x86_64(x, x, t1);
		mpi_sub_mod_p256_x86_64(x, x, t4);
		mpi_sub_mod_p256_x86_64(t3, t3, x);
		mpi_mul_mont_mod_p256_x86_64(t3, t3, t2);
		mpi_mul_mont_mod_p256_x86_64(t4, t4, y);
		mpi_sub_mod_p256_x86_64(y, t3, t4);
	}

	ecp256_copy(r->x, x);
	ecp256_copy(r->y, y);
	ecp256_copy(r->z, z);
}

/**
 * The ecp256_mul_comb() specialization for R = m * G.
 *
 * #8: Explore [14] and N.A.F.Mohamed et al, "Improved Fixed-base Comb Method
 * for Fast Scalar Multiplication" for more efficient non-constant time fixed
 * point multiplication - we can use the methods with point randomization.
 * [15] discussed that the current multi-table comb method isn't bad at all.
 */
static void
ecp256_mul_comb_g(TlsEcpPoint *R, const TlsMpi *m)
{
	unsigned long M[4], mm[4];
	unsigned char k[G_D + 1];
	Ecp256Point r;
	unsigned char m_is_odd = MPI_P(m)[0] & 1;

	/*
	 * Make sure M is odd (M = m or M = N - m, since N is odd)
	 * using the fact that m * P = - (N - m) * P
	 */
	ecp256_mpi_read(M, m);
	mpi_sub_mod_p256_x86_64(mm, G.secp256r1_n, MPI_P(m));
	ecp256_safe_cond_assign(M, mm, !m_is_odd);

	/* Go for comb multiplication, R = M * G */
	ecp256_comb_fixed(k, G_D, G_W, M);
	ecp256_mul_comb_core_g(&r, k);

	/* Now get m * G from M * G and normalize it. */
	ecp256_safe_invert_jac(&r, !m_is_odd);
	ecp256_normalize_jac(&r, true);

	ecp256_mpi_write(&R->X, r.x);
	ecp256_mpi_write(&R->Y, r.y);
	ecp256_mpi_write(&R->Z, r.z);
}

/*
 * Multiplication and addition of two points by integers: R = m * G + n * Q
 * In contrast to ttls_ecp_mul(), this function does not guarantee a constant
 * execution flow and timing - there is no secret data, so we don't need to care
 * about SCAs.
 *
 * TODO #769: The algorithm is naive. The Shamir's trick and/or
 * multi-exponentiation (Bodo Möller, "Algorithms for multi-exponentiation")
 * should be used. See OpenSSL's ec_wNAF_mul() as the reference.
 */
static void
ecp256_muladd(TlsEcpPoint *R, const TlsMpi *m, const TlsEcpPoint *Q,
	      const TlsMpi *n)
{
	unsigned long pXY[G_LIMBS * 2];
	TlsEcpPoint *mP;
	Ecp256Point r[2];

	ttls_ecp_point_tmp_alloc_init(mP, G_LIMBS, G_LIMBS, G_LIMBS);

	ecp256_mul_comb_g(mP, m);

	ecp256_copy(pXY, MPI_P(&Q->X));
	ecp256_copy(&pXY[G_LIMBS], MPI_P(&Q->Y));

	ecp256_mul_comb(R, n, pXY);

	ecp256_mpi_read(r[0].x, &R->X);
	ecp256_mpi_read(r[0].y, &R->Y);
	ecp256_mpi_read(r[0].z, &R->Z);
	ecp256_mpi_read(r[1].x, &mP->X);
	ecp256_mpi_read(r[1].y, &mP->Y);
	ecp256_mpi_read(r[1].z, &mP->Z);

	ecp256_add_mixed(&r[0], &r[1], &r[0]);
	ecp256_normalize_jac(&r[0], false);

	ecp256_mpi_write(&R->X, r[0].x);
	ecp256_mpi_write(&R->Y, r[0].y);
	ecp256_mpi_write(&R->Z, r[0].z);
}

/**
 * Generate a keypair with configurable base point - SEC1 3.2.1:
 * generate d such that 1 <= n < N.
 */
int
ecp256_gen_keypair(TlsMpi *d, TlsEcpPoint *Q)
{
	int count = 0;

	/*
	 * Match the procedure given in RFC 6979 (deterministic ECDSA):
	 * - use the same byte ordering;
	 * - keep the leftmost bits bits of the generated octet string;
	 * - try until result is in the desired range.
	 * This also avoids any biais, which is especially important
	 * for ECDSA.
	 */
	do {
		ttls_mpi_fill_random(d, G_BITS / 8);

		/*
		 * Each try has at worst a probability 1/2 of failing
		 * (the msb has a probability 1/2 of being 0, and then
		 * the result will be < N), so after 30 tries failure
		 * probability is a most 2**(-30).
		 *
		 * For most curves, 1 try is enough with overwhelming
		 * probability, since N starts with a lot of 1s in
		 * binary, but some curves such as secp224k1 are
		 * actually very close to the worst case.
		 */
		if (WARN_ON_ONCE(++count > 10))
			return TTLS_ERR_ECP_RANDOM_FAILED;
	} while (ttls_mpi_eq_0(d) || ttls_mpi_cmp_mpi(d, &G.N) >= 0);

	ecp256_mul_comb_g(Q, d);

	return 0;
}

/*
 * Derive a suitable integer for the group from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static void
derive_mpi(TlsMpi *x, const unsigned char *buf, size_t blen)
{
	const size_t n_size = G_BITS / 8;
	const size_t use_size = blen > n_size ? n_size : blen;

	ttls_mpi_read_binary(x, buf, use_size);

	/* While at it, reduce modulo N */
	if (ttls_mpi_cmp_mpi(x, &G.N) >= 0)
		ttls_mpi_sub_mpi(x, x, &G.N);
}

/**
 * This function computes the ECDSA signature of a hashed message (SEC1 4.1.3)
 * and writes it to a buffer, serialized as defined in RFC 8422 5.4.
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message).
 *
 * The sig buffer must be at least twice as large as the size of the curve used,
 * plus 9. For example, 73 Bytes if a 256-bit curve is used. A buffer length of
 * TTLS_ECDSA_MAX_LEN is always safe.
 *
 * If the bitlength of the message hash is larger than the bitlength of the
 * group order, then the hash is truncated as defined in Standards for Efficient
 * Cryptography Group (SECG): SEC1 Elliptic Curve Cryptography, section 4.1.3,
 * step 5.
 *
 * This is the late phase of ServerKeyExchange, so no need to clear the mpool
 * stack at the end of the function.
 */
static int
ecp256_ecdsa_sign(const TlsMpi *d, const unsigned char *hash, size_t hlen,
		  unsigned char *sig, size_t *slen)
{
	int key_tries, sign_tries, blind_tries;
	TlsEcpPoint *R;
	DECLARE_MPI_AUTO(k, G_LIMBS * 2);
	DECLARE_MPI_AUTO(e, G_LIMBS * 3 + 1);
	DECLARE_MPI_AUTO(s, G_LIMBS * 4);
	DECLARE_MPI_AUTO(t, G_LIMBS);
	DECLARE_MPI_AUTO(r, G_LIMBS);

	BUG_ON(d->s < 0);

	ttls_ecp_point_tmp_alloc_init(R, G_LIMBS, G_LIMBS, G_LIMBS);

	sign_tries = 0;
	do {
		/* Generate a suitable ephemeral keypair and set r = xR mod n */
		key_tries = 0;
		do {
			/*
			 * TODO #1064: use ecp256_mul_comb_g() directly:
			 * 1. merge random generation in one call
			 * 2. call ecp256_normalize_jac() only for R->X
			 */
			MPI_CHK(ecp256_gen_keypair(&k, R));
			ttls_mpi_mod_mpi(&r, &R->X, &G.N);

			if (key_tries++ > 10)
				return TTLS_ERR_ECP_RANDOM_FAILED;
		} while (ttls_mpi_eq_0(&r));

		/* Derive MPI from hashed message. */
		derive_mpi(&e, hash, hlen);

		/*
		 * Generate a random value to blind inv_mod in next step,
		 * avoiding a potential timing leak.
		 */
		blind_tries = 0;
		do {
			ttls_mpi_fill_random(&t, G_BITS / 8);

			/* See ttls_ecp_gen_keypair() */
			if (++blind_tries > 10)
				return TTLS_ERR_ECP_RANDOM_FAILED;
		} while (ttls_mpi_eq_0(&t) || ttls_mpi_cmp_mpi(&t, &G.N) >= 0);

		/* Compute s = (e + r * d) / k = t (e + rd) / (kt) mod n */
		mpi_mul_x86_64_4(MPI_P(&s), MPI_P(&r), MPI_P(d));

		mpi_fixup_used(&s, G_LIMBS * 2);
		ttls_mpi_add_mpi(&e, &e, &s);

		ttls_mpi_mul_mpi(&e, &e, &t);

		mpi_mul_x86_64_4(MPI_P(&k), MPI_P(&k), MPI_P(&t));

		mpi_fixup_used(&k, G_LIMBS * 2);
		ttls_mpi_mod_mpi(&k, &k, &G.N);
		ecp256_inv_mod(&s, &k, &G.N);
		ttls_mpi_mul_mpi(&s, &s, &e);
		ttls_mpi_mod_mpi(&s, &s, &G.N);

		if (sign_tries++ > 10)
			return TTLS_ERR_ECP_RANDOM_FAILED;
	} while (ttls_mpi_eq_0(&s));

	return ecdsa_signature_to_asn1(&r, &s, sig, slen);
}

/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message).
 *
 * @buf		- the message hash;
 * @blen	- the length of the hash buf;
 * @Q		- the public key to use for verification;
 * @r		- the first integer of the signature;
 * @s		- the second integer of the signature.
 *
 * If the bitlength of the message hash is larger than the bitlength of the
 * group order, then the hash is truncated as defined in Standards for Efficient
 * Cryptography Group (SECG): SEC1 Elliptic Curve Cryptography, section 4.1.4,
 * step 3.
 */
static int
ecp256_ecdsa_verify(const unsigned char *buf, size_t blen, const TlsEcpPoint *Q,
		    const TlsMpi *r, const TlsMpi *s)
{
	TlsEcpPoint *R;
	DECLARE_MPI_AUTO(e, G_LIMBS);
	DECLARE_MPI_AUTO(s_inv, G_LIMBS * 2);
	DECLARE_MPI_AUTO(u1, G_LIMBS * 2);
	DECLARE_MPI_AUTO(u2, G_LIMBS * 2);

	ttls_ecp_point_tmp_alloc_init(R, G_LIMBS, G_LIMBS, G_LIMBS);

	/* Step 1: make sure r and s are in range 1..n-1 */
	if (ttls_mpi_cmp_int(r, 1) < 0 || ttls_mpi_cmp_mpi(r, &G.N) >= 0
	    || ttls_mpi_cmp_int(s, 1) < 0 || ttls_mpi_cmp_mpi(s, &G.N) >= 0)
		return TTLS_ERR_ECP_VERIFY_FAILED;

	/* Step 3: derive MPI from hashed message. */
	derive_mpi(&e, buf, blen);

	/* Step 4: u1 = e / s mod n, u2 = r / s mod n */
	ecp256_inv_mod(&s_inv, s, &G.N);
	ecp256_mul(&u1, &e, &s_inv);
	ttls_mpi_mod_mpi(&u1, &u1, &G.N);
	ecp256_mul(&u2, r, &s_inv);
	ttls_mpi_mod_mpi(&u2, &u2, &G.N);

	/*
	 * Step 5: R = u1 G + u2 Q
	 *
	 * Since we're not using any secret data, no need to pass a RNG to
	 * ttls_ecp_mul() for countermesures.
	 */
	ecp256_muladd(R, &u1, Q, &u2);
	if (ttls_ecp_is_zero(R))
		return TTLS_ERR_ECP_VERIFY_FAILED;

	/*
	 * Step 6: convert xR to an integer (no-op)
	 * Step 7: reduce xR mod n (gives v)
	 */
	ttls_mpi_mod_mpi(&R->X, &R->X, &G.N);

	/* Step 8: check if v (that is, R.X) is equal to r. */
	return ttls_mpi_cmp_mpi(&R->X, r);
}

const TlsEcpGrp SECP256_G ____cacheline_aligned = {
	.id		= TTLS_ECP_DP_SECP256R1,
	.bits		= G_BITS,

	.mul		= ecp256_mul_comb,
	.muladd		= ecp256_muladd,
	.gen_keypair	= ecp256_gen_keypair,
	.ecdsa_sign	= ecp256_ecdsa_sign,
	.ecdsa_verify	= ecp256_ecdsa_verify,
};
