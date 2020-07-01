/**
 *		Tempesta TLS
 *
 * Elliptic curve 25519 (Montgomery).
 *
 * TODO #1335: the slow and incomplete implementation is still based on mbed TLS.
 *
 * For Montgomery curves, we do all the internal arithmetic in projective
 * coordinates. Import/export of points uses only the x coordinates, which is
 * internaly represented as X / Z.
 *
 * For scalar multiplication, we'll use a Montgomery ladder.
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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
#include "ecp.h"
#include "mpool.h"

#define G_BITS		254
#define G_LIMBS		((G_BITS + 7) / BIL)

static const struct {
	unsigned long	c25519_p[G_LIMBS];
	unsigned long	c25519_a[G_LIMBS];
	unsigned long	c25519_gx[G_LIMBS];
	unsigned long	c25519_gz[G_LIMBS];

	TlsMpi		P;
	TlsMpi		A;
	TlsMpi		__align_placeholder[2];
	TlsEcpPoint	G;
} ____cacheline_aligned __attribute__((packed)) G = {
	/* P = 2^255 - 19 */
	.c25519_p = {
		0xffffffffffffffedUL, 0xffffffffffffffffUL,
		0xffffffffffffffffUL, 0x7fffffffffffffffUL
	},
	.c25519_a = {
		0x1db42UL, 0, 0, 0
	},
	.c25519_gx = {
		0x9UL, 0, 0, 0
	},
	.c25519_gz = {
		0x1UL, 0, 0, 0
	},
	.P = {
		.s	= 1,
		.used	= G_LIMBS,
		.limbs	= G_LIMBS,
		._off	= -4 * (short)(G_LIMBS * CIL)
	},
	.A = {
		.s	= 1,
		.used	= 1,
		.limbs	= G_LIMBS,
		._off	= -3 * (short)(G_LIMBS * CIL) - 1 * (short)sizeof(TlsMpi)
	},
	.__align_placeholder = {},
	.G = {
		/*
		 * Y intentionaly isn't set, since we use x/z coordinates.
		 * This is used as a marker to identify Montgomery curves -
		 * see ecp_get_type().
		 */
		.X = {
			.s	= 1,
			.used	= G_LIMBS,
			.limbs	= G_LIMBS,
			._off	= -2 * (short)(G_LIMBS * CIL)
				  - 4 * (short)sizeof(TlsMpi)
		},
		.Z = {
			.s	= 1,
			.used	= 1,
			.limbs	= G_LIMBS,
			._off	= -1 * (short)(G_LIMBS * CIL)
				  - 5 * (short)sizeof(TlsMpi)
		}
	}
};

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * multiplication are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a TlsMpi mod p in-place, to use after ttls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
static inline void
MOD_SUB(TlsMpi *N)
{
	while ((N)->s < 0 && ttls_mpi_cmp_int(N, 0))
		ttls_mpi_add_mpi(N, N, &G.P);
}

/*
 * Reduce a TlsMpi mod p in-place, to use after ttls_mpi_add_mpi().
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
static inline void
MOD_ADD(TlsMpi *N)
{
	while (ttls_mpi_cmp_mpi(N, &G.P) >= 0)
		ttls_mpi_sub_abs(N, N, &G.P);
}

/**
 * Fast quasi-reduction modulo p255 = 2^255 - 19.
 * Write N as A0 + 2^255 A1, return A0 + 19 * A1.
 */
void
ecp_mod_p255(TlsMpi *N)
{
	size_t n;
	TlsMpi *M;

	BUG_ON(N->used < G_LIMBS);

	M = ttls_mpi_alloc_stack_init(G_LIMBS + 2);

	/* M = A1 */
	M->used = N->used - (G_LIMBS - 1);
	if (M->used > G_LIMBS + 1)
		M->used = G_LIMBS + 1;
	n = M->used * CIL;
	memcpy_fast(MPI_P(M), MPI_P(N) + G_LIMBS - 1, n);
	bzero_fast((char *)MPI_P(M) + n, (G_LIMBS + 2) * CIL - n);
	ttls_mpi_shift_r(M, 255 % BIL);

	/* N = A0 */
	ttls_mpi_set_bit(N, 255, 0);
	N->used = G_LIMBS;

	/* N = A0 + 19 * A1 */
	ttls_mpi_mul_uint(M, M, 19);
	ttls_mpi_add_abs(N, N, M);
}

static void
c25519_mul_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	ttls_mpi_mul_mpi(X, A, B);

	BUG_ON(X->limbs < G_LIMBS * 2);
	BUG_ON(X->s < 0);

	if (X->used > G_LIMBS)
		/*
		 * P modulo is very close to the maximum value of 4-limbs MPI,
		 * so only one addition or subtraction will be enough to
		 * get the modulo and we don't need to execute the exepnsive
		 * reduction operation.
		 */
		ecp_mod_p255(X);

	while (X->s < 0 && ttls_mpi_cmp_int(X, 0))
		ttls_mpi_add_mpi(X, X, &G.P);

	while (ttls_mpi_cmp_mpi(X, &G.P) >= 0)
		/* We known P, N and the result are positive. */
		ttls_mpi_sub_abs(X, X, &G.P);
}

#define ecp_sqr_mod(X, A)	c25519_mul_mod(X, A, A)

/*
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * Cost: 1M + 1I
 */
static void
ecp_normalize_mxz(TlsEcpPoint *P)
{
	ttls_mpi_inv_mod(&P->Z, &P->Z, &G.P);
	c25519_mul_mod(&P->X, &P->X, &P->Z);
	ttls_mpi_lset(&P->Z, 1);
}

/*
 * Randomize projective x/z coordinates: (X, Z) -> (l X, l Z) for random l.
 * This is sort of the reverse operation of ecp_normalize_mxz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 2M
 */
static int
ecp_randomize_mxz(TlsEcpPoint *P)
{
	TlsMpi *l = ttls_mpi_alloc_stack_init(0);
	size_t p_size;
	int count = 0;

	p_size = (G_BITS + 7) / 8;

	/* Generate l such that 1 < l < p */
	do {
		ttls_mpi_fill_random(l, p_size);

		while (ttls_mpi_cmp_mpi(l, &G.P) >= 0)
			ttls_mpi_shift_r(l, 1);

		if (count++ > 10)
			return TTLS_ERR_ECP_RANDOM_FAILED;
	} while (ttls_mpi_cmp_int(l, 1) <= 0);

	c25519_mul_mod(&P->X, &P->X, l);
	c25519_mul_mod(&P->Z, &P->Z, l);

	return 0;
}

/**
 * Double-and-add: R = 2P, S = P + Q, with d = X(P - Q), for Montgomery curves
 * in x/z coordinates.
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/montgom/xz/ladder/mladd-1987-m.op3
 * with
 * d =  X1
 * P = (X2, Z2)
 * Q = (X3, Z3)
 * R = (X4, Z4)
 * S = (X5, Z5)
 * and eliminating temporary variables tO, ..., t4.
 *
 * Cost: 5M + 4S
 */
static int
ecp_double_add_mxz(TlsEcpPoint *R, TlsEcpPoint *S, const TlsEcpPoint *P,
		   const TlsEcpPoint *Q, const TlsMpi *d)
{
	TlsMpi *A, *AA, *B, *BB, *E, *C, *D, *DA, *CB;
	size_t n;

	n = sizeof(TlsMpi) * 9 + CIL * ((max(P->X.used, P->Z.used) + 1) * 9
					+ (max(Q->X.used, Q->Z.used) + 1) * 4);
	A = ttls_mpool_alloc_stack(n);
	AA = ttls_mpi_init_next(A, max(P->X.used, P->Z.used) + 1);
	B = ttls_mpi_init_next(AA, A->limbs * 2);
	BB = ttls_mpi_init_next(B, max(P->X.used, P->Z.used));
	E = ttls_mpi_init_next(BB, B->limbs * 2);
	C = ttls_mpi_init_next(E, max(P->X.used, P->Z.used) * 2);
	D = ttls_mpi_init_next(C, max(Q->X.used, Q->Z.used) + 1);
	DA = ttls_mpi_init_next(D, max(Q->X.used, Q->Z.used));
	CB = ttls_mpi_init_next(DA, D->limbs + A->limbs);
	ttls_mpi_init_next(CB, C->limbs + B->limbs);

	ttls_mpi_add_mpi(A, &P->X, &P->Z);
	MOD_ADD(A);
	ecp_sqr_mod(AA, A);
	ttls_mpi_sub_mpi(B, &P->X, &P->Z);
	MOD_SUB(B);
	ecp_sqr_mod(BB, B);
	ttls_mpi_sub_mpi(E, AA, BB);
	MOD_SUB(E);
	ttls_mpi_add_mpi(C, &Q->X, &Q->Z);
	MOD_ADD(C);
	ttls_mpi_sub_mpi(D, &Q->X, &Q->Z);
	MOD_SUB(D);
	c25519_mul_mod(DA, D, A);
	c25519_mul_mod(CB, C, B);
	ttls_mpi_add_mpi(&S->X, DA, CB);
	MOD_ADD(&S->X);
	ecp_sqr_mod(&S->X, &S->X);
	ttls_mpi_sub_mpi(&S->Z, DA, CB);
	MOD_SUB(&S->Z);
	ecp_sqr_mod(&S->Z, &S->Z);
	c25519_mul_mod(&S->Z, &S->Z, d);
	c25519_mul_mod(&R->X, AA, BB);
	c25519_mul_mod(&R->Z, &G.A, E);
	ttls_mpi_add_mpi(&R->Z, BB, &R->Z);
	MOD_ADD(&R->Z);
	c25519_mul_mod(&R->Z, &R->Z, E);

	return 0;
}

/**
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form.
 */
static int
ecp_mul_mxz(TlsEcpPoint *R, const TlsMpi *m, const unsigned long *pX,
	    const unsigned long *pY, bool rng)
{
	size_t i;
	unsigned char b;
	TlsEcpPoint *RP;
	TlsMpi *PX;

	PX = ttls_mpi_alloc_stack_init(G_LIMBS);
	memcpy_fast(MPI_P(PX), pX, G_LIMBS << LSHIFT);
	mpi_fixup_used(PX, G_LIMBS);

	ttls_ecp_point_tmp_alloc_init(RP, G_LIMBS, G_LIMBS, G_LIMBS);
	memcpy_fast(MPI_P(&RP->X), pX, G_LIMBS * CIL);
	mpi_fixup_used(&RP->X, G_LIMBS);
	memcpy_fast(MPI_P(&RP->Y), pY, G_LIMBS * CIL);
	mpi_fixup_used(&RP->Y, G_LIMBS);
	ttls_mpi_lset(&RP->Z, 1);

	/* Set R to zero in modified x/z coordinates */
	ttls_mpi_lset(&R->X, 1);
	ttls_mpi_lset(&R->Z, 0);
	ttls_mpi_lset(&R->Y, 0); /* TODO #1335 reset/free the MPI */

	/* RP.X might be sligtly larger than P, so reduce it */
	MOD_ADD(&RP->X);

	/* Randomize coordinates of the starting point */
	if (rng)
		MPI_CHK(ecp_randomize_mxz(RP));

	/*
	 * Loop invariant: R = result so far, RP = R + P.
	 * One past the (zero-based) most significant bit.
	 */
	i = ttls_mpi_bitlen(m);
	while (i-- > 0) {
		b = ttls_mpi_get_bit(m, i);
		/*
		 *  if (b) R = 2R + P else R = 2R,
		 * which is:
		 *  if (b) double_add(RP, R, RP, R)
		 *  else   double_add(R, RP, R, RP)
		 * but using safe conditional swaps to avoid leaks
		 */
		MPI_CHK(ttls_mpi_safe_cond_swap(&R->X, &RP->X, b));
		MPI_CHK(ttls_mpi_safe_cond_swap(&R->Z, &RP->Z, b));
		MPI_CHK(ecp_double_add_mxz(R, RP, R, RP, PX));
		MPI_CHK(ttls_mpi_safe_cond_swap(&R->X, &RP->X, b));
		MPI_CHK(ttls_mpi_safe_cond_swap(&R->Z, &RP->Z, b));
	}

	ecp_normalize_mxz(R);

	return 0;
}

/* TODO #1335 specialize the routine. */
static int
ecp_mul_mxz_g(TlsEcpPoint *R, const TlsMpi *m, bool rnd)
{
	return ecp_mul_mxz(R, m, MPI_P(&G.G.X), MPI_P(&G.G.Y), rnd);
}

/*
 * TODO #1335 revert the projective coordinates randomization if DPA is
 * required or remove completely.
 */
static int
ecp_mul_mxz_rnd(TlsEcpPoint *R, const TlsMpi *m, const unsigned long *P)
{
	return ecp_mul_mxz(R, m, P, P + G_LIMBS, false);
}

/**
 * Generate a keypair with configurable base point: [M225] page 5.
 */
static int
ec25519_gen_keypair(TlsMpi *d, TlsEcpPoint *Q)
{
	size_t n_size = (G_BITS + 7) / 8;
	size_t b;

	do {
		ttls_mpi_fill_random(d, n_size);
	} while (!ttls_mpi_bitlen(d));

	/* Make sure the most significant bit is bits */
	b = ttls_mpi_bitlen(d) - 1; /* ttls_mpi_bitlen is one-based */
	if (b > G_BITS)
		ttls_mpi_shift_r(d, b - G_BITS);
	else
		ttls_mpi_set_bit(d, G_BITS, 1);

	/* Make sure the last three bits are unset */
	ttls_mpi_set_bit(d, 0, 0);
	ttls_mpi_set_bit(d, 1, 0);
	ttls_mpi_set_bit(d, 2, 0);

	return ecp_mul_mxz_g(Q, d, true);
}

const TlsEcpGrp CURVE25519_G ____cacheline_aligned = {
	.id		= TTLS_ECP_DP_CURVE25519,
	.bits		= G_BITS,

	.mul		= ecp_mul_mxz_rnd,
	.gen_keypair	= ec25519_gen_keypair,
};
