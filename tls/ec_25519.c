/**
 *		Tempesta TLS
 *
 * Elliptic curve 25519 (Montgomery).
 *
 * TODO #1335: the slow implementation is still based on mbed TLS.
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

/* Size of p255 in terms of unsigned long */
#define P255_WIDTH	  (255 / 8 / sizeof(unsigned long) + 1)

/**
 * Fast quasi-reduction modulo p255 = 2^255 - 19.
 * Write N as A0 + 2^255 A1, return A0 + 19 * A1.
 */
void
ecp_mod_p255(TlsMpi *N)
{
	size_t n;
	TlsMpi *M;

	BUG_ON(N->used < P255_WIDTH);

	M = ttls_mpi_alloc_stack_init(P255_WIDTH + 2);

	/* M = A1 */
	M->used = N->used - (P255_WIDTH - 1);
	if (M->used > P255_WIDTH + 1)
		M->used = P255_WIDTH + 1;
	n = M->used * CIL;
	memcpy_fast(MPI_P(M), MPI_P(N) + P255_WIDTH - 1, n);
	bzero_fast((char *)MPI_P(M) + n, (P255_WIDTH + 2) * CIL - n);
	ttls_mpi_shift_r(M, 255 % BIL);

	/* N = A0 */
	ttls_mpi_set_bit(N, 255, 0);
	N->used = P255_WIDTH;

	/* N = A0 + 19 * A1 */
	ttls_mpi_mul_uint(M, M, 19);
	ttls_mpi_add_abs(N, N, M);
}

static void
c25519_mul_mod(const TlsEcpGrp *grp, TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	ttls_mpi_mul_mpi(X, A, B);

	BUG_ON(X->limbs < grp->bits * 2 / BIL);
	BUG_ON(X->s < 0);

	if (X->used > grp->bits / BIL)
		/*
		 * P modulo is very close to the maximum value of 4-limbs MPI,
		 * so only one addition or subtraction will be enough to
		 * get the modulo and we don't need to execute the exepnsive
		 * reduction operation.
		 */
		ecp_mod_p255(X);

	while (X->s < 0 && ttls_mpi_cmp_int(X, 0))
		ttls_mpi_add_mpi(X, X, &grp->P);

	while (ttls_mpi_cmp_mpi(X, &grp->P) >= 0)
		/* We known P, N and the result are positive. */
		ttls_mpi_sub_abs(X, X, &grp->P);
}

/*
 * Normalize Montgomery x/z coordinates: X = X/Z, Z = 1
 * Cost: 1M + 1I
 */
static int
ecp_normalize_mxz(const TlsEcpGrp *grp, TlsEcpPoint *P)
{
	MPI_CHK(ttls_mpi_inv_mod(&P->Z, &P->Z, &grp->P));
	c25519_mul_mod(grp, &P->X, &P->X, &P->Z);
	ttls_mpi_lset(&P->Z, 1);

	return 0;
}

/*
 * Randomize projective x/z coordinates: (X, Z) -> (l X, l Z) for random l.
 * This is sort of the reverse operation of ecp_normalize_mxz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 2M
 */
static int
ecp_randomize_mxz(const TlsEcpGrp *grp, TlsEcpPoint *P)
{
	TlsMpi *l = ttls_mpi_alloc_stack_init(0);
	size_t p_size;
	int count = 0;

	p_size = (grp->bits + 7) / 8;

	/* Generate l such that 1 < l < p */
	do {
		ttls_mpi_fill_random(l, p_size);

		while (ttls_mpi_cmp_mpi(l, &grp->P) >= 0)
			ttls_mpi_shift_r(l, 1);

		if (count++ > 10)
			return TTLS_ERR_ECP_RANDOM_FAILED;
	} while (ttls_mpi_cmp_int(l, 1) <= 0);

	c25519_mul_mod(grp, &P->X, &P->X, l);
	c25519_mul_mod(grp, &P->Z, &P->Z, l);

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
ecp_double_add_mxz(const TlsEcpGrp *grp, TlsEcpPoint *R, TlsEcpPoint *S,
		   const TlsEcpPoint *P, const TlsEcpPoint *Q, const TlsMpi *d)
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
	ecp_sqr_mod(grp, AA, A);
	ttls_mpi_sub_mpi(B, &P->X, &P->Z);
	MOD_SUB(B);
	ecp_sqr_mod(grp, BB, B);
	ttls_mpi_sub_mpi(E, AA, BB);
	MOD_SUB(E);
	ttls_mpi_add_mpi(C, &Q->X, &Q->Z);
	MOD_ADD(C);
	ttls_mpi_sub_mpi(D, &Q->X, &Q->Z);
	MOD_SUB(D);
	c25519_mul_mod(grp, DA, D, A);
	c25519_mul_mod(grp, CB, C, B);
	ttls_mpi_add_mpi(&S->X, DA, CB);
	MOD_ADD(&S->X);
	ecp_sqr_mod(grp, &S->X, &S->X);
	ttls_mpi_sub_mpi(&S->Z, DA, CB);
	MOD_SUB(&S->Z);
	ecp_sqr_mod(grp, &S->Z, &S->Z);
	c25519_mul_mod(grp, &S->Z, &S->Z, d);
	c25519_mul_mod(grp, &R->X, AA, BB);
	c25519_mul_mod(grp, &R->Z, &grp->A, E);
	ttls_mpi_add_mpi(&R->Z, BB, &R->Z);
	MOD_ADD(&R->Z);
	c25519_mul_mod(grp, &R->Z, &R->Z, E);

	return 0;
}

/**
 * Multiplication with Montgomery ladder in x/z coordinates,
 * for curves in Montgomery form.
 */
static int
ecp_mul_mxz(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
	    const TlsEcpPoint *P, bool rng)
{
	size_t i;
	unsigned char b;
	TlsEcpPoint *RP;
	TlsMpi *PX;

	PX = ttls_mpi_alloc_stack_init(0);
	RP = ttls_mpool_alloc_stack(sizeof(*RP));
	ttls_ecp_point_init(RP);

	/* Save PX and read from P before writing to R, in case P == R */
	ttls_mpi_copy(PX, &P->X);
	ttls_ecp_copy(RP, P);

	/* Set R to zero in modified x/z coordinates */
	ttls_mpi_lset(&R->X, 1);
	ttls_mpi_lset(&R->Z, 0);
	ttls_mpi_reset(&R->Y);

	/* RP.X might be sligtly larger than P, so reduce it */
	MOD_ADD(&RP->X);

	/* Randomize coordinates of the starting point */
	if (rng)
		MPI_CHK(ecp_randomize_mxz(grp, RP));

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
		MPI_CHK(ecp_double_add_mxz(grp, R, RP, R, RP, PX));
		MPI_CHK(ttls_mpi_safe_cond_swap(&R->X, &RP->X, b));
		MPI_CHK(ttls_mpi_safe_cond_swap(&R->Z, &RP->Z, b));
	}

	return ecp_normalize_mxz(grp, R);
}

/* TODO #1335 specialize the routine. */
static int
ecp_mul_mxz_g(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m, bool rnd)
{
	return ecp_mul_mxz(grp, R, m, &grp->G, rnd);
}

/*
 * Specialized function for creating the Curve25519 group
 */
void
ec_grp_init_curve25519(TlsEcpGrp *grp)
{
	T_WARN("Try to load ECP group for unsupported Curve25519.\n");

	/* Actually (A + 2) / 4 */
	ttls_mpi_read_binary(&grp->A, "\x01\xDB\x42", 3);

	/* P = 2^255 - 19 */
	ttls_mpi_lset(&grp->P, 1);
	ttls_mpi_shift_l(&grp->P, 255);
	ttls_mpi_sub_int(&grp->P, &grp->P, 19);

	/*
	 * Y intentionaly isn't set, since we use x/z coordinates.
	 * This is used as a marker to identify Montgomery curves -
	 * see ecp_get_type().
	 */
	ttls_mpi_lset(&grp->G.X, 9);
	ttls_mpi_lset(&grp->G.Z, 1);

	/* Actually, the required msb for private keys */
	grp->bits = 254;

	grp->mul = ecp_mul_mxz;
	grp->mul_g = ecp_mul_mxz_g;
}
