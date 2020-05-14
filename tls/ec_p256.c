/**
 *		Tempesta TLS
 *
 * Elliptic curve NIST secp256r1 (prime256v1, short Weierstrass).
 * See implementation references in ecp.c.
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

/*
 * Domain parameters for secp256r1 (prime256v1) - Generalized Mersenne primes.
 * The constants are in little-endian order to be directly copied into MPIs.
 */
static const unsigned long secp256r1_p[] = {
	0xffffffffffffffffUL, 0xffffffffUL, 0UL, 0xffffffff00000001UL
};
static const unsigned long secp256r1_b[] = {
	0x3bce3c3e27d2604bUL, 0x651d06b0cc53b0f6UL,
	0xb3ebbd55769886bcUL, 0x5ac635d8aa3a93e7UL
};
static const unsigned long secp256r1_gx[] = {
	0xf4a13945d898c296UL, 0x77037d812deb33a0UL,
	0xf8bce6e563a440f2UL, 0x6b17d1f2e12c4247UL
};
static const unsigned long secp256r1_gy[] = {
	0xcbb6406837bf51f5UL, 0x2bce33576b315eceUL,
	0x8ee7eb4a7c0f9e16UL, 0x4fe342e2fe1a7f9bUL
};
static const unsigned long secp256r1_n[] = {
	0xf3b9cac2fc632551UL, 0xbce6faada7179e84UL,
	0xffffffffffffffffUL, 0xffffffff00000000UL
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
#define MOD_SUB(N)							\
	while ((N)->s < 0 && ttls_mpi_cmp_int(N, 0))			\
		ttls_mpi_add_mpi(N, N, &grp->P)

/*
 * Reduce a TlsMpi mod p in-place, to use after ttls_mpi_add_mpi().
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD(N)							\
	while (ttls_mpi_cmp_mpi(N, &grp->P) >= 0)			\
		ttls_mpi_sub_abs(N, N, &grp->P)

/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

static void
ecp256_mul_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	BUG_ON(X->limbs < 4);
	BUG_ON(A->limbs < 4 || B->limbs < 4);
	BUG_ON(A->s < 0 || B->s < 0);
	BUG_ON(A->used != 4 || B->used != 4);

	mpi_mul_x86_64_4(MPI_P(X), MPI_P(A), MPI_P(B));

	mpi_fixup_used(X, 8);
	X->s = A->s * B->s;

	ecp_mod_p256_x86_64(MPI_P(X), X->used);
	mpi_fixup_used(X, 4);
}

static void
ecp256_sqr_mod(TlsMpi *X, const TlsMpi *A)
{
	BUG_ON(X->limbs < 4);
	BUG_ON(A->limbs < 4);
	BUG_ON(A->s < 0);
	BUG_ON(A->used != 4);

	mpi_sqr_x86_64_4(MPI_P(X), MPI_P(A));

	mpi_fixup_used(X, 8);
	X->s = 1;

	ecp_mod_p256_x86_64(MPI_P(X), X->used);
	mpi_fixup_used(X, 4);
}

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int
ecp256_normalize_jac(const TlsEcpGrp *grp, TlsEcpPoint *pt)
{
	TlsMpi *Zi, *ZZi;

	if (!ttls_mpi_cmp_int(&pt->Z, 0))
		return 0;

	Zi = ttls_mpi_alloc_stack_init(grp->bits / BIL);
	ZZi = ttls_mpi_alloc_stack_init(grp->bits * 2 / BIL);

	/* X = X / Z^2  mod p */
	MPI_CHK(ttls_mpi_inv_mod(Zi, &pt->Z, &grp->P));
	ecp256_sqr_mod(ZZi, Zi);
	ecp256_mul_mod(&pt->X, &pt->X, ZZi);

	/* Y = Y / Z^3  mod p */
	ecp256_mul_mod(&pt->Y, &pt->Y, ZZi);
	ecp256_mul_mod(&pt->Y, &pt->Y, Zi);

	/* Z = 1 */
	ttls_mpi_lset(&pt->Z, 1);

	return 0;
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int
ecp256_normalize_jac_many(const TlsEcpGrp *grp, TlsEcpPoint *T[], size_t t_len)
{
#define __INIT_C(i)							\
do {									\
	c[i].s = 1;							\
	c[i].used = 0;							\
	c[i].limbs = n_limbs;						\
	c[i]._off = (unsigned long)p_limbs - (unsigned long)(c + i);	\
	p_limbs += n_limbs;						\
} while (0)

	int i, ret = 0;
	unsigned long *p_limbs, n_limbs = grp->bits * 2 / BIL;
	TlsMpi *u, *Zi, *ZZi, *c;

	WARN_ON_ONCE(t_len < 2);
	BUG_ON(t_len > TTLS_ECP_WINDOW_SIZE);

	c = ttls_mpool_alloc_stack((sizeof(TlsMpi) + n_limbs * CIL) * t_len);
	u = ttls_mpi_alloc_stack_init(n_limbs);
	Zi = ttls_mpi_alloc_stack_init(n_limbs);
	ZZi = ttls_mpi_alloc_stack_init(n_limbs);
	bzero_fast(c, sizeof(TlsMpi) * t_len);
	p_limbs = (unsigned long *)&c[t_len];

	/* c[i] = Z_0 * ... * Z_i */
	__INIT_C(0);
	ttls_mpi_copy_alloc(&c[0], &T[0]->Z, false);
	for (i = 1; i < t_len; i++) {
		__INIT_C(i);
		ecp256_mul_mod(&c[i], &c[i - 1], &T[i]->Z);
	}

	/* u = 1 / (Z_0 * ... * Z_n) mod P */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(u, &c[t_len - 1], &grp->P));

	for (i = t_len - 1; i >= 0; i--) {
		/*
		 * Zi = 1 / Z_i mod p
		 * u = 1 / (Z_0 * ... * Z_i) mod P
		 */
		if (!i) {
			ttls_mpi_copy(Zi, u);
		} else {
			ecp256_mul_mod(Zi, u, &c[i - 1]);
			ecp256_mul_mod(u, u, &T[i]->Z);
		}

		/* proceed as in normalize(). */
		ecp256_sqr_mod(ZZi, Zi);
		ecp256_mul_mod(&T[i]->X, &T[i]->X, ZZi);
		ecp256_mul_mod(&T[i]->Y, &T[i]->Y, ZZi);
		ecp256_mul_mod(&T[i]->Y, &T[i]->Y, Zi);
		/*
		 * At the moment Z coordinate stores a garbage, so free it now
		 * and treat as 1 on subsequent processing.
		 */
		ttls_mpi_reset(&T[i]->Z);
	}

cleanup:
	ttls_mpi_pool_cleanup_ctx((unsigned long)c, false);
	return ret;
#undef __INIT_C
}

/**
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid.
 */
static void
ecp256_safe_invert_jac(const TlsEcpGrp *grp, TlsEcpPoint *Q, unsigned char inv)
{
	unsigned char nonzero;
	TlsMpi *mQY = ttls_mpi_alloc_stack_init(grp->P.used);

	/* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
	ttls_mpi_sub_mpi(mQY, &grp->P, &Q->Y);
	nonzero = !!ttls_mpi_cmp_int(&Q->Y, 0);

	ttls_mpi_safe_cond_assign(&Q->Y, mQY, inv & nonzero);
}

/**
 * Point doubling R = 2 P, Jacobian coordinates [8, "dbl-1998-cmo-2"].
 *
 * We follow the variable naming fairly closely. The formula variations that
 * trade a MUL for a SQR (plus a few ADDs) aren't useful as our bignum
 * implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of {0, -3}.
 *
 * Cost: 1D := 3M + 4S	(A ==  0)
 *	 4M + 4S	(A == -3)
 *	 3M + 6S + 1a	otherwise
 */
static int
ecp256_double_jac(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsEcpPoint *P)
{
	TlsMpi M, S, T, U;

	ttls_mpi_alloca_init(&M, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&S, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&T, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&U, grp->bits * 2 / BIL);

	if (ttls_mpi_empty(&grp->A)) {
		/*
		 * NIST curves case: A = -3
		 * M = 3(X + Z^2)(X - Z^2)
		 */
		if (likely(ttls_mpi_cmp_int(&P->Z, 1)))
			ecp256_sqr_mod(&S, &P->Z);
		else
			ttls_mpi_lset(&S, 1);
		ttls_mpi_add_mpi(&T, &P->X, &S);
		MOD_ADD(&T);
		ttls_mpi_sub_mpi(&U, &P->X, &S);
		MOD_SUB(&U);
		ecp256_mul_mod(&S, &T, &U);
		ttls_mpi_copy_alloc(&M, &S, false);
		ttls_mpi_shift_l(&M, 1);
		ttls_mpi_add_mpi(&M, &M, &S);
		MOD_ADD(&M);
	} else {
		/* M = 3 * X^2 */
		ecp256_sqr_mod(&S, &P->X);
		ttls_mpi_copy_alloc(&M, &S, false);
		ttls_mpi_shift_l(&M, 1);
		ttls_mpi_add_mpi(&M, &M, &S);
		MOD_ADD(&M);
	}

	/* S = 4 * X * Y^2 */
	ecp256_sqr_mod(&T, &P->Y);
	ttls_mpi_shift_l(&T, 1);
	MOD_ADD(&T);
	ecp256_mul_mod(&S, &P->X, &T);
	ttls_mpi_shift_l(&S, 1);
	MOD_ADD(&S);

	/* U = 8.Y^4 */
	ecp256_sqr_mod(&U, &T);
	ttls_mpi_shift_l(&U, 1);
	MOD_ADD(&U);

	/* T = M^2 - 2 * S */
	ecp256_sqr_mod(&T, &M);
	ttls_mpi_sub_mpi(&T, &T, &S);
	MOD_SUB(&T);
	ttls_mpi_sub_mpi(&T, &T, &S);
	MOD_SUB(&T);

	/* S = M(S - T) - U */
	ttls_mpi_sub_mpi(&S, &S, &T);
	MOD_SUB(&S);
	ecp256_mul_mod(&S, &S, &M);
	ttls_mpi_sub_mpi(&S, &S, &U);
	MOD_SUB(&S);

	/* U = 2 * Y * Z */
	if (likely(ttls_mpi_cmp_int(&P->Z, 1)))
		ecp256_mul_mod(&U, &P->Y, &P->Z);
	else
		ttls_mpi_copy(&U, &P->Y);
	ttls_mpi_shift_l(&U, 1);
	MOD_ADD(&U);

	ttls_mpi_copy(&R->X, &T);
	ttls_mpi_copy(&R->Y, &S);
	ttls_mpi_copy(&R->Z, &U);

	return 0;
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * #TODO #1064: the implementation uses formula [8, "madd-2008-g"] and I'm not
 * sure if it's the most efficient one - [9] refernces another formula.
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S (same as Chudnovsky-Affine time, GECC 3.2.2).
 */
static int
ecp256_add_mixed(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsEcpPoint *P,
	      const TlsEcpPoint *Q)
{
	TlsMpi T1, T2, T3, T4, X, Y, Z;

	/* Trivial cases: P == 0 or Q == 0 (case 1). */
	if (!ttls_mpi_cmp_int(&P->Z, 0)) {
		ttls_ecp_copy(R, Q);
		return 0;
	}
	if (!ttls_mpi_empty(&Q->Z)) {
		if (!ttls_mpi_cmp_int(&Q->Z, 0)) {
			ttls_ecp_copy(R, P);
			return 0;
		}
		/* Make sure Q coordinates are normalized. */
		if (ttls_mpi_cmp_int(&Q->Z, 1))
			return -EINVAL;
	}

	ttls_mpi_alloca_init(&T1, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&T2, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&T3, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&T4, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&X, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&Y, grp->bits * 2 / BIL);
	ttls_mpi_alloca_init(&Z, grp->bits * 2 / BIL);

	if (unlikely(!ttls_mpi_cmp_int(&P->Z, 1))) {
		/* Relatively rare case, ~1/60. */
		ttls_mpi_sub_mpi(&T1, &Q->X, &P->X);
		MOD_SUB(&T1);
		ttls_mpi_sub_mpi(&T2, &Q->Y, &P->Y);
		MOD_SUB(&T2);
	} else {
		ecp256_sqr_mod(&T1, &P->Z);
		ecp256_mul_mod(&T2, &T1, &P->Z);
		ecp256_mul_mod(&T1, &T1, &Q->X);
		ecp256_mul_mod(&T2, &T2, &Q->Y);
		ttls_mpi_sub_mpi(&T1, &T1, &P->X);
		MOD_SUB(&T1);
		ttls_mpi_sub_mpi(&T2, &T2, &P->Y);
		MOD_SUB(&T2);
	}

	/* Special cases (2) and (3) */
	if (!ttls_mpi_cmp_int(&T1, 0)) {
		if (!ttls_mpi_cmp_int(&T2, 0)) {
			return ecp256_double_jac(grp, R, P);
		} else {
			ttls_ecp_set_zero(R);
			return 0;
		}
	}

	if (unlikely(!ttls_mpi_cmp_int(&P->Z, 1)))
		ttls_mpi_copy_alloc(&Z, &T1, false);
	else
		ecp256_mul_mod(&Z, &P->Z, &T1);
	ecp256_sqr_mod(&T3, &T1);
	ecp256_mul_mod(&T4, &T3, &T1);
	ecp256_mul_mod(&T3, &T3, &P->X);
	ttls_mpi_copy_alloc(&T1, &T3, false);
	ttls_mpi_shift_l(&T1, 1);
	MOD_ADD(&T1);
	ecp256_sqr_mod(&X, &T2);
	ttls_mpi_sub_mpi(&X, &X, &T1);
	MOD_SUB(&X);
	ttls_mpi_sub_mpi(&X, &X, &T4);
	MOD_SUB(&X);
	ttls_mpi_sub_mpi(&T3, &T3, &X);
	MOD_SUB(&T3);
	ecp256_mul_mod(&T3, &T3, &T2);
	ecp256_mul_mod(&T4, &T4, &P->Y);
	ttls_mpi_sub_mpi(&Y, &T3, &T4);
	MOD_SUB(&Y);

	/* Resulting coorinates are twice smaller than the temporary MPIs. */
	ttls_mpi_copy(&R->X, &X);
	ttls_mpi_copy(&R->Y, &Y);
	ttls_mpi_copy(&R->Z, &Z);

	return 0;
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp256_normalize_jac().
 *
 * This countermeasure was first suggested in [2]. See also the recommendation
 * for SPA and DPA attacks prevention in J.Coron, "Resistance against
 * Differential Power Analysis for Elliptic Curve Cryptosystems".
 */
static int
ecp256_randomize_jac(const TlsEcpGrp *grp, TlsEcpPoint *pt)
{
	TlsMpi l, ll;
	size_t p_size = (grp->bits + 7) / 8;
	int count = 0;

	ttls_mpi_alloca_init(&l, p_size);
	ttls_mpi_alloca_init(&ll, p_size * 2);

	/* Generate l such that 1 < l < p */
	do {
		ttls_mpi_fill_random(&l, p_size);

		while (ttls_mpi_cmp_mpi(&l, &grp->P) >= 0)
			ttls_mpi_shift_r(&l, 1);

		if (count++ > 10)
			return TTLS_ERR_ECP_RANDOM_FAILED;
	} while (ttls_mpi_cmp_int(&l, 1) <= 0);

	/* Z = l * Z */
	if (likely(ttls_mpi_cmp_int(&pt->Z, 1)))
		ecp256_mul_mod(&pt->Z, &pt->Z, &l);
	else
		ttls_mpi_copy_alloc(&pt->Z, &l, false);

	/* X = l^2 * X */
	ecp256_sqr_mod(&ll, &l);
	ecp256_mul_mod(&pt->X, &pt->X, &ll);

	/* Y = l^3 * Y */
	ecp256_mul_mod(&ll, &ll, &l);
	ecp256_mul_mod(&pt->Y, &pt->Y, &ll);

	return 0;
}

/* d = ceil(n / w) */
#define COMB_MAX_D	  (TTLS_ECP_MAX_BITS + 1) / 2

/*
 * Compute the representation of m that will be used with our comb method.
 *
 * The basic comb method is described in GECC 3.44 for example. We use a
 * modified version that provides resistance to SPA by avoiding zero
 * digits in the representation as in [3]. We modify the method further by
 * requiring that all K_i be odd, which has the small cost that our
 * representation uses one more K_i, due to carries.
 *
 * Also, for the sake of compactness, only the seven low-order bits of x[i]
 * are used to represent K_i, and the msb of x[i] encodes the sign (s_i in
 * the paper): it is set if and only if s_i == -1;
 *
 * Calling conventions:
 * - x is an array of size d + 1
 * - w is the size, ie number of teeth, of the comb, and must be between
 *   2 and 7 (in practice, between 2 and TTLS_ECP_WINDOW_ORDER)
 * - m is the MPI, expected to be odd and such that bitlength(m) <= w * d
 *   (the result will be incorrect if these assumptions are not satisfied)
 */
static void
ecp256_comb_fixed(unsigned char x[], size_t d, unsigned char w, const TlsMpi *m)
{
	size_t i, j, b, bits = m->used * BIL;
	unsigned long *p = MPI_P(m);
	unsigned char c, cc, adjust;

	bzero_fast(x, d + 1);

	/* First get the classical comb values (except for x_d = 0) */
	for (i = 0; i < d; i++)
		for (j = 0; j < w; j++) {
			b = i + d * j;
			if (unlikely(b >= bits))
				break;
			x[i] |= ((p[b >> BSHIFT] >> (b & BMASK)) & 1) << j;
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

/*
 * Precompute points for the comb method
 *
 * If i = i_{w-1} ... i_1 is the binary representation of i, then
 * T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
 *
 * T must be able to hold 2^{w - 1} elements
 *
 * Cost: d(w-1) D + (2^{w-1} - 1) A + 1 N(w-1) + 1 N(2^{w-1} - 1)
 */
int
ecp256_precompute_comb(const TlsEcpGrp *grp, TlsEcpPoint T[], const TlsEcpPoint *P,
		    unsigned char w, size_t d)
{
	int i, j, k;
	TlsEcpPoint *cur, *TT[TTLS_ECP_WINDOW_SIZE];

	/*
	 * Set T[0] = P and T[2^{i-1}] = 2^{di} P for i = 1 .. w-1
	 * (this is not the final value).
	 */
	ttls_ecp_copy(&T[0], P);

	k = 0;
	for (i = 1; i < (1U << (w - 1)); i <<= 1) {
		cur = T + i;
		ttls_ecp_copy(cur, T + (i >> 1));
		for (j = 0; j < d; j++)
			/*
			 * TODO #1064 use repeated doubling optimization.
			 * E.g. see sp_256_proj_point_dbl_n_store_avx2_4() and
			 * sp_256_proj_point_dbl_n_avx2_4() from WolfSSL.
			 */
			MPI_CHK(ecp256_double_jac(grp, cur, cur));

		TT[k++] = cur;
	}
	BUG_ON(!k || k >= TTLS_ECP_WINDOW_ORDER);

	MPI_CHK(ecp256_normalize_jac_many(grp, TT, k));

	/*
	 * Compute the remaining ones using the minimal number of additions
	 * Be careful to update T[2^l] only after using it!
	 */
	k = 0;
	for (i = 1; i < (1U << (w - 1)); i <<= 1) {
		j = i;
		while (j--) {
			MPI_CHK(ecp256_add_mixed(grp, &T[i + j], &T[j], &T[i]));
			TT[k++] = &T[i + j];
		}
	}

	MPI_CHK(ecp256_normalize_jac_many(grp, TT, k));

	return 0;
}

/*
 * Select precomputed point: R = sign(i) * T[ abs(i) / 2 ]
 */
static void
ecp256_select_comb(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsEcpPoint T[],
		unsigned char t_len, unsigned char i)
{
	unsigned char ii, j;

	/* Ignore the "sign" bit and scale down */
	ii =  (i & 0x7Fu) >> 1;

	/* Read the whole table to thwart cache-based timing attacks */
	for (j = 0; j < t_len; j++) {
		/* TODO #1064 do specialization to avoid conditions. */
		ttls_mpi_safe_cond_assign(&R->X, &T[j].X, j == ii);
		ttls_mpi_safe_cond_assign(&R->Y, &T[j].Y, j == ii);
	}

	/* Safely invert result if i is "negative" */
	ecp256_safe_invert_jac(grp, R, i >> 7);
}

/*
 * Core multiplication algorithm for the (modified) comb method.
 * This part is actually common with the basic comb method (GECC 3.44)
 *
 * Cost: d A + d D + 1 R
 */
static int
ecp256_mul_comb_core(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsEcpPoint T[],
		  unsigned char t_len, const unsigned char x[], size_t d,
		  bool rnd)
{
	TlsEcpPoint *Txi;
	size_t i;

	ttls_ecp_point_tmp_alloc_init(Txi, T->X.used, T->Y.used, 0);
	ttls_mpi_alloc(&R->X, grp->bits * 2 / BIL);
	ttls_mpi_alloc(&R->Y, grp->bits * 2 / BIL);
	ttls_mpi_alloc(&R->Z, grp->bits / BIL + 1);

	/*
	 * We operate with precimputed table which is significantly smaller
	 * than L1d cache - for secp384 and w=6:
	 *
	 *	(sizeof(ECP)=(3 * 8) + 3 * 48) * (1 << (w - 1)) = 5376
	 *
	 * Also there is no preemption and point doubling and addition
	 * aren't memory hungry, so once read T resides in L1d cache and
	 * we can address T directly without sacrificing safety against SCAs.
	 *
	 * Start with a non-zero point and randomize its coordinates */
	i = d;
	ecp256_select_comb(grp, R, T, t_len, x[i]);
	ttls_mpi_lset(&R->Z, 1);
	if (rnd)
		MPI_CHK(ecp256_randomize_jac(grp, R));

	while (i--) {
		unsigned char ii = (x[i] & 0x7Fu) >> 1;

		/*
		 * TODO #1064 use repeated doubling optimization.
		 * E.g. see sp_256_proj_point_dbl_n_store_avx2_4() and
		 * sp_256_proj_point_dbl_n_avx2_4() from WolfSSL.
		 */
		MPI_CHK(ecp256_double_jac(grp, R, R));

		ttls_mpi_copy(&Txi->X, &T[ii].X);
		ttls_mpi_copy(&Txi->Y, &T[ii].Y);
		ecp256_safe_invert_jac(grp, Txi, x[i] >> 7);

		MPI_CHK(ecp256_add_mixed(grp, R, R, Txi));
	}

	return 0;
}

/*
 * Multiplication R = m * P using the comb method.
 *
 * In order to prevent timing attacks, this function executes the exact same
 * sequence of (base field) operations for any valid m. It avoids any if-branch
 * or array index depending on the value of m.
 *
 * If @rng is true, the functions randomizes intermediate results in order to
 * prevent potential timing attacks targeting these results.
 *
 * TODO #1064: This function is used for unknown points only, i.e. the public
 * key Q from the peer in ECDHE exchange, so we see @P only once and there is
 * sense to cache computation results for the scalar (our secret) only.
 *
 * May allocate @R point on the stack, so while the function uses plenty of
 * memory we can't call ttls_mpi_pool_cleanup_ctx() here.
 *
 * TODO #1064: why wNAF isn't used? Is comb the most efficient method?
 * It seems WolfSSL's sp_256_ecc_mulmod_win_add_sub_avx2_4() also uses comb,
 * but with d=43 (w=6).
 * OpenSSL's ecp_nistz256_windowed_mul() use Booth windowed method.
 * It seems the both OpenSSL and WolfSSL don't use coordinates randomization.
 */
static int
ecp256_mul_comb(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
		const TlsEcpPoint *P, bool rnd)
{
	int ret = -EINVAL;
	unsigned char w, m_is_odd, p_eq_g, pre_len;
	size_t d = max(m->used, grp->N.used);
	TlsEcpPoint *T;
	TlsMpi *M, *mm;
	unsigned char k[COMB_MAX_D + 1];

	/* We need N to be odd to transform m in an odd number, check now. */
	if (WARN_ON_ONCE(ttls_mpi_get_bit(&grp->N, 0) != 1))
		return -EINVAL;

	M = ttls_mpi_alloc_stack_init(d);
	mm = ttls_mpi_alloc_stack_init(d);

	/*
	 * Minimize the number of multiplications, that is minimize
	 * 10 * d * w + 18 * 2^(w-1) + 11 * d + 7 * w, with d = ceil(bits / w)
	 * (see costs of the various parts, with 1S = 1M).
	 * TODO #1064 make sure that w size is the best one.
	 */
	BUG_ON(grp->bits > 384);
	w = 4; /* TODO #1064: grp->bits == 384 ? 5 : 4; */

	/*
	 * If P == G, pre-compute a bit more, since this may be re-used later.
	 * Just adding one avoids upping the cost of the first mul too much,
	 * and the memory cost too.
	 */
	p_eq_g = !ttls_mpi_cmp_mpi(&P->Y, &grp->G.Y)
		 && !ttls_mpi_cmp_mpi(&P->X, &grp->G.X);
	if (p_eq_g) {
		w += 3;
		T = (TlsEcpPoint *)grp->T; /* we won't change it */
		MPI_CHK(ttls_mpi_empty(&T->X) | ttls_mpi_empty(&T->Y));
	} else {
		if (!(T = ttls_mpool_ecp_create_tmp_T(1 << (w - 1), P)))
			return -ENOMEM;
	}
	WARN_ON_ONCE(w > TTLS_ECP_WINDOW_ORDER);

	/* Other sizes that depend on w */
	pre_len = 1U << (w - 1);
	if (WARN_ON_ONCE(pre_len > TTLS_ECP_WINDOW_SIZE))
		goto cleanup;
	d = (grp->bits + w - 1) / w;
	BUG_ON(d > COMB_MAX_D);

	/*
	 * Compute T if it wasn't precomputed for the case.
	 * ecp256_precompute_comb() is good with uninitialized T.
	 *
	 * TODO #1064: remove this branch after ttls_ecp_mul_g().
	 */
	if (!p_eq_g)
		TTLS_MPI_CHK(ecp256_precompute_comb(grp, T, P, w, d));

	/*
	 * Make sure M is odd (M = m or M = N - m, since N is odd)
	 * using the fact that m * P = - (N - m) * P
	 */
	m_is_odd = (ttls_mpi_get_bit(m, 0) == 1);
	ttls_mpi_copy(M, m);
	ttls_mpi_sub_mpi(mm, &grp->N, m);
	ttls_mpi_safe_cond_assign(M, mm, !m_is_odd);

	/* Go for comb multiplication, R = M * P */
	ecp256_comb_fixed(k, d, w, M);
	TTLS_MPI_CHK(ecp256_mul_comb_core(grp, R, T, pre_len, k, d, rnd));

	/* Now get m * P from M * P and normalize it. */
	ecp256_safe_invert_jac(grp, R, !m_is_odd);
	TTLS_MPI_CHK(ecp256_normalize_jac(grp, R));

cleanup:
	if (!p_eq_g)
		ttls_mpool_shrink_tailtmp(ttls_mpool(T), false);

	return ret;
}

/**
 * TODO #1064: Specialization for R = m * G.
 * TODO #1064: Do we need coordinates randomization?
 */
int
ecp256_mul_comb_g(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m, bool rnd)
{
	return ecp256_mul_comb(grp, R, m, &grp->G, rnd);
}

/**
 * R = m * P with shortcuts for m == 1 and m == -1.
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int
ecp256_mul_shortcuts(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
		     const TlsEcpPoint *P)
{
	if (!ttls_mpi_cmp_int(m, 1)) {
		ttls_ecp_copy(R, P);
	}
	else if (!ttls_mpi_cmp_int(m, -1)) {
		ttls_ecp_copy(R, P);
		if (ttls_mpi_cmp_int(&R->Y, 0))
			ttls_mpi_sub_mpi(&R->Y, &grp->P, &R->Y);
	}
	else {
		return ecp256_mul_comb(grp, R, m, P, false);
	}

	return 0;
}

/*
 * Multiplication and addition of two points by integers: R = m * grp->G + n * Q
 * In contrast to ttls_ecp_mul(), this function does not guarantee a constant
 * execution flow and timing - ther is no secret data, so we don't need to care
 * about SCAs.
 *
 * TODO #769: The algorithm is naive. The Shamir's trick and/or
 * multi-exponentiation (Bodo Möller, "Algorithms for multi-exponentiation")
 * should be used. See OpenSSL's ec_wNAF_mul() as the reference.
 */
static int
ecp256_muladd(const TlsEcpGrp *grp, TlsEcpPoint *R, const TlsMpi *m,
	      const TlsEcpPoint *Q, const TlsMpi *n)
{
	TlsEcpPoint *mP;

	mP = ttls_mpool_alloc_stack(sizeof(TlsEcpPoint));
	ttls_ecp_point_init(mP);

	MPI_CHK(ecp256_mul_shortcuts(grp, mP, m, &grp->G));
	MPI_CHK(ecp256_mul_shortcuts(grp, R, n, Q));
	MPI_CHK(ecp256_add_mixed(grp, R, mP, R));
	MPI_CHK(ecp256_normalize_jac(grp, R));

	return 0;
}

void
ec_grp_init_p256(TlsEcpGrp *grp)
{
	LOAD_GROUP(grp, secp256r1, 32);

	// TODO #1064: remove @grp as a parameter and use the ulong arrays
	// directly => remove the MPIs from TlsEcpGrp.
	grp->mul = ecp256_mul_comb;
	grp->mul_g = ecp256_mul_comb_g;
	grp->muladd = ecp256_muladd;
}
