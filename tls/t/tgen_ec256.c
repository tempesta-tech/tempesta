/**
 *		Tempesta TLS
 *
 * Precomputation of the static table for m * G in NIST secp256r1.
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
#include "ttls_mocks.h"
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c" /* mpool.c requires DHM routines. */
#include "../asn1.c"
#include "../ec_p256.c"
#include "../ecp.c"
#include "../mpool.c"

/* Mock irrelevant groups. */
const TlsEcpGrp CURVE25519_G = {};

static void
print_T(Ecp256Point *T, int tid)
{
	int i;

	printf("\t{ /*    Table %d    */\n", tid);
	for (i = 0; i < G_W_SZ; ++i) {
		unsigned long *x = T[i].x;
		unsigned long *y = T[i].y;

		printf("\t {{%#16lxUL, %#16lxUL,\n", x[0], x[1]);
		printf("\t   %#16lxUL, %#16lxUL},\n", x[2], x[3]);
		printf("\t  {%#16lxUL, %#16lxUL,\n", y[0], y[1]);
		printf("\t   %#16lxUL, %#16lxUL}}%s\n", y[2], y[3],
			i < G_W_SZ - 1 ? "," : "");
	}
	printf("\t}%s\n", tid == G_D ? "" : ",");
}

static void
tgen256_double_jac(Ecp256Point *r, const Ecp256Point *p)
{
	unsigned long m[4], s[8], t[8], u[8];

	if (likely(!ecp256_mpi_eq_1(p->z))) {
		/* M = 3(X + Z^2)(X - Z^2) */
		mpi_sqr_mod_p256_x86_64_4(s, p->z);
		mpi_add_mod_p256_x86_64(t, p->x, s);
		mpi_sub_mod_p256_x86_64(u, p->x, s);
		mpi_mul_mod_p256_x86_64_4(s, t, u);
	} else {
		/* M = 3 * (X^2 - 1) */
		mpi_sqr_mod_p256_x86_64_4(s, p->x);
		ecp256_lset(t, 1);
		mpi_sub_mod_p256_x86_64(s, s, t);
	}
	mpi_tpl_mod_p256_x86_64(m, s);

	/* S = 4 * X * Y^2 = X * (2 * Y)^2 */
	mpi_shift_l1_mod_p256_x86_64(t, p->y);
	mpi_sqr_mod_p256_x86_64_4(t, t);
	mpi_mul_mod_p256_x86_64_4(s, p->x, t);

	/* U = 8 * Y^4 = ((2 * Y)^2)^2 / 2 */
	mpi_sqr_mod_p256_x86_64_4(u, t);
	mpi_div2_x86_64_4(u, u);

	/* T = M^2 - 2 * S */
	mpi_sqr_mod_p256_x86_64_4(t, m);
	mpi_sub_mod_p256_x86_64(t, t, s);
	mpi_sub_mod_p256_x86_64(t, t, s);

	/* S = M(S - T) - U */
	mpi_sub_mod_p256_x86_64(s, s, t);
	mpi_mul_mod_p256_x86_64_4(s, s, m);
	mpi_sub_mod_p256_x86_64(s, s, u);

	/* U = 2 * Y * Z */
	if (likely(!ecp256_mpi_eq_1(p->z))) {
		mpi_mul_mod_p256_x86_64_4(u, p->y, p->z);
		mpi_shift_l1_mod_p256_x86_64(u, u);
	} else {
		mpi_shift_l1_mod_p256_x86_64(u, p->y);
	}

	ecp256_copy(r->x, t);
	ecp256_copy(r->y, s);
	ecp256_copy(r->z, u);
}

static void
tgen256_add_mixed(Ecp256Point *R, const Ecp256Point *P, const Ecp256Point *Q,
		 bool no_qz)
{
	unsigned long t1[8], t2[8], t3[8], t4[8], x[8], z[8];

	/* Trivial cases: P == 0 or Q == 0 (case 1). */
	if (ecp256_mpi_eq_0(P->z)) {
		memcpy(R, Q, sizeof(*R));
		return;
	}
	if (unlikely(!no_qz)) {
		if (ecp256_mpi_eq_0(Q->z)) {
			memcpy(R, P, sizeof(*R));
			return;
		}
		/* Make sure Q coordinates are normalized. */
		WARN_ON_ONCE(!ecp256_mpi_eq_1(Q->z));
	}

	if (unlikely(ecp256_mpi_eq_1(P->z))) {
		/* Relatively rare case, ~1/60. */
		mpi_sub_mod_p256_x86_64(t1, Q->x, P->x);
		mpi_sub_mod_p256_x86_64(t2, Q->y, P->y);
	} else {
		mpi_sqr_mod_p256_x86_64_4(t1, P->z);
		mpi_mul_mod_p256_x86_64_4(t2, t1, P->z);
		mpi_mul_mod_p256_x86_64_4(t1, t1, Q->x);
		mpi_mul_mod_p256_x86_64_4(t2, t2, Q->y);
		mpi_sub_mod_p256_x86_64(t1, t1, P->x);
		mpi_sub_mod_p256_x86_64(t2, t2, P->y);
	}

	/* Special cases (2) and (3) */
	if (ecp256_mpi_eq_0(t1)) {
		if (ecp256_mpi_eq_0(t2))
			tgen256_double_jac(R, P);
		else
			ecp256_set_zero(R);
		return;
	}

	if (unlikely(ecp256_mpi_eq_1(P->z)))
		memcpy_fast(z, t1, 4 * CIL);
	else
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

static int
tgen256_normalize_jac_many(Ecp256Point *T[], size_t t_len)
{
	int i;
	unsigned long *c, zi[8], zzi[8], t[8];
	DECLARE_MPI_AUTO(u, 8);
	TlsMpi *C;

	c = ttls_mpool_alloc_stack(G_LIMBS * 2 * CIL * t_len);

	C = ttls_mpool_alloc_stack(sizeof(TlsMpi));
	ttls_mpi_init_next(C, 0);
	C->_off = (short)((unsigned long)c + (t_len - 1) * 8 * CIL
			  - (unsigned long)C);
	C->limbs = 8;

	/* c[i] = Z_0 * ... * Z_i */
	memcpy_fast(c, T[0]->z, 4 * CIL);
	for (i = 1; i < t_len; i++)
		mpi_mul_mod_p256_x86_64_4(&c[i * 8], &c[(i - 1) * 8], T[i]->z);

	/* The modular inversion can not handle zero values. */
	if (WARN_ON_ONCE(ecp256_mpi_eq_0(&c[(t_len - 1) * 8])))
		return -EINVAL;

	/* u = 1 / (Z_0 * ... * Z_n) mod P */
	C->used = 4;
	ecp256_inv_mod(&u, C, &G.P);

	for (i = t_len - 1; i >= 0; i--) {
		/*
		 * Zi = 1 / Z_i mod p
		 * u = 1 / (Z_0 * ... * Z_i) mod P
		 */
		if (!i) {
			ecp256_mpi_read(zi, &u);
		} else {
			mpi_mul_mod_p256_x86_64_4(zi, MPI_P(&u), &c[(i - 1) * 8]);
			mpi_mul_mod_p256_x86_64_4(MPI_P(&u), MPI_P(&u), T[i]->z);
		}

		/* proceed as in normalize(). */
		mpi_sqr_mod_p256_x86_64_4(zzi, zi);
		mpi_mul_mod_p256_x86_64_4(t, T[i]->x, zzi);
		ecp256_copy(T[i]->x, t);
		mpi_mul_mod_p256_x86_64_4(t, T[i]->y, zzi);
		mpi_mul_mod_p256_x86_64_4(t, t, zi);
		ecp256_copy(T[i]->y, t);
		/*
		 * At the moment Z coordinate stores a garbage, so free
		 * it now and treat as 1 on subsequent processing.
		 */
		ecp256_lset(T[i]->z, 1);
	}

	ttls_mpi_pool_cleanup_ctx((unsigned long)c, false);

	return 0;
}

/*
 * Prepare precomputed points to use them in ecp_mul_comb().
 *
 * Wse fixed-base comb method with V=D tables, GECC 3.45 & 3.47.
 *
 * If i = i_{w-1} ... i_1 is the binary representation of i, then
 * T[i] = i_{w-1} 2^{(w-1)d} P + ... + i_1 2^d P + P
 */
static void
generate_T0(Ecp256Point T[G_W_SZ])
{
	int i, j, k;
	Ecp256Point *cur, *TT[G_W_SZ];

	/*
	 * Set T[0] = P and T[2^{i-1}] = 2^{di} P for i = 1 .. w-1
	 * (this is not the final value).
	 */
	ecp256_mpi_read(T->x, &G.G.X);
	ecp256_mpi_read(T->y, &G.G.Y);
	ecp256_mpi_read(T->z, &G.G.Z);

	for (k = 0, i = 1; i < G_W_SZ; i <<= 1) {
		cur = &T[i];
		memcpy_fast(cur, &T[i >> 1], sizeof(*cur));
		for (j = 0; j < G_D; j++)
			tgen256_double_jac(cur, cur);

		TT[k++] = cur;
	}
	tgen256_normalize_jac_many(TT, k);

	/*
	 * Compute the remaining ones using the minimal number of additions
	 * Be careful to update T[2^l] only after using it!
	 */
	for (k = 0, i = 1; i < G_W_SZ; i <<= 1) {
		j = i;
		while (j--) {
			tgen256_add_mixed(&T[i + j], &T[j], &T[i], false);
			TT[k++] = &T[i + j];
		}
	}
	tgen256_normalize_jac_many(TT, k);
}

/**
 * Generate i'th table for multi-table fixed-base comb (GECC 3.45, 3.47):
 *
 *	T_{i}[j] = 2 * T_{i-1}[j]
 */
static void
generate_Ti(Ecp256Point T[G_W_SZ])
{
	int i;
	Ecp256Point *TT[G_W_SZ];

	for (i = 0; i < G_W_SZ; ++i) {
		tgen256_double_jac(&T[i], &T[i]);
		TT[i] = &T[i];
	}
	tgen256_normalize_jac_many(TT, G_W_SZ);
}

int
main(int argc, char *argv[])
{
	int i;
	static Ecp256Point T[G_W_SZ];

	ttls_mpool_init();

	printf("\t/*\n"
	       "\t * Generated by t/tgen_ec256.c for G_W_SZ=%u G_D=%u,"
	       " total size = %lu.\n"
	       "\t */\n", G_W_SZ, G_D, G_W_SZ * (G_D + 1) * sizeof(EcpXY));

	generate_T0(T);
	print_T(T, 0);

	for (i = 1; i <= G_D; ++i) {
		generate_Ti(T);
		print_T(T, i);
	}

	ttls_mpool_exit();

	return 0;
}
