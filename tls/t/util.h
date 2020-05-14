/**
 *		Tempesta TLS common utils for the tests
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
#ifndef __TTLS_UTILS_H__
#define __TTLS_UTILS_H__

#define ERROR_ON(file, line, expr)					\
do {									\
	if (expr) {							\
		fprintf(stderr, "Assertion on %s:%d %s\n", file, line, #expr); \
		BUG();							\
	}								\
} while (0)

/**
 * Test assertion that MPI @m uses @n limbs and the limbs are equal to
 * unsigned long values passed as the variadic list or arguments.
 */
static inline void
__expect_mpi(const char *file, int line, const TlsMpi *m, unsigned short n, ...)
{
	va_list args;

	ERROR_ON(file, line, n != m->used);
	ERROR_ON(file, line, n > m->limbs);

	va_start(args, n);
	for ( ; n; --n) {
		unsigned long l = va_arg(args, unsigned long);
		ERROR_ON(file, line, MPI_P(m)[m->used - n] != l);
	}
	va_end(args);
}

#define EXPECT_MPI(m, n, ...)						\
	__expect_mpi(__FILE__, __LINE__, m, n, __VA_ARGS__)

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
static inline int
ecp256_check_pubkey(const TlsEcpGrp *grp, const TlsEcpPoint *pt)
{
	TlsMpi *YY, *RHS;

	/* Must use affine coordinates */
	if (WARN_ON_ONCE(ttls_mpi_cmp_int(&pt->Z, 1)))
		return -EINVAL;

	if (ecp_get_type(grp) == ECP_TYPE_MONTGOMERY) {
		/*
		 * Check validity of a public key for Montgomery curves with
		 * x-only schemes. [Curve25519 p. 5] Just check X is the correct
		 * number of bytes.
		 */
		if (WARN_ON_ONCE(ttls_mpi_size(&pt->X) > (grp->bits + 7) / 8))
			return -EINVAL;
		return 0;
	}

	/*
	 * Check that an affine point is valid as a public key,
	 * short Weierstrass curves (SEC1 3.2.3.1).
	 *
	 * pt coordinates must be normalized for our checks.
	 */
	if (ttls_mpi_cmp_mpi(&pt->X, &grp->P) >= 0
	    || ttls_mpi_cmp_mpi(&pt->Y, &grp->P) >= 0)
	{
		T_DBG_MPI3("ECP invalid weierstrass public key",
			   &pt->X, &pt->Y, &grp->P);
		return -EINVAL;
	}

	YY = ttls_mpi_alloc_stack_init(grp->bits * 2 / BIL);
	RHS = ttls_mpi_alloc_stack_init(grp->bits * 2 / BIL);

	/*
	 * YY = Y^2
	 * RHS = X (X^2 + A) + B = X^3 + A X + B
	 */
	ecp256_sqr_mod(YY, &pt->Y);
	ecp256_sqr_mod(RHS, &pt->X);

	/* Special case for A = -3 */
	if (ttls_mpi_empty(&grp->A)) {
		ttls_mpi_sub_int(RHS, RHS, 3);
		MOD_SUB(RHS);
	} else {
		ttls_mpi_add_mpi(RHS, RHS, &grp->A);
		MOD_ADD(RHS);
	}

	ecp256_mul_mod(RHS, RHS, &pt->X);
	ttls_mpi_add_mpi(RHS, RHS, &grp->B);
	MOD_ADD(RHS);

	if (ttls_mpi_cmp_mpi(YY, RHS)) {
		T_DBG_MPI2("ECP invalid weierstrass public key", YY, RHS);
		return -EINVAL;
	}

	return 0;
}
#endif /* __TTLS_UTILS_H__ */
