/*
 *  Helper functions for the RSA module
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include "rsa.h"
#include "bignum.h"
#include "rsa_internal.h"

/*
 * Compute RSA prime factors from public and private exponents
 *
 * Summary of algorithm:
 * Setting F := lcm(P-1,Q-1), the idea is as follows:
 *
 * (a) For any 1 <= X < N with gcd(X,N)=1, we have X^F = 1 modulo N, so X^(F/2)
 *	 is a square root of 1 in Z/NZ. Since Z/NZ ~= Z/PZ x Z/QZ by CRT and the
 *	 square roots of 1 in Z/PZ and Z/QZ are +1 and -1, this leaves the four
 *	 possibilities X^(F/2) = (+-1, +-1). If it happens that X^(F/2) = (-1,+1)
 *	 or (+1,-1), then gcd(X^(F/2) + 1, N) will be equal to one of the prime
 *	 factors of N.
 *
 * (b) If we don't know F/2 but (F/2) * K for some odd (!) K, then the same
 *	 construction still applies since (-)^K is the identity on the set of
 *	 roots of 1 in Z/NZ.
 *
 * The public and private key primitives (-)^E and (-)^D are mutually inverse
 * bijections on Z/NZ if and only if (-)^(DE) is the identity on Z/NZ, i.e.
 * if and only if DE - 1 is a multiple of F, say DE - 1 = F * L.
 * Splitting L = 2^t * K with K odd, we have
 *
 *   DE - 1 = FL = (F/2) * (2^(t+1)) * K,
 *
 * so (F / 2) * K is among the numbers
 *
 *   (DE - 1) >> 1, (DE - 1) >> 2, ..., (DE - 1) >> ord
 *
 * where ord is the order of 2 in (DE - 1).
 * We can therefore iterate through these numbers apply the construction
 * of (a) and (b) above to attempt to factor N.
 *
 */
int ttls_rsa_deduce_primes(TlsMpi const *N,
		 TlsMpi const *E, TlsMpi const *D,
		 TlsMpi *P, TlsMpi *Q)
{
	int ret = 0;

	uint16_t attempt;  /* Number of current attempt  */
	uint16_t iter;	 /* Number of squares computed in the current attempt */

	uint16_t order;	/* Order of 2 in DE - 1 */

	TlsMpi T;  /* Holds largest odd divisor of DE - 1	 */
	TlsMpi K;  /* Temporary holding the current candidate */

	const unsigned char primes[] = { 2,
		   3,	5,	7,   11,   13,   17,   19,   23,
		  29,   31,   37,   41,   43,   47,   53,   59,
		  61,   67,   71,   73,   79,   83,   89,   97,
		 101,  103,  107,  109,  113,  127,  131,  137,
		 139,  149,  151,  157,  163,  167,  173,  179,
		 181,  191,  193,  197,  199,  211,  223,  227,
		 229,  233,  239,  241,  251
	};

	const size_t num_primes = sizeof(primes) / sizeof(*primes);

	if (P == NULL || Q == NULL || P->p != NULL || Q->p != NULL)
		return -EINVAL;

	if (ttls_mpi_cmp_int(N, 0) <= 0 ||
		ttls_mpi_cmp_int(D, 1) <= 0 ||
		ttls_mpi_cmp_mpi(D, N) >= 0 ||
		ttls_mpi_cmp_int(E, 1) <= 0 ||
		ttls_mpi_cmp_mpi(E, N) >= 0)
	{
		return -EINVAL;
	}

	/*
	 * Initializations and temporary changes
	 */

	ttls_mpi_init(&K);
	ttls_mpi_init(&T);

	/* T := DE - 1 */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T, D,  E));
	TTLS_MPI_CHK(ttls_mpi_sub_int(&T, &T, 1));

	if ((order = (uint16_t) ttls_mpi_lsb(&T)) == 0)
	{
		ret = -EINVAL;
		goto cleanup;
	}

	/* After this operation, T holds the largest odd divisor of DE - 1. */
	TTLS_MPI_CHK(ttls_mpi_shift_r(&T, order));

	/*
	 * Actual work
	 */

	/* Skip trying 2 if N == 1 mod 8 */
	attempt = 0;
	if (N->p[0] % 8 == 1)
		attempt = 1;

	for (; attempt < num_primes; ++attempt)
	{
		ttls_mpi_lset(&K, primes[attempt]);

		/* Check if gcd(K,N) = 1 */
		TTLS_MPI_CHK(ttls_mpi_gcd(P, &K, N));
		if (ttls_mpi_cmp_int(P, 1) != 0)
			continue;

		/*
		 * Go through K^T + 1, K^(2T) + 1, K^(4T) + 1, ...
		 * and check whether they have nontrivial GCD with N.
		 *
		 * Temporarily use Q for storing Montgomery multiplication
		 * helper values.
		 */
		TTLS_MPI_CHK(ttls_mpi_exp_mod(&K, &K, &T, N, Q));

		for (iter = 1; iter <= order; ++iter)
		{
			/* If we reach 1 prematurely, there's no point
			 * in continuing to square K */
			if (ttls_mpi_cmp_int(&K, 1) == 0)
				break;

			TTLS_MPI_CHK(ttls_mpi_add_int(&K, &K, 1));
			TTLS_MPI_CHK(ttls_mpi_gcd(P, &K, N));

			if (ttls_mpi_cmp_int(P, 1) ==  1 &&
				ttls_mpi_cmp_mpi(P, N) == -1)
			{
				/*
				 * Have found a nontrivial divisor P of N.
				 * Set Q := N / P.
				 */

				TTLS_MPI_CHK(ttls_mpi_div_mpi(Q, NULL, N, P));
				goto cleanup;
			}

			TTLS_MPI_CHK(ttls_mpi_sub_int(&K, &K, 1));
			TTLS_MPI_CHK(ttls_mpi_mul_mpi(&K, &K, &K));
			TTLS_MPI_CHK(ttls_mpi_mod_mpi(&K, &K, N));
		}

		/*
		 * If we get here, then either we prematurely aborted the loop because
		 * we reached 1, or K holds primes[attempt]^(DE - 1) mod N, which must
		 * be 1 if D,E,N were consistent.
		 * Check if that's the case and abort if not, to avoid very long,
		 * yet eventually failing, computations if N,D,E were not sane.
		 */
		if (ttls_mpi_cmp_int(&K, 1) != 0)
		{
			break;
		}
	}

	ret = -EINVAL;

cleanup:

	ttls_mpi_free(&K);
	ttls_mpi_free(&T);
	return ret;
}

/*
 * Given P, Q and the public exponent E, deduce D.
 * This is essentially a modular inversion.
 */
int ttls_rsa_deduce_private_exponent(TlsMpi const *P,
				 TlsMpi const *Q,
				 TlsMpi const *E,
				 TlsMpi *D)
{
	int ret = 0;
	TlsMpi K, L;

	if (D == NULL || ttls_mpi_cmp_int(D, 0) != 0)
		return -EINVAL;

	if (ttls_mpi_cmp_int(P, 1) <= 0 ||
		ttls_mpi_cmp_int(Q, 1) <= 0 ||
		ttls_mpi_cmp_int(E, 0) == 0)
	{
		return -EINVAL;
	}

	ttls_mpi_init(&K);
	ttls_mpi_init(&L);

	/* Temporarily put K := P-1 and L := Q-1 */
	TTLS_MPI_CHK(ttls_mpi_sub_int(&K, P, 1));
	TTLS_MPI_CHK(ttls_mpi_sub_int(&L, Q, 1));

	/* Temporarily put D := gcd(P-1, Q-1) */
	TTLS_MPI_CHK(ttls_mpi_gcd(D, &K, &L));

	/* K := LCM(P-1, Q-1) */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&K, &K, &L));
	TTLS_MPI_CHK(ttls_mpi_div_mpi(&K, NULL, &K, D));

	/* Compute modular inverse of E in LCM(P-1, Q-1) */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(D, E, &K));

cleanup:

	ttls_mpi_free(&K);
	ttls_mpi_free(&L);

	return ret;
}

int ttls_rsa_deduce_crt(const TlsMpi *P, const TlsMpi *Q,
				const TlsMpi *D, TlsMpi *DP,
				TlsMpi *DQ, TlsMpi *QP)
{
	int ret = 0;
	TlsMpi K;
	ttls_mpi_init(&K);

	/* DP = D mod P-1 */
	if (DP != NULL)
	{
		TTLS_MPI_CHK(ttls_mpi_sub_int(&K, P, 1 ));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(DP, D, &K));
	}

	/* DQ = D mod Q-1 */
	if (DQ != NULL)
	{
		TTLS_MPI_CHK(ttls_mpi_sub_int(&K, Q, 1 ));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(DQ, D, &K));
	}

	/* QP = Q^{-1} mod P */
	if (QP != NULL)
	{
		TTLS_MPI_CHK(ttls_mpi_inv_mod(QP, Q, P));
	}

cleanup:
	ttls_mpi_free(&K);

	return ret;
}
