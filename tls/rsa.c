/*
 *  The RSA public-key cryptosystem
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

/*
 *  The following sources were referenced in the design of this implementation
 *  of the RSA algorithm:
 *
 *  [1] A method for obtaining digital signatures and public-key cryptosystems
 *	  R Rivest, A Shamir, and L Adleman
 *	  http://people.csail.mit.edu/rivest/pubs.html#RSA78
 *
 *  [2] Handbook of Applied Cryptography - 1997, Chapter 8
 *	  Menezes, van Oorschot and Vanstone
 *
 *  [3] Malware Guard Extension: Using SGX to Conceal Cache Attacks
 *	  Michael Schwarz, Samuel Weiser, Daniel Gruss, Clémentine Maurice and
 *	  Stefan Mangard
 *	  https://arxiv.org/abs/1702.08719v2
 *
 */
#include "config.h"
#include "rsa.h"
#include "rsa_internal.h"
#include "oid.h"
#include "md.h"

#if !defined(TTLS_RSA_ALT)

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = (unsigned char*)v; while (n--) *p++ = 0;
}

/* constant-time buffer comparison */
static inline int ttls_safer_memcmp(const void *a, const void *b, size_t n)
{
	size_t i;
	const unsigned char *A = (const unsigned char *) a;
	const unsigned char *B = (const unsigned char *) b;
	unsigned char diff = 0;

	for (i = 0; i < n; i++)
		diff |= A[i] ^ B[i];

	return(diff);
}

int ttls_rsa_import(ttls_rsa_context *ctx,
						const ttls_mpi *N,
						const ttls_mpi *P, const ttls_mpi *Q,
						const ttls_mpi *D, const ttls_mpi *E)
{
	int ret;

	if ((N != NULL && (ret = ttls_mpi_copy(&ctx->N, N)) != 0) ||
		(P != NULL && (ret = ttls_mpi_copy(&ctx->P, P)) != 0) ||
		(Q != NULL && (ret = ttls_mpi_copy(&ctx->Q, Q)) != 0) ||
		(D != NULL && (ret = ttls_mpi_copy(&ctx->D, D)) != 0) ||
		(E != NULL && (ret = ttls_mpi_copy(&ctx->E, E)) != 0))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);
	}

	if (N != NULL)
		ctx->len = ttls_mpi_size(&ctx->N);

	return 0;
}

int ttls_rsa_import_raw(ttls_rsa_context *ctx,
							unsigned char const *N, size_t N_len,
							unsigned char const *P, size_t P_len,
							unsigned char const *Q, size_t Q_len,
							unsigned char const *D, size_t D_len,
							unsigned char const *E, size_t E_len)
{
	int ret = 0;

	if (N != NULL)
	{
		TTLS_MPI_CHK(ttls_mpi_read_binary(&ctx->N, N, N_len));
		ctx->len = ttls_mpi_size(&ctx->N);
	}

	if (P != NULL)
		TTLS_MPI_CHK(ttls_mpi_read_binary(&ctx->P, P, P_len));

	if (Q != NULL)
		TTLS_MPI_CHK(ttls_mpi_read_binary(&ctx->Q, Q, Q_len));

	if (D != NULL)
		TTLS_MPI_CHK(ttls_mpi_read_binary(&ctx->D, D, D_len));

	if (E != NULL)
		TTLS_MPI_CHK(ttls_mpi_read_binary(&ctx->E, E, E_len));

cleanup:

	if (ret != 0)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);

	return 0;
}

/*
 * Checks whether the context fields are set in such a way
 * that the RSA primitives will be able to execute without error.
 * It does *not* make guarantees for consistency of the parameters.
 */
static int rsa_check_context(ttls_rsa_context const *ctx, int is_priv,
							  int blinding_needed)
{
#if !defined(TTLS_RSA_NO_CRT)
	/* blinding_needed is only used for NO_CRT to decide whether
	 * P,Q need to be present or not. */
	((void) blinding_needed);
#endif

	if (ctx->len != ttls_mpi_size(&ctx->N) ||
		ctx->len > TTLS_MPI_MAX_SIZE)
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	/*
	 * 1. Modular exponentiation needs positive, odd moduli.
	 */

	/* Modular exponentiation wrt. N is always used for
	 * RSA public key operations. */
	if (ttls_mpi_cmp_int(&ctx->N, 0) <= 0 ||
		ttls_mpi_get_bit(&ctx->N, 0) == 0 )
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

#if !defined(TTLS_RSA_NO_CRT)
	/* Modular exponentiation for P and Q is only
	 * used for private key operations and if CRT
	 * is used. */
	if (is_priv &&
		(ttls_mpi_cmp_int(&ctx->P, 0) <= 0 ||
		  ttls_mpi_get_bit(&ctx->P, 0) == 0 ||
		  ttls_mpi_cmp_int(&ctx->Q, 0) <= 0 ||
		  ttls_mpi_get_bit(&ctx->Q, 0) == 0 ))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}
#endif /* !TTLS_RSA_NO_CRT */

	/*
	 * 2. Exponents must be positive
	 */

	/* Always need E for public key operations */
	if (ttls_mpi_cmp_int(&ctx->E, 0) <= 0)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

#if defined(TTLS_RSA_NO_CRT)
	/* For private key operations, use D or DP & DQ
	 * as (unblinded) exponents. */
	if (is_priv && ttls_mpi_cmp_int(&ctx->D, 0) <= 0)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
#else
	if (is_priv &&
		(ttls_mpi_cmp_int(&ctx->DP, 0) <= 0 ||
		  ttls_mpi_cmp_int(&ctx->DQ, 0) <= 0 ))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}
#endif /* TTLS_RSA_NO_CRT */

	/* Blinding shouldn't make exponents negative either,
	 * so check that P, Q >= 1 if that hasn't yet been
	 * done as part of 1. */
#if defined(TTLS_RSA_NO_CRT)
	if (is_priv && blinding_needed &&
		(ttls_mpi_cmp_int(&ctx->P, 0) <= 0 ||
		  ttls_mpi_cmp_int(&ctx->Q, 0) <= 0))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}
#endif

	/* It wouldn't lead to an error if it wasn't satisfied,
	 * but check for QP >= 1 nonetheless. */
#if !defined(TTLS_RSA_NO_CRT)
	if (is_priv &&
		ttls_mpi_cmp_int(&ctx->QP, 0) <= 0)
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}
#endif

	return 0;
}

int ttls_rsa_complete(ttls_rsa_context *ctx)
{
	int ret = 0;

	const int have_N = (ttls_mpi_cmp_int(&ctx->N, 0) != 0);
	const int have_P = (ttls_mpi_cmp_int(&ctx->P, 0) != 0);
	const int have_Q = (ttls_mpi_cmp_int(&ctx->Q, 0) != 0);
	const int have_D = (ttls_mpi_cmp_int(&ctx->D, 0) != 0);
	const int have_E = (ttls_mpi_cmp_int(&ctx->E, 0) != 0);

	/*
	 * Check whether provided parameters are enough
	 * to deduce all others. The following incomplete
	 * parameter sets for private keys are supported:
	 *
	 * (1) P, Q missing.
	 * (2) D and potentially N missing.
	 *
	 */

	const int n_missing  =			  have_P &&  have_Q &&  have_D && have_E;
	const int pq_missing =   have_N && !have_P && !have_Q &&  have_D && have_E;
	const int d_missing  =			  have_P &&  have_Q && !have_D && have_E;
	const int is_pub	 =   have_N && !have_P && !have_Q && !have_D && have_E;

	/* These three alternatives are mutually exclusive */
	const int is_priv = n_missing || pq_missing || d_missing;

	if (!is_priv && !is_pub)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/*
	 * Step 1: Deduce N if P, Q are provided.
	 */

	if (!have_N && have_P && have_Q)
	{
		if ((ret = ttls_mpi_mul_mpi(&ctx->N, &ctx->P,
										 &ctx->Q)) != 0)
		{
			return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);
		}

		ctx->len = ttls_mpi_size(&ctx->N);
	}

	/*
	 * Step 2: Deduce and verify all remaining core parameters.
	 */

	if (pq_missing)
	{
		ret = ttls_rsa_deduce_primes(&ctx->N, &ctx->E, &ctx->D,
										 &ctx->P, &ctx->Q);
		if (ret != 0)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);

	}
	else if (d_missing)
	{
		if ((ret = ttls_rsa_deduce_private_exponent(&ctx->P,
														 &ctx->Q,
														 &ctx->E,
														 &ctx->D)) != 0)
		{
			return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);
		}
	}

	/*
	 * Step 3: Deduce all additional parameters specific
	 *		 to our current RSA implementation.
	 */

#if !defined(TTLS_RSA_NO_CRT)
	if (is_priv)
	{
		ret = ttls_rsa_deduce_crt(&ctx->P,  &ctx->Q,  &ctx->D,
									  &ctx->DP, &ctx->DQ, &ctx->QP);
		if (ret != 0)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);
	}
#endif /* TTLS_RSA_NO_CRT */

	/*
	 * Step 3: Basic sanity checks
	 */

	return(rsa_check_context(ctx, is_priv, 1));
}

int ttls_rsa_export_raw(const ttls_rsa_context *ctx,
							unsigned char *N, size_t N_len,
							unsigned char *P, size_t P_len,
							unsigned char *Q, size_t Q_len,
							unsigned char *D, size_t D_len,
							unsigned char *E, size_t E_len)
{
	int ret = 0;

	/* Check if key is private or public */
	const int is_priv =
		ttls_mpi_cmp_int(&ctx->N, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->P, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->D, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv)
	{
		/* If we're trying to export private parameters for a public key,
		 * something must be wrong. */
		if (P != NULL || Q != NULL || D != NULL)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	}

	if (N != NULL)
		TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->N, N, N_len));

	if (P != NULL)
		TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->P, P, P_len));

	if (Q != NULL)
		TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->Q, Q, Q_len));

	if (D != NULL)
		TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->D, D, D_len));

	if (E != NULL)
		TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->E, E, E_len));

cleanup:

	return ret;
}

int ttls_rsa_export(const ttls_rsa_context *ctx,
						ttls_mpi *N, ttls_mpi *P, ttls_mpi *Q,
						ttls_mpi *D, ttls_mpi *E)
{
	int ret;

	/* Check if key is private or public */
	int is_priv =
		ttls_mpi_cmp_int(&ctx->N, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->P, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->D, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv)
	{
		/* If we're trying to export private parameters for a public key,
		 * something must be wrong. */
		if (P != NULL || Q != NULL || D != NULL)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	}

	/* Export all requested core parameters. */

	if ((N != NULL && (ret = ttls_mpi_copy(N, &ctx->N)) != 0) ||
		(P != NULL && (ret = ttls_mpi_copy(P, &ctx->P)) != 0) ||
		(Q != NULL && (ret = ttls_mpi_copy(Q, &ctx->Q)) != 0) ||
		(D != NULL && (ret = ttls_mpi_copy(D, &ctx->D)) != 0) ||
		(E != NULL && (ret = ttls_mpi_copy(E, &ctx->E)) != 0))
	{
		return ret;
	}

	return 0;
}

/*
 * Export CRT parameters
 * This must also be implemented if CRT is not used, for being able to
 * write DER encoded RSA keys. The helper function ttls_rsa_deduce_crt
 * can be used in this case.
 */
int ttls_rsa_export_crt(const ttls_rsa_context *ctx,
							ttls_mpi *DP, ttls_mpi *DQ, ttls_mpi *QP)
{
	int ret;

	/* Check if key is private or public */
	int is_priv =
		ttls_mpi_cmp_int(&ctx->N, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->P, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->D, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

#if !defined(TTLS_RSA_NO_CRT)
	/* Export all requested blinding parameters. */
	if ((DP != NULL && (ret = ttls_mpi_copy(DP, &ctx->DP)) != 0) ||
		(DQ != NULL && (ret = ttls_mpi_copy(DQ, &ctx->DQ)) != 0) ||
		(QP != NULL && (ret = ttls_mpi_copy(QP, &ctx->QP)) != 0))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);
	}
#else
	if ((ret = ttls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
										DP, DQ, QP)) != 0)
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA + ret);
	}
#endif

	return 0;
}

/*
 * Initialize an RSA context
 */
void ttls_rsa_init(ttls_rsa_context *ctx,
			   int padding,
			   int hash_id)
{
	memset(ctx, 0, sizeof(ttls_rsa_context));

	ttls_rsa_set_padding(ctx, padding, hash_id);

	spin_lock_init(&ctx->mutex);
}

/*
 * Set padding for an existing RSA context
 */
void ttls_rsa_set_padding(ttls_rsa_context *ctx, int padding, int hash_id)
{
	ctx->padding = padding;
	ctx->hash_id = hash_id;
}

/*
 * Get length in bytes of RSA modulus
 */

size_t ttls_rsa_get_len(const ttls_rsa_context *ctx)
{
	return(ctx->len);
}


#if defined(TTLS_GENPRIME)

/*
 * Generate an RSA keypair
 */
int ttls_rsa_gen_key(ttls_rsa_context *ctx,
				 int (*f_rng)(void *, unsigned char *, size_t),
				 void *p_rng,
				 unsigned int nbits, int exponent)
{
	int ret;
	ttls_mpi H, G;

	if (f_rng == NULL || nbits < 128 || exponent < 3)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	if (nbits % 2)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	ttls_mpi_init(&H);
	ttls_mpi_init(&G);

	/*
	 * find primes P and Q with Q < P so that:
	 * GCD(E, (P-1)*(Q-1)) == 1
	 */
	TTLS_MPI_CHK(ttls_mpi_lset(&ctx->E, exponent));

	do
	{
		TTLS_MPI_CHK(ttls_mpi_gen_prime(&ctx->P, nbits >> 1, 0,
												f_rng, p_rng));

		TTLS_MPI_CHK(ttls_mpi_gen_prime(&ctx->Q, nbits >> 1, 0,
												f_rng, p_rng));

		if (ttls_mpi_cmp_mpi(&ctx->P, &ctx->Q) == 0)
			continue;

		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ctx->N, &ctx->P, &ctx->Q));
		if (ttls_mpi_bitlen(&ctx->N) != nbits)
			continue;

		if (ttls_mpi_cmp_mpi(&ctx->P, &ctx->Q) < 0)
			ttls_mpi_swap(&ctx->P, &ctx->Q);

		/* Temporarily replace P,Q by P-1, Q-1 */
		TTLS_MPI_CHK(ttls_mpi_sub_int(&ctx->P, &ctx->P, 1));
		TTLS_MPI_CHK(ttls_mpi_sub_int(&ctx->Q, &ctx->Q, 1));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&H, &ctx->P, &ctx->Q));
		TTLS_MPI_CHK(ttls_mpi_gcd(&G, &ctx->E, &H ));
	}
	while (ttls_mpi_cmp_int(&G, 1) != 0);

	/* Restore P,Q */
	TTLS_MPI_CHK(ttls_mpi_add_int(&ctx->P,  &ctx->P, 1));
	TTLS_MPI_CHK(ttls_mpi_add_int(&ctx->Q,  &ctx->Q, 1));

	ctx->len = ttls_mpi_size(&ctx->N);

	/*
	 * D  = E^-1 mod ((P-1)*(Q-1))
	 * DP = D mod (P - 1)
	 * DQ = D mod (Q - 1)
	 * QP = Q^-1 mod P
	 */

	TTLS_MPI_CHK(ttls_mpi_inv_mod(&ctx->D, &ctx->E, &H ));

#if !defined(TTLS_RSA_NO_CRT)
	TTLS_MPI_CHK(ttls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
											 &ctx->DP, &ctx->DQ, &ctx->QP));
#endif /* TTLS_RSA_NO_CRT */

	/* Double-check */
	TTLS_MPI_CHK(ttls_rsa_check_privkey(ctx));

cleanup:

	ttls_mpi_free(&H);
	ttls_mpi_free(&G);

	if (ret != 0)
	{
		ttls_rsa_free(ctx);
		return(TTLS_ERR_RSA_KEY_GEN_FAILED + ret);
	}

	return 0;
}

#endif /* TTLS_GENPRIME */

/*
 * Check a public RSA key
 */
int ttls_rsa_check_pubkey(const ttls_rsa_context *ctx)
{
	if (rsa_check_context(ctx, 0 /* public */, 0 /* no blinding */) != 0)
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);

	if (ttls_mpi_bitlen(&ctx->N) < 128)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

	if (ttls_mpi_get_bit(&ctx->E, 0) == 0 ||
		ttls_mpi_bitlen(&ctx->E)	 < 2  ||
		ttls_mpi_cmp_mpi(&ctx->E, &ctx->N) >= 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

	return 0;
}

/*
 * Check for the consistency of all fields in an RSA private key context
 */
int ttls_rsa_check_privkey(const ttls_rsa_context *ctx)
{
	if (ttls_rsa_check_pubkey(ctx) != 0 ||
		rsa_check_context(ctx, 1 /* private */, 1 /* blinding */) != 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

	if (ttls_rsa_validate_params(&ctx->N, &ctx->P, &ctx->Q,
									 &ctx->D, &ctx->E, NULL, NULL) != 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

#if !defined(TTLS_RSA_NO_CRT)
	else if (ttls_rsa_validate_crt(&ctx->P, &ctx->Q, &ctx->D,
									   &ctx->DP, &ctx->DQ, &ctx->QP) != 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}
#endif

	return 0;
}

/*
 * Check if contexts holding a public and private key match
 */
int ttls_rsa_check_pub_priv(const ttls_rsa_context *pub,
								const ttls_rsa_context *prv)
{
	if (ttls_rsa_check_pubkey(pub)  != 0 ||
		ttls_rsa_check_privkey(prv) != 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

	if (ttls_mpi_cmp_mpi(&pub->N, &prv->N) != 0 ||
		ttls_mpi_cmp_mpi(&pub->E, &prv->E) != 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

	return 0;
}

/*
 * Do an RSA public key operation
 */
int ttls_rsa_public(ttls_rsa_context *ctx,
				const unsigned char *input,
				unsigned char *output)
{
	int ret;
	size_t olen;
	ttls_mpi T;

	if (rsa_check_context(ctx, 0 /* public */, 0 /* no blinding */))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	ttls_mpi_init(&T);

	spin_lock(&ctx->mutex);

	TTLS_MPI_CHK(ttls_mpi_read_binary(&T, input, ctx->len));

	if (ttls_mpi_cmp_mpi(&T, &ctx->N) >= 0)
	{
		ret = TTLS_ERR_MPI_BAD_INPUT_DATA;
		goto cleanup;
	}

	olen = ctx->len;
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&T, &T, &ctx->E, &ctx->N, &ctx->RN));
	TTLS_MPI_CHK(ttls_mpi_write_binary(&T, output, olen));

cleanup:
	spin_unlock(&ctx->mutex);

	ttls_mpi_free(&T);

	if (ret != 0)
		return(TTLS_ERR_RSA_PUBLIC_FAILED + ret);

	return 0;
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding(ttls_rsa_context *ctx,
				 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret, count = 0;

	if (ctx->Vf.p != NULL)
	{
		/* We already have blinding values, just update them by squaring */
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ctx->Vi, &ctx->Vi, &ctx->Vi));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&ctx->Vi, &ctx->Vi, &ctx->N));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ctx->Vf, &ctx->Vf, &ctx->Vf));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&ctx->Vf, &ctx->Vf, &ctx->N));

		goto cleanup;
	}

	/* Unblinding value: Vf = random number, invertible mod N */
	do {
		if (count++ > 10)
			return(TTLS_ERR_RSA_RNG_FAILED);

		TTLS_MPI_CHK(ttls_mpi_fill_random(&ctx->Vf, ctx->len - 1, f_rng, p_rng));
		TTLS_MPI_CHK(ttls_mpi_gcd(&ctx->Vi, &ctx->Vf, &ctx->N));
	} while (ttls_mpi_cmp_int(&ctx->Vi, 1) != 0);

	/* Blinding value: Vi =  Vf^(-e) mod N */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(&ctx->Vi, &ctx->Vf, &ctx->N));
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN));


cleanup:
	return ret;
}

/*
 * Exponent blinding supposed to prevent side-channel attacks using multiple
 * traces of measurements to recover the RSA key. The more collisions are there,
 * the more bits of the key can be recovered. See [3].
 *
 * Collecting n collisions with m bit long blinding value requires 2^(m-m/n)
 * observations on avarage.
 *
 * For example with 28 byte blinding to achieve 2 collisions the adversary has
 * to make 2^112 observations on avarage.
 *
 * (With the currently (as of 2017 April) known best algorithms breaking 2048
 * bit RSA requires approximately as much time as trying out 2^112 random keys.
 * Thus in this sense with 28 byte blinding the security is not reduced by
 * side-channel attacks like the one in [3])
 *
 * This countermeasure does not help if the key recovery is possible with a
 * single trace.
 */
#define RSA_EXPONENT_BLINDING 28

/*
 * Do an RSA private key operation
 */
int ttls_rsa_private(ttls_rsa_context *ctx,
				 int (*f_rng)(void *, unsigned char *, size_t),
				 void *p_rng,
				 const unsigned char *input,
				 unsigned char *output)
{
	int ret;
	size_t olen;

	/* Temporary holding the result */
	ttls_mpi T;

	/* Temporaries holding P-1, Q-1 and the
	 * exponent blinding factor, respectively. */
	ttls_mpi P1, Q1, R;

#if !defined(TTLS_RSA_NO_CRT)
	/* Temporaries holding the results mod p resp. mod q. */
	ttls_mpi TP, TQ;

	/* Temporaries holding the blinded exponents for
	 * the mod p resp. mod q computation (if used). */
	ttls_mpi DP_blind, DQ_blind;

	/* Pointers to actual exponents to be used - either the unblinded
	 * or the blinded ones, depending on the presence of a PRNG. */
	ttls_mpi *DP = &ctx->DP;
	ttls_mpi *DQ = &ctx->DQ;
#else
	/* Temporary holding the blinded exponent (if used). */
	ttls_mpi D_blind;

	/* Pointer to actual exponent to be used - either the unblinded
	 * or the blinded one, depending on the presence of a PRNG. */
	ttls_mpi *D = &ctx->D;
#endif /* TTLS_RSA_NO_CRT */

	/* Temporaries holding the initial input and the double
	 * checked result; should be the same in the end. */
	ttls_mpi I, C;

	if (rsa_check_context(ctx, 1			 /* private key checks */,
								f_rng != NULL /* blinding y/n	   */) != 0)
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	spin_lock(&ctx->mutex);

	/* MPI Initialization */
	ttls_mpi_init(&T);

	ttls_mpi_init(&P1);
	ttls_mpi_init(&Q1);
	ttls_mpi_init(&R);

	if (f_rng != NULL)
	{
#if defined(TTLS_RSA_NO_CRT)
		ttls_mpi_init(&D_blind);
#else
		ttls_mpi_init(&DP_blind);
		ttls_mpi_init(&DQ_blind);
#endif
	}

#if !defined(TTLS_RSA_NO_CRT)
	ttls_mpi_init(&TP); ttls_mpi_init(&TQ);
#endif

	ttls_mpi_init(&I);
	ttls_mpi_init(&C);

	/* End of MPI initialization */

	TTLS_MPI_CHK(ttls_mpi_read_binary(&T, input, ctx->len));
	if (ttls_mpi_cmp_mpi(&T, &ctx->N) >= 0)
	{
		ret = TTLS_ERR_MPI_BAD_INPUT_DATA;
		goto cleanup;
	}

	TTLS_MPI_CHK(ttls_mpi_copy(&I, &T));

	if (f_rng != NULL)
	{
		/*
		 * Blinding
		 * T = T * Vi mod N
		 */
		TTLS_MPI_CHK(rsa_prepare_blinding(ctx, f_rng, p_rng));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T, &T, &ctx->Vi));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&T, &T, &ctx->N));

		/*
		 * Exponent blinding
		 */
		TTLS_MPI_CHK(ttls_mpi_sub_int(&P1, &ctx->P, 1));
		TTLS_MPI_CHK(ttls_mpi_sub_int(&Q1, &ctx->Q, 1));

#if defined(TTLS_RSA_NO_CRT)
		/*
		 * D_blind = (P - 1) * (Q - 1) * R + D
		 */
		TTLS_MPI_CHK(ttls_mpi_fill_random(&R, RSA_EXPONENT_BLINDING,
						 f_rng, p_rng));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&D_blind, &P1, &Q1));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&D_blind, &D_blind, &R));
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&D_blind, &D_blind, &ctx->D));

		D = &D_blind;
#else
		/*
		 * DP_blind = (P - 1) * R + DP
		 */
		TTLS_MPI_CHK(ttls_mpi_fill_random(&R, RSA_EXPONENT_BLINDING,
						 f_rng, p_rng));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&DP_blind, &P1, &R));
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&DP_blind, &DP_blind,
					&ctx->DP));

		DP = &DP_blind;

		/*
		 * DQ_blind = (Q - 1) * R + DQ
		 */
		TTLS_MPI_CHK(ttls_mpi_fill_random(&R, RSA_EXPONENT_BLINDING,
						 f_rng, p_rng));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&DQ_blind, &Q1, &R));
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&DQ_blind, &DQ_blind,
					&ctx->DQ));

		DQ = &DQ_blind;
#endif /* TTLS_RSA_NO_CRT */
	}

#if defined(TTLS_RSA_NO_CRT)
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&T, &T, D, &ctx->N, &ctx->RN));
#else
	/*
	 * Faster decryption using the CRT
	 *
	 * TP = input ^ dP mod P
	 * TQ = input ^ dQ mod Q
	 */

	TTLS_MPI_CHK(ttls_mpi_exp_mod(&TP, &T, DP, &ctx->P, &ctx->RP));
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&TQ, &T, DQ, &ctx->Q, &ctx->RQ));

	/*
	 * T = (TP - TQ) * (Q^-1 mod P) mod P
	 */
	TTLS_MPI_CHK(ttls_mpi_sub_mpi(&T, &TP, &TQ));
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&TP, &T, &ctx->QP));
	TTLS_MPI_CHK(ttls_mpi_mod_mpi(&T, &TP, &ctx->P));

	/*
	 * T = TQ + T * Q
	 */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&TP, &T, &ctx->Q));
	TTLS_MPI_CHK(ttls_mpi_add_mpi(&T, &TQ, &TP));
#endif /* TTLS_RSA_NO_CRT */

	if (f_rng != NULL)
	{
		/*
		 * Unblind
		 * T = T * Vf mod N
		 */
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&T, &T, &ctx->Vf));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&T, &T, &ctx->N));
	}

	/* Verify the result to prevent glitching attacks. */
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&C, &T, &ctx->E,
										  &ctx->N, &ctx->RN));
	if (ttls_mpi_cmp_mpi(&C, &I) != 0)
	{
		ret = TTLS_ERR_RSA_VERIFY_FAILED;
		goto cleanup;
	}

	olen = ctx->len;
	TTLS_MPI_CHK(ttls_mpi_write_binary(&T, output, olen));

cleanup:
	spin_unlock(&ctx->mutex);

	ttls_mpi_free(&P1);
	ttls_mpi_free(&Q1);
	ttls_mpi_free(&R);

	if (f_rng != NULL)
	{
#if defined(TTLS_RSA_NO_CRT)
		ttls_mpi_free(&D_blind);
#else
		ttls_mpi_free(&DP_blind);
		ttls_mpi_free(&DQ_blind);
#endif
	}

	ttls_mpi_free(&T);

#if !defined(TTLS_RSA_NO_CRT)
	ttls_mpi_free(&TP); ttls_mpi_free(&TQ);
#endif

	ttls_mpi_free(&C);
	ttls_mpi_free(&I);

	if (ret != 0)
		return(TTLS_ERR_RSA_PRIVATE_FAILED + ret);

	return 0;
}

/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst	   buffer to mask
 * \param dlen	  length of destination buffer
 * \param src	   source of the mask generation
 * \param slen	  length of the source buffer
 * \param md_ctx	message digest context to use
 */
static int mgf_mask(unsigned char *dst, size_t dlen, unsigned char *src,
					  size_t slen, ttls_md_context_t *md_ctx)
{
	unsigned char mask[TTLS_MD_MAX_SIZE];
	unsigned char counter[4];
	unsigned char *p;
	unsigned int hlen;
	size_t i, use_len;
	int ret = 0;

	memset(mask, 0, TTLS_MD_MAX_SIZE);
	memset(counter, 0, 4);

	hlen = ttls_md_get_size(md_ctx->md_info);

	/* Generate and apply dbMask */
	p = dst;

	while (dlen > 0)
	{
		use_len = hlen;
		if (dlen < hlen)
			use_len = dlen;

		if ((ret = ttls_md_starts(md_ctx)) != 0)
			goto exit;
		if ((ret = ttls_md_update(md_ctx, src, slen)) != 0)
			goto exit;
		if ((ret = ttls_md_update(md_ctx, counter, 4)) != 0)
			goto exit;
		if ((ret = ttls_md_finish(md_ctx, mask)) != 0)
			goto exit;

		for (i = 0; i < use_len; ++i)
			*p++ ^= mask[i];

		counter[3]++;

		dlen -= use_len;
	}

exit:
	ttls_zeroize(mask, sizeof(mask));

	return ret;
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int ttls_rsa_rsaes_oaep_encrypt(ttls_rsa_context *ctx,
							int (*f_rng)(void *, unsigned char *, size_t),
							void *p_rng,
							int mode,
							const unsigned char *label, size_t label_len,
							size_t ilen,
							const unsigned char *input,
							unsigned char *output)
{
	size_t olen;
	int ret;
	unsigned char *p = output;
	unsigned int hlen;
	const ttls_md_info_t *md_info;
	ttls_md_context_t md_ctx;

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V21)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	if (f_rng == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	md_info = ttls_md_info_from_type((ttls_md_type_t) ctx->hash_id);
	if (md_info == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	olen = ctx->len;
	hlen = ttls_md_get_size(md_info);

	/* first comparison checks for overflow */
	if (ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	memset(output, 0, olen);

	*p++ = 0;

	/* Generate a random octet string seed */
	if ((ret = f_rng(p_rng, p, hlen)) != 0)
		return(TTLS_ERR_RSA_RNG_FAILED + ret);

	p += hlen;

	/* Construct DB */
	if ((ret = ttls_md(md_info, label, label_len, p)) != 0)
		return ret;
	p += hlen;
	p += olen - 2 * hlen - 2 - ilen;
	*p++ = 1;
	memcpy(p, input, ilen);

	ttls_md_init(&md_ctx);
	if ((ret = ttls_md_setup(&md_ctx, md_info, 0)) != 0)
		goto exit;

	/* maskedDB: Apply dbMask to DB */
	if ((ret = mgf_mask(output + hlen + 1, olen - hlen - 1, output + 1, hlen,
						  &md_ctx)) != 0)
		goto exit;

	/* maskedSeed: Apply seedMask to seed */
	if ((ret = mgf_mask(output + 1, hlen, output + hlen + 1, olen - hlen - 1,
						  &md_ctx)) != 0)
		goto exit;

exit:
	ttls_md_free(&md_ctx);

	if (ret != 0)
		return ret;

	return((mode == TTLS_RSA_PUBLIC)
			? ttls_rsa_public( ctx, output, output)
			: ttls_rsa_private(ctx, f_rng, p_rng, output, output));
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int ttls_rsa_rsaes_pkcs1_v15_encrypt(ttls_rsa_context *ctx,
								 int (*f_rng)(void *, unsigned char *, size_t),
								 void *p_rng,
								 int mode, size_t ilen,
								 const unsigned char *input,
								 unsigned char *output)
{
	size_t nb_pad, olen;
	int ret;
	unsigned char *p = output;

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V15)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	// We don't check p_rng because it won't be dereferenced here
	if (f_rng == NULL || input == NULL || output == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	olen = ctx->len;

	/* first comparison checks for overflow */
	if (ilen + 11 < ilen || olen < ilen + 11)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	nb_pad = olen - 3 - ilen;

	*p++ = 0;
	if (mode == TTLS_RSA_PUBLIC)
	{
		*p++ = TTLS_RSA_CRYPT;

		while (nb_pad-- > 0)
		{
			int rng_dl = 100;

			do {
				ret = f_rng(p_rng, p, 1);
			} while (*p == 0 && --rng_dl && ret == 0);

			/* Check if RNG failed to generate data */
			if (rng_dl == 0 || ret != 0)
				return(TTLS_ERR_RSA_RNG_FAILED + ret);

			p++;
		}
	}
	else
	{
		*p++ = TTLS_RSA_SIGN;

		while (nb_pad-- > 0)
			*p++ = 0xFF;
	}

	*p++ = 0;
	memcpy(p, input, ilen);

	return((mode == TTLS_RSA_PUBLIC)
			? ttls_rsa_public( ctx, output, output)
			: ttls_rsa_private(ctx, f_rng, p_rng, output, output));
}

/*
 * Add the message padding, then do an RSA operation
 */
int ttls_rsa_pkcs1_encrypt(ttls_rsa_context *ctx,
					   int (*f_rng)(void *, unsigned char *, size_t),
					   void *p_rng,
					   int mode, size_t ilen,
					   const unsigned char *input,
					   unsigned char *output)
{
	switch(ctx->padding)
	{
		case TTLS_RSA_PKCS_V15:
			return ttls_rsa_rsaes_pkcs1_v15_encrypt(ctx, f_rng, p_rng, mode, ilen,
												input, output);

		case TTLS_RSA_PKCS_V21:
			return ttls_rsa_rsaes_oaep_encrypt(ctx, f_rng, p_rng, mode, NULL, 0,
										   ilen, input, output);

		default:
			return(TTLS_ERR_RSA_INVALID_PADDING);
	}
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int ttls_rsa_rsaes_oaep_decrypt(ttls_rsa_context *ctx,
							int (*f_rng)(void *, unsigned char *, size_t),
							void *p_rng,
							int mode,
							const unsigned char *label, size_t label_len,
							size_t *olen,
							const unsigned char *input,
							unsigned char *output,
							size_t output_max_len)
{
	int ret;
	size_t ilen, i, pad_len;
	unsigned char *p, bad, pad_done;
	unsigned char buf[TTLS_MPI_MAX_SIZE];
	unsigned char lhash[TTLS_MD_MAX_SIZE];
	unsigned int hlen;
	const ttls_md_info_t *md_info;
	ttls_md_context_t md_ctx;

	/*
	 * Parameters sanity checks
	 */
	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V21)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	ilen = ctx->len;

	if (ilen < 16 || ilen > sizeof(buf))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	md_info = ttls_md_info_from_type((ttls_md_type_t) ctx->hash_id);
	if (md_info == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	hlen = ttls_md_get_size(md_info);

	// checking for integer underflow
	if (2 * hlen + 2 > ilen)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/*
	 * RSA operation
	 */
	ret = (mode == TTLS_RSA_PUBLIC)
		  ? ttls_rsa_public( ctx, input, buf)
		  : ttls_rsa_private(ctx, f_rng, p_rng, input, buf);

	if (ret != 0)
		goto cleanup;

	/*
	 * Unmask data and generate lHash
	 */
	ttls_md_init(&md_ctx);
	if ((ret = ttls_md_setup(&md_ctx, md_info, 0)) != 0)
	{
		ttls_md_free(&md_ctx);
		goto cleanup;
	}

	/* seed: Apply seedMask to maskedSeed */
	if ((ret = mgf_mask(buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
						  &md_ctx)) != 0 ||
	/* DB: Apply dbMask to maskedDB */
		(ret = mgf_mask(buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
						  &md_ctx)) != 0)
	{
		ttls_md_free(&md_ctx);
		goto cleanup;
	}

	ttls_md_free(&md_ctx);

	/* Generate lHash */
	if ((ret = ttls_md(md_info, label, label_len, lhash)) != 0)
		goto cleanup;

	/*
	 * Check contents, in "constant-time"
	 */
	p = buf;
	bad = 0;

	bad |= *p++; /* First byte must be 0 */

	p += hlen; /* Skip seed */

	/* Check lHash */
	for (i = 0; i < hlen; i++)
		bad |= lhash[i] ^ *p++;

	/* Get zero-padding len, but always read till end of buffer
	 * (minus one, for the 01 byte) */
	pad_len = 0;
	pad_done = 0;
	for (i = 0; i < ilen - 2 * hlen - 2; i++)
	{
		pad_done |= p[i];
		pad_len += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
	}

	p += pad_len;
	bad |= *p++ ^ 0x01;

	/*
	 * The only information "leaked" is whether the padding was correct or not
	 * (eg, no data is copied if it was not correct). This meets the
	 * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
	 * the different error conditions.
	 */
	if (bad != 0)
	{
		ret = TTLS_ERR_RSA_INVALID_PADDING;
		goto cleanup;
	}

	if (ilen - (p - buf) > output_max_len)
	{
		ret = TTLS_ERR_RSA_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

	*olen = ilen - (p - buf);
	memcpy(output, p, *olen);
	ret = 0;

cleanup:
	ttls_zeroize(buf, sizeof(buf));
	ttls_zeroize(lhash, sizeof(lhash));

	return ret;
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int ttls_rsa_rsaes_pkcs1_v15_decrypt(ttls_rsa_context *ctx,
								 int (*f_rng)(void *, unsigned char *, size_t),
								 void *p_rng,
								 int mode, size_t *olen,
								 const unsigned char *input,
								 unsigned char *output,
								 size_t output_max_len)
{
	int ret;
	size_t ilen, pad_count = 0, i;
	unsigned char *p, bad, pad_done = 0;
	unsigned char buf[TTLS_MPI_MAX_SIZE];

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V15)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	ilen = ctx->len;

	if (ilen < 16 || ilen > sizeof(buf))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	ret = (mode == TTLS_RSA_PUBLIC)
		  ? ttls_rsa_public( ctx, input, buf)
		  : ttls_rsa_private(ctx, f_rng, p_rng, input, buf);

	if (ret != 0)
		goto cleanup;

	p = buf;
	bad = 0;

	/*
	 * Check and get padding len in "constant-time"
	 */
	bad |= *p++; /* First byte must be 0 */

	/* This test does not depend on secret data */
	if (mode == TTLS_RSA_PRIVATE)
	{
		bad |= *p++ ^ TTLS_RSA_CRYPT;

		/* Get padding len, but always read till end of buffer
		 * (minus one, for the 00 byte) */
		for (i = 0; i < ilen - 3; i++)
		{
			pad_done  |= ((p[i] | (unsigned char)-p[i]) >> 7) ^ 1;
			pad_count += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
		}

		p += pad_count;
		bad |= *p++; /* Must be zero */
	}
	else
	{
		bad |= *p++ ^ TTLS_RSA_SIGN;

		/* Get padding len, but always read till end of buffer
		 * (minus one, for the 00 byte) */
		for (i = 0; i < ilen - 3; i++)
		{
			pad_done |= (p[i] != 0xFF);
			pad_count += (pad_done == 0);
		}

		p += pad_count;
		bad |= *p++; /* Must be zero */
	}

	bad |= (pad_count < 8);

	if (bad)
	{
		ret = TTLS_ERR_RSA_INVALID_PADDING;
		goto cleanup;
	}

	if (ilen - (p - buf) > output_max_len)
	{
		ret = TTLS_ERR_RSA_OUTPUT_TOO_LARGE;
		goto cleanup;
	}

	*olen = ilen - (p - buf);
	memcpy(output, p, *olen);
	ret = 0;

cleanup:
	ttls_zeroize(buf, sizeof(buf));

	return ret;
}

/*
 * Do an RSA operation, then remove the message padding
 */
int ttls_rsa_pkcs1_decrypt(ttls_rsa_context *ctx,
					   int (*f_rng)(void *, unsigned char *, size_t),
					   void *p_rng,
					   int mode, size_t *olen,
					   const unsigned char *input,
					   unsigned char *output,
					   size_t output_max_len)
{
	switch(ctx->padding)
	{
		case TTLS_RSA_PKCS_V15:
			return ttls_rsa_rsaes_pkcs1_v15_decrypt(ctx, f_rng, p_rng, mode, olen,
												input, output, output_max_len);

		case TTLS_RSA_PKCS_V21:
			return ttls_rsa_rsaes_oaep_decrypt(ctx, f_rng, p_rng, mode, NULL, 0,
										   olen, input, output,
										   output_max_len);

		default:
			return(TTLS_ERR_RSA_INVALID_PADDING);
	}
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
int ttls_rsa_rsassa_pss_sign(ttls_rsa_context *ctx,
						 int (*f_rng)(void *, unsigned char *, size_t),
						 void *p_rng,
						 int mode,
						 ttls_md_type_t md_alg,
						 unsigned int hashlen,
						 const unsigned char *hash,
						 unsigned char *sig)
{
	size_t olen;
	unsigned char *p = sig;
	unsigned char salt[TTLS_MD_MAX_SIZE];
	unsigned int slen, hlen, offset = 0;
	int ret;
	size_t msb;
	const ttls_md_info_t *md_info;
	ttls_md_context_t md_ctx;

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V21)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	if (f_rng == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	olen = ctx->len;

	if (md_alg != TTLS_MD_NONE)
	{
		/* Gather length of hash to sign */
		md_info = ttls_md_info_from_type(md_alg);
		if (md_info == NULL)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

		hashlen = ttls_md_get_size(md_info);
	}

	md_info = ttls_md_info_from_type((ttls_md_type_t) ctx->hash_id);
	if (md_info == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	hlen = ttls_md_get_size(md_info);
	slen = hlen;

	if (olen < hlen + slen + 2)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	memset(sig, 0, olen);

	/* Generate salt of length slen */
	if ((ret = f_rng(p_rng, salt, slen)) != 0)
		return(TTLS_ERR_RSA_RNG_FAILED + ret);

	/* Note: EMSA-PSS encoding is over the length of N - 1 bits */
	msb = ttls_mpi_bitlen(&ctx->N) - 1;
	p += olen - hlen * 2 - 2;
	*p++ = 0x01;
	memcpy(p, salt, slen);
	p += slen;

	ttls_md_init(&md_ctx);
	if ((ret = ttls_md_setup(&md_ctx, md_info, 0)) != 0)
		goto exit;

	/* Generate H = Hash(M') */
	if ((ret = ttls_md_starts(&md_ctx)) != 0)
		goto exit;
	if ((ret = ttls_md_update(&md_ctx, p, 8)) != 0)
		goto exit;
	if ((ret = ttls_md_update(&md_ctx, hash, hashlen)) != 0)
		goto exit;
	if ((ret = ttls_md_update(&md_ctx, salt, slen)) != 0)
		goto exit;
	if ((ret = ttls_md_finish(&md_ctx, p)) != 0)
		goto exit;

	/* Compensate for boundary condition when applying mask */
	if (msb % 8 == 0)
		offset = 1;

	/* maskedDB: Apply dbMask to DB */
	if ((ret = mgf_mask(sig + offset, olen - hlen - 1 - offset, p, hlen,
						  &md_ctx)) != 0)
		goto exit;

	msb = ttls_mpi_bitlen(&ctx->N) - 1;
	sig[0] &= 0xFF >> (olen * 8 - msb);

	p += hlen;
	*p++ = 0xBC;

	ttls_zeroize(salt, sizeof(salt));

exit:
	ttls_md_free(&md_ctx);

	if (ret != 0)
		return ret;

	return((mode == TTLS_RSA_PUBLIC)
			? ttls_rsa_public( ctx, sig, sig)
			: ttls_rsa_private(ctx, f_rng, p_rng, sig, sig));
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */

/* Construct a PKCS v1.5 encoding of a hashed message
 *
 * This is used both for signature generation and verification.
 *
 * Parameters:
 * - md_alg:  Identifies the hash algorithm used to generate the given hash;
 *			TTLS_MD_NONE if raw data is signed.
 * - hashlen: Length of hash in case hashlen is TTLS_MD_NONE.
 * - hash:	Buffer containing the hashed message or the raw data.
 * - dst_len: Length of the encoded message.
 * - dst:	 Buffer to hold the encoded message.
 *
 * Assumptions:
 * - hash has size hashlen if md_alg == TTLS_MD_NONE.
 * - hash has size corresponding to md_alg if md_alg != TTLS_MD_NONE.
 * - dst points to a buffer of size at least dst_len.
 *
 */
static int rsa_rsassa_pkcs1_v15_encode(ttls_md_type_t md_alg,
										unsigned int hashlen,
										const unsigned char *hash,
										size_t dst_len,
										unsigned char *dst)
{
	size_t oid_size  = 0;
	size_t nb_pad	= dst_len;
	unsigned char *p = dst;
	const char *oid  = NULL;

	/* Are we signing hashed or raw data? */
	if (md_alg != TTLS_MD_NONE)
	{
		const ttls_md_info_t *md_info = ttls_md_info_from_type(md_alg);
		if (md_info == NULL)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

		if (ttls_oid_get_oid_by_md(md_alg, &oid, &oid_size) != 0)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

		hashlen = ttls_md_get_size(md_info);

		/* Double-check that 8 + hashlen + oid_size can be used as a
		 * 1-byte ASN.1 length encoding and that there's no overflow. */
		if (8 + hashlen + oid_size  >= 0x80		 ||
			10 + hashlen			<  hashlen	  ||
			10 + hashlen + oid_size <  10 + hashlen)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

		/*
		 * Static bounds check:
		 * - Need 10 bytes for five tag-length pairs.
		 *   (Insist on 1-byte length encodings to protect against variants of
		 *	Bleichenbacher's forgery attack against lax PKCS#1v1.5 verification)
		 * - Need hashlen bytes for hash
		 * - Need oid_size bytes for hash alg OID.
		 */
		if (nb_pad < 10 + hashlen + oid_size)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);
		nb_pad -= 10 + hashlen + oid_size;
	}
	else
	{
		if (nb_pad < hashlen)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

		nb_pad -= hashlen;
	}

	/* Need space for signature header and padding delimiter (3 bytes),
	 * and 8 bytes for the minimal padding */
	if (nb_pad < 3 + 8)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	nb_pad -= 3;

	/* Now nb_pad is the amount of memory to be filled
	 * with padding, and at least 8 bytes long. */

	/* Write signature header and padding */
	*p++ = 0;
	*p++ = TTLS_RSA_SIGN;
	memset(p, 0xFF, nb_pad);
	p += nb_pad;
	*p++ = 0;

	/* Are we signing raw data? */
	if (md_alg == TTLS_MD_NONE)
	{
		memcpy(p, hash, hashlen);
		return 0;
	}

	/* Signing hashed data, add corresponding ASN.1 structure
	 *
	 * DigestInfo ::= SEQUENCE {
	 *   digestAlgorithm DigestAlgorithmIdentifier,
	 *   digest Digest }
	 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
	 * Digest ::= OCTET STRING
	 *
	 * Schematic:
	 * TAG-SEQ + LEN [ TAG-SEQ + LEN [ TAG-OID  + LEN [ OID  ]
	 *								 TAG-NULL + LEN [ NULL ] ]
	 *				 TAG-OCTET + LEN [ HASH ] ]
	 */
	*p++ = TTLS_ASN1_SEQUENCE | TTLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char)(0x08 + oid_size + hashlen);
	*p++ = TTLS_ASN1_SEQUENCE | TTLS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char)(0x04 + oid_size);
	*p++ = TTLS_ASN1_OID;
	*p++ = (unsigned char) oid_size;
	memcpy(p, oid, oid_size);
	p += oid_size;
	*p++ = TTLS_ASN1_NULL;
	*p++ = 0x00;
	*p++ = TTLS_ASN1_OCTET_STRING;
	*p++ = (unsigned char) hashlen;
	memcpy(p, hash, hashlen);
	p += hashlen;

	/* Just a sanity-check, should be automatic
	 * after the initial bounds check. */
	if (p != dst + dst_len)
	{
		ttls_zeroize(dst, dst_len);
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	return 0;
}

/*
 * Do an RSA operation to sign the message digest
 */
int ttls_rsa_rsassa_pkcs1_v15_sign(ttls_rsa_context *ctx,
							   int (*f_rng)(void *, unsigned char *, size_t),
							   void *p_rng,
							   int mode,
							   ttls_md_type_t md_alg,
							   unsigned int hashlen,
							   const unsigned char *hash,
							   unsigned char *sig)
{
	int ret;
	unsigned char *sig_try = NULL, *verif = NULL;

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V15)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/*
	 * Prepare PKCS1-v1.5 encoding (padding and hash identifier)
	 */

	if ((ret = rsa_rsassa_pkcs1_v15_encode(md_alg, hashlen, hash,
											 ctx->len, sig)) != 0)
		return ret;

	/*
	 * Call respective RSA primitive
	 */

	if (mode == TTLS_RSA_PUBLIC)
	{
		/* Skip verification on a public key operation */
		return(ttls_rsa_public(ctx, sig, sig));
	}

	/* Private key operation
	 *
	 * In order to prevent Lenstra's attack, make the signature in a
	 * temporary buffer and check it before returning it.
	 */

	sig_try = ttls_calloc(1, ctx->len);
	if (sig_try == NULL)
		return(TTLS_ERR_MPI_ALLOC_FAILED);

	verif = ttls_calloc(1, ctx->len);
	if (verif == NULL)
	{
		ttls_free(sig_try);
		return(TTLS_ERR_MPI_ALLOC_FAILED);
	}

	TTLS_MPI_CHK(ttls_rsa_private(ctx, f_rng, p_rng, sig, sig_try));
	TTLS_MPI_CHK(ttls_rsa_public(ctx, sig_try, verif));

	if (ttls_safer_memcmp(verif, sig, ctx->len) != 0)
	{
		ret = TTLS_ERR_RSA_PRIVATE_FAILED;
		goto cleanup;
	}

	memcpy(sig, sig_try, ctx->len);

cleanup:
	ttls_free(sig_try);
	ttls_free(verif);

	return ret;
}

/*
 * Do an RSA operation to sign the message digest
 */
int ttls_rsa_pkcs1_sign(ttls_rsa_context *ctx,
					int (*f_rng)(void *, unsigned char *, size_t),
					void *p_rng,
					int mode,
					ttls_md_type_t md_alg,
					unsigned int hashlen,
					const unsigned char *hash,
					unsigned char *sig)
{
	switch(ctx->padding)
	{
		case TTLS_RSA_PKCS_V15:
			return ttls_rsa_rsassa_pkcs1_v15_sign(ctx, f_rng, p_rng, mode, md_alg,
											  hashlen, hash, sig);

		case TTLS_RSA_PKCS_V21:
			return ttls_rsa_rsassa_pss_sign(ctx, f_rng, p_rng, mode, md_alg,
										hashlen, hash, sig);

		default:
			return(TTLS_ERR_RSA_INVALID_PADDING);
	}
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int ttls_rsa_rsassa_pss_verify_ext(ttls_rsa_context *ctx,
							   int (*f_rng)(void *, unsigned char *, size_t),
							   void *p_rng,
							   int mode,
							   ttls_md_type_t md_alg,
							   unsigned int hashlen,
							   const unsigned char *hash,
							   ttls_md_type_t mgf1_hash_id,
							   int expected_salt_len,
							   const unsigned char *sig)
{
	int ret;
	size_t siglen;
	unsigned char *p;
	unsigned char *hash_start;
	unsigned char result[TTLS_MD_MAX_SIZE];
	unsigned char zeros[8];
	unsigned int hlen;
	size_t observed_salt_len, msb;
	const ttls_md_info_t *md_info;
	ttls_md_context_t md_ctx;
	unsigned char buf[TTLS_MPI_MAX_SIZE];

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V21)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	siglen = ctx->len;

	if (siglen < 16 || siglen > sizeof(buf))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	ret = (mode == TTLS_RSA_PUBLIC)
		  ? ttls_rsa_public( ctx, sig, buf)
		  : ttls_rsa_private(ctx, f_rng, p_rng, sig, buf);

	if (ret != 0)
		return ret;

	p = buf;

	if (buf[siglen - 1] != 0xBC)
		return(TTLS_ERR_RSA_INVALID_PADDING);

	if (md_alg != TTLS_MD_NONE)
	{
		/* Gather length of hash to sign */
		md_info = ttls_md_info_from_type(md_alg);
		if (md_info == NULL)
			return(TTLS_ERR_RSA_BAD_INPUT_DATA);

		hashlen = ttls_md_get_size(md_info);
	}

	md_info = ttls_md_info_from_type(mgf1_hash_id);
	if (md_info == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	hlen = ttls_md_get_size(md_info);

	memset(zeros, 0, 8);

	/*
	 * Note: EMSA-PSS verification is over the length of N - 1 bits
	 */
	msb = ttls_mpi_bitlen(&ctx->N) - 1;

	if (buf[0] >> (8 - siglen * 8 + msb))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/* Compensate for boundary condition when applying mask */
	if (msb % 8 == 0)
	{
		p++;
		siglen -= 1;
	}

	if (siglen < hlen + 2)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	hash_start = p + siglen - hlen - 1;

	ttls_md_init(&md_ctx);
	if ((ret = ttls_md_setup(&md_ctx, md_info, 0)) != 0)
		goto exit;

	ret = mgf_mask(p, siglen - hlen - 1, hash_start, hlen, &md_ctx);
	if (ret != 0)
		goto exit;

	buf[0] &= 0xFF >> (siglen * 8 - msb);

	while (p < hash_start - 1 && *p == 0)
		p++;

	if (*p++ != 0x01)
	{
		ret = TTLS_ERR_RSA_INVALID_PADDING;
		goto exit;
	}

	observed_salt_len = hash_start - p;

	if (expected_salt_len != TTLS_RSA_SALT_LEN_ANY &&
		observed_salt_len != (size_t) expected_salt_len)
	{
		ret = TTLS_ERR_RSA_INVALID_PADDING;
		goto exit;
	}

	/*
	 * Generate H = Hash(M')
	 */
	ret = ttls_md_starts(&md_ctx);
	if (ret != 0)
		goto exit;
	ret = ttls_md_update(&md_ctx, zeros, 8);
	if (ret != 0)
		goto exit;
	ret = ttls_md_update(&md_ctx, hash, hashlen);
	if (ret != 0)
		goto exit;
	ret = ttls_md_update(&md_ctx, p, observed_salt_len);
	if (ret != 0)
		goto exit;
	ret = ttls_md_finish(&md_ctx, result);
	if (ret != 0)
		goto exit;

	if (memcmp(hash_start, result, hlen) != 0)
	{
		ret = TTLS_ERR_RSA_VERIFY_FAILED;
		goto exit;
	}

exit:
	ttls_md_free(&md_ctx);

	return ret;
}

/*
 * Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function
 */
int ttls_rsa_rsassa_pss_verify(ttls_rsa_context *ctx,
						   int (*f_rng)(void *, unsigned char *, size_t),
						   void *p_rng,
						   int mode,
						   ttls_md_type_t md_alg,
						   unsigned int hashlen,
						   const unsigned char *hash,
						   const unsigned char *sig)
{
	ttls_md_type_t mgf1_hash_id = (ctx->hash_id != TTLS_MD_NONE)
							 ? (ttls_md_type_t) ctx->hash_id
							 : md_alg;

	return(ttls_rsa_rsassa_pss_verify_ext(ctx, f_rng, p_rng, mode,
									   md_alg, hashlen, hash,
									   mgf1_hash_id, TTLS_RSA_SALT_LEN_ANY,
									   sig));

}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
int ttls_rsa_rsassa_pkcs1_v15_verify(ttls_rsa_context *ctx,
								 int (*f_rng)(void *, unsigned char *, size_t),
								 void *p_rng,
								 int mode,
								 ttls_md_type_t md_alg,
								 unsigned int hashlen,
								 const unsigned char *hash,
								 const unsigned char *sig)
{
	int ret = 0;
	const size_t sig_len = ctx->len;
	unsigned char *encoded = NULL, *encoded_expected = NULL;

	if (mode == TTLS_RSA_PRIVATE && ctx->padding != TTLS_RSA_PKCS_V15)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/*
	 * Prepare expected PKCS1 v1.5 encoding of hash.
	 */

	if ((encoded		  = ttls_calloc(1, sig_len)) == NULL ||
		(encoded_expected = ttls_calloc(1, sig_len)) == NULL)
	{
		ret = TTLS_ERR_MPI_ALLOC_FAILED;
		goto cleanup;
	}

	if ((ret = rsa_rsassa_pkcs1_v15_encode(md_alg, hashlen, hash, sig_len,
											 encoded_expected)) != 0)
		goto cleanup;

	/*
	 * Apply RSA primitive to get what should be PKCS1 encoded hash.
	 */

	ret = (mode == TTLS_RSA_PUBLIC)
		  ? ttls_rsa_public( ctx, sig, encoded)
		  : ttls_rsa_private(ctx, f_rng, p_rng, sig, encoded);
	if (ret != 0)
		goto cleanup;

	/*
	 * Compare
	 */

	if ((ret = ttls_safer_memcmp(encoded, encoded_expected,
									  sig_len)) != 0)
	{
		ret = TTLS_ERR_RSA_VERIFY_FAILED;
		goto cleanup;
	}

cleanup:

	if (encoded != NULL)
	{
		ttls_zeroize(encoded, sig_len);
		ttls_free(encoded);
	}

	if (encoded_expected != NULL)
	{
		ttls_zeroize(encoded_expected, sig_len);
		ttls_free(encoded_expected);
	}

	return ret;
}

/*
 * Do an RSA operation and check the message digest
 */
int ttls_rsa_pkcs1_verify(ttls_rsa_context *ctx,
					  int (*f_rng)(void *, unsigned char *, size_t),
					  void *p_rng,
					  int mode,
					  ttls_md_type_t md_alg,
					  unsigned int hashlen,
					  const unsigned char *hash,
					  const unsigned char *sig)
{
	switch(ctx->padding)
	{
		case TTLS_RSA_PKCS_V15:
			return ttls_rsa_rsassa_pkcs1_v15_verify(ctx, f_rng, p_rng, mode, md_alg,
												hashlen, hash, sig);

		case TTLS_RSA_PKCS_V21:
			return ttls_rsa_rsassa_pss_verify(ctx, f_rng, p_rng, mode, md_alg,
										  hashlen, hash, sig);

		default:
			return(TTLS_ERR_RSA_INVALID_PADDING);
	}
}

/*
 * Copy the components of an RSA key
 */
int ttls_rsa_copy(ttls_rsa_context *dst, const ttls_rsa_context *src)
{
	int ret;

	dst->ver = src->ver;
	dst->len = src->len;

	TTLS_MPI_CHK(ttls_mpi_copy(&dst->N, &src->N));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->E, &src->E));

	TTLS_MPI_CHK(ttls_mpi_copy(&dst->D, &src->D));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->P, &src->P));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->Q, &src->Q));

#if !defined(TTLS_RSA_NO_CRT)
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->DP, &src->DP));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->DQ, &src->DQ));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->QP, &src->QP));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->RP, &src->RP));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->RQ, &src->RQ));
#endif

	TTLS_MPI_CHK(ttls_mpi_copy(&dst->RN, &src->RN));

	TTLS_MPI_CHK(ttls_mpi_copy(&dst->Vi, &src->Vi));
	TTLS_MPI_CHK(ttls_mpi_copy(&dst->Vf, &src->Vf));

	dst->padding = src->padding;
	dst->hash_id = src->hash_id;

cleanup:
	if (ret != 0)
		ttls_rsa_free(dst);

	return ret;
}

/*
 * Free the components of an RSA key
 */
void ttls_rsa_free(ttls_rsa_context *ctx)
{
	ttls_mpi_free(&ctx->Vi); ttls_mpi_free(&ctx->Vf);
	ttls_mpi_free(&ctx->RN); ttls_mpi_free(&ctx->D );
	ttls_mpi_free(&ctx->Q ); ttls_mpi_free(&ctx->P );
	ttls_mpi_free(&ctx->E ); ttls_mpi_free(&ctx->N );

#if !defined(TTLS_RSA_NO_CRT)
	ttls_mpi_free(&ctx->RQ); ttls_mpi_free(&ctx->RP);
	ttls_mpi_free(&ctx->QP); ttls_mpi_free(&ctx->DQ);
	ttls_mpi_free(&ctx->DP);
#endif /* TTLS_RSA_NO_CRT */
}

#endif /* !TTLS_RSA_ALT */

#include <linux/random.h>
#include "sha1.h"

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
				"8ED1D5BF35786190FA2F23EBC0848AEA" \
				"DDA92CA6C3D80B32C4D109BE0F36D6AE" \
				"7130B9CED7ACDF54CFC7555AC14EEBAB" \
				"93A89813FBF3C4F8066D2D800F7C38A8" \
				"1AE31942917403FF4946B0A83D3D3E05" \
				"EE57C6F5F5606FB5D4BC6CD34EE0801A" \
				"5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
				"66CA472BC44D253102F8B4A9D3BFA750" \
				"91386C0077937FE33FA3252D28855837" \
				"AE1B484A8A9A45F7EE8C0C634F99E8CD" \
				"DF79C5CE07EE72C7F123142198164234" \
				"CABB724CF78B8173B9F880FC86322407" \
				"AF1FEDFDDE2BEB674CA15F3E81A1521E" \
				"071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
				"2C01CAD19EA484A87EA4377637E75500" \
				"FCB2005C5C7DD6EC4AC023CDA285D796" \
				"C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
				"E211C2B9E5DB1ED0BF61D0D9899620F4" \
				"910E4168387E3C30AA1E00C339A79508" \
				"8452DD96A9A5EA5D9DCA68DA636032AF"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
				"\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
	size_t i;

	if (rng_state != NULL)
		rng_state  = NULL;

	for (i = 0; i < len; ++i)
		output[i] = get_random_int();

	return 0;
}

/*
 * Checkup routine
 */
int ttls_rsa_self_test(int verbose)
{
	int ret = 0;
	size_t len;
	ttls_rsa_context rsa;
	unsigned char rsa_plaintext[PT_LEN];
	unsigned char rsa_decrypted[PT_LEN];
	unsigned char rsa_ciphertext[KEY_LEN];

	ttls_mpi K;

	ttls_mpi_init(&K);
	ttls_rsa_init(&rsa, TTLS_RSA_PKCS_V15, 0);

	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_N ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, &K, NULL, NULL, NULL, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_P ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, &K, NULL, NULL, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_Q ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, NULL, &K, NULL, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_D ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, NULL, NULL, &K, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_E ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, NULL, NULL, NULL, &K));

	TTLS_MPI_CHK(ttls_rsa_complete(&rsa));

	if (verbose != 0)
		ttls_printf("  RSA key validation: ");

	if (ttls_rsa_check_pubkey( &rsa) != 0 ||
		ttls_rsa_check_privkey(&rsa) != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		ttls_printf("passed\n  PKCS#1 encryption : ");

	memcpy(rsa_plaintext, RSA_PT, PT_LEN);

	if (ttls_rsa_pkcs1_encrypt(&rsa, myrand, NULL, TTLS_RSA_PUBLIC,
								   PT_LEN, rsa_plaintext,
								   rsa_ciphertext) != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		ttls_printf("passed\n  PKCS#1 decryption : ");

	if (ttls_rsa_pkcs1_decrypt(&rsa, myrand, NULL, TTLS_RSA_PRIVATE,
								   &len, rsa_ciphertext, rsa_decrypted,
								   sizeof(rsa_decrypted)) != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (memcmp(rsa_decrypted, rsa_plaintext, len) != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		ret = 1;
		goto cleanup;
	}

	if (verbose != 0)
		ttls_printf("passed\n");

	if (verbose != 0)
		ttls_printf("\n");

cleanup:
	ttls_mpi_free(&K);
	ttls_rsa_free(&rsa);
	return ret;
}
