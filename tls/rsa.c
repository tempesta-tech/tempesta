/**
 *		Tempesta TLS
 *
 * The RSA public-key cryptosystem.
 *
 * TODO #1335: The Linux crypt API already has RSA implementation, so probably
 * the stuff below should be just thrown out.
 *
 * The following sources were referenced in the design of this implementation
 * of the RSA algorithm:
 *
 * [1] A method for obtaining digital signatures and public-key cryptosystems
 *     R Rivest, A Shamir, and L Adleman
 *     http://people.csail.mit.edu/rivest/pubs.html#RSA78
 *
 * [2] Handbook of Applied Cryptography - 1997, Chapter 8
 *     Menezes, van Oorschot and Vanstone
 *
 * [3] Malware Guard Extension: Using SGX to Conceal Cache Attacks
 *     Michael Schwarz, Samuel Weiser, Daniel Gruss, Clémentine Maurice and
 *     Stefan Mangard
 *     https://arxiv.org/abs/1702.08719v2
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#include <linux/random.h>

#include "lib/str.h"
#include "crypto.h"
#include "mpool.h"
#include "oid.h"
#include "rsa.h"
#include "tls_internal.h"

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

/**
 * Initialize an RSA context.
 *
 * TODO #1335: Set padding to #TTLS_RSA_PKCS_V21 for the RSAES-OAEP encryption
 * scheme and the RSASSA-PSS signature scheme. The choice of padding mode is
 * strictly enforced for private key operations, since there might be security
 * concerns in mixing padding modes. For public key operations it is a default
 * value, which can be overridden by calling specific rsa_rsaes_xxx or
 * rsa_rsassa_xxx functions.
 *
 * The hash selected in hash_id is always used for OEAP encryption. For PSS
 * signatures, it is always used for making signatures, but can be overridden
 * for verifying them. If set to TTLS_MD_NONE, it is always overridden.
 */
void
ttls_rsa_init(TlsRSACtx *ctx, int padding, int hash_id)
{
	/*
	 * TODO Select padding mode: TTLS_RSA_PKCS_V15 or TTLS_RSA_PKCS_V21.
	 */
	ctx->padding = padding;
	/*
	 * TODO The hash identifier of ttls_md_type_t type, if padding is
	 * TTLS_RSA_PKCS_V21. The hash_id parameter is ignored when using
	 * TTLS_RSA_PKCS_V15 padding.
	 */
	ctx->hash_id = hash_id;
}

/**
 * Setup the RSA context when we know the size of the N prime.
 * This is another half for ttls_rsa_init().
 */
static int
__rsa_setup_ctx(TlsRSACtx *ctx)
{
	int cpu, count = 0;

	/*
	 * Do nothing if the context is already setup or N or E aren't loaded
	 * yet (public and private context always load both the MPIs).
	 */
	if (ctx->len || ttls_mpi_empty(&ctx->N) || ttls_mpi_empty(&ctx->E))
		return 0;

	ctx->len = ttls_mpi_size(&ctx->N);

	ctx->Vi = __alloc_percpu(sizeof(TlsMpi) + ctx->len * 2,
				 __alignof__(TlsMpi));
	if (!ctx->Vi)
		return -ENOMEM;

	ctx->Vf = __alloc_percpu(sizeof(TlsMpi) + ctx->len * 2,
				 __alignof__(TlsMpi));
	if (!ctx->Vf) {
		free_percpu(ctx->Vi);
		return -ENOMEM;
	}

	/*
	 * Generate blinding values.
	 * Unblinding value: Vf = random number, invertible mod N.
	 */
	for_each_possible_cpu(cpu) {
		TlsMpi *vi = per_cpu_ptr(ctx->Vi, cpu);
		TlsMpi *vf = per_cpu_ptr(ctx->Vf, cpu);

		ttls_mpi_init_next(vi, ctx->len * 2 / CIL);
		ttls_mpi_init_next(vf, ctx->len * 2 / CIL);

		do {
			if (WARN_ON_ONCE(count++ > 10))
				return TTLS_ERR_RSA_RNG_FAILED;
			ttls_mpi_fill_random(vf, ctx->len - 1);
			ttls_mpi_gcd(vi, vf, &ctx->N);
		} while (ttls_mpi_cmp_int(vi, 1));
		/* Blinding value: Vi =  Vf^(-e) mod N */
		ttls_mpi_inv_mod(vi, vf, &ctx->N);
		ttls_mpi_exp_mod(vi, vi, &ctx->E, &ctx->N, &ctx->RN);
	}

	return 0;
}

void
ttls_rsa_free(TlsRSACtx *ctx)
{
	free_percpu(ctx->Vi);
	free_percpu(ctx->Vf);
}

/**
 * Get length in bytes of RSA modulus.
 */
size_t
ttls_rsa_get_len(const TlsRSACtx *ctx)
{
	return ctx->len;
}

/**
 * Import core RSA parameters, in raw big-endian binary format,
 * into an RSA context.
 *
 * This function can be called multiple times for successive imports, if the
 * parameters are not simultaneously present.
 *
 * Any sequence of calls to this function should be followed by a call to
 * ttls_rsa_complete(), which checks and completes the provided information to
 * a ready-for-use public or private RSA key.
 *
 * See ttls_rsa_complete() for more information on which parameters are
 * necessary to set up a private or public RSA key.
 *
 * The imported parameters are copied and need not be preserved for the lifetime
 * of the RSA context being set up.
 */
int
ttls_rsa_import_raw(TlsRSACtx *ctx, unsigned char const *N, size_t N_len,
		    unsigned char const *P, size_t P_len,
		    unsigned char const *Q, size_t Q_len,
		    unsigned char const *D, size_t D_len,
		    unsigned char const *E, size_t E_len)
{
	if (N)
		ttls_mpi_read_binary(&ctx->N, N, N_len);
	if (P)
		ttls_mpi_read_binary(&ctx->P, P, P_len);
	if (Q)
		ttls_mpi_read_binary(&ctx->Q, Q, Q_len);
	if (D)
		ttls_mpi_read_binary(&ctx->D, D, D_len);
	if (E)
		ttls_mpi_read_binary(&ctx->E, E, E_len);

	return __rsa_setup_ctx(ctx);
}

/*
 * Compute RSA prime factors from public and private exponents
 *
 * @N	- RSA modulus N = PQ, with P, Q to be found;
 * @E	- RSA public exponent;
 * @D	- RSA private exponent;
 * @P	- Pointer to MPI holding first prime factor of N on success;
 * @Q	- Pointer to MPI holding second prime factor of N on success.

 * Summary of algorithm:
 * Setting F := lcm(P-1,Q-1), the idea is as follows:
 *
 * (a) For any 1 <= X < N with gcd(X,N)=1, we have X^F = 1 modulo N, so X^(F/2)
 *     is a square root of 1 in Z/NZ. Since Z/NZ ~= Z/PZ x Z/QZ by CRT and the
 *     square roots of 1 in Z/PZ and Z/QZ are +1 and -1, this leaves the four
 *     possibilities X^(F/2) = (+-1, +-1). If it happens that X^(F/2) = (-1,+1)
 *     or (+1,-1), then gcd(X^(F/2) + 1, N) will be equal to one of the prime
 *     factors of N.
 *
 * (b) If we don't know F/2 but (F/2) * K for some odd (!) K, then the same
 *     construction still applies since (-)^K is the identity on the set of
 *     roots of 1 in Z/NZ.
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
 */
int
ttls_rsa_deduce_primes(TlsMpi const *N, TlsMpi const *E, TlsMpi const *D,
		       TlsMpi *P, TlsMpi *Q)
{
	uint16_t attempt;  /* Number of current attempt  */
	uint16_t iter;	 /* Number of squares computed in the current attempt */

	uint16_t order;	/* Order of 2 in DE - 1 */

	TlsMpi *T;  /* Holds largest odd divisor of DE - 1	 */
	TlsMpi *K;  /* Temporary holding the current candidate */

	static const unsigned char primes[] = {
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
		61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
		131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
		197, 199, 211, 223, 227, 229, 233, 239, 241, 251
	};

	if (WARN_ON_ONCE(!P || ttls_mpi_empty(P))
	    || WARN_ON_ONCE(!Q || ttls_mpi_empty(Q)))
		return -EINVAL;

	if (ttls_mpi_cmp_int(N, 0) <= 0 || ttls_mpi_cmp_int(D, 1) <= 0
	    || ttls_mpi_cmp_mpi(D, N) >= 0 || ttls_mpi_cmp_int(E, 1) <= 0
	    || ttls_mpi_cmp_mpi(E, N) >= 0)
		return -EINVAL;

	T = ttls_mpi_alloc_stack_init(D->used + E->used);
	K = ttls_mpi_alloc_stack_init(N->used + 1);

	/* T := DE - 1 */
	ttls_mpi_mul_mpi(T, D,  E);
	ttls_mpi_sub_int(T, T, 1);

	if (!(order = (uint16_t)ttls_mpi_lsb(T)))
		return -EINVAL;

	/* After this operation, T holds the largest odd divisor of DE - 1. */
	ttls_mpi_shift_r(T, order);

	/* Skip trying 2 if N == 1 mod 8 */
	attempt = 0;
	if (MPI_P(N)[0] % 8 == 1)
		attempt = 1;

	for ( ; attempt < ARRAY_SIZE(primes); ++attempt) {
		ttls_mpi_lset(K, primes[attempt]);

		/* Check if gcd(K,N) = 1 */
		ttls_mpi_gcd(P, K, N);
		if (ttls_mpi_cmp_int(P, 1))
			continue;

		/*
		 * Go through K^T + 1, K^(2T) + 1, K^(4T) + 1, ...
		 * and check whether they have nontrivial GCD with N.
		 *
		 * Temporarily use Q for storing Montgomery multiplication
		 * helper values.
		 */
		MPI_CHK(ttls_mpi_exp_mod(K, K, T, N, Q));

		for (iter = 1; iter <= order; ++iter) {
			/*
			 * If we reach 1 prematurely, there's no point
			 * in continuing to square K.
			 */
			if (!ttls_mpi_cmp_int(K, 1))
				break;

			ttls_mpi_add_int(K, K, 1);
			ttls_mpi_gcd(P, K, N);

			if (ttls_mpi_cmp_int(P, 1) > 0
			    && ttls_mpi_cmp_mpi(P, N) < 0)
			{
				/*
				 * Have found a nontrivial divisor P of N.
				 * Set Q := N / P.
				 */
				ttls_mpi_div_mpi(Q, NULL, N, P);
				return 0;
			}

			ttls_mpi_sub_int(K, K, 1);
			ttls_mpi_mul_mpi(K, K, K);
			ttls_mpi_mod_mpi(K, K, N);
		}

		/*
		 * If we get here, then either we prematurely aborted the loop
		 * because we reached 1, or K holds
		 * primes[attempt]^(DE - 1) mod N, which must be 1 if D, E, N
		 * were consistent. Check if that's the case and abort if not,
		 * to avoid very long, yet eventually failing, computations if
		 * N, D, E were not sane.
		 */
		if (ttls_mpi_cmp_int(K, 1))
			break;
	}

	return -EINVAL;
}

/**
 * Compute RSA private exponent from prime modulus and public key:
 * given P, Q and the public exponent E, deduce D.
 *
 * This is essentially a modular inversion.
 *
 * @P	- First prime factor of RSA modulus;
 * @Q	- Second prime factor of RSA modulus;
 * @E	- RSA public exponent;
 * @D	- Pointer to MPI holding the private exponent on success.
 */
int
ttls_rsa_deduce_private_exponent(TlsMpi const *P, TlsMpi const *Q,
				 TlsMpi const *E, TlsMpi *D)
{
	TlsMpi *K, *L;

	if (!D || ttls_mpi_cmp_int(D, 0))
		return -EINVAL;

	if (ttls_mpi_cmp_int(P, 1) <= 0 || ttls_mpi_cmp_int(Q, 1) <= 0
	    || !ttls_mpi_cmp_int(E, 0))
		return -EINVAL;

	K = ttls_mpi_alloc_stack_init(P->used + Q->used);
	L = ttls_mpi_alloc_stack_init(Q->used);

	/* Temporarily put K := P-1 and L := Q-1 */
	ttls_mpi_sub_int(K, P, 1);
	ttls_mpi_sub_int(L, Q, 1);

	/* Temporarily put D := gcd(P-1, Q-1) */
	ttls_mpi_gcd(D, K, L);

	/* K := LCM(P-1, Q-1) */
	ttls_mpi_mul_mpi(K, K, L);
	ttls_mpi_div_mpi(K, NULL, K, D);

	/* Compute modular inverse of E in LCM(P-1, Q-1) */
	ttls_mpi_inv_mod(D, E, K);

	return 0;
}

/**
 * Generate RSA-CRT parameters.
 *
 * @P	- First prime factor of N;
 * @Q	- Second prime factor of N;
 * @D	- RSA private exponent;
 * @DP	- Output variable for D modulo P-1;
 * @DQ	- Output variable for D modulo Q-1;
 * @QP	- Output variable for the modular inverse of Q modulo P.
 */
int
ttls_rsa_deduce_crt(const TlsMpi *P, const TlsMpi *Q, const TlsMpi *D,
		    TlsMpi *DP, TlsMpi *DQ, TlsMpi *QP)
{
	TlsMpi *K = ttls_mpi_alloc_stack_init(max(P->used, Q->used));

	/* DP = D mod P-1 */
	if (DP) {
		ttls_mpi_sub_int(K, P, 1 );
		ttls_mpi_mod_mpi(DP, D, K);
	}

	/* DQ = D mod Q-1 */
	if (DQ) {
		ttls_mpi_sub_int(K, Q, 1 );
		ttls_mpi_mod_mpi(DQ, D, K);
	}

	/* QP = Q^{-1} mod P */
	if (QP)
		ttls_mpi_inv_mod(QP, Q, P);

	return 0;
}

/*
 * Checks whether the context fields are set in such a way
 * that the RSA primitives will be able to execute without error.
 * It does *not* make guarantees for consistency of the parameters.
 */
static int
rsa_check_context(const TlsRSACtx *ctx, int is_priv)
{
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

	/*
	 * Modular exponentiation for P and Q is only used for private key
	 * operations and if Chinese Remainder Theorem (CRT) is used.
	 */
	if (is_priv &&
		(ttls_mpi_cmp_int(&ctx->P, 0) <= 0 ||
		  ttls_mpi_get_bit(&ctx->P, 0) == 0 ||
		  ttls_mpi_cmp_int(&ctx->Q, 0) <= 0 ||
		  ttls_mpi_get_bit(&ctx->Q, 0) == 0 ))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	/*
	 * 2. Exponents must be positive
	 */

	/* Always need E for public key operations */
	if (ttls_mpi_cmp_int(&ctx->E, 0) <= 0)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	if (is_priv &&
		(ttls_mpi_cmp_int(&ctx->DP, 0) <= 0 ||
		  ttls_mpi_cmp_int(&ctx->DQ, 0) <= 0 ))
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	/* It wouldn't lead to an error if it wasn't satisfied,
	 * but check for QP >= 1 nonetheless. */
	if (is_priv &&
		ttls_mpi_cmp_int(&ctx->QP, 0) <= 0)
	{
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	return 0;
}

/**
 * Update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static void
rsa_prepare_blinding(TlsRSACtx *ctx)
{
	TlsMpi *vi = this_cpu_ptr(ctx->Vi);
	TlsMpi *vf = this_cpu_ptr(ctx->Vf);

	/* We already have blinding values, just update them by squaring. */
	ttls_mpi_mul_mpi(vi, vi, vi);
	ttls_mpi_mod_mpi(vi, vi, &ctx->N);
	ttls_mpi_mul_mpi(vf, vf, vf);
	ttls_mpi_mod_mpi(vf, vf, &ctx->N);
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
 * to make 2^112 observations on average.
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
 * Do an RSA private key operation.
 *
 * The input and output buffers must be large enough.
 * For example, 128 Bytes if RSA-1024 is used.
 */
static int
ttls_rsa_private(TlsRSACtx *ctx, const unsigned char *input,
		 unsigned char *output)
{
	int r = 0;
	size_t olen, n;
	const size_t eb_n = (RSA_EXPONENT_BLINDING + CIL - 1) / CIL;
	TlsMpi *vi = this_cpu_ptr(ctx->Vi);
	TlsMpi *vf = this_cpu_ptr(ctx->Vf);

	/* Temporary holding the result */
	TlsMpi *T;

	/* Temporaries holding P-1, Q-1 and the
	 * exponent blinding factor, respectively. */
	TlsMpi *P1, *Q1, *R;

	/* Temporaries holding the results mod p resp. mod q. */
	TlsMpi *TP, *TQ;

	/* Temporaries holding the blinded exponents for
	 * the mod p resp. mod q computation (if used). */
	TlsMpi *DP_blind, *DQ_blind;

	/* Temporaries holding the initial input and the double
	 * checked result; should be the same in the end. */
	TlsMpi *I, *C;

	n = sizeof(TlsMpi) * 10
	    + CIL * (ctx->N.used * 3 + ctx->len / CIL * 2 + vi->used
		     + ctx->P.used * 2 + ctx->Q.used * 2 + eb_n * 3 + 3);
	T = ttls_mpool_alloc_stack(n);
	I = ttls_mpi_init_next(T, ctx->len * 2 / CIL);
	P1 = ttls_mpi_init_next(I, ctx->len / CIL);
	Q1 = ttls_mpi_init_next(P1, ctx->P.used);
	R = ttls_mpi_init_next(Q1, ctx->Q.used);
	DP_blind = ttls_mpi_init_next(R, eb_n);
	DQ_blind = ttls_mpi_init_next(DP_blind, eb_n + ctx->P.used);
	TP = ttls_mpi_init_next(DQ_blind, eb_n + ctx->Q.used);
	TQ = ttls_mpi_init_next(TP, ctx->N.used + 1);
	C = ttls_mpi_init_next(TQ, ctx->N.used + 1);
	ttls_mpi_init_next(C, ctx->N.used + 1);

	ttls_mpi_read_binary(T, input, ctx->len);
	if (ttls_mpi_cmp_mpi(T, &ctx->N) >= 0) {
		r = -EINVAL;
		goto cleanup;
	}

	ttls_mpi_copy(I, T);

	/* Blinding: T = T * Vi mod N */
	rsa_prepare_blinding(ctx);
	ttls_mpi_mul_mpi(T, T, vi);
	ttls_mpi_mod_mpi(T, T, &ctx->N);

	/* Exponent blinding. */
	ttls_mpi_sub_int(P1, &ctx->P, 1);
	ttls_mpi_sub_int(Q1, &ctx->Q, 1);

	/* DP_blind = (P - 1) * R + DP */
	ttls_mpi_fill_random(R, RSA_EXPONENT_BLINDING);
	ttls_mpi_mul_mpi(DP_blind, P1, R);
	ttls_mpi_add_mpi(DP_blind, DP_blind, &ctx->DP);

	/* DQ_blind = (Q - 1) * R + DQ */
	ttls_mpi_fill_random(R, RSA_EXPONENT_BLINDING);
	ttls_mpi_mul_mpi(DQ_blind, Q1, R);
	ttls_mpi_add_mpi(DQ_blind, DQ_blind, &ctx->DQ);

	/*
	 * Faster decryption using the CRT
	 *
	 * TP = input ^ dP mod P
	 * TQ = input ^ dQ mod Q
	 */
	MPI_CHK(ttls_mpi_exp_mod(TP, T, DP_blind, &ctx->P, &ctx->RP));
	MPI_CHK(ttls_mpi_exp_mod(TQ, T, DQ_blind, &ctx->Q, &ctx->RQ));

	/* T = (TP - TQ) * (Q^-1 mod P) mod P */
	ttls_mpi_sub_mpi(T, TP, TQ);
	ttls_mpi_mul_mpi(TP, T, &ctx->QP);
	ttls_mpi_mod_mpi(T, TP, &ctx->P);

	/* T = TQ + T * Q */
	ttls_mpi_mul_mpi(TP, T, &ctx->Q);
	ttls_mpi_add_mpi(T, TQ, TP);

	/* Unblind: T = T * Vf mod N */
	ttls_mpi_mul_mpi(T, T, vf);
	ttls_mpi_mod_mpi(T, T, &ctx->N);

	/* Verify the result to prevent glitching attacks. */
	MPI_CHK(ttls_mpi_exp_mod(C, T, &ctx->E, &ctx->N, &ctx->RN));
	if (ttls_mpi_cmp_mpi(C, I)) {
		r = TTLS_ERR_RSA_VERIFY_FAILED;
		goto cleanup;
	}

	olen = ctx->len;
	MPI_CHK(ttls_mpi_write_binary(T, output, olen));

cleanup:
	ttls_mpi_pool_cleanup_ctx((unsigned long)T, false);

	return r;
}

/**
 * This function completes an RSA context from a set of imported core
 * parameters.
 * To setup an RSA public key, precisely N and E must have been imported.
 * To setup an RSA private key, sufficient information must be present for
 * the other parameters to be derivable.
 *
 * The implementation supports the following:
 * - Derive P, Q from N, D, E;
 * - Derive N, D from P, Q, E.
 *
 * If this function runs successfully, it guarantees that the RSA context can
 * be used for RSA operations without the risk of failure or crash.
 */
int
ttls_rsa_complete(TlsRSACtx *ctx)
{
	int r = 0;
	const int have_N = !!ttls_mpi_cmp_int(&ctx->N, 0);
	const int have_P = !!ttls_mpi_cmp_int(&ctx->P, 0);
	const int have_Q = !!ttls_mpi_cmp_int(&ctx->Q, 0);
	const int have_D = !!ttls_mpi_cmp_int(&ctx->D, 0);
	const int have_E = !!ttls_mpi_cmp_int(&ctx->E, 0);
	/*
	 * Check whether provided parameters are enough
	 * to deduce all others. The following incomplete
	 * parameter sets for private keys are supported:
	 *
	 * (1) P, Q missing.
	 * (2) D and potentially N missing.
	 *
	 */
	const int n_missing = have_P && have_Q && have_D && have_E;
	const int pq_missing = have_N && !have_P && !have_Q && have_D && have_E;
	const int d_missing = have_P && have_Q && !have_D && have_E;
	/* These three alternatives are mutually exclusive */
	const int is_priv = n_missing || pq_missing || d_missing;
	const int is_pub = have_N && !have_P && !have_Q && !have_D && have_E;

	if (!is_priv && !is_pub)
		return TTLS_ERR_RSA_BAD_INPUT_DATA;

	/* Step 1: Deduce N if P, Q are provided. */

	if (!have_N && have_P && have_Q) {
		ttls_mpi_mul_mpi(&ctx->N, &ctx->P, &ctx->Q);
		ctx->len = ttls_mpi_size(&ctx->N);
	}

	/* Step 2: Deduce and verify all remaining core parameters. */
	if (pq_missing) {
		r = ttls_rsa_deduce_primes(&ctx->N, &ctx->E, &ctx->D, &ctx->P,
					   &ctx->Q);
		if (r)
			return TTLS_ERR_RSA_BAD_INPUT_DATA + r;
	}
	else if (d_missing) {
		r = ttls_rsa_deduce_private_exponent(&ctx->P, &ctx->Q, &ctx->E,
						     &ctx->D);
		if (r)
			return TTLS_ERR_RSA_BAD_INPUT_DATA + r;
	}

	/*
	 * Step 3: Deduce all additional parameters specific to our current RSA
	 * implementation.
	 */
	if (is_priv) {
		r = ttls_rsa_deduce_crt(&ctx->P,  &ctx->Q,  &ctx->D, &ctx->DP,
					&ctx->DQ, &ctx->QP);
		if (r)
			return TTLS_ERR_RSA_BAD_INPUT_DATA + r;
	}

	/* Step 3: Basic sanity checks. */
	return rsa_check_context(ctx, is_priv);
}

int ttls_rsa_export_raw(const TlsRSACtx *ctx,
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

int ttls_rsa_export(const TlsRSACtx *ctx,
			TlsMpi *N, TlsMpi *P, TlsMpi *Q,
			TlsMpi *D, TlsMpi *E)
{
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
	if (N)
		ttls_mpi_copy(N, &ctx->N);
	if (P)
		ttls_mpi_copy(P, &ctx->P);
	if (Q)
		ttls_mpi_copy(Q, &ctx->Q);
	if (D)
		ttls_mpi_copy(D, &ctx->D);
	if (E)
		ttls_mpi_copy(E, &ctx->E);

	return 0;
}

/*
 * Export CRT parameters
 * This must also be implemented if CRT is not used, for being able to
 * write DER encoded RSA keys. The helper function ttls_rsa_deduce_crt
 * can be used in this case.
 *
 * TODO #1335: CRT deduction should be offloaded to configuration stage and
 * the parameters should be written to speedup handshake private key operations.
 */
int ttls_rsa_export_crt(const TlsRSACtx *ctx,
				TlsMpi *DP, TlsMpi *DQ, TlsMpi *QP)
{
	/* Check if key is private or public */
	int is_priv =
		ttls_mpi_cmp_int(&ctx->N, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->P, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->Q, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->D, 0) != 0 &&
		ttls_mpi_cmp_int(&ctx->E, 0) != 0;

	if (!is_priv)
		return TTLS_ERR_RSA_BAD_INPUT_DATA;

	/* Export all requested blinding parameters. */
	if (DP)
		ttls_mpi_copy(DP, &ctx->DP);
	if (DQ)
		ttls_mpi_copy(DQ, &ctx->DQ);
	if (QP)
		ttls_mpi_copy(QP, &ctx->QP);

	return 0;
}

/**
 * Check a public RSA key: if a context contains at least an RSA public key.
 * If the function runs successfully, it is guaranteed that enough information
 * is present to perform an RSA public key operation using ttls_rsa_public().
 *
 * @ctx may contain the public key as well as the private one.
 */
int
ttls_rsa_check_pubkey(TlsRSACtx *ctx)
{
	if (ttls_rsa_complete(ctx))
		return TTLS_ERR_RSA_KEY_CHECK_FAILED;

	if (ttls_mpi_bitlen(&ctx->N) < 128)
		return TTLS_ERR_RSA_KEY_CHECK_FAILED;

	if (!ttls_mpi_get_bit(&ctx->E, 0)
	    || ttls_mpi_bitlen(&ctx->E) < 2
	    || ttls_mpi_cmp_mpi(&ctx->E, &ctx->N) >= 0)
		return TTLS_ERR_RSA_KEY_CHECK_FAILED;

	return 0;
}

/*
 * Do an RSA public key operation.
 *
 * This function does not handle message padding.
 * Make sure to set input[0] = 0 or ensure that input is smaller than N.
 * The input and output buffers must be large enough. For example, 128 Bytes
 * if RSA-1024 is used.
 */
static int
ttls_rsa_public(TlsRSACtx *ctx, const unsigned char *input,
		unsigned char *output)
{
	size_t olen;
	TlsMpi *T = ttls_mpi_alloc_stack_init(ctx->len / CIL + 1);

	ttls_mpi_read_binary(T, input, ctx->len);

	if (ttls_mpi_cmp_mpi(T, &ctx->N) >= 0)
		return -EINVAL;

	olen = ctx->len;
	MPI_CHK(ttls_mpi_exp_mod(T, T, &ctx->E, &ctx->N, &ctx->RN));
	MPI_CHK(ttls_mpi_write_binary(T, output, olen));

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
		  size_t slen, TlsMdCtx *md_ctx)
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
	bzero_fast(mask, sizeof(mask));

	return ret;
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN signature.
 *
 * @hash_id in the RSA context is the one used for the encoding.
 * @md_alg in the function call is the type of hash that is encoded.
 * According to RFC-3447: Public-Key Cryptography Standards (PKCS) #1 v2.1:
 * RSA Cryptography Specifications it is advised to keep both hashes the same.
 */
static int
ttls_rsa_rsassa_pss_sign(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			 const unsigned char *hash, size_t hashlen,
			 unsigned char *sig)
{
	size_t olen;
	unsigned char *p = sig;
	unsigned char salt[TTLS_MD_MAX_SIZE];
	unsigned int slen, hlen, offset = 0;
	int ret;
	size_t msb;
	const TlsMdInfo *md_info;
	TlsMdCtx md_ctx;

	if (ctx->padding != TTLS_RSA_PKCS_V21)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	olen = ctx->len;

	/* Gather length of hash to sign */
	md_info = ttls_md_info_from_type(md_alg);
	if (md_info == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	md_info = ttls_md_info_from_type((ttls_md_type_t) ctx->hash_id);
	if (md_info == NULL)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	hlen = ttls_md_get_size(md_info);
	slen = hlen;

	if (olen < hlen + slen + 2)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	memset(sig, 0, olen);

	/* Generate salt of length slen */
	ttls_rnd(salt, slen);

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

	bzero_fast(salt, sizeof(salt));

exit:
	ttls_md_free(&md_ctx);

	if (ret != 0)
		return ret;

	return ttls_rsa_private(ctx, sig, sig);
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 *
 * Construct a PKCS v1.5 encoding of a hashed message.
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
 * - md_alg != TTLS_MD_NONE.
 * - hash has size corresponding to md_alg.
 * - dst points to a buffer of size at least dst_len.
 */
static int
rsa_rsassa_pkcs1_v15_encode(ttls_md_type_t md_alg, const unsigned char *hash,
			    size_t hashlen, size_t dst_len, unsigned char *dst)
{
	size_t oid_size  = 0;
	size_t nb_pad	= dst_len;
	unsigned char *p = dst;
	const char *oid  = NULL;

	if (ttls_oid_get_oid_by_md(md_alg, &oid, &oid_size) != 0)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/*
	 * Double-check that 8 + hashlen + oid_size can be used as a
	 * 1-byte ASN.1 length encoding and that there's no overflow.
	 */
	if (8 + hashlen + oid_size >= 0x80
	    || 10 + hashlen < hashlen
	    || 10 + hashlen + oid_size < 10 + hashlen)
	{
		return TTLS_ERR_RSA_BAD_INPUT_DATA;
	}

	/*
	 * Static bounds check:
	 * - Need 10 bytes for five tag-length pairs. (Insist on 1-byte length
	 *   encodings to protect against variants of Bleichenbacher's forgery
	 *   attack against lax PKCS#1v1.5 verification)
	 * - Need hashlen bytes for hash
	 * - Need oid_size bytes for hash alg OID.
	 */
	if (nb_pad < 10 + hashlen + oid_size)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	nb_pad -= 10 + hashlen + oid_size;

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
	 *		 TAG-NULL + LEN [ NULL ] ]
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
		bzero_fast(dst, dst_len);
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);
	}

	return 0;
}

/*
 * Compute an RSA PKCS#1 v1.5 signature (RSASSA-PKCS1-v1_5-SIGN) for a message
 * digest.
 */
static int
ttls_rsa_rsassa_pkcs1_v15_sign(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			       const unsigned char *hash, size_t hashlen,
			       unsigned char *sig)
{
	int ret;
	unsigned char *sig_try = NULL, *verif = NULL;

	if (ctx->padding != TTLS_RSA_PKCS_V15)
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	/*
	 * Prepare PKCS1-v1.5 encoding (padding and hash identifier)
	 */
	if ((ret = rsa_rsassa_pkcs1_v15_encode(md_alg, hash, hashlen,
					       ctx->len, sig)))
		return ret;

	/* Private key operation
	 *
	 * In order to prevent Lenstra's attack, make the signature in a
	 * temporary buffer and check it before returning it.
	 */
	if (!(sig_try = kzalloc(ctx->len * 2, GFP_ATOMIC)))
		return -ENOMEM;

	verif = sig_try + ctx->len;

	TTLS_MPI_CHK(ttls_rsa_private(ctx, sig, sig_try));
	TTLS_MPI_CHK(ttls_rsa_public(ctx, sig_try, verif));

	if (ttls_safer_memcmp(verif, sig, ctx->len) != 0)
	{
		ret = TTLS_ERR_RSA_PRIVATE_FAILED;
		goto cleanup;
	}

	memcpy(sig, sig_try, ctx->len);

cleanup:
	kfree(sig_try);

	return ret;
}

/**
 * This function performs a private RSA operation to sign a message digest using
 * PKCS#1.
 *
 * The @sig buffer must be as large as the size of ctx->N.
 * For example, 128 Bytes if RSA-1024 is used.
 */
int
ttls_rsa_pkcs1_sign(TlsRSACtx *ctx, ttls_md_type_t md_alg,
		    const unsigned char *hash, size_t hashlen,
		    unsigned char *sig)
{
	switch(ctx->padding) {
	case TTLS_RSA_PKCS_V15:
		return ttls_rsa_rsassa_pkcs1_v15_sign(ctx, md_alg, hash,
						      hashlen, sig);
	case TTLS_RSA_PKCS_V21:
		return ttls_rsa_rsassa_pss_sign(ctx, md_alg, hash, hashlen, sig);
	default:
		return TTLS_ERR_RSA_INVALID_PADDING;
	}
}

/**
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-VERIFY function.
 * The hash function for the MGF mask generating function is that specified in
 * @mgf1_hash_id.
 */
int
ttls_rsa_rsassa_pss_verify_ext(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			       unsigned int hashlen, const unsigned char *hash,
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
	const TlsMdInfo *md_info;
	TlsMdCtx md_ctx;
	unsigned char buf[TTLS_MPI_MAX_SIZE];

	siglen = ctx->len;

	if (siglen < 16 || siglen > sizeof(buf))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	if ((ret = ttls_rsa_public(ctx, sig, buf)))
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
	if (expected_salt_len != TTLS_RSA_SALT_LEN_ANY
	    && observed_salt_len != (size_t)expected_salt_len)
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
 * Simplified PKCS#1 v2.1 RSASSA-PSS-VERIFY function.
 * The hash function for the MGF mask generating function is that specified in
 * the RSA context.
 *
 * @hashlen is the length of the message digest. Only used if md_alg is
 * #TTLS_MD_NONE.
 *
 * The @hash_id in the RSA context is the one used for the verification.
 * @md_alg in the function call is the type of hash that is verified.
 * According to RFC-3447: Public-Key Cryptography Standards (PKCS) #1 v2.1:
 * RSA Cryptography Specifications it is advised to keep both hashes the same.
 * If hash_id in the RSA context is unset, the @md_alg from the function call
 * is used.
 */
int
ttls_rsa_rsassa_pss_verify(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			   unsigned int hashlen, const unsigned char *hash,
			   const unsigned char *sig)
{
	ttls_md_type_t mgf1_hash_id = (ctx->hash_id != TTLS_MD_NONE)
				      ? (ttls_md_type_t) ctx->hash_id
				      : md_alg;

	return ttls_rsa_rsassa_pss_verify_ext(ctx, md_alg, hashlen, hash,
					      mgf1_hash_id,
					      TTLS_RSA_SALT_LEN_ANY, sig);

}

/**
 * Implementation of the PKCS#1 v1.5 RSASSA-PKCS1-v1_5-VERIFY function.
 *
 * @ctx		- The RSA public key context;
 * @md_alg	- The message-digest algorithm used to hash the original data,
 *		  or #TTLS_MD_NONE for signing raw data;
 * @hashlen	- The length of the message digest. Only used if @md_alg is
 *		  #TTLS_MD_NONE;
 * @hash	- The buffer holding the message digest;
 * @sig		- The buffer holding the ciphertext;
 */
static int
ttls_rsa_rsassa_pkcs1_v15_verify(TlsRSACtx *ctx, ttls_md_type_t md_alg,
				 unsigned int hashlen,
				 const unsigned char *hash,
				 const unsigned char *sig)
{
	int ret = 0;
	const size_t sig_len = ctx->len;
	unsigned char *encoded = NULL, *encoded_expected = NULL;

	/*
	 * Prepare expected PKCS1 v1.5 encoding of hash.
	 */

	if ((encoded = kzalloc(sig_len, GFP_ATOMIC)) == NULL ||
		(encoded_expected = kzalloc(sig_len, GFP_ATOMIC)) == NULL)
	{
		ret = -ENOMEM;
		goto cleanup;
	}

	if ((ret = rsa_rsassa_pkcs1_v15_encode(md_alg, hash, hashlen, sig_len,
					       encoded_expected)))
		goto cleanup;

	/*
	 * Apply RSA primitive to get what should be PKCS1 encoded hash.
	 */
	if ((ret = ttls_rsa_public(ctx, sig, encoded)))
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
		bzero_fast(encoded, sig_len);
		kfree(encoded);
	}

	if (encoded_expected != NULL)
	{
		bzero_fast(encoded_expected, sig_len);
		kfree(encoded_expected);
	}

	return ret;
}

/*
 * Do an RSA operation and check the message digest.
 */
int
ttls_rsa_pkcs1_verify(TlsRSACtx *ctx, ttls_md_type_t md_alg,
		      unsigned int hashlen, const unsigned char *hash,
		      const unsigned char *sig)
{
	switch (ctx->padding) {
	case TTLS_RSA_PKCS_V15:
		return ttls_rsa_rsassa_pkcs1_v15_verify(ctx, md_alg, hashlen,
							hash, sig);
	case TTLS_RSA_PKCS_V21:
		return ttls_rsa_rsassa_pss_verify(ctx, md_alg, hashlen, hash,
						  sig);
	default:
		return TTLS_ERR_RSA_INVALID_PADDING;
	}
}
