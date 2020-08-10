/*
 *		Tempesta TLS
 *
 * Diffie-Hellman-Merkle key exchange.
 *
 * The following sources were referenced in the design of this implementation
 * of the Diffie-Hellman-Merkle algorithm:
 *
 * [1] Handbook of Applied Cryptography - 1997, Chapter 12
 *     Menezes, van Oorschot and Vanstone
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
#include "lib/str.h"

#include "dhm.h"
#include "pem.h"
#include "asn1.h"
#include "tls_internal.h"

/**
 * RFC 3526, RFC 5114 and RFC 7919 standardize a number of Diffie-Hellman
 * groups, some of which are included here for use within the TLS module.
 *
 * The following lists the source of the above groups in the standards:
 * - RFC 5114 section 2.2: 2048-bit MODP Group with 224-bit Prime Order Subgroup
 * - RFC 3526 section 3:   2048-bit MODP Group
 * - RFC 3526 section 4:   3072-bit MODP Group
 * - RFC 3526 section 5:   4096-bit MODP Group
 * - RFC 7919 section A.1: ffdhe2048
 * - RFC 7919 section A.2: ffdhe3072
 * - RFC 7919 section A.3: ffdhe4096
 * - RFC 7919 section A.4: ffdhe6144
 * - RFC 7919 section A.5: ffdhe8192
 *
 * The constants with suffix "_p" denote the chosen prime moduli, while the
 * constants with suffix "_g" denote the chosen generator of the associated
 * prime field.
 *
 * The constants further suffixed with "_bin" are provided in binary format,
 * while all other constants represent null-terminated strings holding the
 * hexadecimal presentation of the respective numbers.
 *
 * The primes from RFC 3526 and RFC 7919 have been generating by the following
 * trust-worthy procedure:
 * - Fix N in { 2048, 3072, 4096, 6144, 8192 } and consider the N-bit number
 *   the first and last 64 bits are all 1, and the remaining N - 128 bits of
 *   which are 0x7ff...ff.
 * - Add the smallest multiple of the first N - 129 bits of the binary expansion
 *   of pi (for RFC 5236) or e (for RFC 7919) to this intermediate bit-string
 *   such that the resulting integer is a safe-prime.
 * - The result is the respective RFC 3526 / 7919 prime, and the corresponding
 *   generator is always chosen to be 2 (which is a square for these prime,
 *   hence the corresponding subgroup has order (p-1)/2 and avoids leaking a
 *   bit in the private exponent).
 */
static const unsigned char ttls_dhm_rfc3526_modp_2048_p[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
	0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
	0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
	0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
	0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
	0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
	0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
	0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
	0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
	0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
	0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
	0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
	0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
	0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
	0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
	0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
	0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
	0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
	0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
	0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
	0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
	0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
	0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
	0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
	0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
	0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const unsigned char ttls_dhm_rfc3526_modp_2048_g[] = { 0x02 };

/*
 * Set DHM prime modulus and generator defined in NSA Suite B (257 bytes).
 */
void
ttls_dhm_load(TlsDHMCtx *ctx)
{
	ttls_mpi_read_binary(&ctx->P, ttls_dhm_rfc3526_modp_2048_p,
			     sizeof(ttls_dhm_rfc3526_modp_2048_p));
	ttls_mpi_read_binary(&ctx->G, ttls_dhm_rfc3526_modp_2048_g,
			     sizeof(ttls_dhm_rfc3526_modp_2048_g));
	ctx->len = ttls_mpi_size(&ctx->P);
}

/*
 * helper to validate the TlsMpi size and import it
 */
static int
dhm_read_bignum(TlsMpi *X, unsigned char **p, const unsigned char *end)
{
	int n;

	if (end - *p < 2)
		return TTLS_ERR_DHM_BAD_INPUT_DATA;

	n = ((*p)[0] << 8) | (*p)[1];
	(*p) += 2;

	if ((int)(end - *p) < n)
		return TTLS_ERR_DHM_BAD_INPUT_DATA;

	ttls_mpi_read_binary(X, *p, n);

	(*p) += n;

	return 0;
}

/**
 * Verify sanity of parameter with regards to P
 *
 * Parameter should be: 2 <= public_param <= P - 2
 *
 * This means that we need to return an error if
 *			  public_param < 2 or public_param > P-2
 *
 * For more information on the attack, see:
 *  http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
 *  http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
 */
static int
dhm_check_range(const TlsMpi *param, const TlsMpi *P)
{
	TlsMpi *U = ttls_mpi_alloc_stack_init(P->used);

	ttls_mpi_sub_int(U, P, 2);
	if (ttls_mpi_cmp_int(param, 2) < 0
	    || ttls_mpi_cmp_mpi(param, U) > 0)
		return -EINVAL;

	return 0;
}

/*
 * Parse the ServerKeyExchange parameters
 */
int ttls_dhm_read_params(TlsDHMCtx *ctx,
		 unsigned char **p,
		 const unsigned char *end)
{
	int ret;

	if ((ret = dhm_read_bignum(&ctx->P,  p, end)) != 0 ||
		(ret = dhm_read_bignum(&ctx->G,  p, end)) != 0 ||
		(ret = dhm_read_bignum(&ctx->GY, p, end)) != 0)
		return ret;

	if ((ret = dhm_check_range(&ctx->GY, &ctx->P)) != 0)
		return ret;

	ctx->len = ttls_mpi_size(&ctx->P);

	return 0;
}

/*
 * Setup and write the ServerKeyExchange parameters.
 *
 * The destination buffer must be large enough to hold the reduced binary
 * presentation of the modulus, the generator and the public key, each wrapped
 * with a 2-byte length field.
 */
int
ttls_dhm_make_params(TlsDHMCtx *ctx, int x_size, unsigned char *output,
		     size_t *olen)
{
	int r = -EINVAL, count = 0;
	size_t n1, n2, n3;
	unsigned char *p;

	if (WARN_ON_ONCE(!ttls_mpi_cmp_int(&ctx->P, 0)))
		return -EINVAL;

	/* Generate X as large as possible (< P). */
	do {
		ttls_mpi_fill_random(&ctx->X, x_size);

		while (ttls_mpi_cmp_mpi(&ctx->X, &ctx->P) >= 0)
			ttls_mpi_shift_r(&ctx->X, 1);

		if (count++ > 10) {
			T_WARN("DHM random failed\n");
			goto err;
		}
	} while (dhm_check_range(&ctx->X, &ctx->P));

	/* Calculate GX = G^X mod P. */
	r = ttls_mpi_exp_mod(&ctx->GX, &ctx->G, &ctx->X, &ctx->P, &ctx->RP);
	if (r)
		goto err;
	if ((r = dhm_check_range(&ctx->GX, &ctx->P)))
		goto err;

	/* Export P, G, GX. */
#define DHM_MPI_EXPORT(X, n)						\
	if ((r = ttls_mpi_write_binary(X, p + 2, n)))			\
		goto err;						\
	*p++ = (unsigned char)(n >> 8);					\
	*p++ = (unsigned char)n;					\
	p += n;

	n1 = ttls_mpi_size(&ctx->P);
	n2 = ttls_mpi_size(&ctx->G);
	n3 = ttls_mpi_size(&ctx->GX);

	p = output;
	DHM_MPI_EXPORT(&ctx->P, n1);
	DHM_MPI_EXPORT(&ctx->G, n2);
	DHM_MPI_EXPORT(&ctx->GX, n3);

	*olen = p - output;

	ctx->len = n1;

#undef DHM_MPI_EXPORT
err:
	if (r)
		T_WARN("Making of the DHM parameters failed, %d\n", r);
	return r;
}

/*
 * Import the peer's public value G^Y
 */
int
ttls_dhm_read_public(TlsDHMCtx *ctx, const unsigned char *input, size_t ilen)
{
	if (!ctx || ilen < 1 || ilen > ctx->len)
		return -EINVAL;

	ttls_mpi_read_binary(&ctx->GY, input, ilen);

	return 0;
}

/*
 * Create own private value X and export G^X
 */
int ttls_dhm_make_public(TlsDHMCtx *ctx, int x_size,
		 unsigned char *output, size_t olen)
{
	int ret, count = 0;

	if (ctx == NULL || olen < 1 || olen > ctx->len)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	if (ttls_mpi_cmp_int(&ctx->P, 0) == 0)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	/*
	 * generate X and calculate GX = G^X mod P
	 */
	do {
		ttls_mpi_fill_random(&ctx->X, x_size);

		while (ttls_mpi_cmp_mpi(&ctx->X, &ctx->P) >= 0)
			ttls_mpi_shift_r(&ctx->X, 1);

		if (count++ > 10)
			return(TTLS_ERR_DHM_MAKE_PUBLIC_FAILED);
	}
	while (dhm_check_range(&ctx->X, &ctx->P) != 0);

	TTLS_MPI_CHK(ttls_mpi_exp_mod(&ctx->GX, &ctx->G, &ctx->X,
			  &ctx->P , &ctx->RP));

	if ((ret = dhm_check_range(&ctx->GX, &ctx->P)) != 0)
		return ret;

	TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->GX, output, olen));

cleanup:

	if (ret != 0)
		return(TTLS_ERR_DHM_MAKE_PUBLIC_FAILED + ret);

	return 0;
}

/*
 * Use the blinding method and optimisation suggested in section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int dhm_update_blinding(TlsDHMCtx *ctx)
{
	int ret, count;

	/*
	 * Don't use any blinding the first time a particular X is used,
	 * but remember it to use blinding next time.
	 */
	if (ttls_mpi_cmp_mpi(&ctx->X, &ctx->pX)) {
		ttls_mpi_copy(&ctx->pX, &ctx->X);
		ttls_mpi_lset(&ctx->Vi, 1);
		ttls_mpi_lset(&ctx->Vf, 1);
		return 0;
	}

	/*
	 * Ok, we need blinding. Can we re-use existing values?
	 * If yes, just update them by squaring them.
	 */
	if (ttls_mpi_cmp_int(&ctx->Vi, 1)) {
		ttls_mpi_mul_mpi(&ctx->Vi, &ctx->Vi, &ctx->Vi);
		ttls_mpi_mod_mpi(&ctx->Vi, &ctx->Vi, &ctx->P);

		ttls_mpi_mul_mpi(&ctx->Vf, &ctx->Vf, &ctx->Vf);
		ttls_mpi_mod_mpi(&ctx->Vf, &ctx->Vf, &ctx->P);

		return 0;
	}

	/*
	 * We need to generate blinding values from scratch
	 */

	/* Vi = random(2, P-1) */
	count = 0;
	do {
		ttls_mpi_fill_random(&ctx->Vi, ttls_mpi_size(&ctx->P));

		while (ttls_mpi_cmp_mpi(&ctx->Vi, &ctx->P) >= 0)
			ttls_mpi_shift_r(&ctx->Vi, 1);

		if (count++ > 10)
			return -EINVAL;
	}
	while (ttls_mpi_cmp_int(&ctx->Vi, 1) <= 0);

	/* Vf = Vi^-X mod P */
	ttls_mpi_inv_mod(&ctx->Vf, &ctx->Vi, &ctx->P);
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&ctx->Vf, &ctx->Vf, &ctx->X, &ctx->P, &ctx->RP));

cleanup:
	return ret;
}

/**
 * Derive and export the shared secret (G^Y)^X mod P
 */
int
ttls_dhm_calc_secret(TlsDHMCtx *ctx, unsigned char *output, size_t output_size,
		     size_t *olen)
{
	int r;
	TlsMpi *GYb;

	if (unlikely(!ctx || output_size < ctx->len))
		return -EINVAL;

	if ((r = dhm_check_range(&ctx->GY, &ctx->P)))
		return r;

	GYb = ttls_mpi_alloc_stack_init(ctx->GY.used + ctx->Vi.used);

	/* Blind peer's value */
	MPI_CHK(dhm_update_blinding(ctx));
	ttls_mpi_mul_mpi(GYb, &ctx->GY, &ctx->Vi);
	ttls_mpi_mod_mpi(GYb, GYb, &ctx->P);

	/* Do modular exponentiation */
	MPI_CHK(ttls_mpi_exp_mod(&ctx->K, GYb, &ctx->X, &ctx->P, &ctx->RP));

	/* Unblind secret value */
	ttls_mpi_mul_mpi(&ctx->K, &ctx->K, &ctx->Vf);
	ttls_mpi_mod_mpi(&ctx->K, &ctx->K, &ctx->P);

	*olen = ttls_mpi_size(&ctx->K);

	MPI_CHK(ttls_mpi_write_binary(&ctx->K, output, *olen));

	return 0;
}
