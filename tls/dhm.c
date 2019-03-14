/*
 *  Diffie-Hellman-Merkle key exchange
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
 */
/*
 *  The following sources were referenced in the design of this implementation
 *  of the Diffie-Hellman-Merkle algorithm:
 *
 *  [1] Handbook of Applied Cryptography - 1997, Chapter 12
 *	  Menezes, van Oorschot and Vanstone
 */
#include "dhm.h"
#include "pem.h"
#include "asn1.h"

/*
 * helper to validate the ttls_mpi size and import it
 */
static int dhm_read_bignum(ttls_mpi *X,
				unsigned char **p,
				const unsigned char *end)
{
	int ret, n;

	if (end - *p < 2)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	n = ((*p)[0] << 8) | (*p)[1];
	(*p) += 2;

	if ((int)(end - *p) < n)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	if ((ret = ttls_mpi_read_binary(X, *p, n)) != 0)
		return(TTLS_ERR_DHM_READ_PARAMS_FAILED + ret);

	(*p) += n;

	return 0;
}

/*
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
static int dhm_check_range(const ttls_mpi *param, const ttls_mpi *P)
{
	ttls_mpi L, U;
	int ret = 0;

	ttls_mpi_init(&L); ttls_mpi_init(&U);

	TTLS_MPI_CHK(ttls_mpi_lset(&L, 2));
	TTLS_MPI_CHK(ttls_mpi_sub_int(&U, P, 2));

	if (ttls_mpi_cmp_mpi(param, &L) < 0 ||
		ttls_mpi_cmp_mpi(param, &U) > 0)
	{
		ret = TTLS_ERR_DHM_BAD_INPUT_DATA;
	}

cleanup:
	ttls_mpi_free(&L); ttls_mpi_free(&U);
	return ret;
}

void ttls_dhm_init(ttls_dhm_context *ctx)
{
	memset(ctx, 0, sizeof(ttls_dhm_context));
}

void
ttls_dhm_free(ttls_dhm_context *ctx)
{
	ttls_mpi_free(&ctx->pX);
	ttls_mpi_free(&ctx->Vf);
	ttls_mpi_free(&ctx->Vi);
	ttls_mpi_free(&ctx->RP);
	ttls_mpi_free(&ctx->K);
	ttls_mpi_free(&ctx->GY);
	ttls_mpi_free(&ctx->GX);
	ttls_mpi_free(&ctx->X);
	ttls_mpi_free(&ctx->G);
	ttls_mpi_free(&ctx->P);
}

/*
 * Parse the ServerKeyExchange parameters
 */
int ttls_dhm_read_params(ttls_dhm_context *ctx,
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
 * Setup and write the ServerKeyExchange parameters
 */
int ttls_dhm_make_params(ttls_dhm_context *ctx, int x_size,
			unsigned char *output, size_t *olen)
{
	int ret, count = 0;
	size_t n1, n2, n3;
	unsigned char *p;

	if (ttls_mpi_cmp_int(&ctx->P, 0) == 0)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	/*
	 * Generate X as large as possible (< P)
	 */
	do
	{
		TTLS_MPI_CHK(ttls_mpi_fill_random(&ctx->X, x_size));

		while (ttls_mpi_cmp_mpi(&ctx->X, &ctx->P) >= 0)
			TTLS_MPI_CHK(ttls_mpi_shift_r(&ctx->X, 1));

		if (count++ > 10)
			return(TTLS_ERR_DHM_MAKE_PARAMS_FAILED);
	}
	while (dhm_check_range(&ctx->X, &ctx->P) != 0);

	/*
	 * Calculate GX = G^X mod P
	 */
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&ctx->GX, &ctx->G, &ctx->X,
			  &ctx->P , &ctx->RP));

	if ((ret = dhm_check_range(&ctx->GX, &ctx->P)) != 0)
		return ret;

	/*
	 * export P, G, GX
	 */
#define DHM_MPI_EXPORT(X, n)				  \
	do {				\
		TTLS_MPI_CHK(ttls_mpi_write_binary((X),			   \
			   p + 2,			   \
			   (n)));		   \
		*p++ = (unsigned char)((n) >> 8);			   \
		*p++ = (unsigned char)((n)	 );			   \
		p += (n);				 \
	} while (0)

	n1 = ttls_mpi_size(&ctx->P );
	n2 = ttls_mpi_size(&ctx->G );
	n3 = ttls_mpi_size(&ctx->GX);

	p = output;
	DHM_MPI_EXPORT(&ctx->P , n1);
	DHM_MPI_EXPORT(&ctx->G , n2);
	DHM_MPI_EXPORT(&ctx->GX, n3);

	*olen = p - output;

	ctx->len = n1;

cleanup:

	if (ret != 0)
		return(TTLS_ERR_DHM_MAKE_PARAMS_FAILED + ret);

	return 0;
}

/*
 * Set prime modulus and generator
 */
int ttls_dhm_set_group(ttls_dhm_context *ctx,
			   const ttls_mpi *P,
			   const ttls_mpi *G)
{
	int ret;

	if (ctx == NULL || P == NULL || G == NULL)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	if ((ret = ttls_mpi_copy(&ctx->P, P)) != 0 ||
		(ret = ttls_mpi_copy(&ctx->G, G)) != 0)
	{
		return(TTLS_ERR_DHM_SET_GROUP_FAILED + ret);
	}

	ctx->len = ttls_mpi_size(&ctx->P);
	return 0;
}

/*
 * Import the peer's public value G^Y
 */
int ttls_dhm_read_public(ttls_dhm_context *ctx,
		 const unsigned char *input, size_t ilen)
{
	int ret;

	if (ctx == NULL || ilen < 1 || ilen > ctx->len)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	if ((ret = ttls_mpi_read_binary(&ctx->GY, input, ilen)) != 0)
		return(TTLS_ERR_DHM_READ_PUBLIC_FAILED + ret);

	return 0;
}

/*
 * Create own private value X and export G^X
 */
int ttls_dhm_make_public(ttls_dhm_context *ctx, int x_size,
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
		TTLS_MPI_CHK(ttls_mpi_fill_random(&ctx->X, x_size));

		while (ttls_mpi_cmp_mpi(&ctx->X, &ctx->P) >= 0)
			TTLS_MPI_CHK(ttls_mpi_shift_r(&ctx->X, 1));

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
static int dhm_update_blinding(ttls_dhm_context *ctx)
{
	int ret, count;

	/*
	 * Don't use any blinding the first time a particular X is used,
	 * but remember it to use blinding next time.
	 */
	if (ttls_mpi_cmp_mpi(&ctx->X, &ctx->pX) != 0)
	{
		TTLS_MPI_CHK(ttls_mpi_copy(&ctx->pX, &ctx->X));
		TTLS_MPI_CHK(ttls_mpi_lset(&ctx->Vi, 1));
		TTLS_MPI_CHK(ttls_mpi_lset(&ctx->Vf, 1));

		return 0;
	}

	/*
	 * Ok, we need blinding. Can we re-use existing values?
	 * If yes, just update them by squaring them.
	 */
	if (ttls_mpi_cmp_int(&ctx->Vi, 1) != 0)
	{
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ctx->Vi, &ctx->Vi, &ctx->Vi));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&ctx->Vi, &ctx->Vi, &ctx->P));

		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ctx->Vf, &ctx->Vf, &ctx->Vf));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&ctx->Vf, &ctx->Vf, &ctx->P));

		return 0;
	}

	/*
	 * We need to generate blinding values from scratch
	 */

	/* Vi = random(2, P-1) */
	count = 0;
	do {
		TTLS_MPI_CHK(ttls_mpi_fill_random(&ctx->Vi,
						  ttls_mpi_size(&ctx->P)));

		while (ttls_mpi_cmp_mpi(&ctx->Vi, &ctx->P) >= 0)
			TTLS_MPI_CHK(ttls_mpi_shift_r(&ctx->Vi, 1));

		if (count++ > 10)
			return(TTLS_ERR_MPI_NOT_ACCEPTABLE);
	}
	while (ttls_mpi_cmp_int(&ctx->Vi, 1) <= 0);

	/* Vf = Vi^-X mod P */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(&ctx->Vf, &ctx->Vi, &ctx->P));
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&ctx->Vf, &ctx->Vf, &ctx->X, &ctx->P, &ctx->RP));

cleanup:
	return ret;
}

/*
 * Derive and export the shared secret (G^Y)^X mod P
 */
int ttls_dhm_calc_secret(ttls_dhm_context *ctx,
		 unsigned char *output, size_t output_size, size_t *olen)
{
	int ret;
	ttls_mpi GYb;

	if (ctx == NULL || output_size < ctx->len)
		return(TTLS_ERR_DHM_BAD_INPUT_DATA);

	if ((ret = dhm_check_range(&ctx->GY, &ctx->P)) != 0)
		return ret;

	ttls_mpi_init(&GYb);

	/* Blind peer's value */
	TTLS_MPI_CHK(dhm_update_blinding(ctx));
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&GYb, &ctx->GY, &ctx->Vi));
	TTLS_MPI_CHK(ttls_mpi_mod_mpi(&GYb, &GYb, &ctx->P));

	/* Do modular exponentiation */
	TTLS_MPI_CHK(ttls_mpi_exp_mod(&ctx->K, &GYb, &ctx->X,
			  &ctx->P, &ctx->RP));

	/* Unblind secret value */
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&ctx->K, &ctx->K, &ctx->Vf));
	TTLS_MPI_CHK(ttls_mpi_mod_mpi(&ctx->K, &ctx->K, &ctx->P));

	*olen = ttls_mpi_size(&ctx->K);

	TTLS_MPI_CHK(ttls_mpi_write_binary(&ctx->K, output, *olen));

cleanup:
	ttls_mpi_free(&GYb);

	if (ret != 0)
		return(TTLS_ERR_DHM_CALC_SECRET_FAILED + ret);

	return 0;
}
