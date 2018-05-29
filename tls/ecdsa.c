/*
 *  Elliptic curve DSA
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
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#if defined(TTLS_ECDSA_C)

#include "ecdsa.h"
#include "asn1write.h"

#include <string.h>

#if defined(TTLS_ECDSA_DETERMINISTIC)
#include "hmac_drbg.h"
#endif

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi(const ttls_ecp_group *grp, ttls_mpi *x,
					   const unsigned char *buf, size_t blen)
{
	int ret;
	size_t n_size = (grp->nbits + 7) / 8;
	size_t use_size = blen > n_size ? n_size : blen;

	TTLS_MPI_CHK(ttls_mpi_read_binary(x, buf, use_size));
	if (use_size * 8 > grp->nbits)
		TTLS_MPI_CHK(ttls_mpi_shift_r(x, use_size * 8 - grp->nbits));

	/* While at it, reduce modulo N */
	if (ttls_mpi_cmp_mpi(x, &grp->N) >= 0)
		TTLS_MPI_CHK(ttls_mpi_sub_mpi(x, x, &grp->N));

cleanup:
	return ret;
}

#if !defined(TTLS_ECDSA_SIGN_ALT)
/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int ttls_ecdsa_sign(ttls_ecp_group *grp, ttls_mpi *r, ttls_mpi *s,
				const ttls_mpi *d, const unsigned char *buf, size_t blen,
				int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret, key_tries, sign_tries, blind_tries;
	ttls_ecp_point R;
	ttls_mpi k, e, t;

	/* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
	if (grp->N.p == NULL)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/* Make sure d is in range 1..n-1 */
	if (ttls_mpi_cmp_int(d, 1) < 0 || ttls_mpi_cmp_mpi(d, &grp->N) >= 0)
		return(TTLS_ERR_ECP_INVALID_KEY);

	ttls_ecp_point_init(&R);
	ttls_mpi_init(&k); ttls_mpi_init(&e); ttls_mpi_init(&t);

	sign_tries = 0;
	do
	{
		/*
		 * Steps 1-3: generate a suitable ephemeral keypair
		 * and set r = xR mod n
		 */
		key_tries = 0;
		do
		{
			TTLS_MPI_CHK(ttls_ecp_gen_keypair(grp, &k, &R, f_rng, p_rng));
			TTLS_MPI_CHK(ttls_mpi_mod_mpi(r, &R.X, &grp->N));

			if (key_tries++ > 10)
			{
				ret = TTLS_ERR_ECP_RANDOM_FAILED;
				goto cleanup;
			}
		}
		while (ttls_mpi_cmp_int(r, 0) == 0);

		/*
		 * Step 5: derive MPI from hashed message
		 */
		TTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

		/*
		 * Generate a random value to blind inv_mod in next step,
		 * avoiding a potential timing leak.
		 */
		blind_tries = 0;
		do
		{
			size_t n_size = (grp->nbits + 7) / 8;
			TTLS_MPI_CHK(ttls_mpi_fill_random(&t, n_size, f_rng, p_rng));
			TTLS_MPI_CHK(ttls_mpi_shift_r(&t, 8 * n_size - grp->nbits));

			/* See ttls_ecp_gen_keypair() */
			if (++blind_tries > 30)
				return(TTLS_ERR_ECP_RANDOM_FAILED);
		}
		while (ttls_mpi_cmp_int(&t, 1) < 0 ||
			   ttls_mpi_cmp_mpi(&t, &grp->N) >= 0);

		/*
		 * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
		 */
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(s, r, d));
		TTLS_MPI_CHK(ttls_mpi_add_mpi(&e, &e, s));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&e, &e, &t));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(&k, &k, &t));
		TTLS_MPI_CHK(ttls_mpi_inv_mod(s, &k, &grp->N));
		TTLS_MPI_CHK(ttls_mpi_mul_mpi(s, s, &e));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(s, s, &grp->N));

		if (sign_tries++ > 10)
		{
			ret = TTLS_ERR_ECP_RANDOM_FAILED;
			goto cleanup;
		}
	}
	while (ttls_mpi_cmp_int(s, 0) == 0);

cleanup:
	ttls_ecp_point_free(&R);
	ttls_mpi_free(&k); ttls_mpi_free(&e); ttls_mpi_free(&t);

	return ret;
}
#endif /* TTLS_ECDSA_SIGN_ALT */

#if defined(TTLS_ECDSA_DETERMINISTIC)
/*
 * Deterministic signature wrapper
 */
int ttls_ecdsa_sign_det(ttls_ecp_group *grp, ttls_mpi *r, ttls_mpi *s,
					const ttls_mpi *d, const unsigned char *buf, size_t blen,
					ttls_md_type_t md_alg)
{
	int ret;
	ttls_hmac_drbg_context rng_ctx;
	unsigned char data[2 * TTLS_ECP_MAX_BYTES];
	size_t grp_len = (grp->nbits + 7) / 8;
	const ttls_md_info_t *md_info;
	ttls_mpi h;

	if ((md_info = ttls_md_info_from_type(md_alg)) == NULL)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	ttls_mpi_init(&h);
	ttls_hmac_drbg_init(&rng_ctx);

	/* Use private key and message hash (reduced) to initialize HMAC_DRBG */
	TTLS_MPI_CHK(ttls_mpi_write_binary(d, data, grp_len));
	TTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
	TTLS_MPI_CHK(ttls_mpi_write_binary(&h, data + grp_len, grp_len));
	ttls_hmac_drbg_seed_buf(&rng_ctx, md_info, data, 2 * grp_len);

	ret = ttls_ecdsa_sign(grp, r, s, d, buf, blen,
					  ttls_hmac_drbg_random, &rng_ctx);

cleanup:
	ttls_hmac_drbg_free(&rng_ctx);
	ttls_mpi_free(&h);

	return ret;
}
#endif /* TTLS_ECDSA_DETERMINISTIC */

#if !defined(TTLS_ECDSA_VERIFY_ALT)
/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int ttls_ecdsa_verify(ttls_ecp_group *grp,
				  const unsigned char *buf, size_t blen,
				  const ttls_ecp_point *Q, const ttls_mpi *r, const ttls_mpi *s)
{
	int ret;
	ttls_mpi e, s_inv, u1, u2;
	ttls_ecp_point R;

	ttls_ecp_point_init(&R);
	ttls_mpi_init(&e); ttls_mpi_init(&s_inv); ttls_mpi_init(&u1); ttls_mpi_init(&u2);

	/* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
	if (grp->N.p == NULL)
		return(TTLS_ERR_ECP_BAD_INPUT_DATA);

	/*
	 * Step 1: make sure r and s are in range 1..n-1
	 */
	if (ttls_mpi_cmp_int(r, 1) < 0 || ttls_mpi_cmp_mpi(r, &grp->N) >= 0 ||
		ttls_mpi_cmp_int(s, 1) < 0 || ttls_mpi_cmp_mpi(s, &grp->N) >= 0)
	{
		ret = TTLS_ERR_ECP_VERIFY_FAILED;
		goto cleanup;
	}

	/*
	 * Additional precaution: make sure Q is valid
	 */
	TTLS_MPI_CHK(ttls_ecp_check_pubkey(grp, Q));

	/*
	 * Step 3: derive MPI from hashed message
	 */
	TTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

	/*
	 * Step 4: u1 = e / s mod n, u2 = r / s mod n
	 */
	TTLS_MPI_CHK(ttls_mpi_inv_mod(&s_inv, s, &grp->N));

	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&u1, &e, &s_inv));
	TTLS_MPI_CHK(ttls_mpi_mod_mpi(&u1, &u1, &grp->N));

	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&u2, r, &s_inv));
	TTLS_MPI_CHK(ttls_mpi_mod_mpi(&u2, &u2, &grp->N));

	/*
	 * Step 5: R = u1 G + u2 Q
	 *
	 * Since we're not using any secret data, no need to pass a RNG to
	 * ttls_ecp_mul() for countermesures.
	 */
	TTLS_MPI_CHK(ttls_ecp_muladd(grp, &R, &u1, &grp->G, &u2, Q));

	if (ttls_ecp_is_zero(&R))
	{
		ret = TTLS_ERR_ECP_VERIFY_FAILED;
		goto cleanup;
	}

	/*
	 * Step 6: convert xR to an integer (no-op)
	 * Step 7: reduce xR mod n (gives v)
	 */
	TTLS_MPI_CHK(ttls_mpi_mod_mpi(&R.X, &R.X, &grp->N));

	/*
	 * Step 8: check if v (that is, R.X) is equal to r
	 */
	if (ttls_mpi_cmp_mpi(&R.X, r) != 0)
	{
		ret = TTLS_ERR_ECP_VERIFY_FAILED;
		goto cleanup;
	}

cleanup:
	ttls_ecp_point_free(&R);
	ttls_mpi_free(&e); ttls_mpi_free(&s_inv); ttls_mpi_free(&u1); ttls_mpi_free(&u2);

	return ret;
}
#endif /* TTLS_ECDSA_VERIFY_ALT */

/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1(const ttls_mpi *r, const ttls_mpi *s,
									unsigned char *sig, size_t *slen)
{
	int ret;
	unsigned char buf[TTLS_ECDSA_MAX_LEN];
	unsigned char *p = buf + sizeof(buf);
	size_t len = 0;

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_mpi(&p, buf, s));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_mpi(&p, buf, r));

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&p, buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&p, buf,
									   TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE));

	memcpy(sig, p, len);
	*slen = len;

	return 0;
}

/*
 * Compute and write signature
 */
int ttls_ecdsa_write_signature(ttls_ecdsa_context *ctx, ttls_md_type_t md_alg,
						   const unsigned char *hash, size_t hlen,
						   unsigned char *sig, size_t *slen,
						   int (*f_rng)(void *, unsigned char *, size_t),
						   void *p_rng)
{
	int ret;
	ttls_mpi r, s;

	ttls_mpi_init(&r);
	ttls_mpi_init(&s);

#if defined(TTLS_ECDSA_DETERMINISTIC)
	(void) f_rng;
	(void) p_rng;

	TTLS_MPI_CHK(ttls_ecdsa_sign_det(&ctx->grp, &r, &s, &ctx->d,
							 hash, hlen, md_alg));
#else
	(void) md_alg;

	TTLS_MPI_CHK(ttls_ecdsa_sign(&ctx->grp, &r, &s, &ctx->d,
						 hash, hlen, f_rng, p_rng));
#endif

	TTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, slen));

cleanup:
	ttls_mpi_free(&r);
	ttls_mpi_free(&s);

	return ret;
}

#if ! defined(TTLS_DEPRECATED_REMOVED) && \
	defined(TTLS_ECDSA_DETERMINISTIC)
int ttls_ecdsa_write_signature_det(ttls_ecdsa_context *ctx,
							   const unsigned char *hash, size_t hlen,
							   unsigned char *sig, size_t *slen,
							   ttls_md_type_t md_alg)
{
	return(ttls_ecdsa_write_signature(ctx, md_alg, hash, hlen, sig, slen,
								   NULL, NULL));
}
#endif

/*
 * Read and check signature
 */
int ttls_ecdsa_read_signature(ttls_ecdsa_context *ctx,
						  const unsigned char *hash, size_t hlen,
						  const unsigned char *sig, size_t slen)
{
	int ret;
	unsigned char *p = (unsigned char *) sig;
	const unsigned char *end = sig + slen;
	size_t len;
	ttls_mpi r, s;

	ttls_mpi_init(&r);
	ttls_mpi_init(&s);

	if ((ret = ttls_asn1_get_tag(&p, end, &len,
					TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ret += TTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	if (p + len != end)
	{
		ret = TTLS_ERR_ECP_BAD_INPUT_DATA +
			  TTLS_ERR_ASN1_LENGTH_MISMATCH;
		goto cleanup;
	}

	if ((ret = ttls_asn1_get_mpi(&p, end, &r)) != 0 ||
		(ret = ttls_asn1_get_mpi(&p, end, &s)) != 0)
	{
		ret += TTLS_ERR_ECP_BAD_INPUT_DATA;
		goto cleanup;
	}

	if ((ret = ttls_ecdsa_verify(&ctx->grp, hash, hlen,
							  &ctx->Q, &r, &s)) != 0)
		goto cleanup;

	if (p != end)
		ret = TTLS_ERR_ECP_SIG_LEN_MISMATCH;

cleanup:
	ttls_mpi_free(&r);
	ttls_mpi_free(&s);

	return ret;
}

#if !defined(TTLS_ECDSA_GENKEY_ALT)
/*
 * Generate key pair
 */
int ttls_ecdsa_genkey(ttls_ecdsa_context *ctx, ttls_ecp_group_id gid,
				  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	return(ttls_ecp_group_load(&ctx->grp, gid) ||
			ttls_ecp_gen_keypair(&ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng));
}
#endif /* TTLS_ECDSA_GENKEY_ALT */

/*
 * Set context from an ttls_ecp_keypair
 */
int ttls_ecdsa_from_keypair(ttls_ecdsa_context *ctx, const ttls_ecp_keypair *key)
{
	int ret;

	if ((ret = ttls_ecp_group_copy(&ctx->grp, &key->grp)) != 0 ||
		(ret = ttls_mpi_copy(&ctx->d, &key->d)) != 0 ||
		(ret = ttls_ecp_copy(&ctx->Q, &key->Q)) != 0)
	{
		ttls_ecdsa_free(ctx);
	}

	return ret;
}

/*
 * Initialize context
 */
void ttls_ecdsa_init(ttls_ecdsa_context *ctx)
{
	ttls_ecp_keypair_init(ctx);
}

/*
 * Free context
 */
void ttls_ecdsa_free(ttls_ecdsa_context *ctx)
{
	ttls_ecp_keypair_free(ctx);
}

#endif /* TTLS_ECDSA_C */
