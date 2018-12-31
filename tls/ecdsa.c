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
 */
/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */
#include "config.h"
#include "ecdsa.h"
#include "asn1write.h"

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
int
ttls_ecdsa_sign(ttls_ecp_group *grp, ttls_mpi *r, ttls_mpi *s,
		const ttls_mpi *d, const unsigned char *buf, size_t blen)
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
			TTLS_MPI_CHK(ttls_ecp_gen_keypair(grp, &k, &R));
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
			TTLS_MPI_CHK(ttls_mpi_fill_random(&t, n_size));
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

/**
 * This function computes the ECDSA signature and writes it to a buffer,
 * serialized as defined in RFC-4492.
 *
 * The sig buffer must be at least twice as large as the size of the curve used,
 * plus 9. For example, 73 Bytes if a 256-bit curve is used. A buffer length of
 * TTLS_ECDSA_MAX_LEN is always safe.
 *
 * If the bitlength of the message hash is larger than the bitlength of the
 * group order, then the hash is truncated as defined in Standards for Efficient
 * Cryptography Group (SECG): SEC1 Elliptic Curve Cryptography, section 4.1.3,
 * step 5.
 */
int
ttls_ecdsa_write_signature(ttls_ecdsa_context *ctx, const unsigned char *hash,
			   size_t hlen, unsigned char *sig, size_t *slen)
{
	int ret;
	ttls_mpi r, s;

	ttls_mpi_init(&r);
	ttls_mpi_init(&s);

	TTLS_MPI_CHK(ttls_ecdsa_sign(&ctx->grp, &r, &s, &ctx->d, hash, hlen));
	TTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, slen));

cleanup:
	ttls_mpi_free(&r);
	ttls_mpi_free(&s);

	return ret;
}

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

/*
 * Generate key pair
 */
int ttls_ecdsa_genkey(ttls_ecdsa_context *ctx, ttls_ecp_group_id gid)
{
	return ttls_ecp_group_load(&ctx->grp, gid)
		|| ttls_ecp_gen_keypair(&ctx->grp, &ctx->d, &ctx->Q);
}

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
