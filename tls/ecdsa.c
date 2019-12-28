/**
 *		Tempesta TLS
 *
 * Elliptic curve DSA.
 * References:
 *	SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
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
#include "asn1write.h"
#include "ecp.h"
#include "tls_internal.h"

/*
 * RFC 8422 page 18:
 *
 *  Ecdsa-Sig-Value ::= SEQUENCE {
 *	r	INTEGER,
 *	s	INTEGER
 *  }
 *
 * Size is at most 1 (tag) + 1 (len) + 1 (initial 0) + ECP_MAX_BYTES for each
 * of r and s, twice that + 1 (tag) + 2 (len) for the sequence (assuming
 * ECP_MAX_BYTES is less than 126 for r and s, and less than 124
 * (total len <= 255) for the sequence).
 */
#if TTLS_ECP_MAX_BYTES > 124
#error "TTLS_ECP_MAX_BYTES bigger than expected, please fix TTLS_ECDSA_MAX_LEN"
#endif
/* The maximal size of an ECDSA signature in bytes. */
#define TTLS_ECDSA_MAX_LEN	(3 + 2 * (3 + TTLS_ECP_MAX_BYTES))

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi(const TlsEcpGrp *grp, TlsMpi *x,
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

/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message).
 *
 * @buf		- the message hash;
 * @blen	- the length of the hash buf;
 * @Q		- the public key to use for verification;
 * @r		- the first integer of the signature;
 * @s		- the second integer of the signature.
 *
 * If the bitlength of the message hash is larger than the bitlength of the
 * group order, then the hash is truncated as defined in Standards for Efficient
 * Cryptography Group (SECG): SEC1 Elliptic Curve Cryptography, section 4.1.4,
 * step 3.
 */
static int
ttls_ecdsa_verify(TlsEcpGrp *grp, const unsigned char *buf, size_t blen,
		  const TlsEcpPoint *Q, const TlsMpi *r, const TlsMpi *s)
{
	TlsMpi *e, *s_inv, *u1, *u2;
	TlsEcpPoint *R;

	if (!(e = ttls_mpi_alloc_stck_init((grp->nbits + 7) / 8 / CIL))
	    || !(s_inv = ttls_mpi_alloc_stck_init(grp->N.used))
	    || !(u1 = ttls_mpi_alloc_stck_init(e->limbs + s_inv->limbs))
	    || !(u2 = ttls_mpi_alloc_stck_init(r->limbs + s_inv->limbs))
	    || !(R = ttls_mpool_alloc_stck(sizeof(*R))))
		return -ENOMEM;
	ttls_ecp_point_init(R);

	/*
	 * Fail cleanly on curves such as Curve25519 that can't be used for
	 * ECDSA.
	 */
	if (!ttls_mpi_initialized(&grp->N))
		return -EINVAL;

	/* Step 1: make sure r and s are in range 1..n-1 */
	if (ttls_mpi_cmp_int(r, 1) < 0 || ttls_mpi_cmp_mpi(r, &grp->N) >= 0
	    || ttls_mpi_cmp_int(s, 1) < 0 || ttls_mpi_cmp_mpi(s, &grp->N) >= 0)
		return TTLS_ERR_ECP_VERIFY_FAILED;

	/* Additional precaution: make sure Q is valid. */
	MPI_CHK(ttls_ecp_check_pubkey(grp, Q));

	/* Step 3: derive MPI from hashed message. */
	MPI_CHK(derive_mpi(grp, e, buf, blen));

	/* Step 4: u1 = e / s mod n, u2 = r / s mod n */
	MPI_CHK(ttls_mpi_inv_mod(s_inv, s, &grp->N));
	MPI_CHK(ttls_mpi_mul_mpi(u1, e, s_inv));
	MPI_CHK(ttls_mpi_mod_mpi(u1, u1, &grp->N));
	MPI_CHK(ttls_mpi_mul_mpi(u2, r, s_inv));
	MPI_CHK(ttls_mpi_mod_mpi(u2, u2, &grp->N));

	/*
	 * Step 5: R = u1 G + u2 Q
	 *
	 * Since we're not using any secret data, no need to pass a RNG to
	 * ttls_ecp_mul() for countermesures.
	 */
	MPI_CHK(ttls_ecp_muladd(grp, R, u1, u2, Q));
	if (ttls_ecp_is_zero(R))
		return TTLS_ERR_ECP_VERIFY_FAILED;

	/*
	 * Step 6: convert xR to an integer (no-op)
	 * Step 7: reduce xR mod n (gives v)
	 */
	MPI_CHK(ttls_mpi_mod_mpi(&R->X, &R->X, &grp->N));

	/* Step 8: check if v (that is, R.X) is equal to r. */
	return ttls_mpi_cmp_mpi(&R->X, r);
}

/**
 * Convert a signature (given by context) to ASN.1.
 */
static int
ecdsa_signature_to_asn1(const TlsMpi *r, const TlsMpi *s, unsigned char *sig,
			size_t *slen)
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

	memcpy_fast(sig, p, len);
	*slen = len;

	return 0;
}

/**
 * This function computes the ECDSA signature of a hashed message (SEC1 4.1.3)
 * and writes it to a buffer, serialized as defined in RFC 8422 5.4.
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message).
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
ttls_ecdsa_write_signature(TlsEcpKeypair *ctx, const unsigned char *hash,
			   size_t hlen, unsigned char *sig, size_t *slen)
{
	int key_tries, sign_tries, blind_tries;
	TlsMpi *k, *e, *t, *r, *s, *d = &ctx->d;
	TlsEcpGrp *grp = &ctx->grp;
	TlsEcpPoint *R;

	/*
	 * Fail cleanly on curves such as Curve25519 that can't be used for
	 * ECDSA.
	 */
	if (!ttls_mpi_initialized(&grp->N))
		return -EINVAL;

	/* Make sure d is in range 1..n-1 */
	if (ttls_mpi_cmp_int(d, 1) < 0 || ttls_mpi_cmp_mpi(d, &grp->N) >= 0) {
		T_DBG_MPI2("ECDSA invalid sign key", d, &grp->N);
		return -EINVAL;
	}

	if (!(k = ttls_mpi_alloc_stck_init((grp->nbits + 7) / 8 / CIL))
	    || !(e = ttls_mpi_alloc_stck_init(hlen / CIL))
	    || !(t = ttls_mpi_alloc_stck_init((grp->nbits + 7) / 8 / CIL))
	    || !(r = ttls_mpi_alloc_stck_init(grp->N.used))
	    || !(s = ttls_mpi_alloc_stck_init(max(grp->N.used + d->used,
					      (int)(hlen / CIL))))
	    || !(R = ttls_mpool_alloc_stck(sizeof(*R))))
		return -ENOMEM;
	ttls_ecp_point_init(R);

	sign_tries = 0;
	do {
		/*
		 * Steps 1-3: generate a suitable ephemeral keypair
		 * and set r = xR mod n
		 */
		key_tries = 0;
		do {
			MPI_CHK(ttls_ecp_gen_keypair(grp, k, R));
			MPI_CHK(ttls_mpi_mod_mpi(r, &R->X, &grp->N));

			if (key_tries++ > 10)
				return TTLS_ERR_ECP_RANDOM_FAILED;
		} while (!ttls_mpi_cmp_int(r, 0));

		/* Step 5: derive MPI from hashed message. */
		MPI_CHK(derive_mpi(grp, e, hash, hlen));

		/*
		 * Generate a random value to blind inv_mod in next step,
		 * avoiding a potential timing leak.
		 */
		blind_tries = 0;
		do {
			size_t n_size = (grp->nbits + 7) / 8;
			MPI_CHK(ttls_mpi_fill_random(t, n_size));
			MPI_CHK(ttls_mpi_shift_r(t, 8 * n_size - grp->nbits));

			/* See ttls_ecp_gen_keypair() */
			if (++blind_tries > 30)
				return TTLS_ERR_ECP_RANDOM_FAILED;
		} while (ttls_mpi_cmp_int(t, 1) < 0
			 || ttls_mpi_cmp_mpi(t, &grp->N) >= 0);

		/*
		 * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
		 */
		MPI_CHK(ttls_mpi_mul_mpi(s, r, d));
		MPI_CHK(ttls_mpi_add_mpi(e, e, s));
		MPI_CHK(ttls_mpi_mul_mpi(e, e, t));
		MPI_CHK(ttls_mpi_mul_mpi(k, k, t));
		MPI_CHK(ttls_mpi_inv_mod(s, k, &grp->N));
		MPI_CHK(ttls_mpi_mul_mpi(s, s, e));
		MPI_CHK(ttls_mpi_mod_mpi(s, s, &grp->N));

		if (sign_tries++ > 10)
			return TTLS_ERR_ECP_RANDOM_FAILED;
	} while (!ttls_mpi_cmp_int(s, 0));

	return ecdsa_signature_to_asn1(r, s, sig, slen);
}

/**
 * Read and check signature.
 *
 * If the bitlength of the message hash is larger than the bitlength of the
 * group order, then the hash is truncated as defined in Standards for
 * Efficient Cryptography Group (SECG): SEC1 Elliptic Curve Cryptography,
 * section 4.1.4, step 3.
 */
int
ttls_ecdsa_read_signature(TlsEcpKeypair *ctx, const unsigned char *hash,
			  size_t hlen, const unsigned char *sig, size_t slen)
{
	int ret;
	unsigned char *p = (unsigned char *)sig;
	const unsigned char *end = sig + slen;
	size_t len;
	TlsMpi *r, *s;

	if (!(r = ttls_mpi_alloc_stck_init(0))
	    || !(s = ttls_mpi_alloc_stck_init(0)))
		return -ENOMEM;

	ret = ttls_asn1_get_tag(&p, end, &len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (ret)
		return ret + TTLS_ERR_ECP_BAD_INPUT_DATA;

	if (p + len != end)
		return TTLS_ERR_ECP_BAD_INPUT_DATA
		       + TTLS_ERR_ASN1_LENGTH_MISMATCH;

	if ((ret = ttls_asn1_get_mpi(&p, end, r))
	    || (ret = ttls_asn1_get_mpi(&p, end, s)))
		return ret + TTLS_ERR_ECP_BAD_INPUT_DATA;

	if ((ret = ttls_ecdsa_verify(&ctx->grp, hash, hlen, &ctx->Q, r, s)))
		return ret;

	return p != end ? TTLS_ERR_ECP_SIG_LEN_MISMATCH : 0;
}
