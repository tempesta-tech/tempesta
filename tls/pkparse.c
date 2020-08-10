/**
 *		Tempesta TLS
 *
 * Public Key layer for parsing key files and structures
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
#include "pk.h"
#include "asn1.h"
#include "mpool.h"
#include "oid.h"
#include "rsa.h"
#include "ecp.h"
#include "pem.h"
#include "tls_internal.h"

/* Minimally parse an ECParameters buffer to and ttls_asn1_buf
 *
 * ECParameters ::= CHOICE {
 *   namedCurve		 OBJECT IDENTIFIER
 *   specifiedCurve	 SpecifiedECDomain -- = SEQUENCE { ... }
 *   -- implicitCurve   NULL
 * }
 */
static int pk_get_ecparams(unsigned char **p, const unsigned char *end,
				ttls_asn1_buf *params)
{
	int ret;

	if (end - *p < 1)
		return(TTLS_ERR_PK_KEY_INVALID_FORMAT +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	/* Tag may be either OID or SEQUENCE */
	params->tag = **p;
	if (params->tag != TTLS_ASN1_OID)
	{
		return(TTLS_ERR_PK_KEY_INVALID_FORMAT +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);
	}

	if ((ret = ttls_asn1_get_tag(p, end, &params->len, params->tag)) != 0)
	{
		return(TTLS_ERR_PK_KEY_INVALID_FORMAT + ret);
	}

	params->p = *p;
	*p += params->len;

	if (*p != end)
		return(TTLS_ERR_PK_KEY_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/**
 * Use EC parameters to find an EC group from initialized MPI profiles.
 *
 * ECParameters ::= CHOICE {
 *	namedCurve		OBJECT IDENTIFIER
 *	specifiedCurve		SpecifiedECDomain -- = SEQUENCE { ... }
 *	-- implicitCurve	NULL
 */
static int
pk_use_ecparams(const ttls_asn1_buf *params, const TlsEcpGrp **grp)
{
	ttls_ecp_group_id grp_id;

	if (params->tag != TTLS_ASN1_OID) {
		T_ERR("Bad ASN1 OID tag %d, elliptic curve ID is expected\n",
		      params->tag);
		return -EINVAL;
	}
	if (ttls_oid_get_ec_grp(params, &grp_id)) {
		T_ERR("Unsupported elliptic curve\n");
		return -EINVAL;
	}

	if (*grp) {
		if (WARN_ON_ONCE((*grp)->id != grp_id))
			return -EEXIST;
		return 0;
	}

	if (!(*grp = ttls_ecp_group_lookup(grp_id)))
		return -ENOENT;

	return 0;
}

/*
 * EC public key is an EC point
 *
 * The caller is responsible for clearing the structure upon failure if
 * desired. Take care to pass along the possible ECP_FEATURE_UNAVAILABLE
 * return code of ttls_ecp_point_read_binary() and leave p in a usable state.
 */
static int
pk_get_ecpubkey(unsigned char **p, const unsigned char *end, TlsEcpKeypair *key)
{
	int r;

	r = ttls_ecp_point_read_binary(key->grp, &key->Q,
				       (const unsigned char *)*p, end - *p);
	/* We know ttls_ecp_point_read_binary consumed all bytes or failed. */
	if (!r)
		*p = (unsigned char *)end;

	return r;
}

/*
 *  RSAPublicKey ::= SEQUENCE {
 *	  modulus		   INTEGER,  -- n
 *	  publicExponent	INTEGER   -- e
 *  }
 */
static int
pk_get_rsapubkey(unsigned char **p, const unsigned char *end, TlsRSACtx *rsa)
{
	int r;
	size_t len;

	r = ttls_asn1_get_tag(p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r)
		return TTLS_ERR_PK_INVALID_PUBKEY + r;

	if (*p + len != end)
		return TTLS_ERR_PK_INVALID_PUBKEY
			+ TTLS_ERR_ASN1_LENGTH_MISMATCH;

	/* Import N */
	if ((r = ttls_asn1_get_tag(p, end, &len, TTLS_ASN1_INTEGER)))
		return TTLS_ERR_PK_INVALID_PUBKEY + r;

	if (ttls_rsa_import_raw(rsa, *p, len, NULL, 0, NULL, 0, NULL, 0,
				NULL, 0))
		return -ENOMEM;
	*p += len;

	/* Import E */
	if ((r = ttls_asn1_get_tag(p, end, &len, TTLS_ASN1_INTEGER)))
		return TTLS_ERR_PK_INVALID_PUBKEY + r;

	if (ttls_rsa_import_raw(rsa, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
				*p, len))
		return -ENOMEM;
	*p += len;

	if (ttls_rsa_check_pubkey(rsa))
		return TTLS_ERR_PK_INVALID_PUBKEY;

	if (*p != end)
		return TTLS_ERR_PK_INVALID_PUBKEY
			+ TTLS_ERR_ASN1_LENGTH_MISMATCH;

	return 0;
}

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *	   algorithm			   OBJECT IDENTIFIER,
 *	   parameters			  ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg(unsigned char **p,
			  const unsigned char *end,
			  ttls_pk_type_t *pk_alg, ttls_asn1_buf *params)
{
	int ret;
	ttls_asn1_buf alg_oid;

	memset(params, 0, sizeof(ttls_asn1_buf));

	if ((ret = ttls_asn1_get_alg(p, end, &alg_oid, params)) != 0)
		return(TTLS_ERR_PK_INVALID_ALG + ret);

	if (ttls_oid_get_pk_alg(&alg_oid, pk_alg) != 0)
		return(TTLS_ERR_PK_UNKNOWN_PK_ALG);

	/*
	 * No parameters with RSA (only for EC)
	 */
	if (*pk_alg == TTLS_PK_RSA &&
			((params->tag != TTLS_ASN1_NULL && params->tag != 0) ||
				params->len != 0))
	{
		return(TTLS_ERR_PK_INVALID_ALG);
	}

	return 0;
}

/**
 * Parse a SubjectPublicKeyInfo DER structure.
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *	algorithm		AlgorithmIdentifier,
 *	subjectPublicKey	BIT STRING
 * }
 */
int
ttls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
			TlsPkCtx *pk)
{
	int ret;
	size_t len;
	ttls_asn1_buf alg_params;
	ttls_pk_type_t pk_alg = TTLS_PK_NONE;
	const TlsPkInfo *pk_info;

	if ((ret = ttls_asn1_get_tag(p, end, &len,
		TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		return(TTLS_ERR_PK_KEY_INVALID_FORMAT + ret);
	}

	end = *p + len;

	if ((ret = pk_get_pk_alg(p, end, &pk_alg, &alg_params)) != 0)
		return ret;

	if ((ret = ttls_asn1_get_bitstring_null(p, end, &len)) != 0)
		return(TTLS_ERR_PK_INVALID_PUBKEY + ret);

	if (*p + len != end)
		return(TTLS_ERR_PK_INVALID_PUBKEY +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	if ((pk_info = ttls_pk_info_from_type(pk_alg)) == NULL)
		return(TTLS_ERR_PK_UNKNOWN_PK_ALG);

	if ((ret = ttls_pk_setup(pk, pk_info)) != 0)
		return ret;

	/*
	 * The caller is responsible for calling ttls_pk_free(pk) on the
	 * function failure, ttls_x509_crt_free() in particular.
	 */

	if (pk_alg == TTLS_PK_RSA)
	{
		ret = pk_get_rsapubkey(p, end, ttls_pk_rsa(*pk));
	}
	else if (pk_alg == TTLS_PK_ECKEY_DH || pk_alg == TTLS_PK_ECKEY)
	{
		ret = pk_use_ecparams(&alg_params, &ttls_pk_ec(*pk)->grp);
		if (ret == 0)
			ret = pk_get_ecpubkey(p, end, ttls_pk_ec(*pk));
	} else
		ret = TTLS_ERR_PK_UNKNOWN_PK_ALG;

	if (ret == 0 && *p != end)
		ret = TTLS_ERR_PK_INVALID_PUBKEY
			  TTLS_ERR_ASN1_LENGTH_MISMATCH;

	return ret;
}

/**
 * Parse a PKCS#1 encoded private RSA key.
 */
static int
__parse_key_pkcs1_der(TlsRSACtx *rsa, const unsigned char *key, size_t keylen)
{
	int r, version;
	size_t len;
	unsigned char *p, *end;
	TlsMpi *T;

	p = (unsigned char *)key;
	end = p + keylen;

	/*
	 * This function parses the RSAPrivateKey (PKCS#1)
	 *
	 *  RSAPrivateKey ::= SEQUENCE {
	 *	version		Version,
	 *	modulus		INTEGER, -- n
	 *	publicExponent	INTEGER, -- e
	 *	privateExponent	INTEGER, -- d
	 *	prime1		INTEGER, -- p
	 *	prime2		INTEGER, -- q
	 *	exponent1	INTEGER, -- d mod (p-1)
	 *	exponent2	INTEGER, -- d mod (q-1)
	 *	coefficient	INTEGER, -- (inverse of q) mod p
	 *	otherPrimeInfos	OtherPrimeInfos OPTIONAL
	 *  }
	 */
	r = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r)
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;

	end = p + len;

	if ((r = ttls_asn1_get_int(&p, end, &version)))
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;

	if (version)
		return TTLS_ERR_PK_KEY_INVALID_VERSION;

	/* Import N */
	if ((r = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_INTEGER)))
		goto err;
	if ((r = ttls_rsa_import_raw(rsa, p, len, NULL, 0, NULL, 0, NULL, 0,
				     NULL, 0)))
		goto err;
	p += len;

	/* Import E */
	if ((r = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_INTEGER)))
		goto err;
	if ((r = ttls_rsa_import_raw(rsa, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
				     p, len)))
		goto err;
	p += len;

	/* Import D */
	if ((r = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_INTEGER)))
		goto err;
	if ((r = ttls_rsa_import_raw(rsa, NULL, 0, NULL, 0, NULL, 0, p, len,
				     NULL, 0)))
		goto err;
	p += len;

	/* Import P */
	if ((r = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_INTEGER)))
		goto err;
	if ((r = ttls_rsa_import_raw(rsa, NULL, 0, p, len, NULL, 0, NULL, 0,
				     NULL, 0)))
		goto err;
	p += len;

	/* Import Q */
	if ((r = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_INTEGER)))
		goto err;
	if ((r = ttls_rsa_import_raw(rsa, NULL, 0, NULL, 0, p, len, NULL, 0,
				     NULL, 0)))
		goto err;
	p += len;

	/* Complete the RSA private key */
	if ((r = ttls_rsa_complete(rsa)))
		goto err;

	/* Check optional parameters */
	T = ttls_mpi_alloc_stack_init(((end - p) + CIL - 1 ) / CIL);
	if ((r = ttls_asn1_get_mpi(&p, end, T))
	    || (r = ttls_asn1_get_mpi(&p, end, T))
	    || (r = ttls_asn1_get_mpi(&p, end, T)))
	{
		ttls_mpi_pool_cleanup_ctx((unsigned long)T, false);
		goto err;
	}
	ttls_mpi_pool_cleanup_ctx((unsigned long)T, false);

	if (p != end)
		r = TTLS_ERR_PK_KEY_INVALID_FORMAT
		    + TTLS_ERR_ASN1_LENGTH_MISMATCH;

err:
	if (r) {
		/*
		 * Wrap error code if it's coming from a lower level.
		 * Don't free the RSA context - the caller takes care about this
		 * through a unified ttls_pk_free() call.
		 */
		if (!(r & 0xff80))
			r = TTLS_ERR_PK_KEY_INVALID_FORMAT + r;
		else
			r = TTLS_ERR_PK_KEY_INVALID_FORMAT;
		ttls_rsa_free(rsa);
	}
	return r;
}

static int
pk_parse_key_pkcs1_der(TlsRSACtx *rsa, const unsigned char *key, size_t keylen)
{
	int r;

	kernel_fpu_begin();

	r = __parse_key_pkcs1_der(rsa, key, keylen);

	kernel_fpu_end();

	return r;
}

/**
 * Parse a SEC1 encoded private EC key.
 */
static int
pk_parse_key_sec1_der(TlsEcpKeypair *eck, const unsigned char *key,
		      size_t keylen)
{
	int r, version, pubkey_done;
	size_t len;
	ttls_asn1_buf params;
	unsigned char *p = (unsigned char *) key;
	unsigned char *end = p + keylen;
	unsigned char *end2;

	/*
	 * RFC 5915, or SEC1 Appendix C.4
	 *
	 * ECPrivateKey ::= SEQUENCE {
	 *	  version	INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
	 *	  privateKey	OCTET STRING,
	 *	  parameters[0] ECParameters {{ NamedCurve }} OPTIONAL,
	 *	  publicKey [1]	BIT STRING OPTIONAL
	 *	}
	 */
	r = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r)
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;

	end = p + len;

	if ((r = ttls_asn1_get_int(&p, end, &version)))
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;

	if (version != 1)
		return TTLS_ERR_PK_KEY_INVALID_VERSION;

	if ((r = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_OCTET_STRING)))
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;

	ttls_mpi_read_binary(&eck->d, p, len);

	p += len;

	pubkey_done = 0;
	if (p != end) {
		/* Is 'parameters' present? */
		r = ttls_asn1_get_tag(&p, end, &len,
				      TTLS_ASN1_CONTEXT_SPECIFIC
				      | TTLS_ASN1_CONSTRUCTED);
		if (!r) {
			if ((r = pk_get_ecparams(&p, p + len, &params))
			    || (r = pk_use_ecparams(&params, &eck->grp)))
			{
				ttls_ecp_keypair_free(eck);
				return r;
			}
		}
		else if (r != TTLS_ERR_ASN1_UNEXPECTED_TAG) {
			ttls_ecp_keypair_free(eck);
			return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;
		}

		/*
		 * Is 'publickey' present? If not, or if we can't read it (e.g.
		 * because it is compressed), create it from the private key.
		 */
		r = ttls_asn1_get_tag(&p, end, &len,
				      TTLS_ASN1_CONTEXT_SPECIFIC
				      | TTLS_ASN1_CONSTRUCTED | 1);
		if (!r) {
			end2 = p + len;

			if ((r = ttls_asn1_get_bitstring_null(&p, end2, &len)))
				return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;

			if (p + len != end2)
				return TTLS_ERR_PK_KEY_INVALID_FORMAT
					+ TTLS_ERR_ASN1_LENGTH_MISMATCH;

			if (!(r = pk_get_ecpubkey(&p, end2, eck))) {
				pubkey_done = 1;
			} else {
				/*
				 * The only acceptable failure mode of
				 * pk_get_ecpubkey() above is if the point
				 * format is not recognized.
				 */
				if (r != TTLS_ERR_ECP_FEATURE_UNAVAILABLE)
					return TTLS_ERR_PK_KEY_INVALID_FORMAT;
			}
		}
		else if (r != TTLS_ERR_ASN1_UNEXPECTED_TAG) {
			ttls_ecp_keypair_free(eck);
			return TTLS_ERR_PK_KEY_INVALID_FORMAT + r;
		}
	}

	return 0;
}

/**
 * Parse an unencrypted PKCS#8 encoded private key.
 * This function does not own the key buffer. It is the responsibility of the
 * caller to take care of zeroizing and freeing it after use.
 * The function is responsible for freeing the provided PK context on failure.
 */
static int
pk_parse_key_pkcs8_unencrypted_der(TlsPkCtx *pk,
				   const unsigned char *key, size_t keylen)
{
	int ret, version;
	size_t len;
	ttls_asn1_buf params;
	unsigned char *p = (unsigned char *)key;
	unsigned char *end = p + keylen;
	ttls_pk_type_t pk_alg = TTLS_PK_NONE;
	const TlsPkInfo *pk_info;

	/*
	 * This function parses the PrivateKeyInfo object
	 * (PKCS#8 v1.2 = RFC 5208).
	 *
	 *	PrivateKeyInfo ::= SEQUENCE {
	 *	  version		Version,
	 *	  privateKeyAlgorithm	PrivateKeyAlgorithmIdentifier,
	 *	  privateKey		PrivateKey,
	 *	  attributes		[0]  IMPLICIT Attributes OPTIONAL }
	 *
	 * Version ::= INTEGER
	 * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
	 * PrivateKey ::= OCTET STRING
	 *
	 * The PrivateKey OCTET STRING is a SEC1 ECPrivateKey
	 */
	ret = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (ret)
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
	end = p + len;

	if ((ret = ttls_asn1_get_int(&p, end, &version)))
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + ret;
	if (version)
		return TTLS_ERR_PK_KEY_INVALID_VERSION + ret;

	if ((ret = pk_get_pk_alg(&p, end, &pk_alg, &params)))
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + ret;

	if ((ret = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_OCTET_STRING)))
		return TTLS_ERR_PK_KEY_INVALID_FORMAT + ret;

	if (len < 1)
		return TTLS_ERR_PK_KEY_INVALID_FORMAT
		       + TTLS_ERR_ASN1_OUT_OF_DATA;

	if (!(pk_info = ttls_pk_info_from_type(pk_alg)))
		return TTLS_ERR_PK_UNKNOWN_PK_ALG;

	if ((ret = ttls_pk_setup(pk, pk_info)))
		return ret;

	if (pk_alg == TTLS_PK_RSA) {
		if ((ret = pk_parse_key_pkcs1_der(ttls_pk_rsa(*pk), p, len))) {
			ttls_pk_free(pk);
			return ret;
		}
	}
	else if (pk_alg == TTLS_PK_ECKEY || pk_alg == TTLS_PK_ECKEY_DH) {
		if ((ret = pk_use_ecparams(&params, &ttls_pk_ec(*pk)->grp))
		    || (ret = pk_parse_key_sec1_der(ttls_pk_ec(*pk), p, len)))
		{
			ttls_pk_free(pk);
			return ret;
		}
	}
	else {
		return TTLS_ERR_PK_UNKNOWN_PK_ALG;
	}

	return 0;
}

/**
 * Parse a private key in PEM or DER format.
 * On entry, ctx must be empty, either freshly initialised with ttls_pk_init()
 * or reset with ttls_pk_free(). If you need a specific key type, check the
 * result with ttls_pk_can_do().
 */
int
ttls_pk_parse_key(TlsPkCtx *pk, unsigned char *key, size_t keylen)
{
	int r, dec_key_len;
	const TlsPkInfo *pk_info;
	size_t len;

	if (!keylen)
		return TTLS_ERR_PK_KEY_INVALID_FORMAT;
	/* Avoid calling ttls_pem_read_buffer() on non-null-terminated string */
	if (key[keylen - 1] != '\0')
		goto no_pem;

	r = ttls_pem_read_buffer("-----BEGIN RSA PRIVATE KEY-----",
				 "-----END RSA PRIVATE KEY-----",
				 key, &len);
	if (r > 0) {
		dec_key_len = r;
		pk_info = ttls_pk_info_from_type(TTLS_PK_RSA);
		if ((r = ttls_pk_setup(pk, pk_info))
		    || (r = pk_parse_key_pkcs1_der(ttls_pk_rsa(*pk), key,
						   dec_key_len)))
		{
			ttls_pk_free(pk);
		}
		goto cleanup;
	}
	if (r == TTLS_ERR_PEM_PASSWORD_MISMATCH
	    || r == TTLS_ERR_PEM_PASSWORD_REQUIRED
	    || r != TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
	{
		goto cleanup;
	}

	/* Try to read EC key. */
	r = ttls_pem_read_buffer("-----BEGIN EC PRIVATE KEY-----",
				 "-----END EC PRIVATE KEY-----",
				 key, &len);
	if (r > 0) {
		dec_key_len = r;
		pk_info = ttls_pk_info_from_type(TTLS_PK_ECKEY);
		if ((r = ttls_pk_setup(pk, pk_info))
		    || (r = pk_parse_key_sec1_der(ttls_pk_ec(*pk), key,
						  dec_key_len)))
		{
			ttls_pk_free(pk);
		}
		goto cleanup;
	}
	if (r == TTLS_ERR_PEM_PASSWORD_MISMATCH
	    || r == TTLS_ERR_PEM_PASSWORD_REQUIRED
	    || r != TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
	{
		goto cleanup;
	}

	/* Try to read another key. */
	r = ttls_pem_read_buffer("-----BEGIN PRIVATE KEY-----",
				 "-----END PRIVATE KEY-----",
				 key, &len);
	if (r > 0) {
		if ((r = pk_parse_key_pkcs8_unencrypted_der(pk, key, r)))
			ttls_pk_free(pk);
		goto cleanup;
	}
	if (r != TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
		goto cleanup;

no_pem:
	if (!(r = pk_parse_key_pkcs8_unencrypted_der(pk, key, keylen)))
		goto cleanup;

	ttls_pk_free(pk);

	pk_info = ttls_pk_info_from_type(TTLS_PK_RSA);
	if ((r = ttls_pk_setup(pk, pk_info))
	    || (r = pk_parse_key_pkcs1_der(ttls_pk_rsa(*pk), key, keylen)))
	{
		ttls_pk_free(pk);
	} else {
		goto cleanup;
	}

	pk_info = ttls_pk_info_from_type(TTLS_PK_ECKEY);
	if ((r = ttls_pk_setup(pk, pk_info))
	    || (r = pk_parse_key_sec1_der(ttls_pk_ec(*pk), key, keylen)))
	{
		ttls_pk_free(pk);
	}

cleanup:
	/* Does MPI calculations, so pool context must be freed afterwards. */
	ttls_mpi_pool_cleanup_ctx(0, false);

	return r;
}
EXPORT_SYMBOL(ttls_pk_parse_key);
