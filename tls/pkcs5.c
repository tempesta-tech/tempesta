/**
 * \file pkcs5.c
 *
 * \brief PKCS#5 functions
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
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
 * PKCS#5 includes PBKDF2 and more
 *
 * http://tools.ietf.org/html/rfc2898 (Specification)
 * http://tools.ietf.org/html/rfc6070 (Test vectors)
 */
#include "config.h"

#if defined(TTLS_PKCS5_C)

#include "pkcs5.h"
#include "asn1.h"
#include "cipher.h"
#include "oid.h"

static int pkcs5_parse_pbkdf2_params(const ttls_asn1_buf *params,
			  ttls_asn1_buf *salt, int *iterations,
			  int *keylen, ttls_md_type_t *md_type)
{
	int ret;
	ttls_asn1_buf prf_alg_oid;
	unsigned char *p = params->p;
	const unsigned char *end = params->p + params->len;

	if (params->tag != (TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE))
		return(TTLS_ERR_PKCS5_INVALID_FORMAT +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);
	/*
	 *  PBKDF2-params ::= SEQUENCE {
	 *	salt			  OCTET STRING,
	 *	iterationCount	INTEGER,
	 *	keyLength		 INTEGER OPTIONAL
	 *	prf			   AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
	 *  }
	 *
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &salt->len, TTLS_ASN1_OCTET_STRING)) != 0)
		return(TTLS_ERR_PKCS5_INVALID_FORMAT + ret);

	salt->p = p;
	p += salt->len;

	if ((ret = ttls_asn1_get_int(&p, end, iterations)) != 0)
		return(TTLS_ERR_PKCS5_INVALID_FORMAT + ret);

	if (p == end)
		return 0;

	if ((ret = ttls_asn1_get_int(&p, end, keylen)) != 0)
	{
		if (ret != TTLS_ERR_ASN1_UNEXPECTED_TAG)
			return(TTLS_ERR_PKCS5_INVALID_FORMAT + ret);
	}

	if (p == end)
		return 0;

	if ((ret = ttls_asn1_get_alg_null(&p, end, &prf_alg_oid)) != 0)
		return(TTLS_ERR_PKCS5_INVALID_FORMAT + ret);

	if (ttls_oid_get_md_hmac(&prf_alg_oid, md_type) != 0)
		return(TTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

	if (p != end)
		return(TTLS_ERR_PKCS5_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

int ttls_pkcs5_pbes2(const ttls_asn1_buf *pbe_params, int mode,
				 const unsigned char *pwd,  size_t pwdlen,
				 const unsigned char *data, size_t datalen,
				 unsigned char *output)
{
	int ret, iterations = 0, keylen = 0;
	unsigned char *p, *end;
	ttls_asn1_buf kdf_alg_oid, enc_scheme_oid, kdf_alg_params, enc_scheme_params;
	ttls_asn1_buf salt;
	ttls_md_type_t md_type = TTLS_MD_SHA1;
	unsigned char key[32], iv[32];
	size_t olen = 0;
	const ttls_md_info_t *md_info;
	const ttls_cipher_info_t *cipher_info;
	ttls_md_context_t md_ctx;
	ttls_cipher_type_t cipher_alg;
	ttls_cipher_context_t cipher_ctx;

	p = pbe_params->p;
	end = p + pbe_params->len;

	/*
	 *  PBES2-params ::= SEQUENCE {
	 *	keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
	 *	encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
	 *  }
	 */
	if (pbe_params->tag != (TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE))
		return(TTLS_ERR_PKCS5_INVALID_FORMAT +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);

	if ((ret = ttls_asn1_get_alg(&p, end, &kdf_alg_oid, &kdf_alg_params)) != 0)
		return(TTLS_ERR_PKCS5_INVALID_FORMAT + ret);

	// Only PBKDF2 supported at the moment
	//
	if (TTLS_OID_CMP(TTLS_OID_PKCS5_PBKDF2, &kdf_alg_oid) != 0)
		return(TTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

	if ((ret = pkcs5_parse_pbkdf2_params(&kdf_alg_params,
				   &salt, &iterations, &keylen,
				   &md_type)) != 0)
	{
		return ret;
	}

	md_info = ttls_md_info_from_type(md_type);
	if (md_info == NULL)
		return(TTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

	if ((ret = ttls_asn1_get_alg(&p, end, &enc_scheme_oid,
				  &enc_scheme_params)) != 0)
	{
		return(TTLS_ERR_PKCS5_INVALID_FORMAT + ret);
	}

	if (ttls_oid_get_cipher_alg(&enc_scheme_oid, &cipher_alg) != 0)
		return(TTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

	cipher_info = ttls_cipher_info_from_type(cipher_alg);
	if (cipher_info == NULL)
		return(TTLS_ERR_PKCS5_FEATURE_UNAVAILABLE);

	/*
	 * The value of keylen from pkcs5_parse_pbkdf2_params() is ignored
	 * since it is optional and we don't know if it was set or not
	 */
	keylen = cipher_info->key_bitlen / 8;

	if (enc_scheme_params.tag != TTLS_ASN1_OCTET_STRING ||
		enc_scheme_params.len != cipher_info->iv_size)
	{
		return(TTLS_ERR_PKCS5_INVALID_FORMAT);
	}

	ttls_md_init(&md_ctx);
	ttls_cipher_init(&cipher_ctx);

	memcpy(iv, enc_scheme_params.p, enc_scheme_params.len);

	if ((ret = ttls_md_setup(&md_ctx, md_info, 1)) != 0)
		goto exit;

	if ((ret = ttls_pkcs5_pbkdf2_hmac(&md_ctx, pwd, pwdlen, salt.p, salt.len,
		   iterations, keylen, key)) != 0)
	{
		goto exit;
	}

	if ((ret = ttls_cipher_setup(&cipher_ctx, cipher_info)) != 0)
		goto exit;

	if ((ret = ttls_cipher_setkey(&cipher_ctx, key, 8 * keylen, (ttls_operation_t) mode)) != 0)
		goto exit;

	if ((ret = ttls_cipher_crypt(&cipher_ctx, iv, enc_scheme_params.len,
				  data, datalen, output, &olen)) != 0)
		ret = TTLS_ERR_PKCS5_PASSWORD_MISMATCH;

exit:
	ttls_md_free(&md_ctx);
	ttls_cipher_free(&cipher_ctx);

	return ret;
}

int ttls_pkcs5_pbkdf2_hmac(ttls_md_context_t *ctx, const unsigned char *password,
		   size_t plen, const unsigned char *salt, size_t slen,
		   unsigned int iteration_count,
		   uint32_t key_length, unsigned char *output)
{
	int ret, j;
	unsigned int i;
	unsigned char md1[TTLS_MD_MAX_SIZE];
	unsigned char work[TTLS_MD_MAX_SIZE];
	unsigned char md_size = ttls_md_get_size(ctx->md_info);
	size_t use_len;
	unsigned char *out_p = output;
	unsigned char counter[4];

	memset(counter, 0, 4);
	counter[3] = 1;

	if (iteration_count > 0xFFFFFFFF)
		return(TTLS_ERR_PKCS5_BAD_INPUT_DATA);

	while (key_length)
	{
		// U1 ends up in work
		//
		if ((ret = ttls_md_hmac_starts(ctx, password, plen)) != 0)
			return ret;

		if ((ret = ttls_md_hmac_update(ctx, salt, slen)) != 0)
			return ret;

		if ((ret = ttls_md_hmac_update(ctx, counter, 4)) != 0)
			return ret;

		if ((ret = ttls_md_hmac_finish(ctx, work)) != 0)
			return ret;

		memcpy(md1, work, md_size);

		for (i = 1; i < iteration_count; i++)
		{
			// U2 ends up in md1
			//
			if ((ret = ttls_md_hmac_starts(ctx, password, plen)) != 0)
				return ret;

			if ((ret = ttls_md_hmac_update(ctx, md1, md_size)) != 0)
				return ret;

			if ((ret = ttls_md_hmac_finish(ctx, md1)) != 0)
				return ret;

			// U1 xor U2
			//
			for (j = 0; j < md_size; j++)
				work[j] ^= md1[j];
		}

		use_len = (key_length < md_size) ? key_length : md_size;
		memcpy(out_p, work, use_len);

		key_length -= (uint32_t) use_len;
		out_p += use_len;

		for (i = 4; i > 0; i--)
			if (++counter[i - 1] != 0)
				break;
	}

	return 0;
}

int ttls_pkcs5_self_test(int verbose)
{
	if (verbose != 0)
		ttls_printf("  PBKDF2 (SHA1): skipped\n\n");

	return 0;
}
#endif /* TTLS_PKCS5_C */
