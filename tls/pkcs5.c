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

#if !defined(TTLS_SHA1_C)
int ttls_pkcs5_self_test(int verbose)
{
	if (verbose != 0)
		ttls_printf("  PBKDF2 (SHA1): skipped\n\n");

	return 0;
}
#else

#define MAX_TESTS   6

static const size_t plen[MAX_TESTS] =
	{ 8, 8, 8, 24, 9 };

static const unsigned char password[MAX_TESTS][32] =
{
	"password",
	"password",
	"password",
	"passwordPASSWORDpassword",
	"pass\0word",
};

static const size_t slen[MAX_TESTS] =
	{ 4, 4, 4, 36, 5 };

static const unsigned char salt[MAX_TESTS][40] =
{
	"salt",
	"salt",
	"salt",
	"saltSALTsaltSALTsaltSALTsaltSALTsalt",
	"sa\0lt",
};

static const uint32_t it_cnt[MAX_TESTS] =
	{ 1, 2, 4096, 4096, 4096 };

static const uint32_t key_len[MAX_TESTS] =
	{ 20, 20, 20, 25, 16 };

static const unsigned char result_key[MAX_TESTS][32] =
{
	{ 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
	  0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
	  0x2f, 0xe0, 0x37, 0xa6 },
	{ 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
	  0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
	  0xd8, 0xde, 0x89, 0x57 },
	{ 0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
	  0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
	  0x65, 0xa4, 0x29, 0xc1 },
	{ 0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
	  0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
	  0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
	  0x38 },
	{ 0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
	  0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3 },
};

int ttls_pkcs5_self_test(int verbose)
{
	ttls_md_context_t sha1_ctx;
	const ttls_md_info_t *info_sha1;
	int ret, i;
	unsigned char key[64];

	ttls_md_init(&sha1_ctx);

	info_sha1 = ttls_md_info_from_type(TTLS_MD_SHA1);
	if (info_sha1 == NULL)
	{
		ret = 1;
		goto exit;
	}

	if ((ret = ttls_md_setup(&sha1_ctx, info_sha1, 1)) != 0)
	{
		ret = 1;
		goto exit;
	}

	for (i = 0; i < MAX_TESTS; i++)
	{
		if (verbose != 0)
			ttls_printf("  PBKDF2 (SHA1) #%d: ", i);

		ret = ttls_pkcs5_pbkdf2_hmac(&sha1_ctx, password[i], plen[i], salt[i],
								  slen[i], it_cnt[i], key_len[i], key);
		if (ret != 0 ||
			memcmp(result_key[i], key, key_len[i]) != 0)
		{
			if (verbose != 0)
				ttls_printf("failed\n");

			ret = 1;
			goto exit;
		}

		if (verbose != 0)
			ttls_printf("passed\n");
	}

	if (verbose != 0)
		ttls_printf("\n");

exit:
	ttls_md_free(&sha1_ctx);

	return ret;
}
#endif /* TTLS_SHA1_C */

#endif /* TTLS_PKCS5_C */
