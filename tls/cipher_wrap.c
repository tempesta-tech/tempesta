/**
 *		Tempesta TLS
 *
 * Generic cipher wrapper for mbed TLS
 *
 * Author Adriaan de Jong <dejong@fox-it.com>
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#include "config.h"
#include "cipher_internal.h"
#include "aes.h"
#if defined(TTLS_CAMELLIA_C)
#include "camellia.h"
#endif
#if defined(TTLS_DES_C)
#include "des.h"
#endif
#if defined(TTLS_BLOWFISH_C)
#include "blowfish.h"
#endif
#include "gcm.h"
#include "ccm.h"

/* shared by all GCM ciphers */
static void *gcm_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_gcm_context));

	if (ctx != NULL)
		ttls_gcm_init((ttls_gcm_context *) ctx);

	return(ctx);
}

static void gcm_ctx_free(void *ctx)
{
	ttls_gcm_free(ctx);
	ttls_free(ctx);
}

/* shared by all CCM ciphers */
static void *ccm_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_ccm_context));

	if (ctx != NULL)
		ttls_ccm_init((ttls_ccm_context *) ctx);

	return(ctx);
}

static void ccm_ctx_free(void *ctx)
{
	ttls_ccm_free(ctx);
	ttls_free(ctx);
}

static int aes_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	return ttls_aes_crypt_ecb((ttls_aes_context *) ctx, operation, input, output);
}

static int aes_setkey_dec_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	return ttls_aes_setkey_dec((ttls_aes_context *) ctx, key, key_bitlen);
}

static int aes_setkey_enc_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	return ttls_aes_setkey_enc((ttls_aes_context *) ctx, key, key_bitlen);
}

static void * aes_ctx_alloc(void)
{
	ttls_aes_context *aes = ttls_calloc(1, sizeof(ttls_aes_context));

	if (aes == NULL)
		return(NULL);

	ttls_aes_init(aes);

	return(aes);
}

static void aes_ctx_free(void *ctx)
{
	ttls_aes_free((ttls_aes_context *) ctx);
	ttls_free(ctx);
}

static const ttls_cipher_base_t aes_info = {
	TTLS_CIPHER_ID_AES,
	aes_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	aes_setkey_enc_wrap,
	aes_setkey_dec_wrap,
	aes_ctx_alloc,
	aes_ctx_free
};

static const ttls_cipher_info_t aes_128_ecb_info = {
	TTLS_CIPHER_AES_128_ECB,
	TTLS_MODE_ECB,
	128,
	"AES-128-ECB",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_192_ecb_info = {
	TTLS_CIPHER_AES_192_ECB,
	TTLS_MODE_ECB,
	192,
	"AES-192-ECB",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_256_ecb_info = {
	TTLS_CIPHER_AES_256_ECB,
	TTLS_MODE_ECB,
	256,
	"AES-256-ECB",
	16,
	0,
	16,
	&aes_info
};

static int gcm_aes_setkey_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	return ttls_gcm_setkey((ttls_gcm_context *) ctx, TTLS_CIPHER_ID_AES,
					 key, key_bitlen);
}

static const ttls_cipher_base_t gcm_aes_info = {
	TTLS_CIPHER_ID_AES,
	NULL,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	gcm_aes_setkey_wrap,
	gcm_aes_setkey_wrap,
	gcm_ctx_alloc,
	gcm_ctx_free,
};

static const ttls_cipher_info_t aes_128_gcm_info = {
	TTLS_CIPHER_AES_128_GCM,
	TTLS_MODE_GCM,
	128,
	"AES-128-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_aes_info
};

static const ttls_cipher_info_t aes_192_gcm_info = {
	TTLS_CIPHER_AES_192_GCM,
	TTLS_MODE_GCM,
	192,
	"AES-192-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_aes_info
};

static const ttls_cipher_info_t aes_256_gcm_info = {
	TTLS_CIPHER_AES_256_GCM,
	TTLS_MODE_GCM,
	256,
	"AES-256-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_aes_info
};

static int ccm_aes_setkey_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	return ttls_ccm_setkey((ttls_ccm_context *) ctx, TTLS_CIPHER_ID_AES,
					 key, key_bitlen);
}

static const ttls_cipher_base_t ccm_aes_info = {
	TTLS_CIPHER_ID_AES,
	NULL,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	ccm_aes_setkey_wrap,
	ccm_aes_setkey_wrap,
	ccm_ctx_alloc,
	ccm_ctx_free,
};

static const ttls_cipher_info_t aes_128_ccm_info = {
	TTLS_CIPHER_AES_128_CCM,
	TTLS_MODE_CCM,
	128,
	"AES-128-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_aes_info
};

static const ttls_cipher_info_t aes_192_ccm_info = {
	TTLS_CIPHER_AES_192_CCM,
	TTLS_MODE_CCM,
	192,
	"AES-192-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_aes_info
};

static const ttls_cipher_info_t aes_256_ccm_info = {
	TTLS_CIPHER_AES_256_CCM,
	TTLS_MODE_CCM,
	256,
	"AES-256-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_aes_info
};

#if defined(TTLS_CAMELLIA_C)

static int camellia_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	return ttls_camellia_crypt_ecb((ttls_camellia_context *) ctx, operation, input,
							   output);
}

static int camellia_setkey_dec_wrap(void *ctx, const unsigned char *key,
									 unsigned int key_bitlen)
{
	return ttls_camellia_setkey_dec((ttls_camellia_context *) ctx, key, key_bitlen);
}

static int camellia_setkey_enc_wrap(void *ctx, const unsigned char *key,
									 unsigned int key_bitlen)
{
	return ttls_camellia_setkey_enc((ttls_camellia_context *) ctx, key, key_bitlen);
}

static void * camellia_ctx_alloc(void)
{
	ttls_camellia_context *ctx;
	ctx = ttls_calloc(1, sizeof(ttls_camellia_context));

	if (ctx == NULL)
		return(NULL);

	ttls_camellia_init(ctx);

	return(ctx);
}

static void camellia_ctx_free(void *ctx)
{
	ttls_camellia_free((ttls_camellia_context *) ctx);
	ttls_free(ctx);
}

static const ttls_cipher_base_t camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	camellia_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	camellia_setkey_enc_wrap,
	camellia_setkey_dec_wrap,
	camellia_ctx_alloc,
	camellia_ctx_free
};

static const ttls_cipher_info_t camellia_128_ecb_info = {
	TTLS_CIPHER_CAMELLIA_128_ECB,
	TTLS_MODE_ECB,
	128,
	"CAMELLIA-128-ECB",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_192_ecb_info = {
	TTLS_CIPHER_CAMELLIA_192_ECB,
	TTLS_MODE_ECB,
	192,
	"CAMELLIA-192-ECB",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_256_ecb_info = {
	TTLS_CIPHER_CAMELLIA_256_ECB,
	TTLS_MODE_ECB,
	256,
	"CAMELLIA-256-ECB",
	16,
	0,
	16,
	&camellia_info
};

static int gcm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
									 unsigned int key_bitlen)
{
	return ttls_gcm_setkey((ttls_gcm_context *) ctx, TTLS_CIPHER_ID_CAMELLIA,
					 key, key_bitlen);
}

static const ttls_cipher_base_t gcm_camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	NULL,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	gcm_camellia_setkey_wrap,
	gcm_camellia_setkey_wrap,
	gcm_ctx_alloc,
	gcm_ctx_free,
};

static const ttls_cipher_info_t camellia_128_gcm_info = {
	TTLS_CIPHER_CAMELLIA_128_GCM,
	TTLS_MODE_GCM,
	128,
	"CAMELLIA-128-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_camellia_info
};

static const ttls_cipher_info_t camellia_192_gcm_info = {
	TTLS_CIPHER_CAMELLIA_192_GCM,
	TTLS_MODE_GCM,
	192,
	"CAMELLIA-192-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_camellia_info
};

static const ttls_cipher_info_t camellia_256_gcm_info = {
	TTLS_CIPHER_CAMELLIA_256_GCM,
	TTLS_MODE_GCM,
	256,
	"CAMELLIA-256-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_camellia_info
};

static int ccm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
									 unsigned int key_bitlen)
{
	return ttls_ccm_setkey((ttls_ccm_context *) ctx, TTLS_CIPHER_ID_CAMELLIA,
					 key, key_bitlen);
}

static const ttls_cipher_base_t ccm_camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	NULL,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	ccm_camellia_setkey_wrap,
	ccm_camellia_setkey_wrap,
	ccm_ctx_alloc,
	ccm_ctx_free,
};

static const ttls_cipher_info_t camellia_128_ccm_info = {
	TTLS_CIPHER_CAMELLIA_128_CCM,
	TTLS_MODE_CCM,
	128,
	"CAMELLIA-128-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_camellia_info
};

static const ttls_cipher_info_t camellia_192_ccm_info = {
	TTLS_CIPHER_CAMELLIA_192_CCM,
	TTLS_MODE_CCM,
	192,
	"CAMELLIA-192-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_camellia_info
};

static const ttls_cipher_info_t camellia_256_ccm_info = {
	TTLS_CIPHER_CAMELLIA_256_CCM,
	TTLS_MODE_CCM,
	256,
	"CAMELLIA-256-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_camellia_info
};
#endif /* TTLS_CAMELLIA_C */

#if defined(TTLS_DES_C)

static int des_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	((void) operation);
	return ttls_des_crypt_ecb((ttls_des_context *) ctx, input, output);
}

static int des3_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	((void) operation);
	return ttls_des3_crypt_ecb((ttls_des3_context *) ctx, input, output);
}

static int des_setkey_dec_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	((void) key_bitlen);

	return ttls_des_setkey_dec((ttls_des_context *) ctx, key);
}

static int des_setkey_enc_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	((void) key_bitlen);

	return ttls_des_setkey_enc((ttls_des_context *) ctx, key);
}

static int des3_set2key_dec_wrap(void *ctx, const unsigned char *key,
								  unsigned int key_bitlen)
{
	((void) key_bitlen);

	return ttls_des3_set2key_dec((ttls_des3_context *) ctx, key);
}

static int des3_set2key_enc_wrap(void *ctx, const unsigned char *key,
								  unsigned int key_bitlen)
{
	((void) key_bitlen);

	return ttls_des3_set2key_enc((ttls_des3_context *) ctx, key);
}

static int des3_set3key_dec_wrap(void *ctx, const unsigned char *key,
								  unsigned int key_bitlen)
{
	((void) key_bitlen);

	return ttls_des3_set3key_dec((ttls_des3_context *) ctx, key);
}

static int des3_set3key_enc_wrap(void *ctx, const unsigned char *key,
								  unsigned int key_bitlen)
{
	((void) key_bitlen);

	return ttls_des3_set3key_enc((ttls_des3_context *) ctx, key);
}

static void * des_ctx_alloc(void)
{
	ttls_des_context *des = ttls_calloc(1, sizeof(ttls_des_context));

	if (des == NULL)
		return(NULL);

	ttls_des_init(des);

	return(des);
}

static void des_ctx_free(void *ctx)
{
	ttls_des_free((ttls_des_context *) ctx);
	ttls_free(ctx);
}

static void * des3_ctx_alloc(void)
{
	ttls_des3_context *des3;
	des3 = ttls_calloc(1, sizeof(ttls_des3_context));

	if (des3 == NULL)
		return(NULL);

	ttls_des3_init(des3);

	return(des3);
}

static void des3_ctx_free(void *ctx)
{
	ttls_des3_free((ttls_des3_context *) ctx);
	ttls_free(ctx);
}

static const ttls_cipher_base_t des_info = {
	TTLS_CIPHER_ID_DES,
	des_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	des_setkey_enc_wrap,
	des_setkey_dec_wrap,
	des_ctx_alloc,
	des_ctx_free
};

static const ttls_cipher_info_t des_ecb_info = {
	TTLS_CIPHER_DES_ECB,
	TTLS_MODE_ECB,
	TTLS_KEY_LENGTH_DES,
	"DES-ECB",
	8,
	0,
	8,
	&des_info
};

static const ttls_cipher_base_t des_ede_info = {
	TTLS_CIPHER_ID_DES,
	des3_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	des3_set2key_enc_wrap,
	des3_set2key_dec_wrap,
	des3_ctx_alloc,
	des3_ctx_free
};

static const ttls_cipher_info_t des_ede_ecb_info = {
	TTLS_CIPHER_DES_EDE_ECB,
	TTLS_MODE_ECB,
	TTLS_KEY_LENGTH_DES_EDE,
	"DES-EDE-ECB",
	8,
	0,
	8,
	&des_ede_info
};

static const ttls_cipher_base_t des_ede3_info = {
	TTLS_CIPHER_ID_3DES,
	des3_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	des3_set3key_enc_wrap,
	des3_set3key_dec_wrap,
	des3_ctx_alloc,
	des3_ctx_free
};

static const ttls_cipher_info_t des_ede3_ecb_info = {
	TTLS_CIPHER_DES_EDE3_ECB,
	TTLS_MODE_ECB,
	TTLS_KEY_LENGTH_DES_EDE3,
	"DES-EDE3-ECB",
	8,
	0,
	8,
	&des_ede3_info
};
#endif /* TTLS_DES_C */

#if defined(TTLS_BLOWFISH_C)

static int blowfish_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	return ttls_blowfish_crypt_ecb((ttls_blowfish_context *) ctx, operation, input,
							   output);
}

static int blowfish_setkey_wrap(void *ctx, const unsigned char *key,
								 unsigned int key_bitlen)
{
	return ttls_blowfish_setkey((ttls_blowfish_context *) ctx, key, key_bitlen);
}

static void * blowfish_ctx_alloc(void)
{
	ttls_blowfish_context *ctx;
	ctx = ttls_calloc(1, sizeof(ttls_blowfish_context));

	if (ctx == NULL)
		return(NULL);

	ttls_blowfish_init(ctx);

	return(ctx);
}

static void blowfish_ctx_free(void *ctx)
{
	ttls_blowfish_free((ttls_blowfish_context *) ctx);
	ttls_free(ctx);
}

static const ttls_cipher_base_t blowfish_info = {
	TTLS_CIPHER_ID_BLOWFISH,
	blowfish_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_STREAM)
	NULL,
#endif
	blowfish_setkey_wrap,
	blowfish_setkey_wrap,
	blowfish_ctx_alloc,
	blowfish_ctx_free
};

static const ttls_cipher_info_t blowfish_ecb_info = {
	TTLS_CIPHER_BLOWFISH_ECB,
	TTLS_MODE_ECB,
	128,
	"BLOWFISH-ECB",
	8,
	TTLS_CIPHER_VARIABLE_KEY_LEN,
	8,
	&blowfish_info
};
#endif /* TTLS_BLOWFISH_C */

const ttls_cipher_definition_t ttls_cipher_definitions[] =
{
	{ TTLS_CIPHER_AES_128_ECB,		  &aes_128_ecb_info },
	{ TTLS_CIPHER_AES_192_ECB,		  &aes_192_ecb_info },
	{ TTLS_CIPHER_AES_256_ECB,		  &aes_256_ecb_info },
	{ TTLS_CIPHER_AES_128_GCM,		  &aes_128_gcm_info },
	{ TTLS_CIPHER_AES_192_GCM,		  &aes_192_gcm_info },
	{ TTLS_CIPHER_AES_256_GCM,		  &aes_256_gcm_info },
	{ TTLS_CIPHER_AES_128_CCM,		  &aes_128_ccm_info },
	{ TTLS_CIPHER_AES_192_CCM,		  &aes_192_ccm_info },
	{ TTLS_CIPHER_AES_256_CCM,		  &aes_256_ccm_info },

#if defined(TTLS_BLOWFISH_C)
	{ TTLS_CIPHER_BLOWFISH_ECB,		 &blowfish_ecb_info },
#endif /* TTLS_BLOWFISH_C */

#if defined(TTLS_CAMELLIA_C)
	{ TTLS_CIPHER_CAMELLIA_128_ECB,	 &camellia_128_ecb_info },
	{ TTLS_CIPHER_CAMELLIA_192_ECB,	 &camellia_192_ecb_info },
	{ TTLS_CIPHER_CAMELLIA_256_ECB,	 &camellia_256_ecb_info },
	{ TTLS_CIPHER_CAMELLIA_128_GCM,	 &camellia_128_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_192_GCM,	 &camellia_192_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_256_GCM,	 &camellia_256_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_128_CCM,	 &camellia_128_ccm_info },
	{ TTLS_CIPHER_CAMELLIA_192_CCM,	 &camellia_192_ccm_info },
	{ TTLS_CIPHER_CAMELLIA_256_CCM,	 &camellia_256_ccm_info },
#endif /* TTLS_CAMELLIA_C */

#if defined(TTLS_DES_C)
	{ TTLS_CIPHER_DES_ECB,			  &des_ecb_info },
	{ TTLS_CIPHER_DES_EDE_ECB,		  &des_ede_ecb_info },
	{ TTLS_CIPHER_DES_EDE3_ECB,		 &des_ede3_ecb_info },
#endif /* TTLS_DES_C */

	{ TTLS_CIPHER_NONE, NULL }
};

#define NUM_CIPHERS sizeof ttls_cipher_definitions / sizeof ttls_cipher_definitions[0]
int ttls_cipher_supported[NUM_CIPHERS];
