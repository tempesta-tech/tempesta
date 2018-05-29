/**
 * \file cipher_wrap.c
 *
 * \brief Generic cipher wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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
#include "config.h"
#include "cipher_internal.h"
#if defined(TTLS_AES_C)
#include "aes.h"
#endif
#if defined(TTLS_ARC4_C)
#include "arc4.h"
#endif
#if defined(TTLS_CAMELLIA_C)
#include "camellia.h"
#endif
#if defined(TTLS_DES_C)
#include "des.h"
#endif
#if defined(TTLS_BLOWFISH_C)
#include "blowfish.h"
#endif
#if defined(TTLS_GCM_C)
#include "gcm.h"
#endif
#if defined(TTLS_CCM_C)
#include "ccm.h"
#endif

#if defined(TTLS_GCM_C)
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
#endif /* TTLS_GCM_C */

#if defined(TTLS_CCM_C)
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
#endif /* TTLS_CCM_C */

#if defined(TTLS_AES_C)

static int aes_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	return ttls_aes_crypt_ecb((ttls_aes_context *) ctx, operation, input, output);
}

#if defined(TTLS_CIPHER_MODE_CBC)
static int aes_crypt_cbc_wrap(void *ctx, ttls_operation_t operation, size_t length,
		unsigned char *iv, const unsigned char *input, unsigned char *output)
{
	return ttls_aes_crypt_cbc((ttls_aes_context *) ctx, operation, length, iv, input,
						  output);
}
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
static int aes_crypt_cfb128_wrap(void *ctx, ttls_operation_t operation,
		size_t length, size_t *iv_off, unsigned char *iv,
		const unsigned char *input, unsigned char *output)
{
	return ttls_aes_crypt_cfb128((ttls_aes_context *) ctx, operation, length, iv_off, iv,
							 input, output);
}
#endif /* TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
static int aes_crypt_ctr_wrap(void *ctx, size_t length, size_t *nc_off,
		unsigned char *nonce_counter, unsigned char *stream_block,
		const unsigned char *input, unsigned char *output)
{
	return ttls_aes_crypt_ctr((ttls_aes_context *) ctx, length, nc_off, nonce_counter,
						  stream_block, input, output);
}
#endif /* TTLS_CIPHER_MODE_CTR */

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
#if defined(TTLS_CIPHER_MODE_CBC)
	aes_crypt_cbc_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	aes_crypt_cfb128_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	aes_crypt_ctr_wrap,
#endif
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

#if defined(TTLS_CIPHER_MODE_CBC)
static const ttls_cipher_info_t aes_128_cbc_info = {
	TTLS_CIPHER_AES_128_CBC,
	TTLS_MODE_CBC,
	128,
	"AES-128-CBC",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_192_cbc_info = {
	TTLS_CIPHER_AES_192_CBC,
	TTLS_MODE_CBC,
	192,
	"AES-192-CBC",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_256_cbc_info = {
	TTLS_CIPHER_AES_256_CBC,
	TTLS_MODE_CBC,
	256,
	"AES-256-CBC",
	16,
	0,
	16,
	&aes_info
};
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
static const ttls_cipher_info_t aes_128_cfb128_info = {
	TTLS_CIPHER_AES_128_CFB128,
	TTLS_MODE_CFB,
	128,
	"AES-128-CFB128",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_192_cfb128_info = {
	TTLS_CIPHER_AES_192_CFB128,
	TTLS_MODE_CFB,
	192,
	"AES-192-CFB128",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_256_cfb128_info = {
	TTLS_CIPHER_AES_256_CFB128,
	TTLS_MODE_CFB,
	256,
	"AES-256-CFB128",
	16,
	0,
	16,
	&aes_info
};
#endif /* TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
static const ttls_cipher_info_t aes_128_ctr_info = {
	TTLS_CIPHER_AES_128_CTR,
	TTLS_MODE_CTR,
	128,
	"AES-128-CTR",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_192_ctr_info = {
	TTLS_CIPHER_AES_192_CTR,
	TTLS_MODE_CTR,
	192,
	"AES-192-CTR",
	16,
	0,
	16,
	&aes_info
};

static const ttls_cipher_info_t aes_256_ctr_info = {
	TTLS_CIPHER_AES_256_CTR,
	TTLS_MODE_CTR,
	256,
	"AES-256-CTR",
	16,
	0,
	16,
	&aes_info
};
#endif /* TTLS_CIPHER_MODE_CTR */

#if defined(TTLS_GCM_C)
static int gcm_aes_setkey_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	return ttls_gcm_setkey((ttls_gcm_context *) ctx, TTLS_CIPHER_ID_AES,
					 key, key_bitlen);
}

static const ttls_cipher_base_t gcm_aes_info = {
	TTLS_CIPHER_ID_AES,
	NULL,
#if defined(TTLS_CIPHER_MODE_CBC)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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
#endif /* TTLS_GCM_C */

#if defined(TTLS_CCM_C)
static int ccm_aes_setkey_wrap(void *ctx, const unsigned char *key,
								unsigned int key_bitlen)
{
	return ttls_ccm_setkey((ttls_ccm_context *) ctx, TTLS_CIPHER_ID_AES,
					 key, key_bitlen);
}

static const ttls_cipher_base_t ccm_aes_info = {
	TTLS_CIPHER_ID_AES,
	NULL,
#if defined(TTLS_CIPHER_MODE_CBC)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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
#endif /* TTLS_CCM_C */

#endif /* TTLS_AES_C */

#if defined(TTLS_CAMELLIA_C)

static int camellia_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	return ttls_camellia_crypt_ecb((ttls_camellia_context *) ctx, operation, input,
							   output);
}

#if defined(TTLS_CIPHER_MODE_CBC)
static int camellia_crypt_cbc_wrap(void *ctx, ttls_operation_t operation,
		size_t length, unsigned char *iv,
		const unsigned char *input, unsigned char *output)
{
	return ttls_camellia_crypt_cbc((ttls_camellia_context *) ctx, operation, length, iv,
							   input, output);
}
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
static int camellia_crypt_cfb128_wrap(void *ctx, ttls_operation_t operation,
		size_t length, size_t *iv_off, unsigned char *iv,
		const unsigned char *input, unsigned char *output)
{
	return ttls_camellia_crypt_cfb128((ttls_camellia_context *) ctx, operation, length,
								  iv_off, iv, input, output);
}
#endif /* TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
static int camellia_crypt_ctr_wrap(void *ctx, size_t length, size_t *nc_off,
		unsigned char *nonce_counter, unsigned char *stream_block,
		const unsigned char *input, unsigned char *output)
{
	return ttls_camellia_crypt_ctr((ttls_camellia_context *) ctx, length, nc_off,
							   nonce_counter, stream_block, input, output);
}
#endif /* TTLS_CIPHER_MODE_CTR */

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
#if defined(TTLS_CIPHER_MODE_CBC)
	camellia_crypt_cbc_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	camellia_crypt_cfb128_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	camellia_crypt_ctr_wrap,
#endif
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

#if defined(TTLS_CIPHER_MODE_CBC)
static const ttls_cipher_info_t camellia_128_cbc_info = {
	TTLS_CIPHER_CAMELLIA_128_CBC,
	TTLS_MODE_CBC,
	128,
	"CAMELLIA-128-CBC",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_192_cbc_info = {
	TTLS_CIPHER_CAMELLIA_192_CBC,
	TTLS_MODE_CBC,
	192,
	"CAMELLIA-192-CBC",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_256_cbc_info = {
	TTLS_CIPHER_CAMELLIA_256_CBC,
	TTLS_MODE_CBC,
	256,
	"CAMELLIA-256-CBC",
	16,
	0,
	16,
	&camellia_info
};
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
static const ttls_cipher_info_t camellia_128_cfb128_info = {
	TTLS_CIPHER_CAMELLIA_128_CFB128,
	TTLS_MODE_CFB,
	128,
	"CAMELLIA-128-CFB128",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_192_cfb128_info = {
	TTLS_CIPHER_CAMELLIA_192_CFB128,
	TTLS_MODE_CFB,
	192,
	"CAMELLIA-192-CFB128",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_256_cfb128_info = {
	TTLS_CIPHER_CAMELLIA_256_CFB128,
	TTLS_MODE_CFB,
	256,
	"CAMELLIA-256-CFB128",
	16,
	0,
	16,
	&camellia_info
};
#endif /* TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
static const ttls_cipher_info_t camellia_128_ctr_info = {
	TTLS_CIPHER_CAMELLIA_128_CTR,
	TTLS_MODE_CTR,
	128,
	"CAMELLIA-128-CTR",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_192_ctr_info = {
	TTLS_CIPHER_CAMELLIA_192_CTR,
	TTLS_MODE_CTR,
	192,
	"CAMELLIA-192-CTR",
	16,
	0,
	16,
	&camellia_info
};

static const ttls_cipher_info_t camellia_256_ctr_info = {
	TTLS_CIPHER_CAMELLIA_256_CTR,
	TTLS_MODE_CTR,
	256,
	"CAMELLIA-256-CTR",
	16,
	0,
	16,
	&camellia_info
};
#endif /* TTLS_CIPHER_MODE_CTR */

#if defined(TTLS_GCM_C)
static int gcm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
									 unsigned int key_bitlen)
{
	return ttls_gcm_setkey((ttls_gcm_context *) ctx, TTLS_CIPHER_ID_CAMELLIA,
					 key, key_bitlen);
}

static const ttls_cipher_base_t gcm_camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	NULL,
#if defined(TTLS_CIPHER_MODE_CBC)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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
#endif /* TTLS_GCM_C */

#if defined(TTLS_CCM_C)
static int ccm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
									 unsigned int key_bitlen)
{
	return ttls_ccm_setkey((ttls_ccm_context *) ctx, TTLS_CIPHER_ID_CAMELLIA,
					 key, key_bitlen);
}

static const ttls_cipher_base_t ccm_camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	NULL,
#if defined(TTLS_CIPHER_MODE_CBC)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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
#endif /* TTLS_CCM_C */

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

#if defined(TTLS_CIPHER_MODE_CBC)
static int des_crypt_cbc_wrap(void *ctx, ttls_operation_t operation, size_t length,
		unsigned char *iv, const unsigned char *input, unsigned char *output)
{
	return ttls_des_crypt_cbc((ttls_des_context *) ctx, operation, length, iv, input,
						  output);
}
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CBC)
static int des3_crypt_cbc_wrap(void *ctx, ttls_operation_t operation, size_t length,
		unsigned char *iv, const unsigned char *input, unsigned char *output)
{
	return ttls_des3_crypt_cbc((ttls_des3_context *) ctx, operation, length, iv, input,
						   output);
}
#endif /* TTLS_CIPHER_MODE_CBC */

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
#if defined(TTLS_CIPHER_MODE_CBC)
	des_crypt_cbc_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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

#if defined(TTLS_CIPHER_MODE_CBC)
static const ttls_cipher_info_t des_cbc_info = {
	TTLS_CIPHER_DES_CBC,
	TTLS_MODE_CBC,
	TTLS_KEY_LENGTH_DES,
	"DES-CBC",
	8,
	0,
	8,
	&des_info
};
#endif /* TTLS_CIPHER_MODE_CBC */

static const ttls_cipher_base_t des_ede_info = {
	TTLS_CIPHER_ID_DES,
	des3_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_CBC)
	des3_crypt_cbc_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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

#if defined(TTLS_CIPHER_MODE_CBC)
static const ttls_cipher_info_t des_ede_cbc_info = {
	TTLS_CIPHER_DES_EDE_CBC,
	TTLS_MODE_CBC,
	TTLS_KEY_LENGTH_DES_EDE,
	"DES-EDE-CBC",
	8,
	0,
	8,
	&des_ede_info
};
#endif /* TTLS_CIPHER_MODE_CBC */

static const ttls_cipher_base_t des_ede3_info = {
	TTLS_CIPHER_ID_3DES,
	des3_crypt_ecb_wrap,
#if defined(TTLS_CIPHER_MODE_CBC)
	des3_crypt_cbc_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
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
#if defined(TTLS_CIPHER_MODE_CBC)
static const ttls_cipher_info_t des_ede3_cbc_info = {
	TTLS_CIPHER_DES_EDE3_CBC,
	TTLS_MODE_CBC,
	TTLS_KEY_LENGTH_DES_EDE3,
	"DES-EDE3-CBC",
	8,
	0,
	8,
	&des_ede3_info
};
#endif /* TTLS_CIPHER_MODE_CBC */
#endif /* TTLS_DES_C */

#if defined(TTLS_BLOWFISH_C)

static int blowfish_crypt_ecb_wrap(void *ctx, ttls_operation_t operation,
		const unsigned char *input, unsigned char *output)
{
	return ttls_blowfish_crypt_ecb((ttls_blowfish_context *) ctx, operation, input,
							   output);
}

#if defined(TTLS_CIPHER_MODE_CBC)
static int blowfish_crypt_cbc_wrap(void *ctx, ttls_operation_t operation,
		size_t length, unsigned char *iv, const unsigned char *input,
		unsigned char *output)
{
	return ttls_blowfish_crypt_cbc((ttls_blowfish_context *) ctx, operation, length, iv,
							   input, output);
}
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
static int blowfish_crypt_cfb64_wrap(void *ctx, ttls_operation_t operation,
		size_t length, size_t *iv_off, unsigned char *iv,
		const unsigned char *input, unsigned char *output)
{
	return ttls_blowfish_crypt_cfb64((ttls_blowfish_context *) ctx, operation, length,
								 iv_off, iv, input, output);
}
#endif /* TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
static int blowfish_crypt_ctr_wrap(void *ctx, size_t length, size_t *nc_off,
		unsigned char *nonce_counter, unsigned char *stream_block,
		const unsigned char *input, unsigned char *output)
{
	return ttls_blowfish_crypt_ctr((ttls_blowfish_context *) ctx, length, nc_off,
							   nonce_counter, stream_block, input, output);
}
#endif /* TTLS_CIPHER_MODE_CTR */

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
#if defined(TTLS_CIPHER_MODE_CBC)
	blowfish_crypt_cbc_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	blowfish_crypt_cfb64_wrap,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	blowfish_crypt_ctr_wrap,
#endif
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

#if defined(TTLS_CIPHER_MODE_CBC)
static const ttls_cipher_info_t blowfish_cbc_info = {
	TTLS_CIPHER_BLOWFISH_CBC,
	TTLS_MODE_CBC,
	128,
	"BLOWFISH-CBC",
	8,
	TTLS_CIPHER_VARIABLE_KEY_LEN,
	8,
	&blowfish_info
};
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
static const ttls_cipher_info_t blowfish_cfb64_info = {
	TTLS_CIPHER_BLOWFISH_CFB64,
	TTLS_MODE_CFB,
	128,
	"BLOWFISH-CFB64",
	8,
	TTLS_CIPHER_VARIABLE_KEY_LEN,
	8,
	&blowfish_info
};
#endif /* TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
static const ttls_cipher_info_t blowfish_ctr_info = {
	TTLS_CIPHER_BLOWFISH_CTR,
	TTLS_MODE_CTR,
	128,
	"BLOWFISH-CTR",
	8,
	TTLS_CIPHER_VARIABLE_KEY_LEN,
	8,
	&blowfish_info
};
#endif /* TTLS_CIPHER_MODE_CTR */
#endif /* TTLS_BLOWFISH_C */

#if defined(TTLS_ARC4_C)
static int arc4_crypt_stream_wrap(void *ctx, size_t length,
								   const unsigned char *input,
								   unsigned char *output)
{
	return(ttls_arc4_crypt((ttls_arc4_context *) ctx, length, input, output));
}

static int arc4_setkey_wrap(void *ctx, const unsigned char *key,
							 unsigned int key_bitlen)
{
	/* we get key_bitlen in bits, arc4 expects it in bytes */
	if (key_bitlen % 8 != 0)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	ttls_arc4_setup((ttls_arc4_context *) ctx, key, key_bitlen / 8);
	return 0;
}

static void * arc4_ctx_alloc(void)
{
	ttls_arc4_context *ctx;
	ctx = ttls_calloc(1, sizeof(ttls_arc4_context));

	if (ctx == NULL)
		return(NULL);

	ttls_arc4_init(ctx);

	return(ctx);
}

static void arc4_ctx_free(void *ctx)
{
	ttls_arc4_free((ttls_arc4_context *) ctx);
	ttls_free(ctx);
}

static const ttls_cipher_base_t arc4_base_info = {
	TTLS_CIPHER_ID_ARC4,
	NULL,
#if defined(TTLS_CIPHER_MODE_CBC)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	NULL,
#endif
#if defined(TTLS_CIPHER_MODE_STREAM)
	arc4_crypt_stream_wrap,
#endif
	arc4_setkey_wrap,
	arc4_setkey_wrap,
	arc4_ctx_alloc,
	arc4_ctx_free
};

static const ttls_cipher_info_t arc4_128_info = {
	TTLS_CIPHER_ARC4_128,
	TTLS_MODE_STREAM,
	128,
	"ARC4-128",
	0,
	0,
	1,
	&arc4_base_info
};
#endif /* TTLS_ARC4_C */

const ttls_cipher_definition_t ttls_cipher_definitions[] =
{
#if defined(TTLS_AES_C)
	{ TTLS_CIPHER_AES_128_ECB,		  &aes_128_ecb_info },
	{ TTLS_CIPHER_AES_192_ECB,		  &aes_192_ecb_info },
	{ TTLS_CIPHER_AES_256_ECB,		  &aes_256_ecb_info },
#if defined(TTLS_CIPHER_MODE_CBC)
	{ TTLS_CIPHER_AES_128_CBC,		  &aes_128_cbc_info },
	{ TTLS_CIPHER_AES_192_CBC,		  &aes_192_cbc_info },
	{ TTLS_CIPHER_AES_256_CBC,		  &aes_256_cbc_info },
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	{ TTLS_CIPHER_AES_128_CFB128,	   &aes_128_cfb128_info },
	{ TTLS_CIPHER_AES_192_CFB128,	   &aes_192_cfb128_info },
	{ TTLS_CIPHER_AES_256_CFB128,	   &aes_256_cfb128_info },
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	{ TTLS_CIPHER_AES_128_CTR,		  &aes_128_ctr_info },
	{ TTLS_CIPHER_AES_192_CTR,		  &aes_192_ctr_info },
	{ TTLS_CIPHER_AES_256_CTR,		  &aes_256_ctr_info },
#endif
#if defined(TTLS_GCM_C)
	{ TTLS_CIPHER_AES_128_GCM,		  &aes_128_gcm_info },
	{ TTLS_CIPHER_AES_192_GCM,		  &aes_192_gcm_info },
	{ TTLS_CIPHER_AES_256_GCM,		  &aes_256_gcm_info },
#endif
#if defined(TTLS_CCM_C)
	{ TTLS_CIPHER_AES_128_CCM,		  &aes_128_ccm_info },
	{ TTLS_CIPHER_AES_192_CCM,		  &aes_192_ccm_info },
	{ TTLS_CIPHER_AES_256_CCM,		  &aes_256_ccm_info },
#endif
#endif /* TTLS_AES_C */

#if defined(TTLS_ARC4_C)
	{ TTLS_CIPHER_ARC4_128,			 &arc4_128_info },
#endif

#if defined(TTLS_BLOWFISH_C)
	{ TTLS_CIPHER_BLOWFISH_ECB,		 &blowfish_ecb_info },
#if defined(TTLS_CIPHER_MODE_CBC)
	{ TTLS_CIPHER_BLOWFISH_CBC,		 &blowfish_cbc_info },
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	{ TTLS_CIPHER_BLOWFISH_CFB64,	   &blowfish_cfb64_info },
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	{ TTLS_CIPHER_BLOWFISH_CTR,		 &blowfish_ctr_info },
#endif
#endif /* TTLS_BLOWFISH_C */

#if defined(TTLS_CAMELLIA_C)
	{ TTLS_CIPHER_CAMELLIA_128_ECB,	 &camellia_128_ecb_info },
	{ TTLS_CIPHER_CAMELLIA_192_ECB,	 &camellia_192_ecb_info },
	{ TTLS_CIPHER_CAMELLIA_256_ECB,	 &camellia_256_ecb_info },
#if defined(TTLS_CIPHER_MODE_CBC)
	{ TTLS_CIPHER_CAMELLIA_128_CBC,	 &camellia_128_cbc_info },
	{ TTLS_CIPHER_CAMELLIA_192_CBC,	 &camellia_192_cbc_info },
	{ TTLS_CIPHER_CAMELLIA_256_CBC,	 &camellia_256_cbc_info },
#endif
#if defined(TTLS_CIPHER_MODE_CFB)
	{ TTLS_CIPHER_CAMELLIA_128_CFB128,  &camellia_128_cfb128_info },
	{ TTLS_CIPHER_CAMELLIA_192_CFB128,  &camellia_192_cfb128_info },
	{ TTLS_CIPHER_CAMELLIA_256_CFB128,  &camellia_256_cfb128_info },
#endif
#if defined(TTLS_CIPHER_MODE_CTR)
	{ TTLS_CIPHER_CAMELLIA_128_CTR,	 &camellia_128_ctr_info },
	{ TTLS_CIPHER_CAMELLIA_192_CTR,	 &camellia_192_ctr_info },
	{ TTLS_CIPHER_CAMELLIA_256_CTR,	 &camellia_256_ctr_info },
#endif
#if defined(TTLS_GCM_C)
	{ TTLS_CIPHER_CAMELLIA_128_GCM,	 &camellia_128_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_192_GCM,	 &camellia_192_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_256_GCM,	 &camellia_256_gcm_info },
#endif
#if defined(TTLS_CCM_C)
	{ TTLS_CIPHER_CAMELLIA_128_CCM,	 &camellia_128_ccm_info },
	{ TTLS_CIPHER_CAMELLIA_192_CCM,	 &camellia_192_ccm_info },
	{ TTLS_CIPHER_CAMELLIA_256_CCM,	 &camellia_256_ccm_info },
#endif
#endif /* TTLS_CAMELLIA_C */

#if defined(TTLS_DES_C)
	{ TTLS_CIPHER_DES_ECB,			  &des_ecb_info },
	{ TTLS_CIPHER_DES_EDE_ECB,		  &des_ede_ecb_info },
	{ TTLS_CIPHER_DES_EDE3_ECB,		 &des_ede3_ecb_info },
#if defined(TTLS_CIPHER_MODE_CBC)
	{ TTLS_CIPHER_DES_CBC,			  &des_cbc_info },
	{ TTLS_CIPHER_DES_EDE_CBC,		  &des_ede_cbc_info },
	{ TTLS_CIPHER_DES_EDE3_CBC,		 &des_ede3_cbc_info },
#endif
#endif /* TTLS_DES_C */

	{ TTLS_CIPHER_NONE, NULL }
};

#define NUM_CIPHERS sizeof ttls_cipher_definitions / sizeof ttls_cipher_definitions[0]
int ttls_cipher_supported[NUM_CIPHERS];
