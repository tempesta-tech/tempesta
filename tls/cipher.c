/*
 *		Tempesta TLS
 *
 * Generic cipher wrapper.
 *
 * Author Adriaan de Jong <dejong@fox-it.com>
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
#include <crypto/aead.h>
#include <net/tls.h>

#include "lib/str.h"
#include "config.h"
#include "cipher.h"
#include "debug.h"

typedef struct {
	ttls_cipher_type_t		type;
	const ttls_cipher_info_t	*info;
} TlsCipherDef;

extern const TlsCipherDef ttls_cipher_definitions[];

static struct crypto_aead *
gcm_aes_ctx_alloc(void)
{
	struct crypto_aead *a = crypto_alloc_aead("gcm(aes)", 0, 0);

	if (IS_ERR(a))
		T_ERR("cannot initialize gcm(aes) cipher."
		      " Please check /proc/crypto for the algorithm\n");

	return a;
}

static struct crypto_aead *
ccm_aes_ctx_alloc(void)
{
	struct crypto_aead *a = crypto_alloc_aead("ccm(aes)", 0, 0);

	if (IS_ERR(a))
		T_ERR("cannot initialize ccm(aes) cipher."
		      " Please check /proc/crypto for the algorithm\n");

	return a;
}

const ttls_cipher_info_t *
ttls_cipher_info_from_type(const ttls_cipher_type_t cipher_type)
{
	const TlsCipherDef *def;

	for (def = ttls_cipher_definitions; def->info; def++)
		if (def->type == cipher_type)
			return def->info;
	return NULL;
}

void
ttls_cipher_free(TlsCipherCtx *ctx)
{
	if (!ctx)
		return;

	if (ctx->cipher_ctx)
		ctx->cipher_info->base->ctx_free_func(ctx->cipher_ctx);

	bzero_fast(ctx, sizeof(TlsCipherCtx));
}

int
ttls_cipher_setup(TlsCipherCtx *ctx, const ttls_cipher_info_t *ci,
		  unsigned int tag_size)
{
	int r;

	BUG_ON(!ci || !ctx);

	bzero_fast(ctx, sizeof(TlsCipherCtx));

	if (!(ctx->cipher_ctx = ci->base->ctx_alloc_func()))
		return TTLS_ERR_CIPHER_ALLOC_FAILED;
	if ((r = crypto_aead_setauthsize(ctx->cipher_ctx, tag_size))) {
		ttls_cipher_free(ctx);	
		return r;
	}

	/* See IV definitions for all cipher suites at the below. */
	WARN_ON_ONCE(crypto_aead_ivsize(ctx->cipher_ctx) != 12);

	ctx->cipher_info = ci;

	return 0;
}

/**
 * Linux crypt API requires aligned keys to pass them to assembly layer,
 * so copy both the keys at once to avoid additional kmalloc() calls in
 * setkey_unaligned().
 */
int
ttls_cipher_setkeys(TlsCipherCtx *ctx_enc, const unsigned char *key_enc,
		    TlsCipherCtx *ctx_dec, const unsigned char *key_dec,
		    int key_len)
{
	int r;

	if (WARN_ON_ONCE(key_len > 64
			 || !ctx_enc || !ctx_dec
			 || !ctx_enc->cipher_info || !ctx_dec->cipher_info
			 || (!(ctx_enc->cipher_info->flags
			       & TTLS_CIPHER_VARIABLE_KEY_LEN)
				 && ctx_enc->cipher_info->key_len != key_len)
			 || (!(ctx_dec->cipher_info->flags
			       & TTLS_CIPHER_VARIABLE_KEY_LEN)
				 && ctx_dec->cipher_info->key_len != key_len)))
	{
		return TTLS_ERR_CIPHER_BAD_INPUT_DATA;
	}

	if ((r = crypto_aead_setkey(ctx_enc->cipher_ctx, key_enc, key_len)))
		return r;
	return crypto_aead_setkey(ctx_dec->cipher_ctx, key_dec, key_len);
}

static ttls_cipher_base_t gcm_aes_info = {
	.cipher			= TTLS_CIPHER_ID_AES,
	.ctx_alloc_func		= gcm_aes_ctx_alloc,
	.ctx_free_func		= crypto_free_aead,
};

static const ttls_cipher_info_t aes_128_gcm_info = {
	TTLS_CIPHER_AES_128_GCM,
	TTLS_MODE_GCM,
	16,
	"AES-128-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_aes_info
};

static const ttls_cipher_info_t aes_192_gcm_info = {
	TTLS_CIPHER_AES_192_GCM,
	TTLS_MODE_GCM,
	24,
	"AES-192-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_aes_info
};

static const ttls_cipher_info_t aes_256_gcm_info = {
	TTLS_CIPHER_AES_256_GCM,
	TTLS_MODE_GCM,
	32,
	"AES-256-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_aes_info
};

static ttls_cipher_base_t ccm_aes_info = {
	.cipher			= TTLS_CIPHER_ID_AES,
	.ctx_alloc_func		= ccm_aes_ctx_alloc,
	.ctx_free_func		= crypto_free_aead,
};

static const ttls_cipher_info_t aes_128_ccm_info = {
	TTLS_CIPHER_AES_128_CCM,
	TTLS_MODE_CCM,
	16,
	"AES-128-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_aes_info
};

static const ttls_cipher_info_t aes_192_ccm_info = {
	TTLS_CIPHER_AES_192_CCM,
	TTLS_MODE_CCM,
	24,
	"AES-192-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_aes_info
};

static const ttls_cipher_info_t aes_256_ccm_info = {
	TTLS_CIPHER_AES_256_CCM,
	TTLS_MODE_CCM,
	32,
	"AES-256-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_aes_info
};

const TlsCipherDef ttls_cipher_definitions[] =
{
	{ TTLS_CIPHER_AES_128_GCM,		  &aes_128_gcm_info },
	{ TTLS_CIPHER_AES_192_GCM,		  &aes_192_gcm_info },
	{ TTLS_CIPHER_AES_256_GCM,		  &aes_256_gcm_info },
	{ TTLS_CIPHER_AES_128_CCM,		  &aes_128_ccm_info },
	{ TTLS_CIPHER_AES_192_CCM,		  &aes_192_ccm_info },
	{ TTLS_CIPHER_AES_256_CCM,		  &aes_256_ccm_info },
	{ TTLS_CIPHER_NONE, NULL }
};
