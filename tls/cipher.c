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

static ttls_cipher_base_t gcm_aes_info;
static ttls_cipher_base_t ccm_aes_info;

#define DECLARE_CIPHER_ALLOC(name)					\
static struct kmem_cache *ttls_##name##_cache;				\
static struct crypto_aead *name##_ctx_alloc(void)			\
{									\
	void *ctx = kmem_cache_alloc(ttls_##name##_cache, GFP_ATOMIC);	\
	if (!ctx)							\
		return NULL;						\
	memcpy_fast(ctx, name##_info.tfm, ksize(name##_info.tfm));	\
	return ctx;							\
}									\
static void name##_ctx_free(struct crypto_aead *ctx)			\
{									\
	bzero_fast(ctx, ksize(name##_info.tfm));			\
	kmem_cache_free(ttls_##name##_cache, ctx);			\
}

DECLARE_CIPHER_ALLOC(gcm_aes);
DECLARE_CIPHER_ALLOC(ccm_aes);

const ttls_cipher_info_t *
ttls_cipher_info_from_type(const ttls_cipher_type_t cipher_type)
{
	const ttls_cipher_definition_t *def;

	for (def = ttls_cipher_definitions; def->info; def++)
		if (def->type == cipher_type)
			return def->info;
	return NULL;
}

void
ttls_cipher_free(ttls_cipher_context_t *ctx)
{
	if (!ctx)
		return;

	if (ctx->cipher_ctx)
		ctx->cipher_info->base->ctx_free_func(ctx->cipher_ctx);

	bzero_fast(ctx, sizeof(ttls_cipher_context_t));
}

int
ttls_cipher_setup(ttls_cipher_context_t *ctx, const ttls_cipher_info_t *ci,
		  unsigned int tag_size)
{
	int r;

	BUG_ON(!ci || !ctx);

	bzero_fast(ctx, sizeof(ttls_cipher_context_t));

	if (!(ctx->cipher_ctx = ci->base->ctx_alloc_func()))
		return TTLS_ERR_CIPHER_ALLOC_FAILED;
	if ((r = crypto_aead_setauthsize(ctx->cipher_ctx, tag_size))) {
		ttls_cipher_free(ctx);	
		return r;
	}

	ctx->cipher_info = ci;

	return 0;
}

int
ttls_cipher_setkey(ttls_cipher_context_t *ctx, const unsigned char *key,
		   int key_len, const ttls_operation_t operation)
{
	WARN_ON_ONCE(key_len > 64);
	if (!ctx || !ctx->cipher_info
	    || (!(ctx->cipher_info->flags & TTLS_CIPHER_VARIABLE_KEY_LEN)
		&& ctx->cipher_info->key_len != key_len))
	{
		return TTLS_ERR_CIPHER_BAD_INPUT_DATA;
	}

	ctx->key_len = key_len;
	ctx->operation = operation;

	if (operation == TTLS_ENCRYPT)
		return ctx->cipher_info->base->setkey_enc_func(ctx->cipher_ctx,
							       key,
							       ctx->key_len);
	else
		return ctx->cipher_info->base->setkey_dec_func(ctx->cipher_ctx,
							       key,
							       ctx->key_len);
}

static int
aead_aes_setkey_wrap(void *ctx, const unsigned char *key, unsigned int len)
{
	return crypto_aead_setkey((struct crypto_aead *)ctx, key, len);
}

static ttls_cipher_base_t gcm_aes_info = {
	.cipher			= TTLS_CIPHER_ID_AES,
	.setkey_enc_func	= aead_aes_setkey_wrap,
	.setkey_dec_func	= aead_aes_setkey_wrap,
	.ctx_alloc_func		= gcm_aes_ctx_alloc,
	.ctx_free_func		= gcm_aes_ctx_free,
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
	.setkey_enc_func	= aead_aes_setkey_wrap,
	.setkey_dec_func	= aead_aes_setkey_wrap,
	.ctx_alloc_func		= ccm_aes_ctx_alloc,
	.ctx_free_func		= ccm_aes_ctx_free,
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

#if defined(TTLS_CAMELLIA_C)

static int
camellia_setkey_dec_wrap(void *ctx, const unsigned char *key,
			 unsigned int key_len)
{
	return ttls_camellia_setkey_dec((ttls_camellia_context *)ctx, key,
					key_len);
}

static int
camellia_setkey_enc_wrap(void *ctx, const unsigned char *key,
			 unsigned int key_len)
{
	return ttls_camellia_setkey_enc((ttls_camellia_context *)ctx, key,
					key_len);
}

static void *
camellia_ctx_alloc(void)
{
	ttls_camellia_context *ctx;
	ctx = ttls_calloc(1, sizeof(ttls_camellia_context));

	if (!ctx)
		return NULL;

	ttls_camellia_init(ctx);

	return ctx;
}

static void
camellia_ctx_free(void *ctx)
{
	ttls_camellia_free((ttls_camellia_context *)ctx);
	ttls_free(ctx);
}

static void *
gcm_camellia_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_gcm_context));

	if (ctx)
		ttls_gcm_init((ttls_gcm_context *) ctx);

	return ctx;
}

static void
gcm_camellia_ctx_free(void *ctx)
{
	ttls_gcm_free(ctx);
	ttls_free(ctx);
}

static int
gcm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
			 unsigned int key_len)
{
	return ttls_gcm_setkey((ttls_gcm_context *) ctx, TTLS_CIPHER_ID_CAMELLIA,
				key, key_len);
}

static const ttls_cipher_base_t gcm_camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	NULL,
	NULL,
	gcm_camellia_setkey_wrap,
	gcm_camellia_setkey_wrap,
	gcm_camellia_ctx_alloc,
	gcm_camellia_ctx_free,
};

static const ttls_cipher_info_t camellia_128_gcm_info = {
	TTLS_CIPHER_CAMELLIA_128_GCM,
	TTLS_MODE_GCM,
	16,
	"CAMELLIA-128-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_camellia_info
};

static const ttls_cipher_info_t camellia_192_gcm_info = {
	TTLS_CIPHER_CAMELLIA_192_GCM,
	TTLS_MODE_GCM,
	24,
	"CAMELLIA-192-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_camellia_info
};

static const ttls_cipher_info_t camellia_256_gcm_info = {
	TTLS_CIPHER_CAMELLIA_256_GCM,
	TTLS_MODE_GCM,
	32,
	"CAMELLIA-256-GCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&gcm_camellia_info
};

static void *
ccm_camellia_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_ccm_context));

	if (ctx)
		ttls_ccm_init((ttls_ccm_context *)ctx);

	return ctx;
}

static void
ccm_ctx_free(void *ctx)
{
	ttls_ccm_free(ctx);
	ttls_free(ctx);
}

static int
ccm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
			 unsigned int key_len)
{
	return ttls_ccm_setkey((ttls_ccm_context *) ctx, TTLS_CIPHER_ID_CAMELLIA,
				key, key_len);
}

static const ttls_cipher_base_t ccm_camellia_info = {
	TTLS_CIPHER_ID_CAMELLIA,
	NULL,
	NULL,
	ccm_camellia_setkey_wrap,
	ccm_camellia_setkey_wrap,
	ccm_camellia_ctx_alloc,
	ccm_camellia_ctx_free,
};

static const ttls_cipher_info_t camellia_128_ccm_info = {
	TTLS_CIPHER_CAMELLIA_128_CCM,
	TTLS_MODE_CCM,
	16,
	"CAMELLIA-128-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_camellia_info
};

static const ttls_cipher_info_t camellia_192_ccm_info = {
	TTLS_CIPHER_CAMELLIA_192_CCM,
	TTLS_MODE_CCM,
	24,
	"CAMELLIA-192-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_camellia_info
};

static const ttls_cipher_info_t camellia_256_ccm_info = {
	TTLS_CIPHER_CAMELLIA_256_CCM,
	TTLS_MODE_CCM,
	32,
	"CAMELLIA-256-CCM",
	12,
	TTLS_CIPHER_VARIABLE_IV_LEN,
	16,
	&ccm_camellia_info
};
#endif /* TTLS_CAMELLIA_C */

const ttls_cipher_definition_t ttls_cipher_definitions[] =
{
	{ TTLS_CIPHER_AES_128_GCM,		  &aes_128_gcm_info },
	{ TTLS_CIPHER_AES_192_GCM,		  &aes_192_gcm_info },
	{ TTLS_CIPHER_AES_256_GCM,		  &aes_256_gcm_info },
	{ TTLS_CIPHER_AES_128_CCM,		  &aes_128_ccm_info },
	{ TTLS_CIPHER_AES_192_CCM,		  &aes_192_ccm_info },
	{ TTLS_CIPHER_AES_256_CCM,		  &aes_256_ccm_info },

#if defined(TTLS_CAMELLIA_C)
	{ TTLS_CIPHER_CAMELLIA_128_GCM,	 &camellia_128_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_192_GCM,	 &camellia_192_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_256_GCM,	 &camellia_256_gcm_info },
	{ TTLS_CIPHER_CAMELLIA_128_CCM,	 &camellia_128_ccm_info },
	{ TTLS_CIPHER_CAMELLIA_192_CCM,	 &camellia_192_ccm_info },
	{ TTLS_CIPHER_CAMELLIA_256_CCM,	 &camellia_256_ccm_info },
#endif /* TTLS_CAMELLIA_C */

	{ TTLS_CIPHER_NONE, NULL }
};

int ttls_cipher_supported[ARRAY_SIZE(ttls_cipher_definitions)];

#define FREE_CIPHER_CACHE(name)						\
	if (name##_info.tfm)						\
		crypto_free_aead(name##_info.tfm);			\
	if (ttls_##name##_cache)					\
		kmem_cache_destroy(ttls_##name##_cache);

void
ttls_free_cipher_ctx_tmpls(void)
{
	FREE_CIPHER_CACHE(gcm_aes);
	FREE_CIPHER_CACHE(ccm_aes);
}

#define CREATE_CIPHER_CACHE(name, strid)				\
do {									\
	struct crypto_aead *a = crypto_alloc_aead(strid, 0, 0);		\
	if (IS_ERR(a)) {						\
		T_ERR("cannot initialize " strid " cipher. "		\
		      "Please check /proc/crypto for the algorithm\n");	\
		goto err_free;						\
	}								\
	name##_info.tfm = a;						\
	ttls_##name##_cache = kmem_cache_create("ttls_" #name "_cache",	\
						ksize(name##_info.tfm),	\
						0, 0, NULL);		\
	if (!ttls_##name##_cache)					\
		goto err_free;						\
} while (0)

int
ttls_init_cipher_ctx_tmpls(void)
{
	CREATE_CIPHER_CACHE(gcm_aes, "gcm(aes)");
	CREATE_CIPHER_CACHE(ccm_aes, "ccm(aes)");

	return 0;
err_free:
	ttls_free_cipher_ctx_tmpls();
	return -ENOMEM;
}
