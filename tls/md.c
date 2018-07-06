/*
 *		Tempesta TLS
 *
 * Generic message digest wrapper.
 *
 * Adriaan de Jong <dejong@fox-it.com>
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
#include "md.h"

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {
		TTLS_MD_SHA512,
		TTLS_MD_SHA384,
		TTLS_MD_SHA256,
		TTLS_MD_SHA224,
		TTLS_MD_RIPEMD160,
		TTLS_MD_NONE
};

static struct kmem_cache *ttls_hmac_cache;

#define DECLARE_MD_ALLOC(name)						\
static struct kmem_cache *ttls_##name##_cache;				\
static struct shash_desc *name##_ctx_alloc(void)			\
{									\
	struct shash_desc *desc;					\
	desc = (struct shash_desc *)kmem_cache_alloc(ttls_##name##_cache,\
						     GFP_ATOMIC);	\
	if (!desc)							\
		return NULL;						\
	desc->tfm = ttls_##name##_info.tfm;				\
	desc->flags = 0;						\
	return (struct shash_desc *)desc;				\
}									\
static void name##_ctx_free(struct shash_desc *desc)			\
{									\
	bzero_fast(desc, ksize(ttls_##name##_info.ctx_tmpl));		\
	kmem_cache_free(ttls_##name##_cache, desc);			\
}

DECLARE_MD_ALLOC(ripemd160);
DECLARE_MD_ALLOC(sha224);
DECLARE_MD_ALLOC(sha256);
DECLARE_MD_ALLOC(sha384);
DECLARE_MD_ALLOC(sha512);

const ttls_md_info_t ttls_ripemd160_info = {
	.type		= TTLS_MD_RIPEMD160,
	.name		= "RIPEMD160",
	.size		= 20,
	.block_size	= 64,
	.starts_func	= crypto_shash_init,
	.update_func	= crypto_shash_update,
	.finish_func	= crypto_shash_final,
	.ctx_alloc_func	= ripemd160_ctx_alloc,
	.ctx_free_func	= ripemd160_ctx_free,
};

const ttls_md_info_t ttls_sha224_info = {
	.type		= TTLS_MD_SHA224,
	.name		= "SHA224",
	.size		= 28,
	.block_size	= 64,
	.starts_func	= crypto_shash_init,
	.update_func	= crypto_shash_update,
	.finish_func	= crypto_shash_final,
	.ctx_alloc_func	= sha224_ctx_alloc,
	.ctx_free_func	= sha224_ctx_free,
};

const ttls_md_info_t ttls_sha256_info = {
	.type		= TTLS_MD_SHA256,
	.name		= "SHA256",
	.size		= 32,
	.block_size	= 64,
	.starts_func	= crypto_shash_init,
	.update_func	= crypto_shash_update,
	.finish_func	= crypto_shash_final,
	.ctx_alloc_func	= sha224_ctx_alloc,
	.ctx_free_func	= sha224_ctx_free,
};

const ttls_md_info_t ttls_sha384_info = {
	.type		= TTLS_MD_SHA384,
	.name		= "SHA384",
	.size		= 48,
	.block_size	= 128,
	.starts_func	= crypto_shash_init,
	.update_func	= crypto_shash_update,
	.finish_func	= crypto_shash_final,
	.ctx_alloc_func	= sha384_ctx_alloc,
	.ctx_free_func	= sha384_ctx_free,
};

const ttls_md_info_t ttls_sha512_info = {
	.type		= TTLS_MD_SHA512,
	.name		= "SHA512",
	.size		= 64,
	.block_size	= 128,
	.starts_func	= crypto_shash_init,
	.update_func	= crypto_shash_update,
	.finish_func	= crypto_shash_final,
	.ctx_alloc_func	= sha384_ctx_alloc,
	.ctx_free_func	= sha384_ctx_free,
};

void
ttls_md_init(ttls_md_context_t *ctx)
{
	bzero_fast(ctx, sizeof(ttls_md_context_t));
}

void
ttls_md_free(ttls_md_context_t *ctx)
{
	if (!ctx || !ctx->md_info)
		return;

	if (ctx->md_ctx)
		ctx->md_info->ctx_free_func(ctx->md_ctx);

	if (ctx->hmac_ctx) {
		bzero_fast(ctx->hmac_ctx, 2 * ctx->md_info->block_size);
		kmem_cache_free(ttls_hmac_cache, ctx->hmac_ctx);
	}

	bzero_fast(ctx, sizeof(ttls_md_context_t));
}

int
ttls_md_setup(ttls_md_context_t *ctx, const ttls_md_info_t *md_info, int hmac)
{
	BUG_ON(!md_info || !ctx);

	if (!(ctx->md_ctx = md_info->ctx_alloc_func()))
		return TTLS_ERR_MD_ALLOC_FAILED;

	if (hmac) {
		ctx->hmac_ctx = kmem_cache_alloc(ttls_hmac_cache, GFP_KERNEL);
		if (!ctx->hmac_ctx) {
			md_info->ctx_free_func(ctx->md_ctx);
			return TTLS_ERR_MD_ALLOC_FAILED;
		}
	}

	ctx->md_info = md_info;

	return 0;
}

int
ttls_md_starts(ttls_md_context_t *ctx)
{
	BUG_ON(!md_info || !ctx);

	return ctx->md_info->starts_func(ctx->md_ctx);
}

int
ttls_md_update(ttls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
	BUG_ON(!ctx || !ctx->md_info);

	return ctx->md_info->update_func(ctx->md_ctx, input, ilen);
}

int
ttls_md_finish(ttls_md_context_t *ctx, unsigned char *output)
{
	BUG_ON(!ctx || !ctx->md_info);

	return ctx->md_info->finish_func(ctx->md_ctx, output);
}

int
ttls_md(const ttls_md_info_t *md_info, const unsigned char *input, size_t ilen,
	unsigned char *output)
{
	int r;
	ttls_md_context_t ctx = {};

	BUG_ON(!md_info);

	if ((r = ttls_md_setup(&ctx, md_info, 0)))
		return r;
	r = crypto_shash_digest(ctx.md_ctx, input, ilen, output);
	ttls_md_free(&ctx);

	return r;
}

void
ttls_sha256_init_start(ttls_sha256_context *ctx)
{
	ctx->desc.tfm = ttls_sha256_info.tfm;
	ctx->desc.flags = 0;
	crypto_shash_init(&ctx->desc);
}

void
ttls_sha384_init_start(ttls_sha512_context *ctx)
{
	ctx->desc.tfm = ttls_sha384_info.tfm;
	ctx->desc.flags = 0;
	crypto_shash_init(&ctx->desc);
}

/* TODO rework for linux/crypto HMAC, ex. security/keys/trusted.c */
int
ttls_md_hmac_starts(ttls_md_context_t *ctx, const unsigned char *key,
		    size_t keylen)
{
	int i, r;
	unsigned char sum[TTLS_MD_MAX_SIZE];
	unsigned char *ipad, *opad;

	BUG_ON(!ctx || !ctx->md_info || !ctx->hmac_ctx);

	if (keylen > (size_t)ctx->md_info->block_size) {
		if ((r = ctx->md_info->starts_func(ctx->md_ctx)))
			goto cleanup;
		if ((r = ctx->md_info->update_func(ctx->md_ctx, key, keylen)))
			goto cleanup;
		if ((r = ctx->md_info->finish_func(ctx->md_ctx, sum)))
			goto cleanup;

		keylen = ctx->md_info->size;
		key = sum;
	}

	ipad = (unsigned char *)ctx->hmac_ctx;
	opad = (unsigned char *)ctx->hmac_ctx + ctx->md_info->block_size;

	memset(ipad, 0x36, ctx->md_info->block_size);
	memset(opad, 0x5C, ctx->md_info->block_size);

	for (i = 0; i < keylen; i++) {
		ipad[i] = (unsigned char)(ipad[i] ^ key[i]);
		opad[i] = (unsigned char)(opad[i] ^ key[i]);
	}

	if ((r = ctx->md_info->starts_func(ctx->md_ctx)))
		goto cleanup;
	if ((r = ctx->md_info->update_func(ctx->md_ctx, ipad,
					   ctx->md_info->block_size)))
		goto cleanup;

cleanup:
	bzero_fast(sum, sizeof(sum));

	return r;
}

int
ttls_md_hmac_update(ttls_md_context_t *ctx, const unsigned char *input,
		    size_t ilen)
{
	BUG_ON(!ctx || !ctx->md_info || !ctx->hmac_ctx);

	return ctx->md_info->update_func(ctx->md_ctx, input, ilen);
}

int
ttls_md_hmac_finish(ttls_md_context_t *ctx, unsigned char *output)
{
	int r;
	unsigned char tmp[TTLS_MD_MAX_SIZE];
	unsigned char *opad;

	BUG_ON(!ctx || !ctx->md_info || !ctx->hmac_ctx);

	opad = (unsigned char *)ctx->hmac_ctx + ctx->md_info->block_size;

	if ((r = ctx->md_info->finish_func(ctx->md_ctx, tmp)))
		return r;
	if ((r = ctx->md_info->starts_func(ctx->md_ctx)))
		return r;
	if ((r = ctx->md_info->update_func(ctx->md_ctx, opad,
					   ctx->md_info->block_size)))
		return r;
	if ((r = ctx->md_info->update_func(ctx->md_ctx, tmp,
				   ctx->md_info->size)) != 0)
		return r;
	return ctx->md_info->finish_func(ctx->md_ctx, output);
}

int
ttls_md_hmac_reset(ttls_md_context_t *ctx)
{
	int r;
	unsigned char *ipad;

	BUG_ON(!ctx || !ctx->md_info || !ctx->hmac_ctx);

	ipad = (unsigned char *) ctx->hmac_ctx;

	if ((r = ctx->md_info->starts_func(ctx->md_ctx)))
		return r;
	return ctx->md_info->update_func(ctx->md_ctx, ipad,
					 ctx->md_info->block_size);
}

const ttls_md_info_t *
ttls_md_info_from_type(ttls_md_type_t md_type)
{
	switch(md_type) {
		case TTLS_MD_RIPEMD160:
			return &ttls_ripemd160_info;
		case TTLS_MD_SHA224:
			return &ttls_sha224_info;
		case TTLS_MD_SHA256:
			return &ttls_sha256_info;
		case TTLS_MD_SHA384:
			return &ttls_sha384_info;
		case TTLS_MD_SHA512:
			return &ttls_sha512_info;
	}
	return NULL;
}

#define FREE_MD_CACHE(name)						\
	if (ttls_##name##_info.ctx_tmpl)				\
		crypto_free_shash(ttls_##name##_info.ctx_tmpl);		\
	if (ttls_##name##_cache)					\
		kmem_cache_destroy(ttls_##name##_cache);

void
ttls_free_md_ctx_tmpls(void)
{
	FREE_MD_CACHE(ripemd160);
	FREE_MD_CACHE(sha224);
	FREE_MD_CACHE(sha256);
	FREE_MD_CACHE(sha384);
	FREE_MD_CACHE(sha512);
	kmem_cache_destroy(ttls_hmac_cache);
}

#define CREATE_MD_CACHE(name)						\
do {									\
	struct crypto_shash *a = rypto_alloc_shash(#name, 0, 0);	\
	if (!a)								\
		return -ENOMEM;						\
	ttls_##name##_info.tfm = a;					\
	ttls_##name##_cache = kmem_cache_create("ttls_" #name "_cache",	\
						sizeof(struct shash_desc)\
						+ crypto_shash_descsize(a)\
						0, 0, NULL);		\
	if (!ttls_##name##_cache)					\
		goto err_free;

int
ttls_init_md_ctx_tmpls(void)
{
	/* Allocate double of maximum block size. */
	ttls_hmac_cache = kmem_cache_create("ttls_hmac_cache", 256, 0, 0, NULL);
	if (!ttls_hmac_cache)
		return -ENOMEM;
	CREATE_MD_CACHE(ripemd160);
	CREATE_MD_CACHE(sha224);
	CREATE_MD_CACHE(sha256);
	CREATE_MD_CACHE(sha384);
	CREATE_MD_CACHE(sha512);

	return 0;
err_free:
	ttls_free_cipher_ctx_tmpls();
	return -ENOMEM;
}
