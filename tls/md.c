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
#include "lib/str.h"
#include "debug.h"
#include "md.h"

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {
	TTLS_MD_SHA512,
	TTLS_MD_SHA384,
	TTLS_MD_SHA256,
	TTLS_MD_SHA224,
	TTLS_MD_NONE
};

TlsMdInfo ttls_sha224_info = {
	.type		= TTLS_MD_SHA224,
	.name		= "SHA224",
	.alg_name	= "sha224-avx2",
	.hmac_name	= "hmac(sha224-avx2)",
	.size		= 28,
	.block_size	= 64,
};

TlsMdInfo ttls_sha256_info = {
	.type		= TTLS_MD_SHA256,
	.name		= "SHA256",
	.alg_name	= "sha256-avx2",
	.hmac_name	= "hmac(sha256-avx2)",
	.size		= 32,
	.block_size	= 64,
};

TlsMdInfo ttls_sha384_info = {
	.type		= TTLS_MD_SHA384,
	.name		= "SHA384",
	.alg_name	= "sha384-avx2",
	.hmac_name	= "hmac(sha384-avx2)",
	.size		= 48,
	.block_size	= 128,
};

TlsMdInfo ttls_sha512_info = {
	.type		= TTLS_MD_SHA512,
	.name		= "SHA512",
	.alg_name	= "sha512-avx2",
	.hmac_name	= "hmac(sha512-avx2)",
	.size		= 64,
	.block_size	= 128,
};

void
ttls_md_init(TlsMdCtx *ctx)
{
	bzero_fast(ctx, sizeof(TlsMdCtx));
}

void
ttls_md_free(TlsMdCtx *ctx)
{
	if (ctx)
		crypto_free_shash(ctx->md_ctx.tfm);
}

static int
__ttls_md_hash_setup(struct shash_desc *md_ctx, const TlsMdInfo *md_info)
{
	md_ctx->tfm = crypto_alloc_shash(md_info->alg_name, 0, 0);
	if (IS_ERR(md_ctx->tfm)) {
		T_ERR("cannot initizlize hash driver %s."
		      " Please check /proc/crypto for the algorithm\n",
		      md_info->alg_name);
		return TTLS_ERR_MD_ALLOC_FAILED;
	}

	return 0;
}

static int
__ttls_md_hmac_setup(struct shash_desc *md_ctx, const TlsMdInfo *md_info)
{
	md_ctx->tfm = crypto_alloc_shash(md_info->hmac_name, 0, 0);
	if (IS_ERR(md_ctx->tfm)) {
		T_ERR("cannot initizlize HMAC driver %s."
		      " Please check /proc/crypto for the algorithm\n",
		      md_info->hmac_name);
		return TTLS_ERR_MD_ALLOC_FAILED;
	}

	return 0;
}

int
ttls_md_setup(TlsMdCtx *ctx, const TlsMdInfo *md_info, int hmac)
{
	BUG_ON(!ctx);
	if (WARN_ON_ONCE(!md_info))
		return -EINVAL;

	ctx->md_info = md_info;

	return hmac ?  __ttls_md_hmac_setup(&ctx->md_ctx, md_info)
		    :  __ttls_md_hash_setup(&ctx->md_ctx, md_info);
}

int
ttls_md_starts(TlsMdCtx *ctx)
{
	BUG_ON(!ctx || !ctx->md_info);

	return crypto_shash_init(&ctx->md_ctx);
}

int
ttls_md_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen)
{
	BUG_ON(!ctx || !ctx->md_info);

	return crypto_shash_update(&ctx->md_ctx, input, ilen);
}

int
ttls_md_finish(TlsMdCtx *ctx, unsigned char *output)
{
	BUG_ON(!ctx || !ctx->md_info);

	return crypto_shash_final(&ctx->md_ctx, output);
}

int
ttls_md(const TlsMdInfo *md_info, const unsigned char *input, size_t ilen,
	unsigned char *output)
{
	int r;
	TlsMdCtx ctx;

	BUG_ON(!md_info);

	ttls_md_init(&ctx);
	if ((r = ttls_md_setup(&ctx, md_info, 0)))
		return r;
	r = crypto_shash_digest(&ctx.md_ctx, input, ilen, output);
	ttls_md_free(&ctx);

	return r;
}

int
ttls_sha256_init_start(ttls_sha256_context *ctx)
{
	int r;

	if ((r = __ttls_md_hash_setup(&ctx->desc, &ttls_sha256_info)))
		return r;
	ctx->desc.flags = 0;

	return crypto_shash_init(&ctx->desc);
}

int
ttls_sha384_init_start(ttls_sha512_context *ctx)
{
	int r;

	if ((r = __ttls_md_hash_setup(&ctx->desc, &ttls_sha384_info)))
		return r;
	ctx->desc.flags = 0;

	return crypto_shash_init(&ctx->desc);
}

int
ttls_md_hmac_starts(TlsMdCtx *ctx, const unsigned char *key, size_t keylen)
{
	int r;

	if ((r = crypto_shash_setkey(ctx->md_ctx.tfm, key, keylen)))
		return r;
	return crypto_shash_init(&ctx->md_ctx);
}

int
ttls_md_hmac_reset(TlsMdCtx *ctx)
{
	BUG_ON(!ctx || !ctx->md_info);

	return crypto_shash_init(&ctx->md_ctx);
}

const TlsMdInfo *
ttls_md_info_from_type(ttls_md_type_t md_type)
{
	switch(md_type) {
	case TTLS_MD_SHA224:
		return &ttls_sha224_info;
	case TTLS_MD_SHA256:
		return &ttls_sha256_info;
	case TTLS_MD_SHA384:
		return &ttls_sha384_info;
	case TTLS_MD_SHA512:
		return &ttls_sha512_info;
	default:
		return NULL;
	}
}
