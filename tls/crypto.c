/*
 *		Tempesta TLS
 *
 * Generic wrappers for Linux crypto API.
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <crypto/aead.h>
#include <net/tls.h>

#include "lib/str.h"
#include "debug.h"
#include "crypto.h"

/*
 * ------------------------------------------------------------------------
 *	Message digests
 * ------------------------------------------------------------------------
 */
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
		T_ERR("cannot initialize hash driver %s."
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
		T_ERR("cannot initialize HMAC driver %s."
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

/*
 * ------------------------------------------------------------------------
 *	Ciphers
 * ------------------------------------------------------------------------
 */
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

/*
 * ------------------------------------------------------------------------
 *	Common initialization routines
 * ------------------------------------------------------------------------
 */

