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
 *	Ciphers
 * ------------------------------------------------------------------------
 */
typedef struct {
	ttls_cipher_type_t	type;
	TlsCipherInfo		*info;
} TlsCipherDef;

void
ttls_cipher_free(TlsCipherCtx *ctx)
{
	if (!ctx)
		return;
	if (ctx->cipher_ctx)
		crypto_free_aead(ctx->cipher_ctx);
	bzero_fast(ctx, sizeof(TlsCipherCtx));
}

int
ttls_cipher_setup(TlsCipherCtx *ctx, const TlsCipherInfo *ci,
		  unsigned int tag_size)
{
	int r;

	BUG_ON(!ci || !ctx);

	bzero_fast(ctx, sizeof(TlsCipherCtx));

	ctx->cipher_ctx = crypto_alloc_aead_atomic(ci->alg);
	if (IS_ERR(ctx->cipher_ctx))
		return PTR_ERR(ctx->cipher_ctx);

	if ((r = crypto_aead_setauthsize(ctx->cipher_ctx, tag_size))) {
		ttls_cipher_free(ctx);
		return r;
	}

	/* See IV definitions for all cipher suites at the below. */
	WARN_ON_ONCE(crypto_aead_ivsize(ctx->cipher_ctx) != 12);

	ctx->cipher_info = ci;

	return 0;
}

static TlsCipherInfo aes_128_gcm_info = {
	TTLS_CIPHER_AES_128_GCM,
	TTLS_MODE_GCM,
	16,
	"AES-128-GCM",
	"gcm(aes)",
	12,
};

static TlsCipherInfo aes_192_gcm_info = {
	TTLS_CIPHER_AES_192_GCM,
	TTLS_MODE_GCM,
	24,
	"AES-192-GCM",
	"gcm(aes)",
	12,
};

static TlsCipherInfo aes_256_gcm_info = {
	TTLS_CIPHER_AES_256_GCM,
	TTLS_MODE_GCM,
	32,
	"AES-256-GCM",
	"gcm(aes)",
	12,
};

static TlsCipherInfo aes_128_ccm_info = {
	TTLS_CIPHER_AES_128_CCM,
	TTLS_MODE_CCM,
	16,
	"AES-128-CCM",
	"ccm(aes)",
	12,
};

static TlsCipherInfo aes_192_ccm_info = {
	TTLS_CIPHER_AES_192_CCM,
	TTLS_MODE_CCM,
	24,
	"AES-192-CCM",
	"ccm(aes)",
	12,
};

static TlsCipherInfo aes_256_ccm_info = {
	TTLS_CIPHER_AES_256_CCM,
	TTLS_MODE_CCM,
	32,
	"AES-256-CCM",
	"ccm(aes)",
	12,
};

static TlsCipherDef ttls_ciphers[] = {
	{ TTLS_CIPHER_AES_128_GCM,	&aes_128_gcm_info },
	{ TTLS_CIPHER_AES_192_GCM,	&aes_192_gcm_info },
	{ TTLS_CIPHER_AES_256_GCM,	&aes_256_gcm_info },
	{ TTLS_CIPHER_AES_128_CCM,	&aes_128_ccm_info },
	{ TTLS_CIPHER_AES_192_CCM,	&aes_192_ccm_info },
	{ TTLS_CIPHER_AES_256_CCM,	&aes_256_ccm_info },
	{ TTLS_CIPHER_NONE,		NULL }
};

const TlsCipherInfo *
ttls_cipher_info_from_type(const ttls_cipher_type_t cipher_type)
{
	const TlsCipherDef *def;

	for (def = ttls_ciphers; def->info; def++)
		if (def->type == cipher_type)
			return def->info;
	return NULL;
}

/*
 * ------------------------------------------------------------------------
 *	Message digests
 * ------------------------------------------------------------------------
 */
typedef struct {
	ttls_md_type_t		type;
	TlsMdInfo		*info;
} TlsHashDef;

static TlsMdInfo ttls_sha224_info = {
	.type		= TTLS_MD_SHA224,
	.name		= "SHA224",
	.alg_name	= "sha224",
	.hmac_name	= "hmac(sha224)",
};

static TlsMdInfo ttls_sha256_info = {
	.type		= TTLS_MD_SHA256,
	.name		= "SHA256",
	.alg_name	= "sha256",
	.hmac_name	= "hmac(sha256)",
};

static TlsMdInfo ttls_sha384_info = {
	.type		= TTLS_MD_SHA384,
	.name		= "SHA384",
	.alg_name	= "sha384",
	.hmac_name	= "hmac(sha384)",
};

static TlsMdInfo ttls_sha512_info = {
	.type		= TTLS_MD_SHA512,
	.name		= "SHA512",
	.alg_name	= "sha512",
	.hmac_name	= "hmac(sha512)",
};

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static TlsHashDef ttls_hashes[] = {
	{ TTLS_MD_SHA512,	&ttls_sha512_info },
	{ TTLS_MD_SHA384,	&ttls_sha384_info },
	{ TTLS_MD_SHA256,	&ttls_sha256_info },
	{ TTLS_MD_SHA224,	&ttls_sha224_info },
	{ TTLS_MD_NONE,		NULL }
};

void
ttls_md_init(TlsMdCtx *ctx)
{
	bzero_fast(ctx, sizeof(TlsMdCtx));
}

void
ttls_md_free(TlsMdCtx *ctx)
{
	if (!ctx)
		return;
	crypto_free_shash(ctx->md_ctx.tfm);
	bzero_fast(ctx, sizeof(TlsMdCtx));
}

static int
__ttls_md_hash_setup(struct shash_desc *md_ctx, const TlsMdInfo *md_info)
{
	md_ctx->tfm = crypto_alloc_shash_atomic(md_info->alg_hash);
	if (IS_ERR(md_ctx->tfm)) {
		T_DBG("Cannot setup hash ctx, %ld\n", PTR_ERR(md_ctx->tfm));
		return PTR_ERR(md_ctx->tfm);
	}

	return 0;
}

static int
__ttls_md_hmac_setup(struct shash_desc *md_ctx, const TlsMdInfo *md_info)
{
	md_ctx->tfm = crypto_alloc_shash_atomic(md_info->alg_hmac);
	if (IS_ERR(md_ctx->tfm)) {
		T_DBG("Cannot setup hmac ctx, %ld\n", PTR_ERR(md_ctx->tfm));
		return PTR_ERR(md_ctx->tfm);
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
	int r;

	BUG_ON(!ctx || !ctx->md_info);

	r = crypto_shash_init(&ctx->md_ctx);
	if (r)
		T_DBG("cannot start hash ctx, %d\n", r);

	return r;
}

int
ttls_md_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen)
{
	int r;

	BUG_ON(!ctx || !ctx->md_info);

	r = crypto_shash_update(&ctx->md_ctx, input, ilen);
	if (r)
		T_DBG("cannot update hash ctx, %d\n", r);

	return r;
}

int
ttls_md_finish(TlsMdCtx *ctx, unsigned char *output)
{
	int r;

	BUG_ON(!ctx || !ctx->md_info);

	r = crypto_shash_final(&ctx->md_ctx, output);
	if (r)
		T_DBG("cannot finish hash context, %d\n", r);

	return r;
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
	switch (md_type) {
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
 *	Common initialization routines
 * ------------------------------------------------------------------------
 */
static unsigned int g_aead_max_reqsize = sizeof(struct aead_request);

unsigned int
ttls_aead_reqsize(void)
{
	return g_aead_max_reqsize;
}

/**
 * Crypto framework may load crypto modules on the fly during a particular
 * algorithm initialization, so the two routines at the below just allocate and
 * immediately free algorithm descriptors to make all the necessary modules
 * loaded.
 */
static int __init
ttls_ciphermod_preload(const char *alg_name)
{
	unsigned int rs;
	struct crypto_aead *a = crypto_alloc_aead(alg_name, 0, 0);

	if (IS_ERR(a)) {
		T_ERR("Cannot preload %s module, please check /proc/crypto.\n",
		      alg_name);
		return PTR_ERR(a);
	}

	rs = crypto_aead_reqsize(a) + sizeof(struct aead_request);
	if (rs > g_aead_max_reqsize)
		g_aead_max_reqsize = rs;

	crypto_free_aead(a);

	return 0;
}

static int __init
ttls_hashmod_preload(const char *alg_name)
{
	struct crypto_shash *h = crypto_alloc_shash(alg_name, 0, 0);

	if (IS_ERR(h)) {
		T_ERR("Cannot preload %s module, please check /proc/crypto.\n",
		      alg_name);
		return PTR_ERR(h);
	}
	crypto_free_shash(h);

	return 0;
}

int __init
ttls_crypto_modinit(void)
{
	int r;
	const char *name;
	TlsCipherDef *c;
	TlsHashDef *h;
	char *inst_sets[] = {
		"",
		"-ssse3",
		"-avx",
		"-avx2",
		"-ni",
		NULL
	};
	char **inst_set;

	for (c = ttls_ciphers; c->info; c++) {
		name = c->info->drv_name;
		if ((r = ttls_ciphermod_preload(name)))
			return r;
		c->info->alg = crypto_find_aead(name, 0, 0);
		if (IS_ERR(c->info->alg)) {
			r = PTR_ERR(c->info->alg);
			goto err;
		}
	}

	/*
	 * Each hash algorithm may have multiple implementations, optimized for
	 * different instruction set extensions (such as AVX, AVX2, and so on).
	 * As we want the fastest available, we try to load
	 * all the implementations. Crypto API will then choose one with
	 * the highest priority.
	 */
	for (inst_set = inst_sets; *inst_set; ++inst_set)
		for (h = ttls_hashes; h->info; ++h)
			request_module("crypto-%s%s", h->info->alg_name, *inst_set);

	for (h = ttls_hashes; h->info; h++) {
		name = h->info->alg_name;
		if ((r = ttls_hashmod_preload(name)))
			return r;
		h->info->alg_hash = crypto_find_shash(name, 0, 0);
		if (IS_ERR(h->info->alg_hash)) {
			r = PTR_ERR(h->info->alg_hash);
			goto err;
		}

		name = h->info->hmac_name;
		if ((r = ttls_hashmod_preload(name)))
			return r;
		h->info->alg_hmac = crypto_find_shash(name, 0, 0);
		if (IS_ERR(h->info->alg_hmac)) {
			r = PTR_ERR(h->info->alg_hmac);
			goto err;
		}
	}

	return 0;
err:
	T_ERR("Cannot find %s algorithm, please check /proc/crypto for it\n",
	      name);
	return r;
}
