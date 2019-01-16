/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer
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
#include "debug.h"
#include "pk.h"
#include "pk_internal.h"
#include "rsa.h"
#include "tls_internal.h"
#include "ecp.h"
#include "ecdsa.h"

void
ttls_pk_init(ttls_pk_context *ctx)
{
	BUG_ON(!ctx);
	ctx->pk_info = NULL;
	ctx->pk_ctx = NULL;
}
EXPORT_SYMBOL(ttls_pk_init);

#define TTLS_PK_ARGS_SANITY_CHECK(fname)				\
do {									\
	if (unlikely(!ctx || !ctx->pk_info))				\
		return TTLS_ERR_PK_BAD_INPUT_DATA;			\
	if (unlikely(!ctx->pk_info->fname##_func ))			\
		return TTLS_ERR_PK_TYPE_MISMATCH;			\
} while (0)

void
ttls_pk_free(ttls_pk_context *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return;

	ctx->pk_info->ctx_free_func(ctx->pk_ctx);

	ttls_bzero_safe(ctx, sizeof(ttls_pk_context));
}
EXPORT_SYMBOL(ttls_pk_free);

const ttls_pk_info_t *
ttls_pk_info_from_type(ttls_pk_type_t pk_type)
{
	switch (pk_type) {
	case TTLS_PK_RSA:
		return &ttls_rsa_info;
	case TTLS_PK_ECKEY:
		return &ttls_eckey_info;
	case TTLS_PK_ECKEY_DH:
		return &ttls_eckeydh_info;
	case TTLS_PK_ECDSA:
		return &ttls_ecdsa_info;
	/* TTLS_PK_RSA_ALT omitted on purpose */
	default:
		return NULL;
	}
}

int
ttls_pk_setup(ttls_pk_context *ctx, const ttls_pk_info_t *info)
{
	might_sleep();
	BUG_ON(!ctx || !info || ctx->pk_info);

	T_DBG("setup pk context for %s(%d) key\n", info->name, info->type);
	if (!(ctx->pk_ctx = info->ctx_alloc_func()))
		return TTLS_ERR_PK_ALLOC_FAILED;
	ctx->pk_info = info;

	return 0;
}

/**
 * Tell if a PK can do the operations of the given type.
 */
int
ttls_pk_can_do(const ttls_pk_context *ctx, ttls_pk_type_t type)
{
	/* null or NONE context can't do anything */
	if (!ctx || !ctx->pk_info)
		return 0;

	return ctx->pk_info->can_do(type);
}

static inline int
pk_hashlen_helper(ttls_md_type_t md_alg, size_t *hash_len)
{
	const TlsMdInfo *md_info;

	if (*hash_len)
		return 0;

	if (!(md_info = ttls_md_info_from_type(md_alg)))
		return -1;
	*hash_len = ttls_md_get_size(md_info);

	return 0;
}

/**
 * Verify a signature.
 */
int
ttls_pk_verify(ttls_pk_context *ctx, ttls_md_type_t md_alg,
	       const unsigned char *hash, size_t hash_len,
	       const unsigned char *sig, size_t sig_len)
{
	TTLS_PK_ARGS_SANITY_CHECK(verify);
	if (unlikely(pk_hashlen_helper(md_alg, &hash_len)))
		return TTLS_ERR_PK_BAD_INPUT_DATA;

	return ctx->pk_info->verify_func(ctx->pk_ctx, md_alg, hash, hash_len,
					 sig, sig_len);
}

/**
 * Verify a signature with options.
 */
int
ttls_pk_verify_ext(ttls_pk_type_t type, const void *options,
		   ttls_pk_context *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash, size_t hash_len,
		   const unsigned char *sig, size_t sig_len)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return TTLS_ERR_PK_BAD_INPUT_DATA;
	if (!ttls_pk_can_do(ctx, type))
		return TTLS_ERR_PK_TYPE_MISMATCH;

	if (type == TTLS_PK_RSASSA_PSS) {
		int r;
		const ttls_pk_rsassa_pss_options *pss_opts;

		if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
			return TTLS_ERR_PK_BAD_INPUT_DATA;
		if (!options)
			return TTLS_ERR_PK_BAD_INPUT_DATA;

		pss_opts = (const ttls_pk_rsassa_pss_options *)options;

		if (sig_len < ttls_pk_get_len(ctx))
			return TTLS_ERR_RSA_VERIFY_FAILED;

		r = ttls_rsa_rsassa_pss_verify_ext(ttls_pk_rsa(*ctx),
						   TTLS_RSA_PUBLIC, md_alg,
						   (unsigned int)hash_len,
						   hash,
						   pss_opts->mgf1_hash_id,
						   pss_opts->expected_salt_len,
						   sig);
		if (r)
			return r;
		if (sig_len > ttls_pk_get_len(ctx))
			return TTLS_ERR_PK_SIG_LEN_MISMATCH;
		return 0;
	}

	/* General case: no options */
	if (options)
		return TTLS_ERR_PK_BAD_INPUT_DATA;

	return ttls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len);
}

/**
 * Make a signature.
 */
int
ttls_pk_sign(ttls_pk_context *ctx, ttls_md_type_t md_alg,
	     const unsigned char *hash, size_t hash_len,
	     unsigned char *sig, size_t *sig_len)
{
	TTLS_PK_ARGS_SANITY_CHECK(sign);
	if (unlikely(pk_hashlen_helper(md_alg, &hash_len)))
		return TTLS_ERR_PK_BAD_INPUT_DATA;

	return ctx->pk_info->sign_func(ctx->pk_ctx, md_alg, hash, hash_len,
				       sig, sig_len);
}

/**
 * Decrypt message.
 */
int
ttls_pk_decrypt(ttls_pk_context *ctx, const unsigned char *input, size_t ilen,
		unsigned char *output, size_t *olen, size_t osize)
{
	TTLS_PK_ARGS_SANITY_CHECK(decrypt);

	return ctx->pk_info->decrypt_func(ctx->pk_ctx, input, ilen, output,
					  olen, osize);
}

/*
 * Encrypt message
 */
int
ttls_pk_encrypt(ttls_pk_context *ctx, const unsigned char *input, size_t ilen,
		unsigned char *output, size_t *olen, size_t osize)
{
	TTLS_PK_ARGS_SANITY_CHECK(encrypt);

	return ctx->pk_info->encrypt_func(ctx->pk_ctx, input, ilen,
					  output, olen, osize);
}

/**
 * Check public-private key pair.
 */
int
ttls_pk_check_pair(const ttls_pk_context *pub, const ttls_pk_context *prv)
{
	if (unlikely(!pub || !pub->pk_info || !prv || !prv->pk_info
		     || !prv->pk_info->check_pair_func))
	{
		return TTLS_ERR_PK_BAD_INPUT_DATA;
	}

	if (prv->pk_info->type == TTLS_PK_RSA_ALT) {
		if (pub->pk_info->type != TTLS_PK_RSA)
			return TTLS_ERR_PK_TYPE_MISMATCH;
	} else {
		if (pub->pk_info != prv->pk_info)
			return TTLS_ERR_PK_TYPE_MISMATCH;
	}

	return prv->pk_info->check_pair_func(pub->pk_ctx, prv->pk_ctx);
}

/**
 * Get key size in bits.
 */
size_t
ttls_pk_get_bitlen(const ttls_pk_context *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return 0;
	return ctx->pk_info->get_bitlen(ctx->pk_ctx);
}

/**
 * Export debug information.
 */
int
ttls_pk_debug(const ttls_pk_context *ctx, ttls_pk_debug_item *items)
{
	TTLS_PK_ARGS_SANITY_CHECK(debug);

	ctx->pk_info->debug_func(ctx->pk_ctx, items);

	return 0;
}

/**
 * Access the PK type name.
 */
const char *
ttls_pk_get_name(const ttls_pk_context *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return "invalid PK";
	return ctx->pk_info->name;
}

/**
 * Access the PK type.
 */
ttls_pk_type_t
ttls_pk_get_type(const ttls_pk_context *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return TTLS_PK_NONE;
	return ctx->pk_info->type;
}
