/*
 *  Public Key abstraction layer
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
#include "pk.h"
#include "pk_internal.h"
#include "rsa.h"
#include "ecp.h"
#if defined(TTLS_ECDSA_C)
#include "ecdsa.h"
#endif

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

/*
 * Initialise a ttls_pk_context
 */
void ttls_pk_init(ttls_pk_context *ctx)
{
	if (ctx == NULL)
		return;

	ctx->pk_info = NULL;
	ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a ttls_pk_context
 */
void ttls_pk_free(ttls_pk_context *ctx)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return;

	ctx->pk_info->ctx_free_func(ctx->pk_ctx);

	ttls_zeroize(ctx, sizeof(ttls_pk_context));
}

/*
 * Get pk_info structure from type
 */
const ttls_pk_info_t * ttls_pk_info_from_type(ttls_pk_type_t pk_type)
{
	switch(pk_type) {
		case TTLS_PK_RSA:
			return(&ttls_rsa_info);
		case TTLS_PK_ECKEY:
			return(&ttls_eckey_info);
		case TTLS_PK_ECKEY_DH:
			return(&ttls_eckeydh_info);
#if defined(TTLS_ECDSA_C)
		case TTLS_PK_ECDSA:
			return(&ttls_ecdsa_info);
#endif
		/* TTLS_PK_RSA_ALT omitted on purpose */
		default:
			return(NULL);
	}
}

/*
 * Initialise context
 */
int ttls_pk_setup(ttls_pk_context *ctx, const ttls_pk_info_t *info)
{
	if (ctx == NULL || info == NULL || ctx->pk_info != NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL)
		return(TTLS_ERR_PK_ALLOC_FAILED);

	ctx->pk_info = info;

	return 0;
}

#if defined(TTLS_PK_RSA_ALT_SUPPORT)
/*
 * Initialize an RSA-alt context
 */
int ttls_pk_setup_rsa_alt(ttls_pk_context *ctx, void * key,
			 ttls_pk_rsa_alt_decrypt_func decrypt_func,
			 ttls_pk_rsa_alt_sign_func sign_func,
			 ttls_pk_rsa_alt_key_len_func key_len_func)
{
	ttls_rsa_alt_context *rsa_alt;
	const ttls_pk_info_t *info = &ttls_rsa_alt_info;

	if (ctx == NULL || ctx->pk_info != NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL)
		return(TTLS_ERR_PK_ALLOC_FAILED);

	ctx->pk_info = info;

	rsa_alt = (ttls_rsa_alt_context *) ctx->pk_ctx;

	rsa_alt->key = key;
	rsa_alt->decrypt_func = decrypt_func;
	rsa_alt->sign_func = sign_func;
	rsa_alt->key_len_func = key_len_func;

	return 0;
}
#endif /* TTLS_PK_RSA_ALT_SUPPORT */

/*
 * Tell if a PK can do the operations of the given type
 */
int ttls_pk_can_do(const ttls_pk_context *ctx, ttls_pk_type_t type)
{
	/* null or NONE context can't do anything */
	if (ctx == NULL || ctx->pk_info == NULL)
		return 0;

	return(ctx->pk_info->can_do(type));
}

/*
 * Helper for ttls_pk_sign and ttls_pk_verify
 */
static inline int pk_hashlen_helper(ttls_md_type_t md_alg, size_t *hash_len)
{
	const ttls_md_info_t *md_info;

	if (*hash_len != 0)
		return 0;

	if ((md_info = ttls_md_info_from_type(md_alg)) == NULL)
		return(-1);

	*hash_len = ttls_md_get_size(md_info);
	return 0;
}

/*
 * Verify a signature
 */
int ttls_pk_verify(ttls_pk_context *ctx, ttls_md_type_t md_alg,
			   const unsigned char *hash, size_t hash_len,
			   const unsigned char *sig, size_t sig_len)
{
	if (ctx == NULL || ctx->pk_info == NULL ||
		pk_hashlen_helper(md_alg, &hash_len) != 0)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (ctx->pk_info->verify_func == NULL)
		return(TTLS_ERR_PK_TYPE_MISMATCH);

	return(ctx->pk_info->verify_func(ctx->pk_ctx, md_alg, hash, hash_len,
			   sig, sig_len));
}

/*
 * Verify a signature with options
 */
int ttls_pk_verify_ext(ttls_pk_type_t type, const void *options,
				   ttls_pk_context *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   const unsigned char *sig, size_t sig_len)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (! ttls_pk_can_do(ctx, type))
		return(TTLS_ERR_PK_TYPE_MISMATCH);

	if (type == TTLS_PK_RSASSA_PSS)
	{
		int ret;
		const ttls_pk_rsassa_pss_options *pss_opts;

		if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
			return(TTLS_ERR_PK_BAD_INPUT_DATA);

		if (options == NULL)
			return(TTLS_ERR_PK_BAD_INPUT_DATA);

		pss_opts = (const ttls_pk_rsassa_pss_options *) options;

		if (sig_len < ttls_pk_get_len(ctx))
			return(TTLS_ERR_RSA_VERIFY_FAILED);

		ret = ttls_rsa_rsassa_pss_verify_ext(ttls_pk_rsa(*ctx),
				NULL, NULL, TTLS_RSA_PUBLIC,
				md_alg, (unsigned int) hash_len, hash,
				pss_opts->mgf1_hash_id,
				pss_opts->expected_salt_len,
				sig);
		if (ret != 0)
			return ret;

		if (sig_len > ttls_pk_get_len(ctx))
			return(TTLS_ERR_PK_SIG_LEN_MISMATCH);

		return 0;
	}

	/* General case: no options */
	if (options != NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	return(ttls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len));
}

/*
 * Make a signature
 */
int ttls_pk_sign(ttls_pk_context *ctx, ttls_md_type_t md_alg,
			 const unsigned char *hash, size_t hash_len,
			 unsigned char *sig, size_t *sig_len)
{
	if (ctx == NULL || ctx->pk_info == NULL ||
		pk_hashlen_helper(md_alg, &hash_len) != 0)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (ctx->pk_info->sign_func == NULL)
		return(TTLS_ERR_PK_TYPE_MISMATCH);

	return ctx->pk_info->sign_func(ctx->pk_ctx, md_alg, hash, hash_len,
				       sig, sig_len);
}

/*
 * Decrypt message
 */
int
ttls_pk_decrypt(ttls_pk_context *ctx, const unsigned char *input, size_t ilen,
		unsigned char *output, size_t *olen, size_t osize)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (ctx->pk_info->decrypt_func == NULL)
		return(TTLS_ERR_PK_TYPE_MISMATCH);

	return ctx->pk_info->decrypt_func(ctx->pk_ctx, input, ilen, output,
					  olen, osize);
}

/*
 * Encrypt message
 */
int ttls_pk_encrypt(ttls_pk_context *ctx,
				const unsigned char *input, size_t ilen,
				unsigned char *output, size_t *olen, size_t osize,
				int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (ctx->pk_info->encrypt_func == NULL)
		return(TTLS_ERR_PK_TYPE_MISMATCH);

	return(ctx->pk_info->encrypt_func(ctx->pk_ctx, input, ilen,
				output, olen, osize, f_rng, p_rng));
}

/*
 * Check public-private key pair
 */
int ttls_pk_check_pair(const ttls_pk_context *pub, const ttls_pk_context *prv)
{
	if (pub == NULL || pub->pk_info == NULL ||
		prv == NULL || prv->pk_info == NULL ||
		prv->pk_info->check_pair_func == NULL)
	{
		return(TTLS_ERR_PK_BAD_INPUT_DATA);
	}

	if (prv->pk_info->type == TTLS_PK_RSA_ALT)
	{
		if (pub->pk_info->type != TTLS_PK_RSA)
			return(TTLS_ERR_PK_TYPE_MISMATCH);
	}
	else
	{
		if (pub->pk_info != prv->pk_info)
			return(TTLS_ERR_PK_TYPE_MISMATCH);
	}

	return(prv->pk_info->check_pair_func(pub->pk_ctx, prv->pk_ctx));
}

/*
 * Get key size in bits
 */
size_t ttls_pk_get_bitlen(const ttls_pk_context *ctx)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return 0;

	return(ctx->pk_info->get_bitlen(ctx->pk_ctx));
}

/*
 * Export debug information
 */
int ttls_pk_debug(const ttls_pk_context *ctx, ttls_pk_debug_item *items)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (ctx->pk_info->debug_func == NULL)
		return(TTLS_ERR_PK_TYPE_MISMATCH);

	ctx->pk_info->debug_func(ctx->pk_ctx, items);
	return 0;
}

/*
 * Access the PK type name
 */
const char *ttls_pk_get_name(const ttls_pk_context *ctx)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return("invalid PK");

	return(ctx->pk_info->name);
}

/*
 * Access the PK type
 */
ttls_pk_type_t ttls_pk_get_type(const ttls_pk_context *ctx)
{
	if (ctx == NULL || ctx->pk_info == NULL)
		return(TTLS_PK_NONE);

	return(ctx->pk_info->type);
}
