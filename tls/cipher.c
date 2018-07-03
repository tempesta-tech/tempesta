/**
 * \file cipher.c
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
#include "cipher.h"
#include "cipher_internal.h"
#include "gcm.h"
#include "ccm.h"
#if defined(TTLS_CMAC_C)
#include "cmac.h"
#endif

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = (unsigned char*)v; while (n--) *p++ = 0;
}

static int supported_init = 0;

const int *ttls_cipher_list(void)
{
	const ttls_cipher_definition_t *def;
	int *type;

	if (! supported_init)
	{
		def = ttls_cipher_definitions;
		type = ttls_cipher_supported;

		while (def->type != 0)
			*type++ = (*def++).type;

		*type = 0;

		supported_init = 1;
	}

	return(ttls_cipher_supported);
}

const ttls_cipher_info_t *ttls_cipher_info_from_type(const ttls_cipher_type_t cipher_type)
{
	const ttls_cipher_definition_t *def;

	for (def = ttls_cipher_definitions; def->info != NULL; def++)
		if (def->type == cipher_type)
			return(def->info);

	return(NULL);
}

const ttls_cipher_info_t *ttls_cipher_info_from_string(const char *cipher_name)
{
	const ttls_cipher_definition_t *def;

	if (NULL == cipher_name)
		return(NULL);

	for (def = ttls_cipher_definitions; def->info != NULL; def++)
		if (!  strcmp(def->info->name, cipher_name))
			return(def->info);

	return(NULL);
}

const ttls_cipher_info_t *ttls_cipher_info_from_values(const ttls_cipher_id_t cipher_id,
		  int key_bitlen,
		  const ttls_cipher_mode_t mode)
{
	const ttls_cipher_definition_t *def;

	for (def = ttls_cipher_definitions; def->info != NULL; def++)
		if (def->info->base->cipher == cipher_id &&
			def->info->key_bitlen == (unsigned) key_bitlen &&
			def->info->mode == mode)
			return(def->info);

	return(NULL);
}

void ttls_cipher_init(ttls_cipher_context_t *ctx)
{
	memset(ctx, 0, sizeof(ttls_cipher_context_t));
}

void ttls_cipher_free(ttls_cipher_context_t *ctx)
{
	if (ctx == NULL)
		return;

#if defined(TTLS_CMAC_C)
	if (ctx->cmac_ctx)
	{
	   ttls_zeroize(ctx->cmac_ctx, sizeof(ttls_cmac_context_t));
	   ttls_free(ctx->cmac_ctx);
	}
#endif

	if (ctx->cipher_ctx)
		ctx->cipher_info->base->ctx_free_func(ctx->cipher_ctx);

	ttls_zeroize(ctx, sizeof(ttls_cipher_context_t));
}

int ttls_cipher_setup(ttls_cipher_context_t *ctx, const ttls_cipher_info_t *cipher_info)
{
	if (NULL == cipher_info || NULL == ctx)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	memset(ctx, 0, sizeof(ttls_cipher_context_t));

	if (NULL == (ctx->cipher_ctx = cipher_info->base->ctx_alloc_func()))
		return(TTLS_ERR_CIPHER_ALLOC_FAILED);

	ctx->cipher_info = cipher_info;

	return 0;
}

int ttls_cipher_setkey(ttls_cipher_context_t *ctx, const unsigned char *key,
		int key_bitlen, const ttls_operation_t operation)
{
	if (NULL == ctx || NULL == ctx->cipher_info)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	if ((ctx->cipher_info->flags & TTLS_CIPHER_VARIABLE_KEY_LEN) == 0 &&
		(int) ctx->cipher_info->key_bitlen != key_bitlen)
	{
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);
	}

	ctx->key_bitlen = key_bitlen;
	ctx->operation = operation;

	/*
	 * For CFB and CTR mode always use the encryption key schedule
	 */
	if (TTLS_ENCRYPT == operation ||
		TTLS_MODE_CFB == ctx->cipher_info->mode ||
		TTLS_MODE_CTR == ctx->cipher_info->mode)
	{
		return ctx->cipher_info->base->setkey_enc_func(ctx->cipher_ctx, key,
				ctx->key_bitlen);
	}

	if (TTLS_DECRYPT == operation)
		return ctx->cipher_info->base->setkey_dec_func(ctx->cipher_ctx, key,
				ctx->key_bitlen);

	return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);
}

int ttls_cipher_set_iv(ttls_cipher_context_t *ctx,
				   const unsigned char *iv, size_t iv_len)
{
	size_t actual_iv_size;

	if (NULL == ctx || NULL == ctx->cipher_info || NULL == iv)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	/* avoid buffer overflow in ctx->iv */
	if (iv_len > TTLS_MAX_IV_LENGTH)
		return(TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE);

	if ((ctx->cipher_info->flags & TTLS_CIPHER_VARIABLE_IV_LEN) != 0)
		actual_iv_size = iv_len;
	else
	{
		actual_iv_size = ctx->cipher_info->iv_size;

		/* avoid reading past the end of input buffer */
		if (actual_iv_size > iv_len)
			return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);
	}

	memcpy(ctx->iv, iv, actual_iv_size);
	ctx->iv_size = actual_iv_size;

	return 0;
}

int ttls_cipher_reset(ttls_cipher_context_t *ctx)
{
	if (NULL == ctx || NULL == ctx->cipher_info)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	ctx->unprocessed_len = 0;

	return 0;
}

int ttls_cipher_update_ad(ttls_cipher_context_t *ctx,
		  const unsigned char *ad, size_t ad_len)
{
	if (NULL == ctx || NULL == ctx->cipher_info)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	if (TTLS_MODE_GCM == ctx->cipher_info->mode)
	{
		return ttls_gcm_starts((ttls_gcm_context *) ctx->cipher_ctx, ctx->operation,
			   ctx->iv, ctx->iv_size, ad, ad_len);
	}

	return 0;
}

int ttls_cipher_update(ttls_cipher_context_t *ctx, const unsigned char *input,
				   size_t ilen, unsigned char *output, size_t *olen)
{
	int ret;
	size_t block_size = 0;

	if (NULL == ctx || NULL == ctx->cipher_info || NULL == olen)
	{
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);
	}

	*olen = 0;
	block_size = ttls_cipher_get_block_size(ctx);

	if (ctx->cipher_info->mode == TTLS_MODE_ECB)
	{
		if (ilen != block_size)
			return(TTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED);

		*olen = ilen;

		if (0 != (ret = ctx->cipher_info->base->ecb_func(ctx->cipher_ctx,
		ctx->operation, input, output)))
		{
			return ret;
		}

		return 0;
	}

	if (ctx->cipher_info->mode == TTLS_MODE_GCM)
	{
		*olen = ilen;
		return ttls_gcm_update((ttls_gcm_context *) ctx->cipher_ctx, ilen, input,
			   output);
	}

	if (0 == block_size)
	{
		return TTLS_ERR_CIPHER_INVALID_CONTEXT;
	}

	if (input == output &&
	   (ctx->unprocessed_len != 0 || ilen % block_size))
	{
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);
	}

#if defined(TTLS_CIPHER_MODE_STREAM)
	if (ctx->cipher_info->mode == TTLS_MODE_STREAM)
	{
		if (0 != (ret = ctx->cipher_info->base->stream_func(ctx->cipher_ctx,
				ilen, input, output)))
		{
			return ret;
		}

		*olen = ilen;

		return 0;
	}
#endif /* TTLS_CIPHER_MODE_STREAM */

	return(TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE);
}

int ttls_cipher_finish(ttls_cipher_context_t *ctx,
				   unsigned char *output, size_t *olen)
{
	if (NULL == ctx || NULL == ctx->cipher_info || NULL == olen)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	*olen = 0;

	if (TTLS_MODE_CFB == ctx->cipher_info->mode ||
		TTLS_MODE_CTR == ctx->cipher_info->mode ||
		TTLS_MODE_GCM == ctx->cipher_info->mode ||
		TTLS_MODE_STREAM == ctx->cipher_info->mode)
	{
		return 0;
	}

	if (TTLS_MODE_ECB == ctx->cipher_info->mode)
	{
		if (ctx->unprocessed_len != 0)
			return(TTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED);

		return 0;
	}

	return(TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE);
}

int ttls_cipher_write_tag(ttls_cipher_context_t *ctx,
		  unsigned char *tag, size_t tag_len)
{
	if (NULL == ctx || NULL == ctx->cipher_info || NULL == tag)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	if (TTLS_ENCRYPT != ctx->operation)
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

	if (TTLS_MODE_GCM == ctx->cipher_info->mode)
		return ttls_gcm_finish((ttls_gcm_context *) ctx->cipher_ctx, tag, tag_len);

	return 0;
}

int ttls_cipher_check_tag(ttls_cipher_context_t *ctx,
		  const unsigned char *tag, size_t tag_len)
{
	int ret;

	if (NULL == ctx || NULL == ctx->cipher_info ||
		TTLS_DECRYPT != ctx->operation)
	{
		return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);
	}

	if (TTLS_MODE_GCM == ctx->cipher_info->mode)
	{
		unsigned char check_tag[16];
		size_t i;
		int diff;

		if (tag_len > sizeof(check_tag))
			return(TTLS_ERR_CIPHER_BAD_INPUT_DATA);

		if (0 != (ret = ttls_gcm_finish((ttls_gcm_context *) ctx->cipher_ctx,
			 check_tag, tag_len)))
		{
			return ret;
		}

		/* Check the tag in "constant-time" */
		for (diff = 0, i = 0; i < tag_len; i++)
			diff |= tag[i] ^ check_tag[i];

		if (diff != 0)
			return(TTLS_ERR_CIPHER_AUTH_FAILED);

		return 0;
	}

	return 0;
}

/*
 * Packet-oriented wrapper for non-AEAD modes
 */
int ttls_cipher_crypt(ttls_cipher_context_t *ctx,
				  const unsigned char *iv, size_t iv_len,
				  const unsigned char *input, size_t ilen,
				  unsigned char *output, size_t *olen)
{
	int ret;
	size_t finish_olen;

	if ((ret = ttls_cipher_set_iv(ctx, iv, iv_len)) != 0)
		return ret;

	if ((ret = ttls_cipher_reset(ctx)) != 0)
		return ret;

	if ((ret = ttls_cipher_update(ctx, input, ilen, output, olen)) != 0)
		return ret;

	if ((ret = ttls_cipher_finish(ctx, output + *olen, &finish_olen)) != 0)
		return ret;

	*olen += finish_olen;

	return 0;
}

/*
 * Packet-oriented encryption for AEAD modes
 */
int ttls_cipher_auth_encrypt(ttls_cipher_context_t *ctx,
			 const unsigned char *iv, size_t iv_len,
			 const unsigned char *ad, size_t ad_len,
			 const unsigned char *input, size_t ilen,
			 unsigned char *output, size_t *olen,
			 unsigned char *tag, size_t tag_len)
{
	if (TTLS_MODE_GCM == ctx->cipher_info->mode)
	{
		*olen = ilen;
		return(ttls_gcm_crypt_and_tag(ctx->cipher_ctx, TTLS_GCM_ENCRYPT, ilen,
		   iv, iv_len, ad, ad_len, input, output,
		   tag_len, tag));
	}
	if (TTLS_MODE_CCM == ctx->cipher_info->mode)
	{
		*olen = ilen;
		return(ttls_ccm_encrypt_and_tag(ctx->cipher_ctx, ilen,
			 iv, iv_len, ad, ad_len, input, output,
			 tag, tag_len));
	}

	return(TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE);
}

/*
 * Packet-oriented decryption for AEAD modes
 */
int ttls_cipher_auth_decrypt(ttls_cipher_context_t *ctx,
			 const unsigned char *iv, size_t iv_len,
			 const unsigned char *ad, size_t ad_len,
			 const unsigned char *input, size_t ilen,
			 unsigned char *output, size_t *olen,
			 const unsigned char *tag, size_t tag_len)
{
	if (TTLS_MODE_GCM == ctx->cipher_info->mode)
	{
		int ret;

		*olen = ilen;
		ret = ttls_gcm_auth_decrypt(ctx->cipher_ctx, ilen,
			iv, iv_len, ad, ad_len,
			tag, tag_len, input, output);

		if (ret == TTLS_ERR_GCM_AUTH_FAILED)
			ret = TTLS_ERR_CIPHER_AUTH_FAILED;

		return ret;
	}
	if (TTLS_MODE_CCM == ctx->cipher_info->mode)
	{
		int ret;

		*olen = ilen;
		ret = ttls_ccm_auth_decrypt(ctx->cipher_ctx, ilen,
			iv, iv_len, ad, ad_len,
			input, output, tag, tag_len);

		if (ret == TTLS_ERR_CCM_AUTH_FAILED)
			ret = TTLS_ERR_CIPHER_AUTH_FAILED;

		return ret;
	}

	return(TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE);
}
