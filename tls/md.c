/**
 * \file ttls_md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
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
#include "md.h"
#include "md_internal.h"

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(TTLS_SHA512_C)
		TTLS_MD_SHA512,
		TTLS_MD_SHA384,
#endif

#if defined(TTLS_SHA256_C)
		TTLS_MD_SHA256,
		TTLS_MD_SHA224,
#endif

#if defined(TTLS_SHA1_C)
		TTLS_MD_SHA1,
#endif

#if defined(TTLS_RIPEMD160_C)
		TTLS_MD_RIPEMD160,
#endif

#if defined(TTLS_MD5_C)
		TTLS_MD_MD5,
#endif

#if defined(TTLS_MD4_C)
		TTLS_MD_MD4,
#endif

#if defined(TTLS_MD2_C)
		TTLS_MD_MD2,
#endif

		TTLS_MD_NONE
};

const int *ttls_md_list(void)
{
	return(supported_digests);
}

const ttls_md_info_t *ttls_md_info_from_string(const char *md_name)
{
	if (NULL == md_name)
		return(NULL);

	/* Get the appropriate digest information */
#if defined(TTLS_MD2_C)
	if (!strcmp("MD2", md_name))
		return ttls_md_info_from_type(TTLS_MD_MD2);
#endif
#if defined(TTLS_MD4_C)
	if (!strcmp("MD4", md_name))
		return ttls_md_info_from_type(TTLS_MD_MD4);
#endif
#if defined(TTLS_MD5_C)
	if (!strcmp("MD5", md_name))
		return ttls_md_info_from_type(TTLS_MD_MD5);
#endif
#if defined(TTLS_RIPEMD160_C)
	if (!strcmp("RIPEMD160", md_name))
		return ttls_md_info_from_type(TTLS_MD_RIPEMD160);
#endif
#if defined(TTLS_SHA1_C)
	if (!strcmp("SHA1", md_name) || !strcmp("SHA", md_name))
		return ttls_md_info_from_type(TTLS_MD_SHA1);
#endif
#if defined(TTLS_SHA256_C)
	if (!strcmp("SHA224", md_name))
		return ttls_md_info_from_type(TTLS_MD_SHA224);
	if (!strcmp("SHA256", md_name))
		return ttls_md_info_from_type(TTLS_MD_SHA256);
#endif
#if defined(TTLS_SHA512_C)
	if (!strcmp("SHA384", md_name))
		return ttls_md_info_from_type(TTLS_MD_SHA384);
	if (!strcmp("SHA512", md_name))
		return ttls_md_info_from_type(TTLS_MD_SHA512);
#endif
	return(NULL);
}

const ttls_md_info_t *ttls_md_info_from_type(ttls_md_type_t md_type)
{
	switch(md_type)
	{
#if defined(TTLS_MD2_C)
		case TTLS_MD_MD2:
			return(&ttls_md2_info);
#endif
#if defined(TTLS_MD4_C)
		case TTLS_MD_MD4:
			return(&ttls_md4_info);
#endif
#if defined(TTLS_MD5_C)
		case TTLS_MD_MD5:
			return(&ttls_md5_info);
#endif
#if defined(TTLS_RIPEMD160_C)
		case TTLS_MD_RIPEMD160:
			return(&ttls_ripemd160_info);
#endif
#if defined(TTLS_SHA1_C)
		case TTLS_MD_SHA1:
			return(&ttls_sha1_info);
#endif
#if defined(TTLS_SHA256_C)
		case TTLS_MD_SHA224:
			return(&ttls_sha224_info);
		case TTLS_MD_SHA256:
			return(&ttls_sha256_info);
#endif
#if defined(TTLS_SHA512_C)
		case TTLS_MD_SHA384:
			return(&ttls_sha384_info);
		case TTLS_MD_SHA512:
			return(&ttls_sha512_info);
#endif
		default:
			return(NULL);
	}
}

void ttls_md_init(ttls_md_context_t *ctx)
{
	memset(ctx, 0, sizeof(ttls_md_context_t));
}

void ttls_md_free(ttls_md_context_t *ctx)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return;

	if (ctx->md_ctx != NULL)
		ctx->md_info->ctx_free_func(ctx->md_ctx);

	if (ctx->hmac_ctx != NULL)
	{
		ttls_zeroize(ctx->hmac_ctx, 2 * ctx->md_info->block_size);
		ttls_free(ctx->hmac_ctx);
	}

	ttls_zeroize(ctx, sizeof(ttls_md_context_t));
}

int ttls_md_clone(ttls_md_context_t *dst,
					  const ttls_md_context_t *src)
{
	if (dst == NULL || dst->md_info == NULL ||
		src == NULL || src->md_info == NULL ||
		dst->md_info != src->md_info)
	{
		return(TTLS_ERR_MD_BAD_INPUT_DATA);
	}

	dst->md_info->clone_func(dst->md_ctx, src->md_ctx);

	return 0;
}

int ttls_md_setup(ttls_md_context_t *ctx, const ttls_md_info_t *md_info, int hmac)
{
	if (md_info == NULL || ctx == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	if ((ctx->md_ctx = md_info->ctx_alloc_func()) == NULL)
		return(TTLS_ERR_MD_ALLOC_FAILED);

	if (hmac != 0)
	{
		ctx->hmac_ctx = ttls_calloc(2, md_info->block_size);
		if (ctx->hmac_ctx == NULL)
		{
			md_info->ctx_free_func(ctx->md_ctx);
			return(TTLS_ERR_MD_ALLOC_FAILED);
		}
	}

	ctx->md_info = md_info;

	return 0;
}

int ttls_md_starts(ttls_md_context_t *ctx)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	return(ctx->md_info->starts_func(ctx->md_ctx));
}

int ttls_md_update(ttls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	return(ctx->md_info->update_func(ctx->md_ctx, input, ilen));
}

int ttls_md_finish(ttls_md_context_t *ctx, unsigned char *output)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	return(ctx->md_info->finish_func(ctx->md_ctx, output));
}

int ttls_md(const ttls_md_info_t *md_info, const unsigned char *input, size_t ilen,
			unsigned char *output)
{
	if (md_info == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	return(md_info->digest_func(input, ilen, output));
}

int ttls_md_hmac_starts(ttls_md_context_t *ctx, const unsigned char *key, size_t keylen)
{
	int ret;
	unsigned char sum[TTLS_MD_MAX_SIZE];
	unsigned char *ipad, *opad;
	size_t i;

	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	if (keylen > (size_t) ctx->md_info->block_size)
	{
		if ((ret = ctx->md_info->starts_func(ctx->md_ctx)) != 0)
			goto cleanup;
		if ((ret = ctx->md_info->update_func(ctx->md_ctx, key, keylen)) != 0)
			goto cleanup;
		if ((ret = ctx->md_info->finish_func(ctx->md_ctx, sum)) != 0)
			goto cleanup;

		keylen = ctx->md_info->size;
		key = sum;
	}

	ipad = (unsigned char *) ctx->hmac_ctx;
	opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

	memset(ipad, 0x36, ctx->md_info->block_size);
	memset(opad, 0x5C, ctx->md_info->block_size);

	for (i = 0; i < keylen; i++)
	{
		ipad[i] = (unsigned char)(ipad[i] ^ key[i]);
		opad[i] = (unsigned char)(opad[i] ^ key[i]);
	}

	if ((ret = ctx->md_info->starts_func(ctx->md_ctx)) != 0)
		goto cleanup;
	if ((ret = ctx->md_info->update_func(ctx->md_ctx, ipad,
										   ctx->md_info->block_size)) != 0)
		goto cleanup;

cleanup:
	ttls_zeroize(sum, sizeof(sum));

	return ret;
}

int ttls_md_hmac_update(ttls_md_context_t *ctx, const unsigned char *input, size_t ilen)
{
	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	return(ctx->md_info->update_func(ctx->md_ctx, input, ilen));
}

int ttls_md_hmac_finish(ttls_md_context_t *ctx, unsigned char *output)
{
	int ret;
	unsigned char tmp[TTLS_MD_MAX_SIZE];
	unsigned char *opad;

	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

	if ((ret = ctx->md_info->finish_func(ctx->md_ctx, tmp)) != 0)
		return ret;
	if ((ret = ctx->md_info->starts_func(ctx->md_ctx)) != 0)
		return ret;
	if ((ret = ctx->md_info->update_func(ctx->md_ctx, opad,
										   ctx->md_info->block_size)) != 0)
		return ret;
	if ((ret = ctx->md_info->update_func(ctx->md_ctx, tmp,
										   ctx->md_info->size)) != 0)
		return ret;
	return(ctx->md_info->finish_func(ctx->md_ctx, output));
}

int ttls_md_hmac_reset(ttls_md_context_t *ctx)
{
	int ret;
	unsigned char *ipad;

	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	ipad = (unsigned char *) ctx->hmac_ctx;

	if ((ret = ctx->md_info->starts_func(ctx->md_ctx)) != 0)
		return ret;
	return(ctx->md_info->update_func(ctx->md_ctx, ipad,
									   ctx->md_info->block_size));
}

int ttls_md_hmac(const ttls_md_info_t *md_info,
					 const unsigned char *key, size_t keylen,
					 const unsigned char *input, size_t ilen,
					 unsigned char *output)
{
	ttls_md_context_t ctx;
	int ret;

	if (md_info == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	ttls_md_init(&ctx);

	if ((ret = ttls_md_setup(&ctx, md_info, 1)) != 0)
		goto cleanup;

	if ((ret = ttls_md_hmac_starts(&ctx, key, keylen)) != 0)
		goto cleanup;
	if ((ret = ttls_md_hmac_update(&ctx, input, ilen)) != 0)
		goto cleanup;
	if ((ret = ttls_md_hmac_finish(&ctx, output)) != 0)
		goto cleanup;

cleanup:
	ttls_md_free(&ctx);

	return ret;
}

int ttls_md_process(ttls_md_context_t *ctx, const unsigned char *data)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(TTLS_ERR_MD_BAD_INPUT_DATA);

	return(ctx->md_info->process_func(ctx->md_ctx, data));
}

unsigned char ttls_md_get_size(const ttls_md_info_t *md_info)
{
	if (md_info == NULL)
		return 0;

	return md_info->size;
}

ttls_md_type_t ttls_md_get_type(const ttls_md_info_t *md_info)
{
	if (md_info == NULL)
		return(TTLS_MD_NONE);

	return md_info->type;
}

const char *ttls_md_get_name(const ttls_md_info_t *md_info)
{
	if (md_info == NULL)
		return(NULL);

	return md_info->name;
}
