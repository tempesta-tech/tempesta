/**
 * \file md_wrap.c
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
#include "md_internal.h"
#if defined(TTLS_RIPEMD160_C)
#include "ripemd160.h"
#endif
#if defined(TTLS_SHA256_C)
#include "sha256.h"
#endif
#if defined(TTLS_SHA512_C)
#include "sha512.h"
#endif

#if defined(TTLS_RIPEMD160_C)

static int ripemd160_starts_wrap(void *ctx)
{
	return(ttls_ripemd160_starts_ret((ttls_ripemd160_context *) ctx));
}

static int ripemd160_update_wrap(void *ctx, const unsigned char *input,
		   size_t ilen)
{
	return(ttls_ripemd160_update_ret((ttls_ripemd160_context *) ctx,
				  input, ilen));
}

static int ripemd160_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_ripemd160_finish_ret((ttls_ripemd160_context *) ctx,
				  output));
}

static void *ripemd160_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_ripemd160_context));

	if (ctx != NULL)
		ttls_ripemd160_init((ttls_ripemd160_context *) ctx);

	return(ctx);
}

static void ripemd160_ctx_free(void *ctx)
{
	ttls_ripemd160_free((ttls_ripemd160_context *) ctx);
	ttls_free(ctx);
}

static void ripemd160_clone_wrap(void *dst, const void *src)
{
	ttls_ripemd160_clone((ttls_ripemd160_context *) dst,
		   (const ttls_ripemd160_context *) src);
}

static int ripemd160_process_wrap(void *ctx, const unsigned char *data)
{
	return(ttls_internal_ripemd160_process(
		(ttls_ripemd160_context *) ctx, data));
}

const ttls_md_info_t ttls_ripemd160_info = {
	TTLS_MD_RIPEMD160,
	"RIPEMD160",
	20,
	64,
	ripemd160_starts_wrap,
	ripemd160_update_wrap,
	ripemd160_finish_wrap,
	ttls_ripemd160_ret,
	ripemd160_ctx_alloc,
	ripemd160_ctx_free,
	ripemd160_clone_wrap,
	ripemd160_process_wrap,
};

#endif /* TTLS_RIPEMD160_C */

/*
 * Wrappers for generic message digests
 */
#if defined(TTLS_SHA256_C)

static int sha224_starts_wrap(void *ctx)
{
	return(ttls_sha256_starts_ret((ttls_sha256_context *) ctx, 1));
}

static int sha224_update_wrap(void *ctx, const unsigned char *input,
		size_t ilen)
{
	return(ttls_sha256_update_ret((ttls_sha256_context *) ctx,
			   input, ilen));
}

static int sha224_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_sha256_finish_ret((ttls_sha256_context *) ctx,
			   output));
}

static int sha224_wrap(const unsigned char *input, size_t ilen,
			unsigned char *output)
{
	return(ttls_sha256_ret(input, ilen, output, 1));
}

static void *sha224_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_sha256_context));

	if (ctx != NULL)
		ttls_sha256_init((ttls_sha256_context *) ctx);

	return(ctx);
}

static void sha224_ctx_free(void *ctx)
{
	ttls_sha256_free((ttls_sha256_context *) ctx);
	ttls_free(ctx);
}

static void sha224_clone_wrap(void *dst, const void *src)
{
	ttls_sha256_clone((ttls_sha256_context *) dst,
		(const ttls_sha256_context *) src);
}

static int sha224_process_wrap(void *ctx, const unsigned char *data)
{
	return(ttls_internal_sha256_process((ttls_sha256_context *) ctx,
		 data));
}

const ttls_md_info_t ttls_sha224_info = {
	TTLS_MD_SHA224,
	"SHA224",
	28,
	64,
	sha224_starts_wrap,
	sha224_update_wrap,
	sha224_finish_wrap,
	sha224_wrap,
	sha224_ctx_alloc,
	sha224_ctx_free,
	sha224_clone_wrap,
	sha224_process_wrap,
};

static int sha256_starts_wrap(void *ctx)
{
	return(ttls_sha256_starts_ret((ttls_sha256_context *) ctx, 0));
}

static int sha256_wrap(const unsigned char *input, size_t ilen,
			unsigned char *output)
{
	return(ttls_sha256_ret(input, ilen, output, 0));
}

const ttls_md_info_t ttls_sha256_info = {
	TTLS_MD_SHA256,
	"SHA256",
	32,
	64,
	sha256_starts_wrap,
	sha224_update_wrap,
	sha224_finish_wrap,
	sha256_wrap,
	sha224_ctx_alloc,
	sha224_ctx_free,
	sha224_clone_wrap,
	sha224_process_wrap,
};

#endif /* TTLS_SHA256_C */

#if defined(TTLS_SHA512_C)

static int sha384_starts_wrap(void *ctx)
{
	return(ttls_sha512_starts_ret((ttls_sha512_context *) ctx, 1));
}

static int sha384_update_wrap(void *ctx, const unsigned char *input,
				   size_t ilen)
{
	return(ttls_sha512_update_ret((ttls_sha512_context *) ctx,
			   input, ilen));
}

static int sha384_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_sha512_finish_ret((ttls_sha512_context *) ctx,
			   output));
}

static int sha384_wrap(const unsigned char *input, size_t ilen,
			unsigned char *output)
{
	return(ttls_sha512_ret(input, ilen, output, 1));
}

static void *sha384_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_sha512_context));

	if (ctx != NULL)
		ttls_sha512_init((ttls_sha512_context *) ctx);

	return(ctx);
}

static void sha384_ctx_free(void *ctx)
{
	ttls_sha512_free((ttls_sha512_context *) ctx);
	ttls_free(ctx);
}

static void sha384_clone_wrap(void *dst, const void *src)
{
	ttls_sha512_clone((ttls_sha512_context *) dst,
		(const ttls_sha512_context *) src);
}

static int sha384_process_wrap(void *ctx, const unsigned char *data)
{
	return(ttls_internal_sha512_process((ttls_sha512_context *) ctx,
		 data));
}

const ttls_md_info_t ttls_sha384_info = {
	TTLS_MD_SHA384,
	"SHA384",
	48,
	128,
	sha384_starts_wrap,
	sha384_update_wrap,
	sha384_finish_wrap,
	sha384_wrap,
	sha384_ctx_alloc,
	sha384_ctx_free,
	sha384_clone_wrap,
	sha384_process_wrap,
};

static int sha512_starts_wrap(void *ctx)
{
	return(ttls_sha512_starts_ret((ttls_sha512_context *) ctx, 0));
}

static int sha512_wrap(const unsigned char *input, size_t ilen,
			unsigned char *output)
{
	return(ttls_sha512_ret(input, ilen, output, 0));
}

const ttls_md_info_t ttls_sha512_info = {
	TTLS_MD_SHA512,
	"SHA512",
	64,
	128,
	sha512_starts_wrap,
	sha384_update_wrap,
	sha384_finish_wrap,
	sha512_wrap,
	sha384_ctx_alloc,
	sha384_ctx_free,
	sha384_clone_wrap,
	sha384_process_wrap,
};

#endif /* TTLS_SHA512_C */
