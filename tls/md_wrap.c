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

#if defined(TTLS_MD2_C)
#include "md2.h"
#endif

#if defined(TTLS_MD4_C)
#include "md4.h"
#endif

#if defined(TTLS_MD5_C)
#include "md5.h"
#endif

#if defined(TTLS_RIPEMD160_C)
#include "ripemd160.h"
#endif

#if defined(TTLS_SHA1_C)
#include "sha1.h"
#endif

#if defined(TTLS_SHA256_C)
#include "sha256.h"
#endif

#if defined(TTLS_SHA512_C)
#include "sha512.h"
#endif

#if defined(TTLS_MD2_C)

static int md2_starts_wrap(void *ctx)
{
	return(ttls_md2_starts_ret((ttls_md2_context *) ctx));
}

static int md2_update_wrap(void *ctx, const unsigned char *input,
							 size_t ilen)
{
	return(ttls_md2_update_ret((ttls_md2_context *) ctx, input, ilen));
}

static int md2_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_md2_finish_ret((ttls_md2_context *) ctx, output));
}

static void *md2_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_md2_context));

	if (ctx != NULL)
		ttls_md2_init((ttls_md2_context *) ctx);

	return(ctx);
}

static void md2_ctx_free(void *ctx)
{
	ttls_md2_free((ttls_md2_context *) ctx);
	ttls_free(ctx);
}

static void md2_clone_wrap(void *dst, const void *src)
{
	ttls_md2_clone((ttls_md2_context *) dst,
				 (const ttls_md2_context *) src);
}

static int md2_process_wrap(void *ctx, const unsigned char *data)
{
	((void) data);

	return(ttls_internal_md2_process((ttls_md2_context *) ctx));
}

const ttls_md_info_t ttls_md2_info = {
	TTLS_MD_MD2,
	"MD2",
	16,
	16,
	md2_starts_wrap,
	md2_update_wrap,
	md2_finish_wrap,
	ttls_md2_ret,
	md2_ctx_alloc,
	md2_ctx_free,
	md2_clone_wrap,
	md2_process_wrap,
};

#endif /* TTLS_MD2_C */

#if defined(TTLS_MD4_C)

static int md4_starts_wrap(void *ctx)
{
	return(ttls_md4_starts_ret((ttls_md4_context *) ctx));
}

static int md4_update_wrap(void *ctx, const unsigned char *input,
							 size_t ilen)
{
	return(ttls_md4_update_ret((ttls_md4_context *) ctx, input, ilen));
}

static int md4_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_md4_finish_ret((ttls_md4_context *) ctx, output));
}

static void *md4_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_md4_context));

	if (ctx != NULL)
		ttls_md4_init((ttls_md4_context *) ctx);

	return(ctx);
}

static void md4_ctx_free(void *ctx)
{
	ttls_md4_free((ttls_md4_context *) ctx);
	ttls_free(ctx);
}

static void md4_clone_wrap(void *dst, const void *src)
{
	ttls_md4_clone((ttls_md4_context *) dst,
					   (const ttls_md4_context *) src);
}

static int md4_process_wrap(void *ctx, const unsigned char *data)
{
	return(ttls_internal_md4_process((ttls_md4_context *) ctx, data));
}

const ttls_md_info_t ttls_md4_info = {
	TTLS_MD_MD4,
	"MD4",
	16,
	64,
	md4_starts_wrap,
	md4_update_wrap,
	md4_finish_wrap,
	ttls_md4_ret,
	md4_ctx_alloc,
	md4_ctx_free,
	md4_clone_wrap,
	md4_process_wrap,
};

#endif /* TTLS_MD4_C */

#if defined(TTLS_MD5_C)

static int md5_starts_wrap(void *ctx)
{
	return(ttls_md5_starts_ret((ttls_md5_context *) ctx));
}

static int md5_update_wrap(void *ctx, const unsigned char *input,
							 size_t ilen)
{
	return(ttls_md5_update_ret((ttls_md5_context *) ctx, input, ilen));
}

static int md5_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_md5_finish_ret((ttls_md5_context *) ctx, output));
}

static void *md5_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_md5_context));

	if (ctx != NULL)
		ttls_md5_init((ttls_md5_context *) ctx);

	return(ctx);
}

static void md5_ctx_free(void *ctx)
{
	ttls_md5_free((ttls_md5_context *) ctx);
	ttls_free(ctx);
}

static void md5_clone_wrap(void *dst, const void *src)
{
	ttls_md5_clone((ttls_md5_context *) dst,
					   (const ttls_md5_context *) src);
}

static int md5_process_wrap(void *ctx, const unsigned char *data)
{
	return(ttls_internal_md5_process((ttls_md5_context *) ctx, data));
}

const ttls_md_info_t ttls_md5_info = {
	TTLS_MD_MD5,
	"MD5",
	16,
	64,
	md5_starts_wrap,
	md5_update_wrap,
	md5_finish_wrap,
	ttls_md5_ret,
	md5_ctx_alloc,
	md5_ctx_free,
	md5_clone_wrap,
	md5_process_wrap,
};

#endif /* TTLS_MD5_C */

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

#if defined(TTLS_SHA1_C)

static int sha1_starts_wrap(void *ctx)
{
	return(ttls_sha1_starts_ret((ttls_sha1_context *) ctx));
}

static int sha1_update_wrap(void *ctx, const unsigned char *input,
							  size_t ilen)
{
	return(ttls_sha1_update_ret((ttls_sha1_context *) ctx,
									 input, ilen));
}

static int sha1_finish_wrap(void *ctx, unsigned char *output)
{
	return(ttls_sha1_finish_ret((ttls_sha1_context *) ctx, output));
}

static void *sha1_ctx_alloc(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_sha1_context));

	if (ctx != NULL)
		ttls_sha1_init((ttls_sha1_context *) ctx);

	return(ctx);
}

static void sha1_clone_wrap(void *dst, const void *src)
{
	ttls_sha1_clone((ttls_sha1_context *) dst,
				  (const ttls_sha1_context *) src);
}

static void sha1_ctx_free(void *ctx)
{
	ttls_sha1_free((ttls_sha1_context *) ctx);
	ttls_free(ctx);
}

static int sha1_process_wrap(void *ctx, const unsigned char *data)
{
	return(ttls_internal_sha1_process((ttls_sha1_context *) ctx,
										   data));
}

const ttls_md_info_t ttls_sha1_info = {
	TTLS_MD_SHA1,
	"SHA1",
	20,
	64,
	sha1_starts_wrap,
	sha1_update_wrap,
	sha1_finish_wrap,
	ttls_sha1_ret,
	sha1_ctx_alloc,
	sha1_ctx_free,
	sha1_clone_wrap,
	sha1_process_wrap,
};

#endif /* TTLS_SHA1_C */

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
