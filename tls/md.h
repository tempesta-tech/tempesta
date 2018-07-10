/*
 *		Tempesta TLS
 *
 * Adriaan de Jong <dejong@fox-it.com>
 * Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
#ifndef TTLS_MD_H
#define TTLS_MD_H

#include <crypto/hash.h>
#include <crypto/sha.h>

/**< The selected feature is not available. */
#define TTLS_ERR_MD_FEATURE_UNAVAILABLE		-0x5080
/**< Bad input parameters to function. */
#define TTLS_ERR_MD_BAD_INPUT_DATA		-0x5100
/**< Failed to allocate memory. */
#define TTLS_ERR_MD_ALLOC_FAILED		-0x5180
/**< Opening or reading of file failed. */
#define TTLS_ERR_MD_FILE_IO_ERROR		-0x5200
/**< MD hardware accelerator failed. */
#define TTLS_ERR_MD_HW_ACCEL_FAILED		-0x5280

/* Supported message digests. */
typedef enum {
	TTLS_MD_NONE = 0,
	TTLS_MD_SHA1,
	TTLS_MD_SHA224,
	TTLS_MD_SHA256,
	TTLS_MD_SHA384,
	TTLS_MD_SHA512,
	TTLS_MD_RIPEMD160,
} ttls_md_type_t;

#define TTLS_MD_MAX_SIZE		64  /* longest known is SHA512 */

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 *
 * @type		- Digest identifier;
 * @name		- Name of the message digest;
 * @size		- Output length of the digest function in bytes;
 * @block_size		- Block length of the digest function in bytes;
 * @starts_func		- Digest initialisation function;
 * @update_func		- Digest update function;
 * @finish_func		- Digest finalisation function;
 * @ctx_alloc_func	- Allocate a new context;
 * @ctx_free_func	- Free the given context;
 * @ctx_tmpl		- context template;
 */
typedef struct TlsMdInfo {
	ttls_md_type_t		type;
	const char		*name;
	int			size;
	int			block_size;
	int (*starts_func)(struct shash_desc *ctx);
	int (*update_func)(struct shash_desc *ctx, const unsigned char *input,
			   size_t ilen);
	int (*finish_func)(struct shash_desc *ctx, unsigned char *output);
	struct shash_desc *(*ctx_alloc_func)(void);
	void (*ctx_free_func)(struct shash_desc *ctx);
	struct crypto_shash		*tfm;
} TlsMdInfo;

/**
 * The generic message-digest context.
 *
 * @md_info		- Information about the associated message digest;
 * @md_ctx		- The digest-specific context;
 * @hmac_ctx		- The HMAC part of the context;
 */
typedef struct {
	const TlsMdInfo		*md_info;
	struct shash_desc	*md_ctx;
	void			*hmac_ctx;
} ttls_md_context_t;

typedef struct {
	struct shash_desc	desc;
	struct sha256_state	state;
} CRYPTO_MINALIGN_ATTR ttls_sha256_context;

typedef struct {
	struct shash_desc	desc;
	struct sha512_state	state;
} CRYPTO_MINALIGN_ATTR ttls_sha512_context;

const TlsMdInfo *ttls_md_info_from_type(ttls_md_type_t md_type);
void ttls_md_init(ttls_md_context_t *ctx);
void ttls_md_free(ttls_md_context_t *ctx);

/*
 * This function selects the message digest algorithm to use, and allocates
 * internal structures. It should be called after ttls_md_init() or
 * ttls_md_free(). Makes it necessary to call ttls_md_free() later.
 */
int ttls_md_setup(ttls_md_context_t *ctx, const TlsMdInfo *md_info,
		  int hmac);

int ttls_md_starts(ttls_md_context_t *ctx);
int ttls_md_update(ttls_md_context_t *ctx, const unsigned char *input,
		   size_t ilen);
int ttls_md_finish(ttls_md_context_t *ctx, unsigned char *output);

/*
 * This function calculates the message-digest of a buffer, with respect to a
 * configurable message-digest algorithm in a single call.
 */
int ttls_md(const TlsMdInfo *md_info, const unsigned char *input,
	    size_t ilen, unsigned char *output);

/*
 * This function sets the HMAC key and prepares to authenticate a new message.
 * Call this function after ttls_md_setup(), to use the MD context for an HMAC
 * calculation, then call ttls_md_hmac_update() to provide the input data, and
 * ttls_md_hmac_finish() to get the HMAC value.
 */
int ttls_md_hmac_starts(ttls_md_context_t *ctx, const unsigned char *key,
			size_t keylen);
int ttls_md_hmac_update(ttls_md_context_t *ctx, const unsigned char *input,
			size_t ilen);
int ttls_md_hmac_finish(ttls_md_context_t *ctx, unsigned char *output);

/*
 * This function prepares to authenticate a new message with the same key as
 * the previous HMAC operation. You may call this function after
 * ttls_md_hmac_finish(). Afterwards call ttls_md_hmac_update() to pass the new
 * input.
 */
int ttls_md_hmac_reset(ttls_md_context_t *ctx);

void ttls_sha256_init_start(ttls_sha256_context *ctx);
void ttls_sha384_init_start(ttls_sha512_context *ctx);

void ttls_free_md_ctx_tmpls(void);
int ttls_init_md_ctx_tmpls(void);

static inline unsigned char
ttls_md_get_size(const TlsMdInfo *md_info)
{
	BUG_ON(!md_info);

	return md_info->size;
}

static inline const char *
ttls_md_get_name(const TlsMdInfo *md_info)
{
	BUG_ON(!md_info);

	return md_info->name;
}

#endif /* TTLS_MD_H */
