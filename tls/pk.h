/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer.
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
#ifndef TTLS_PK_H
#define TTLS_PK_H

#include "crypto.h"
#include "rsa.h"
#include "ecp.h"
#include "ecdsa.h"

/* Memory allocation failed. */
#define TTLS_ERR_PK_ALLOC_FAILED	-0x3F80
/* Type mismatch, eg attempt to encrypt with an ECDSA key. */
#define TTLS_ERR_PK_TYPE_MISMATCH	-0x3F00
/* Bad input parameters to function. */
#define TTLS_ERR_PK_BAD_INPUT_DATA	-0x3E80
/* Read/write of file failed. */
#define TTLS_ERR_PK_FILE_IO_ERROR	-0x3E00
/* Unsupported key version. */
#define TTLS_ERR_PK_KEY_INVALID_VERSION	-0x3D80
/* Invalid key tag or value. */
#define TTLS_ERR_PK_KEY_INVALID_FORMAT	-0x3D00
/* Key algorithm is unsupported (only RSA and EC are supported). */
#define TTLS_ERR_PK_UNKNOWN_PK_ALG	-0x3C80
/* Private key password can't be empty. */
#define TTLS_ERR_PK_PASSWORD_REQUIRED	-0x3C00
/* Given private key password does not allow for correct decryption. */
#define TTLS_ERR_PK_PASSWORD_MISMATCH	-0x3B80
/* The pubkey tag or value is invalid (only RSA and EC are supported). */
#define TTLS_ERR_PK_INVALID_PUBKEY	-0x3B00
/* The algorithm tag or value is invalid. */
#define TTLS_ERR_PK_INVALID_ALG		-0x3A80
/* Elliptic curve is unsupported (only NIST curves are supported). */
#define TTLS_ERR_PK_UNKNOWN_NAMED_CURVE	-0x3A00
/* Unavailable feature, e.g. RSA disabled for RSA key. */
#define TTLS_ERR_PK_FEATURE_UNAVAILABLE	-0x3980
/* The signature is valid but its length is less than expected. */
#define TTLS_ERR_PK_SIG_LEN_MISMATCH	-0x3900
/* PK hardware accelerator failed. */
#define TTLS_ERR_PK_HW_ACCEL_FAILED	-0x3880

/**
 * Public key types
 */
typedef enum {
	TTLS_PK_NONE = 0,
	TTLS_PK_RSA,
	TTLS_PK_ECKEY,
	TTLS_PK_ECKEY_DH,
	TTLS_PK_ECDSA,
	TTLS_PK_RSA_ALT,
	TTLS_PK_RSASSA_PSS,
} ttls_pk_type_t;

/**
 * Options for RSASSA-PSS signature verification.
 * See ttls_rsa_rsassa_pss_verify_ext().
 */
typedef struct {
	ttls_md_type_t	mgf1_hash_id;
	int		expected_salt_len;
} ttls_pk_rsassa_pss_options;

/**
 * Types for interfacing with the debug module.
 */
typedef enum {
	TTLS_PK_DEBUG_NONE = 0,
	TTLS_PK_DEBUG_MPI,
	TTLS_PK_DEBUG_ECP,
} ttls_pk_debug_type;

/**
 * Item to send to the debug module.
 */
typedef struct {
	ttls_pk_debug_type	type;
	const char		*name;
	void			*value;
} ttls_pk_debug_item;

/* Public key information and operations. */
typedef struct ttls_pk_info_t ttls_pk_info_t;

/**
 * Public key container.
 *
 * @pk_info	- Public key informations;
 * @pk_ctx	- Underlying public key context.
 */
typedef struct {
	const ttls_pk_info_t	*pk_info;
	void			*pk_ctx;
} ttls_pk_context;

const ttls_pk_info_t *ttls_pk_info_from_type(ttls_pk_type_t pk_type);
void ttls_pk_init(ttls_pk_context *ctx);
void ttls_pk_free(ttls_pk_context *ctx);
int ttls_pk_setup(ttls_pk_context *ctx, const ttls_pk_info_t *info);
size_t ttls_pk_get_bitlen(const ttls_pk_context *ctx);
int ttls_pk_can_do(const ttls_pk_context *ctx, ttls_pk_type_t type);
int ttls_pk_verify(ttls_pk_context *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash, size_t hash_len,
		   const unsigned char *sig, size_t sig_len);
int ttls_pk_verify_ext(ttls_pk_type_t type, const void *options,
		       ttls_pk_context *ctx, ttls_md_type_t md_alg,
		       const unsigned char *hash, size_t hash_len,
		       const unsigned char *sig, size_t sig_len);
int ttls_pk_sign(ttls_pk_context *ctx, ttls_md_type_t md_alg,
		 const unsigned char *hash, size_t hash_len,
		 unsigned char *sig, size_t *sig_len);
int ttls_pk_decrypt(ttls_pk_context *ctx,
		    const unsigned char *input, size_t ilen,
		    unsigned char *output, size_t *olen, size_t osize);
int ttls_pk_encrypt(ttls_pk_context *ctx,
		    const unsigned char *input, size_t ilen,
		    unsigned char *output, size_t *olen, size_t osize);
int ttls_pk_check_pair(const ttls_pk_context *pub, const ttls_pk_context *prv);
int ttls_pk_debug(const ttls_pk_context *ctx, ttls_pk_debug_item *items);
const char * ttls_pk_get_name(const ttls_pk_context *ctx);
ttls_pk_type_t ttls_pk_get_type(const ttls_pk_context *ctx);

int ttls_pk_parse_key(ttls_pk_context *ctx, unsigned char *key, size_t keylen);
int ttls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
			    ttls_pk_context *pk);

/**
 * Quick access to an RSA context inside a PK context.
 *
 * WARNING: You must make sure the PK context actually holds an RSA context
 * before using this function!
 */
static inline ttls_rsa_context *
ttls_pk_rsa(const ttls_pk_context pk)
{
	return (ttls_rsa_context *)(pk).pk_ctx;
}

/**
 * Quick access to an EC context inside a PK context.
 *
 * WARNING: You must make sure the PK context actually holds an EC context
 * before using this function!
 */
static inline ttls_ecp_keypair *
ttls_pk_ec(const ttls_pk_context pk)
{
	return (ttls_ecp_keypair *)(pk).pk_ctx;
}

/**
 * Get the length in bytes of the underlying key.
 */
static inline size_t
ttls_pk_get_len(const ttls_pk_context *ctx)
{
	return (ttls_pk_get_bitlen(ctx) + 7) / 8;
}

#endif /* TTLS_PK_H */
