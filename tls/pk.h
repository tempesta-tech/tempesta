/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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

/*
 * @type		- Public key type;
 * @name		- Type name;
 * @get_bitlen		- Get key size in bits;
 * @can_do		- Tell if the context implements this type
 *			  (e.g. ECKEY can do ECDSA);
 * @verify_func		- Verify signature;
 * @sign_func		- Make signature;
 * @ctx_alloc_func	- Allocate a new context;
 */
typedef struct {
	ttls_pk_type_t	type;
	const char	*name;

	size_t (*get_bitlen)(const void *);
	int (*can_do)(ttls_pk_type_t type);
	int (*verify_func)(void *ctx, ttls_md_type_t md_alg,
			   const unsigned char *hash, size_t hash_len,
			   const unsigned char *sig, size_t sig_len);
	int (*sign_func)(void *ctx, ttls_md_type_t md_alg,
			 const unsigned char *hash, size_t hash_len,
			 unsigned char *sig, size_t *sig_len);
	void *(*ctx_alloc_func)(void);
	void (*ctx_free_func)(void *);
} TlsPkInfo;

/**
 * Public key container.
 *
 * @pk_info	- Public key information;
 * @pk_ctx	- Underlying public key context.
 */
typedef struct {
	const TlsPkInfo		*pk_info;
	void			*pk_ctx;
} TlsPkCtx;

const TlsPkInfo *ttls_pk_info_from_type(ttls_pk_type_t pk_type);
void ttls_pk_init(TlsPkCtx *ctx);
void ttls_pk_free(TlsPkCtx *ctx);
int ttls_pk_setup(TlsPkCtx *ctx, const TlsPkInfo *info);
size_t ttls_pk_get_bitlen(const TlsPkCtx *ctx);
int ttls_pk_can_do(const TlsPkCtx *ctx, ttls_pk_type_t type);
int ttls_pk_verify(TlsPkCtx *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash,
		   const unsigned char *sig, size_t sig_len);
int ttls_pk_verify_ext(ttls_pk_type_t type, const void *options,
		       TlsPkCtx *ctx, ttls_md_type_t md_alg,
		       const unsigned char *hash, size_t hash_len,
		       const unsigned char *sig, size_t sig_len);
int ttls_pk_sign(TlsPkCtx *ctx, ttls_md_type_t md_alg,
		 const unsigned char *hash,
		 unsigned char *sig, size_t *sig_len);
ttls_pk_type_t ttls_pk_get_type(const TlsPkCtx *ctx);

int ttls_pk_parse_key(TlsPkCtx *ctx, unsigned char *key, size_t keylen);
int ttls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
			    TlsPkCtx *pk);

/**
 * Quick access to an RSA context inside a PK context.
 *
 * WARNING: You must make sure the PK context actually holds an RSA context
 * before using this function!
 */
static inline TlsRSACtx *
ttls_pk_rsa(const TlsPkCtx pk)
{
	return (TlsRSACtx *)(pk).pk_ctx;
}

/**
 * Quick access to an EC context inside a PK context.
 *
 * WARNING: You must make sure the PK context actually holds an EC context
 * before using this function!
 */
static inline TlsEcpKeypair *
ttls_pk_ec(const TlsPkCtx pk)
{
	return (TlsEcpKeypair *)(pk).pk_ctx;
}

/**
 * Get the length in bytes of the underlying key.
 */
static inline size_t
ttls_pk_get_len(const TlsPkCtx *ctx)
{
	return (ttls_pk_get_bitlen(ctx) + 7) / 8;
}

#endif /* TTLS_PK_H */
