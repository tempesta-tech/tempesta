/*
 *		Tempesta TLS
 *
 * The generic cipher wrapper.
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
 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef TTLS_CIPHER_H
#define TTLS_CIPHER_H

#include "config.h"

/**< The selected feature is not available. */
#define TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE	-0x6080
/**< Bad input parameters. */
#define TTLS_ERR_CIPHER_BAD_INPUT_DATA		-0x6100
/**< Failed to allocate memory. */
#define TTLS_ERR_CIPHER_ALLOC_FAILED		-0x6180
/**< Input data contains invalid padding and is rejected. */
#define TTLS_ERR_CIPHER_INVALID_PADDING		-0x6200
/**< Decryption of block requires a full block. */
#define TTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED	-0x6280
/**< Authentication failed (for AEAD modes). */
#define TTLS_ERR_CIPHER_AUTH_FAILED		-0x6300
/**< The context is invalid. For example, because it was freed. */
#define TTLS_ERR_CIPHER_INVALID_CONTEXT		-0x6380
/**< Cipher hardware accelerator failed. */
#define TTLS_ERR_CIPHER_HW_ACCEL_FAILED		-0x6400

/**< Cipher accepts IVs of variable length. */
#define TTLS_CIPHER_VARIABLE_IV_LEN		0x01
/**< Cipher accepts keys of variable length. */
#define TTLS_CIPHER_VARIABLE_KEY_LEN		0x02

/* An enumeration of supported ciphers. */
typedef enum {
	TTLS_CIPHER_ID_NONE = 0,
	TTLS_CIPHER_ID_AES,
	TTLS_CIPHER_ID_CAMELLIA,
} ttls_cipher_id_t;

/* Supported (cipher, mode) pairs. */
typedef enum {
	TTLS_CIPHER_NONE = 0,
	TTLS_CIPHER_AES_128_GCM,
	TTLS_CIPHER_AES_192_GCM,
	TTLS_CIPHER_AES_256_GCM,
	TTLS_CIPHER_CAMELLIA_128_GCM,
	TTLS_CIPHER_CAMELLIA_192_GCM,
	TTLS_CIPHER_CAMELLIA_256_GCM,
	TTLS_CIPHER_AES_128_CCM,
	TTLS_CIPHER_AES_192_CCM,
	TTLS_CIPHER_AES_256_CCM,
	TTLS_CIPHER_CAMELLIA_128_CCM,
	TTLS_CIPHER_CAMELLIA_192_CCM,
	TTLS_CIPHER_CAMELLIA_256_CCM,
} ttls_cipher_type_t;

/* Supported cipher modes. */
typedef enum {
	TTLS_MODE_NONE = 0,
	TTLS_MODE_GCM,
	TTLS_MODE_STREAM, /* TODO: ChaCha20-Poly1305 */
	TTLS_MODE_CCM,
} ttls_cipher_mode_t;

/* Supported cipher padding types. */
typedef enum {
	TTLS_PADDING_PKCS7 = 0,		/* PKCS7 padding (default) */
	TTLS_PADDING_ONE_AND_ZEROS,	/* ISO/IEC 7816-4 padding */
	TTLS_PADDING_ZEROS_AND_LEN,	/* ANSI X.923 padding */
	TTLS_PADDING_ZEROS,		/* zero padding (not reversible) */
	TTLS_PADDING_NONE,		/* never pad (full blocks only) */
} ttls_cipher_padding_t;

/* Type of operation. */
typedef enum {
	TTLS_OPERATION_NONE = -1,
	TTLS_DECRYPT = 0,
	TTLS_ENCRYPT,
} ttls_operation_t;

/** Maximum length of any IV, in Bytes. */
#define TTLS_MAX_IV_LENGTH		16
/** Maximum block size of any cipher, in Bytes. */
#define TTLS_MAX_BLOCK_LENGTH		16

/**
 * Base cipher information. The non-mode specific functions and values.
 *
 * @cipher		- Base Cipher type (e.g. TTLS_CIPHER_ID_AES);
 * @stream_func		- Encrypt using STREAM;
 * @setkey_enc_func	- Set key for encryption purposes;
 * @setkey_dec_func	- Set key for decryption purposes;
 * @ctx_alloc_func	- Allocate a new context;
 * @ctx_free_func	- Free the given context;
 * @ctx_tmpl		- context template;
 */
struct ttls_cipher_base_t {
	ttls_cipher_id_t	cipher;
#if defined(TTLS_CIPHER_MODE_STREAM)
	int (*stream_func)(void *ctx, size_t length, const unsigned char *input,
			   unsigned char *output);
#endif
	int (*setkey_enc_func)(void *ctx, const unsigned char *key,
			       unsigned int len);
	int (*setkey_dec_func)(void *ctx, const unsigned char *key,
			       unsigned int len);

	void * (*ctx_alloc_func)(void);

	void (*ctx_free_func)(void *ctx);

	struct crypto_aead	*tfm;
};

/**
 * Cipher information. Allows calling cipher functions in a generic way.
 *
 * @type	- Full cipher identifier, e.g. TTLS_CIPHER_AES_256_CBC;
 * @mode	- The cipher mode. For example, TTLS_MODE_CBC;
 * @key_len	- The cipher key length, in bytes. This is the default length
 *		  for variable sized ciphers. Includes parity bits for ciphers
 *		  like DES;
 * @name	- Name of the cipher;
 * @iv_size	- IV or nonce size, in Bytes. For ciphers that accept variable
 *		  IV sizes, this is the recommended size;
 * @flags	- Flags to set. For example, if the cipher supports variable IV
 *		  sizes or variable key sizes;
 * @block_size	- The block size, in Bytes;
 * @base	- Struct for base cipher information and functions;
 */
typedef struct {
	ttls_cipher_type_t		type;
	ttls_cipher_mode_t		mode;
	unsigned int			key_len;
	const char			*name;
	unsigned int			iv_size;
	int				flags;
	unsigned int			block_size;
	const ttls_cipher_base_t	*base;
} ttls_cipher_info_t;

/**
 * Generic cipher context.
 *
 * @cipher_info		- Information about the associated cipher;
 * @cipher_ctx		- The cipher-specific context;
 * @key_len		- Key length to use;
 * @operation		- Operation that the key of the context has been
 *			  initialized for;
 * @unprocessed_len	- Number of Bytes that have not been processed yet;
 * @iv_size		- IV size in Bytes, for ciphers with variable-length
 *			  IVs;
 * @unprocessed_data	- Buffer for input that has not been processed yet;
 * @iv			- Current IV or NONCE_COUNTER for CTR-mode;
 */
typedef struct {
	const ttls_cipher_info_t	*cipher_info;
	struct crypto_aead		*cipher_ctx;
	unsigned char			key_len;
	unsigned char			operation;
	unsigned char			unprocessed_len;
	unsigned char			iv_size;
	unsigned char			unprocessed_data[TTLS_MAX_BLOCK_LENGTH];
	unsigned char			iv[TTLS_MAX_IV_LENGTH];
} ttls_cipher_context_t;

typedef struct {
	ttls_cipher_type_t		type;
	const ttls_cipher_info_t	*info;
} ttls_cipher_definition_t;

const ttls_cipher_info_t *ttls_cipher_info_from_type(
					const ttls_cipher_type_t cipher_type);

void ttls_cipher_init(ttls_cipher_context_t *ctx);
void ttls_cipher_free(ttls_cipher_context_t *ctx);
int ttls_cipher_setup(ttls_cipher_context_t *ctx, const ttls_cipher_info_t *ci,
		      unsigned int tag_size);

int ttls_cipher_setkey(ttls_cipher_context_t *ctx, const unsigned char *key,
		       int key_len, const ttls_operation_t operation);

void ttls_free_cipher_ctx_tmpls(void);
int ttls_init_cipher_ctx_tmpls(void);

extern const ttls_cipher_definition_t ttls_cipher_definitions[];
extern int ttls_cipher_supported[];

#endif /* TTLS_CIPHER_H */
