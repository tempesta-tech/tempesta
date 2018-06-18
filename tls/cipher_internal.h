/**
 * \file cipher_internal.h
 *
 * \brief Cipher wrappers.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
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
#ifndef TTLS_CIPHER_WRAP_H
#define TTLS_CIPHER_WRAP_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Base cipher information. The non-mode specific functions and values.
 */
struct ttls_cipher_base_t
{
	/** Base Cipher type (e.g. TTLS_CIPHER_ID_AES) */
	ttls_cipher_id_t cipher;

	/** Encrypt using ECB */
	int (*ecb_func)(void *ctx, ttls_operation_t mode,
					 const unsigned char *input, unsigned char *output);

#if defined(TTLS_CIPHER_MODE_STREAM)
	/** Encrypt using STREAM */
	int (*stream_func)(void *ctx, size_t length,
						const unsigned char *input, unsigned char *output);
#endif

	/** Set key for encryption purposes */
	int (*setkey_enc_func)(void *ctx, const unsigned char *key,
							unsigned int key_bitlen);

	/** Set key for decryption purposes */
	int (*setkey_dec_func)(void *ctx, const unsigned char *key,
							unsigned int key_bitlen);

	/** Allocate a new context */
	void * (*ctx_alloc_func)(void);

	/** Free the given context */
	void (*ctx_free_func)(void *ctx);

};

typedef struct
{
	ttls_cipher_type_t type;
	const ttls_cipher_info_t *info;
} ttls_cipher_definition_t;

extern const ttls_cipher_definition_t ttls_cipher_definitions[];

extern int ttls_cipher_supported[];

#ifdef __cplusplus
}
#endif

#endif /* TTLS_CIPHER_WRAP_H */
