/**
 * \file pk_internal.h
 *
 * \brief Public Key abstraction layer: wrapper functions
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
#ifndef TTLS_PK_WRAP_H
#define TTLS_PK_WRAP_H

#include "config.h"
#include "pk.h"

struct ttls_pk_info_t
{
	/** Public key type */
	ttls_pk_type_t type;

	/** Type name */
	const char *name;

	/** Get key size in bits */
	size_t (*get_bitlen)(const void *);

	/** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
	int (*can_do)(ttls_pk_type_t type);

	/** Verify signature */
	int (*verify_func)(void *ctx, ttls_md_type_t md_alg,
			const unsigned char *hash, size_t hash_len,
			const unsigned char *sig, size_t sig_len);

	/** Make signature */
	int (*sign_func)(void *ctx, ttls_md_type_t md_alg,
		  const unsigned char *hash, size_t hash_len,
		  unsigned char *sig, size_t *sig_len);

	/** Decrypt message */
	int (*decrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
			 unsigned char *output, size_t *olen, size_t osize);

	/** Encrypt message */
	int (*encrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
			 unsigned char *output, size_t *olen, size_t osize);

	/** Check public-private key pair */
	int (*check_pair_func)(const void *pub, const void *prv);

	/** Allocate a new context */
	void * (*ctx_alloc_func)(void);

	/** Free the given context */
	void (*ctx_free_func)(void *ctx);

	/** Interface with the debug module */
	void (*debug_func)(const void *ctx, ttls_pk_debug_item *items);

};
#if defined(TTLS_PK_RSA_ALT_SUPPORT)
/* Container for RSA-alt */
typedef struct
{
	void *key;
	ttls_pk_rsa_alt_decrypt_func decrypt_func;
	ttls_pk_rsa_alt_sign_func sign_func;
	ttls_pk_rsa_alt_key_len_func key_len_func;
} ttls_rsa_alt_context;
#endif

extern const ttls_pk_info_t ttls_rsa_info;

extern const ttls_pk_info_t ttls_eckey_info;
extern const ttls_pk_info_t ttls_eckeydh_info;
extern const ttls_pk_info_t ttls_ecdsa_info;

#if defined(TTLS_PK_RSA_ALT_SUPPORT)
extern const ttls_pk_info_t ttls_rsa_alt_info;
#endif

#endif /* TTLS_PK_WRAP_H */
