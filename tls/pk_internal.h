/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer: wrapper functions.
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
#ifndef TTLS_PK_WRAP_H
#define TTLS_PK_WRAP_H

#include "config.h"
#include "pk.h"

/*
 * @type		- Public key type;
 * @name		- Type name;
 * @get_bitlen		- Get key size in bits;
 * @can_do		- Tell if the context implements this type
 *			  (e.g. ECKEY can do ECDSA);
 * @verify_func		- Verify signature;
 * @sign_func		- Make signature;
 * @decrypt_func	- Decrypt message;
 * @encrypt_func	- Encrypt message;
 * @check_pair_func	- Check public-private key pair;
 * @ctx_alloc_func	- Allocate a new context;
 * @ctx_free_func	- Free the given context;
 * @debug_func		- Interface with the debug module;
 */
struct ttls_pk_info_t {
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
	int (*decrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
			    unsigned char *output, size_t *olen, size_t osize);
	int (*encrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
			    unsigned char *output, size_t *olen, size_t osize);
	int (*check_pair_func)(const void *pub, const void *prv);
	void *(*ctx_alloc_func)(void);
	void (*ctx_free_func)(void *ctx);
	void (*debug_func)(const void *ctx, ttls_pk_debug_item *items);
};

extern const ttls_pk_info_t ttls_rsa_info;
extern const ttls_pk_info_t ttls_eckey_info;
extern const ttls_pk_info_t ttls_eckeydh_info;
extern const ttls_pk_info_t ttls_ecdsa_info;

#if defined(TTLS_PK_RSA_ALT_SUPPORT)
/* Container for RSA-alt */
typedef struct
{
	void *key;
	ttls_pk_rsa_alt_decrypt_func decrypt_func;
	ttls_pk_rsa_alt_sign_func sign_func;
	ttls_pk_rsa_alt_key_len_func key_len_func;
} ttls_rsa_alt_context;

extern const ttls_pk_info_t ttls_rsa_alt_info;
#endif

#endif /* TTLS_PK_WRAP_H */
