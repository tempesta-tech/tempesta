/**
 * \file pkcs11.h
 *
 * \brief Wrapper for PKCS#11 library libpkcs11-helper
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
#ifndef TTLS_PKCS11_H
#define TTLS_PKCS11_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#if defined(TTLS_PKCS11_C)

#include "x509_crt.h"

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

#if (defined(__ARMCC_VERSION) || defined(_MSC_VER)) && \
	!defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Context for PKCS #11 private keys.
 */
typedef struct {
		pkcs11h_certificate_t pkcs11h_cert;
		int len;
} ttls_pkcs11_context;

/**
 * Initialize a ttls_pkcs11_context.
 * (Just making memory references valid.)
 */
void ttls_pkcs11_init(ttls_pkcs11_context *ctx);

/**
 * Fill in a mbed TLS certificate, based on the given PKCS11 helper certificate.
 *
 * \param cert		  X.509 certificate to fill
 * \param pkcs11h_cert  PKCS #11 helper certificate
 *
 * \return			  0 on success.
 */
int ttls_pkcs11_x509_cert_bind(ttls_x509_crt *cert, pkcs11h_certificate_t pkcs11h_cert);

/**
 * Set up a ttls_pkcs11_context storing the given certificate. Note that the
 * ttls_pkcs11_context will take over control of the certificate, freeing it when
 * done.
 *
 * \param priv_key	  Private key structure to fill.
 * \param pkcs11_cert   PKCS #11 helper certificate
 *
 * \return			  0 on success
 */
int ttls_pkcs11_priv_key_bind(ttls_pkcs11_context *priv_key,
		pkcs11h_certificate_t pkcs11_cert);

/**
 * Free the contents of the given private key context. Note that the structure
 * itself is not freed.
 *
 * \param priv_key	  Private key structure to cleanup
 */
void ttls_pkcs11_priv_key_free(ttls_pkcs11_context *priv_key);

/**
 * \brief		  Do an RSA private key decrypt, then remove the message
 *				 padding
 *
 * \param ctx	  PKCS #11 context
 * \param mode	 must be TTLS_RSA_PRIVATE, for compatibility with rsa.c's signature
 * \param input	buffer holding the encrypted data
 * \param output   buffer that will hold the plaintext
 * \param olen	 will contain the plaintext length
 * \param output_max_len	maximum length of the output buffer
 *
 * \return		 0 if successful, or an TTLS_ERR_RSA_XXX error code
 *
 * \note		   The output buffer must be as large as the size
 *				 of ctx->N (eg. 128 bytes if RSA-1024 is used) otherwise
 *				 an error is thrown.
 */
int ttls_pkcs11_decrypt(ttls_pkcs11_context *ctx,
		   int mode, size_t *olen,
		   const unsigned char *input,
		   unsigned char *output,
		   size_t output_max_len);

/**
 * \brief		  Do a private RSA to sign a message digest
 *
 * \param ctx	  PKCS #11 context
 * \param mode	 must be TTLS_RSA_PRIVATE, for compatibility with rsa.c's signature
 * \param md_alg   a TTLS_MD_XXX (use TTLS_MD_NONE for signing raw data)
 * \param hashlen  message digest length (for TTLS_MD_NONE only)
 * \param hash	 buffer holding the message digest
 * \param sig	  buffer that will hold the ciphertext
 *
 * \return		 0 if the signing operation was successful,
 *				 or an TTLS_ERR_RSA_XXX error code
 *
 * \note		   The "sig" buffer must be as large as the size
 *				 of ctx->N (eg. 128 bytes if RSA-1024 is used).
 */
int ttls_pkcs11_sign(ttls_pkcs11_context *ctx,
		int mode,
		ttls_md_type_t md_alg,
		unsigned int hashlen,
		const unsigned char *hash,
		unsigned char *sig);

/**
 * SSL/TLS wrappers for PKCS#11 functions
 */
static inline int ttls_pkcs11_decrypt(void *ctx, int mode, size_t *olen,
			const unsigned char *input, unsigned char *output,
			size_t output_max_len)
{
	return ttls_pkcs11_decrypt((ttls_pkcs11_context *) ctx, mode, olen, input, output,
			   output_max_len);
}

static inline int ttls_pkcs11_sign(void *ctx,
		 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
		 int mode, ttls_md_type_t md_alg, unsigned int hashlen,
		 const unsigned char *hash, unsigned char *sig)
{
	((void) f_rng);
	((void) p_rng);
	return ttls_pkcs11_sign((ttls_pkcs11_context *) ctx, mode, md_alg,
			hashlen, hash, sig);
}

static inline size_t ttls_pkcs11_key_len(void *ctx)
{
	return ((ttls_pkcs11_context *) ctx)->len;
}

#ifdef __cplusplus
}
#endif

#endif /* TTLS_PKCS11_C */

#endif /* TTLS_PKCS11_H */
