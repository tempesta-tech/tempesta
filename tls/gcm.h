/**
 * \file gcm.h
 *
 * \brief Galois/Counter Mode (GCM) for 128-bit block ciphers, as defined
 *		in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation
 *		(GCM), Natl. Inst. Stand. Technol.</em>
 *
 * For more information on GCM, see <em>NIST SP 800-38D: Recommendation for
 * Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
 *
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef TTLS_GCM_H
#define TTLS_GCM_H

#include "cipher.h"

#include <stdint.h>

#define TTLS_GCM_ENCRYPT	 1
#define TTLS_GCM_DECRYPT	 0

#define TTLS_ERR_GCM_AUTH_FAILED					   -0x0012  /**< Authenticated decryption failed. */
#define TTLS_ERR_GCM_HW_ACCEL_FAILED				   -0x0013  /**< GCM hardware accelerator failed. */
#define TTLS_ERR_GCM_BAD_INPUT						 -0x0014  /**< Bad input parameters to function. */

#if !defined(TTLS_GCM_ALT)

/**
 * \brief		  The GCM context structure.
 */
typedef struct {
	ttls_cipher_context_t cipher_ctx;  /*!< The cipher context used. */
	uint64_t HL[16];					  /*!< Precalculated HTable low. */
	uint64_t HH[16];					  /*!< Precalculated HTable high. */
	uint64_t len;						 /*!< The total length of the encrypted data. */
	uint64_t add_len;					 /*!< The total length of the additional data. */
	unsigned char base_ectr[16];		  /*!< The first ECTR for tag. */
	unsigned char y[16];				  /*!< The Y working value. */
	unsigned char buf[16];				/*!< The buf working value. */
	int mode;							 /*!< The operation to perform:
											   #TTLS_GCM_ENCRYPT or
											   #TTLS_GCM_DECRYPT. */
}
ttls_gcm_context;

/**
 * \brief		   This function initializes the specified GCM context,
 *				  to make references valid, and prepares the context
 *				  for ttls_gcm_setkey() or ttls_gcm_free().
 *
 *				  The function does not bind the GCM context to a particular
 *				  cipher, nor set the key. For this purpose, use
 *				  ttls_gcm_setkey().
 *
 * \param ctx	   The GCM context to initialize.
 */
void ttls_gcm_init(ttls_gcm_context *ctx);

/**
 * \brief		   This function associates a GCM context with a
 *				  cipher algorithm and a key.
 *
 * \param ctx	   The GCM context to initialize.
 * \param cipher	The 128-bit block cipher to use.
 * \param key	   The encryption key.
 * \param keybits   The key size in bits. Valid options are:
 *				  <ul><li>128 bits</li>
 *				  <li>192 bits</li>
 *				  <li>256 bits</li></ul>
 *
 * \return		  \c 0 on success, or a cipher specific error code.
 */
int ttls_gcm_setkey(ttls_gcm_context *ctx,
						ttls_cipher_id_t cipher,
						const unsigned char *key,
						unsigned int keybits);

/**
 * \brief		   This function performs GCM encryption or decryption of a buffer.
 *
 * \note For encryption, the output buffer can be the same as the input buffer.
 *	   For decryption, the output buffer cannot be the same as input buffer.
 *	   If the buffers overlap, the output buffer must trail at least 8 Bytes
 *	   behind the input buffer.
 *
 * \param ctx	   The GCM context to use for encryption or decryption.
 * \param mode	  The operation to perform: #TTLS_GCM_ENCRYPT or
 *				  #TTLS_GCM_DECRYPT.
 * \param length	The length of the input data. This must be a multiple of 16 except in the last call before ttls_gcm_finish().
 * \param iv		The initialization vector.
 * \param iv_len	The length of the IV.
 * \param add	   The buffer holding the additional data.
 * \param add_len   The length of the additional data.
 * \param input	 The buffer holding the input data.
 * \param output	The buffer for holding the output data.
 * \param tag_len   The length of the tag to generate.
 * \param tag	   The buffer for holding the tag.
 *
 * \return		 \c 0 on success.
 */
int ttls_gcm_crypt_and_tag(ttls_gcm_context *ctx,
					   int mode,
					   size_t length,
					   const unsigned char *iv,
					   size_t iv_len,
					   const unsigned char *add,
					   size_t add_len,
					   const unsigned char *input,
					   unsigned char *output,
					   size_t tag_len,
					   unsigned char *tag);

/**
 * \brief		   This function performs a GCM authenticated decryption of a
 *				  buffer.
 *
 * \note For decryption, the output buffer cannot be the same as input buffer.
 *	   If the buffers overlap, the output buffer must trail at least 8 Bytes
 *	   behind the input buffer.
 *
 * \param ctx	   The GCM context.
 * \param length	The length of the input data. This must be a multiple of 16 except in the last call before ttls_gcm_finish().
 * \param iv		The initialization vector.
 * \param iv_len	The length of the IV.
 * \param add	   The buffer holding the additional data.
 * \param add_len   The length of the additional data.
 * \param tag	   The buffer holding the tag.
 * \param tag_len   The length of the tag.
 * \param input	 The buffer holding the input data.
 * \param output	The buffer for holding the output data.
 *
 * \return		 0 if successful and authenticated, or
 *				 #TTLS_ERR_GCM_AUTH_FAILED if tag does not match.
 */
int ttls_gcm_auth_decrypt(ttls_gcm_context *ctx,
					  size_t length,
					  const unsigned char *iv,
					  size_t iv_len,
					  const unsigned char *add,
					  size_t add_len,
					  const unsigned char *tag,
					  size_t tag_len,
					  const unsigned char *input,
					  unsigned char *output);

/**
 * \brief		   This function starts a GCM encryption or decryption
 *				  operation.
 *
 * \param ctx	   The GCM context.
 * \param mode	  The operation to perform: #TTLS_GCM_ENCRYPT or
 *				  #TTLS_GCM_DECRYPT.
 * \param iv		The initialization vector.
 * \param iv_len	The length of the IV.
 * \param add	   The buffer holding the additional data, or NULL if \p add_len is 0.
 * \param add_len   The length of the additional data. If 0, \p  add is NULL.
 *
 * \return		 \c 0 on success.
 */
int ttls_gcm_starts(ttls_gcm_context *ctx,
				int mode,
				const unsigned char *iv,
				size_t iv_len,
				const unsigned char *add,
				size_t add_len);

/**
 * \brief		   This function feeds an input buffer into an ongoing GCM
 *				  encryption or decryption operation.
 *
 *	`			 The function expects input to be a multiple of 16
 *				  Bytes. Only the last call before calling
 *				  ttls_gcm_finish() can be less than 16 Bytes.
 *
 * \note For decryption, the output buffer cannot be the same as input buffer.
 *	   If the buffers overlap, the output buffer must trail at least 8 Bytes
 *	   behind the input buffer.
 *
 * \param ctx	   The GCM context.
 * \param length	The length of the input data. This must be a multiple of 16 except in the last call before ttls_gcm_finish().
 * \param input	 The buffer holding the input data.
 * \param output	The buffer for holding the output data.
 *
 * \return		 \c 0 on success, or #TTLS_ERR_GCM_BAD_INPUT on failure.
 */
int ttls_gcm_update(ttls_gcm_context *ctx,
				size_t length,
				const unsigned char *input,
				unsigned char *output);

/**
 * \brief		   This function finishes the GCM operation and generates
 *				  the authentication tag.
 *
 *				  It wraps up the GCM stream, and generates the
 *				  tag. The tag can have a maximum length of 16 Bytes.
 *
 * \param ctx	   The GCM context.
 * \param tag	   The buffer for holding the tag.
 * \param tag_len   The length of the tag to generate. Must be at least four.
 *
 * \return		  \c 0 on success, or #TTLS_ERR_GCM_BAD_INPUT on failure.
 */
int ttls_gcm_finish(ttls_gcm_context *ctx,
				unsigned char *tag,
				size_t tag_len);

/**
 * \brief		   This function clears a GCM context and the underlying
 *				  cipher sub-context.
 *
 * \param ctx	   The GCM context to clear.
 */
void ttls_gcm_free(ttls_gcm_context *ctx);

#else  /* !TTLS_GCM_ALT */
#include "gcm_alt.h"
#endif /* !TTLS_GCM_ALT */

#endif /* gcm.h */
