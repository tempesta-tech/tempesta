/*
 *		Tempesta TLS
 *
 * The Cipher-based Message Authentication Code (CMAC) Mode for Authentication.
 *
 * Copyright (C) 2015-2018, Arm Limited (or its affiliates), All Rights Reserved
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
#ifndef TTLS_CMAC_H
#define TTLS_CMAC_H

#include "cipher.h"

#define TTLS_ERR_CMAC_HW_ACCEL_FAILED -0x007A  /**< CMAC hardware accelerator failed. */

#define TTLS_AES_BLOCK_SIZE		  16
#define TTLS_DES3_BLOCK_SIZE		 8

#define TTLS_CIPHER_BLKSIZE_MAX	  16  /* The longest block used by CMAC is that of AES. */

#if !defined(TTLS_CMAC_ALT)

/**
 * The CMAC context structure.
 */
struct ttls_cmac_context_t
{
	/** The internal state of the CMAC algorithm.  */
	unsigned char	   state[TTLS_CIPHER_BLKSIZE_MAX];

	/** Unprocessed data - either data that was not block aligned and is still
	 *  pending processing, or the final block. */
	unsigned char	   unprocessed_block[TTLS_CIPHER_BLKSIZE_MAX];

	/** The length of data pending processing. */
	size_t			  unprocessed_len;
};

/**
 * \brief			   This function sets the CMAC key, and prepares to authenticate
 *		  the input data.
 *		  Must be called with an initialized cipher context.
 *
 * \param ctx		   The cipher context used for the CMAC operation, initialized
 *		  as one of the following types:<ul>
 *		  <li>TTLS_CIPHER_AES_128_ECB</li>
 *		  <li>TTLS_CIPHER_AES_192_ECB</li>
 *		  <li>TTLS_CIPHER_AES_256_ECB</li>
 *		  <li>TTLS_CIPHER_DES_EDE3_ECB</li></ul>
 * \param key		   The CMAC key.
 * \param keybits	   The length of the CMAC key in bits.
 *		  Must be supported by the cipher.
 *
 * \return			  \c 0 on success, or a cipher-specific error code.
 */
int ttls_cipher_cmac_starts(ttls_cipher_context_t *ctx,
		const unsigned char *key, size_t keybits);

/**
 * \brief			   This function feeds an input buffer into an ongoing CMAC
 *		  computation.
 *
 *		  It is called between ttls_cipher_cmac_starts() or
 *		  ttls_cipher_cmac_reset(), and ttls_cipher_cmac_finish().
 *		  Can be called repeatedly.
 *
 * \param ctx		   The cipher context used for the CMAC operation.
 * \param input		 The buffer holding the input data.
 * \param ilen		  The length of the input data.
 *
 * \returns			 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA
 *		  if parameter verification fails.
 */
int ttls_cipher_cmac_update(ttls_cipher_context_t *ctx,
		const unsigned char *input, size_t ilen);

/**
 * \brief			   This function finishes the CMAC operation, and writes
 *		  the result to the output buffer.
 *
 *		  It is called after ttls_cipher_cmac_update().
 *		  It can be followed by ttls_cipher_cmac_reset() and
 *		  ttls_cipher_cmac_update(), or ttls_cipher_free().
 *
 * \param ctx		   The cipher context used for the CMAC operation.
 * \param output		The output buffer for the CMAC checksum result.
 *
 * \returns			 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA
 *		  if parameter verification fails.
 */
int ttls_cipher_cmac_finish(ttls_cipher_context_t *ctx,
		unsigned char *output);

/**
 * \brief			   This function prepares the authentication of another
 *		  message with the same key as the previous CMAC
 *		  operation.
 *
 *		  It is called after ttls_cipher_cmac_finish()
 *		  and before ttls_cipher_cmac_update().
 *
 * \param ctx		   The cipher context used for the CMAC operation.
 *
 * \returns			 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA
 *		  if parameter verification fails.
 */
int ttls_cipher_cmac_reset(ttls_cipher_context_t *ctx);

/**
 * \brief			   This function calculates the full generic CMAC
 *		  on the input buffer with the provided key.
 *
 *		  The function allocates the context, performs the
 *		  calculation, and frees the context.
 *
 *		  The CMAC result is calculated as
 *		  output = generic CMAC(cmac key, input buffer).
 *
 *
 * \param cipher_info   The cipher information.
 * \param key		   The CMAC key.
 * \param keylen		The length of the CMAC key in bits.
 * \param input		 The buffer holding the input data.
 * \param ilen		  The length of the input data.
 * \param output		The buffer for the generic CMAC result.
 *
 * \returns			 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA
 *		  if parameter verification fails.
 */
int ttls_cipher_cmac(const ttls_cipher_info_t *cipher_info,
			 const unsigned char *key, size_t keylen,
			 const unsigned char *input, size_t ilen,
			 unsigned char *output);

/**
 * \brief		   This function implements the AES-CMAC-PRF-128 pseudorandom
 *				  function, as defined in
 *				  <em>RFC-4615: The Advanced Encryption Standard-Cipher-based
 *				  Message Authentication Code-Pseudo-Random Function-128
 *				  (AES-CMAC-PRF-128) Algorithm for the Internet Key
 *				  Exchange Protocol (IKE).</em>
 *
 * \param key	   The key to use.
 * \param key_len   The key length in Bytes.
 * \param input	 The buffer holding the input data.
 * \param in_len	The length of the input data in Bytes.
 * \param output	The buffer holding the generated 16 Bytes of
 *				  pseudorandom output.
 *
 * \return		  \c 0 on success.
 */
int ttls_aes_cmac_prf_128(const unsigned char *key, size_t key_len,
				  const unsigned char *input, size_t in_len,
				  unsigned char output[16]);

#else  /* !TTLS_CMAC_ALT */
#include "cmac_alt.h"
#endif /* !TTLS_CMAC_ALT */

#endif /* TTLS_CMAC_H */
