/**
 * \file des.h
 *
 * \brief DES block cipher
 *
 * \warning   DES is considered a weak cipher and its use constitutes a
 *			security risk. We recommend considering stronger ciphers
 *			instead.
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
#ifndef TTLS_DES_H
#define TTLS_DES_H

#include "config.h"

#define TTLS_DES_ENCRYPT	 1
#define TTLS_DES_DECRYPT	 0

#define TTLS_ERR_DES_INVALID_INPUT_LENGTH			  -0x0032  /**< The data input has an invalid length. */
#define TTLS_ERR_DES_HW_ACCEL_FAILED				   -0x0033  /**< DES hardware accelerator failed. */

#define TTLS_DES_KEY_SIZE	8

#if !defined(TTLS_DES_ALT)
// Regular implementation
//

/**
 * \brief		  DES context structure
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
typedef struct
{
	uint32_t sk[32];			/*!<  DES subkeys	   */
}
ttls_des_context;

/**
 * \brief		  Triple-DES context structure
 */
typedef struct
{
	uint32_t sk[96];			/*!<  3DES subkeys	  */
}
ttls_des3_context;

/**
 * \brief		  Initialize DES context
 *
 * \param ctx	  DES context to be initialized
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
void ttls_des_init(ttls_des_context *ctx);

/**
 * \brief		  Clear DES context
 *
 * \param ctx	  DES context to be cleared
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
void ttls_des_free(ttls_des_context *ctx);

/**
 * \brief		  Initialize Triple-DES context
 *
 * \param ctx	  DES3 context to be initialized
 */
void ttls_des3_init(ttls_des3_context *ctx);

/**
 * \brief		  Clear Triple-DES context
 *
 * \param ctx	  DES3 context to be cleared
 */
void ttls_des3_free(ttls_des3_context *ctx);

/**
 * \brief		  Set key parity on the given key to odd.
 *
 *				 DES keys are 56 bits long, but each byte is padded with
 *				 a parity bit to allow verification.
 *
 * \param key	  8-byte secret key
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
void ttls_des_key_set_parity(unsigned char key[TTLS_DES_KEY_SIZE]);

/**
 * \brief		  Check that key parity on the given key is odd.
 *
 *				 DES keys are 56 bits long, but each byte is padded with
 *				 a parity bit to allow verification.
 *
 * \param key	  8-byte secret key
 *
 * \return		 0 is parity was ok, 1 if parity was not correct.
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
int ttls_des_key_check_key_parity(const unsigned char key[TTLS_DES_KEY_SIZE]);

/**
 * \brief		  Check that key is not a weak or semi-weak DES key
 *
 * \param key	  8-byte secret key
 *
 * \return		 0 if no weak key was found, 1 if a weak key was identified.
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
int ttls_des_key_check_weak(const unsigned char key[TTLS_DES_KEY_SIZE]);

/**
 * \brief		  DES key schedule (56-bit, encryption)
 *
 * \param ctx	  DES context to be initialized
 * \param key	  8-byte secret key
 *
 * \return		 0
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
int ttls_des_setkey_enc(ttls_des_context *ctx, const unsigned char key[TTLS_DES_KEY_SIZE]);

/**
 * \brief		  DES key schedule (56-bit, decryption)
 *
 * \param ctx	  DES context to be initialized
 * \param key	  8-byte secret key
 *
 * \return		 0
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
int ttls_des_setkey_dec(ttls_des_context *ctx, const unsigned char key[TTLS_DES_KEY_SIZE]);

/**
 * \brief		  Triple-DES key schedule (112-bit, encryption)
 *
 * \param ctx	  3DES context to be initialized
 * \param key	  16-byte secret key
 *
 * \return		 0
 */
int ttls_des3_set2key_enc(ttls_des3_context *ctx,
					  const unsigned char key[TTLS_DES_KEY_SIZE * 2]);

/**
 * \brief		  Triple-DES key schedule (112-bit, decryption)
 *
 * \param ctx	  3DES context to be initialized
 * \param key	  16-byte secret key
 *
 * \return		 0
 */
int ttls_des3_set2key_dec(ttls_des3_context *ctx,
					  const unsigned char key[TTLS_DES_KEY_SIZE * 2]);

/**
 * \brief		  Triple-DES key schedule (168-bit, encryption)
 *
 * \param ctx	  3DES context to be initialized
 * \param key	  24-byte secret key
 *
 * \return		 0
 */
int ttls_des3_set3key_enc(ttls_des3_context *ctx,
					  const unsigned char key[TTLS_DES_KEY_SIZE * 3]);

/**
 * \brief		  Triple-DES key schedule (168-bit, decryption)
 *
 * \param ctx	  3DES context to be initialized
 * \param key	  24-byte secret key
 *
 * \return		 0
 */
int ttls_des3_set3key_dec(ttls_des3_context *ctx,
					  const unsigned char key[TTLS_DES_KEY_SIZE * 3]);

/**
 * \brief		  DES-ECB block encryption/decryption
 *
 * \param ctx	  DES context
 * \param input	64-bit input block
 * \param output   64-bit output block
 *
 * \return		 0 if successful
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
int ttls_des_crypt_ecb(ttls_des_context *ctx,
					const unsigned char input[8],
					unsigned char output[8]);

#if defined(TTLS_CIPHER_MODE_CBC)
/**
 * \brief		  DES-CBC buffer encryption/decryption
 *
 * \note		   Upon exit, the content of the IV is updated so that you can
 *				 call the function same function again on the following
 *				 block(s) of data and get the same result as if it was
 *				 encrypted in one call. This allows a "streaming" usage.
 *				 If on the other hand you need to retain the contents of the
 *				 IV, you should either save it manually or use the cipher
 *				 module instead.
 *
 * \param ctx	  DES context
 * \param mode	 TTLS_DES_ENCRYPT or TTLS_DES_DECRYPT
 * \param length   length of the input data
 * \param iv	   initialization vector (updated after use)
 * \param input	buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
int ttls_des_crypt_cbc(ttls_des_context *ctx,
					int mode,
					size_t length,
					unsigned char iv[8],
					const unsigned char *input,
					unsigned char *output);
#endif /* TTLS_CIPHER_MODE_CBC */

/**
 * \brief		  3DES-ECB block encryption/decryption
 *
 * \param ctx	  3DES context
 * \param input	64-bit input block
 * \param output   64-bit output block
 *
 * \return		 0 if successful
 */
int ttls_des3_crypt_ecb(ttls_des3_context *ctx,
					 const unsigned char input[8],
					 unsigned char output[8]);

#if defined(TTLS_CIPHER_MODE_CBC)
/**
 * \brief		  3DES-CBC buffer encryption/decryption
 *
 * \note		   Upon exit, the content of the IV is updated so that you can
 *				 call the function same function again on the following
 *				 block(s) of data and get the same result as if it was
 *				 encrypted in one call. This allows a "streaming" usage.
 *				 If on the other hand you need to retain the contents of the
 *				 IV, you should either save it manually or use the cipher
 *				 module instead.
 *
 * \param ctx	  3DES context
 * \param mode	 TTLS_DES_ENCRYPT or TTLS_DES_DECRYPT
 * \param length   length of the input data
 * \param iv	   initialization vector (updated after use)
 * \param input	buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return		 0 if successful, or TTLS_ERR_DES_INVALID_INPUT_LENGTH
 */
int ttls_des3_crypt_cbc(ttls_des3_context *ctx,
					 int mode,
					 size_t length,
					 unsigned char iv[8],
					 const unsigned char *input,
					 unsigned char *output);
#endif /* TTLS_CIPHER_MODE_CBC */

/**
 * \brief		  Internal function for key expansion.
 *				 (Only exposed to allow overriding it,
 *				 see TTLS_DES_SETKEY_ALT)
 *
 * \param SK	   Round keys
 * \param key	  Base key
 *
 * \warning		DES is considered a weak cipher and its use constitutes a
 *				 security risk. We recommend considering stronger ciphers
 *				 instead.
 */
void ttls_des_setkey(uint32_t SK[32],
						 const unsigned char key[TTLS_DES_KEY_SIZE]);

#else  /* TTLS_DES_ALT */
#include "des_alt.h"
#endif /* TTLS_DES_ALT */

#endif /* des.h */
