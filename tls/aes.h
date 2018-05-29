/**
 * \file aes.h
 *
 * \brief   The Advanced Encryption Standard (AES) specifies a FIPS-approved
 *		  cryptographic algorithm that can be used to protect electronic
 *		  data.
 *
 *		  The AES algorithm is a symmetric block cipher that can
 *		  encrypt and decrypt information. For more information, see
 *		  <em>FIPS Publication 197: Advanced Encryption Standard</em> and
 *		  <em>ISO/IEC 18033-2:2006: Information technology -- Security
 *		  techniques -- Encryption algorithms -- Part 2: Asymmetric
 *		  ciphers</em>.
 */
/*  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved.
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef TTLS_AES_H
#define TTLS_AES_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

/* padlock.c and aesni.c rely on these values! */
#define TTLS_AES_ENCRYPT	 1 /**< AES encryption. */
#define TTLS_AES_DECRYPT	 0 /**< AES decryption. */

/* Error codes in range 0x0020-0x0022 */
#define TTLS_ERR_AES_INVALID_KEY_LENGTH				-0x0020  /**< Invalid key length. */
#define TTLS_ERR_AES_INVALID_INPUT_LENGTH			  -0x0022  /**< Invalid data input length. */

/* Error codes in range 0x0023-0x0025 */
#define TTLS_ERR_AES_FEATURE_UNAVAILABLE			   -0x0023  /**< Feature not available. For example, an unsupported AES key size. */
#define TTLS_ERR_AES_HW_ACCEL_FAILED				   -0x0025  /**< AES hardware accelerator failed. */

#if (defined(__ARMCC_VERSION) || defined(_MSC_VER)) && \
	!defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if !defined(TTLS_AES_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief The AES context-type definition.
 */
typedef struct
{
	int nr;					 /*!< The number of rounds. */
	uint32_t *rk;			   /*!< AES round keys. */
	uint32_t buf[68];		   /*!< Unaligned data buffer. This buffer can
									 hold 32 extra Bytes, which can be used for
									 one of the following purposes:
									 <ul><li>Alignment if VIA padlock is
											 used.</li>
									 <li>Simplifying key expansion in the 256-bit
										 case by generating an extra round key.
										 </li></ul> */
}
ttls_aes_context;

/**
 * \brief		  This function initializes the specified AES context.
 *
 *				 It must be the first API called before using
 *				 the context.
 *
 * \param ctx	  The AES context to initialize.
 */
void ttls_aes_init(ttls_aes_context *ctx);

/**
 * \brief		  This function releases and clears the specified AES context.
 *
 * \param ctx	  The AES context to clear.
 */
void ttls_aes_free(ttls_aes_context *ctx);

/**
 * \brief		  This function sets the encryption key.
 *
 * \param ctx	  The AES context to which the key should be bound.
 * \param key	  The encryption key.
 * \param keybits  The size of data passed in bits. Valid options are:
 *				 <ul><li>128 bits</li>
 *				 <li>192 bits</li>
 *				 <li>256 bits</li></ul>
 *
 * \return		 \c 0 on success or #TTLS_ERR_AES_INVALID_KEY_LENGTH
 *				 on failure.
 */
int ttls_aes_setkey_enc(ttls_aes_context *ctx, const unsigned char *key,
					unsigned int keybits);

/**
 * \brief		  This function sets the decryption key.
 *
 * \param ctx	  The AES context to which the key should be bound.
 * \param key	  The decryption key.
 * \param keybits  The size of data passed. Valid options are:
 *				 <ul><li>128 bits</li>
 *				 <li>192 bits</li>
 *				 <li>256 bits</li></ul>
 *
 * \return		 \c 0 on success, or #TTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int ttls_aes_setkey_dec(ttls_aes_context *ctx, const unsigned char *key,
					unsigned int keybits);

/**
 * \brief		  This function performs an AES single-block encryption or
 *				 decryption operation.
 *
 *				 It performs the operation defined in the \p mode parameter
 *				 (encrypt or decrypt), on the input data buffer defined in
 *				 the \p input parameter.
 *
 *				 ttls_aes_init(), and either ttls_aes_setkey_enc() or
 *				 ttls_aes_setkey_dec() must be called before the first
 *				 call to this API with the same context.
 *
 * \param ctx	  The AES context to use for encryption or decryption.
 * \param mode	 The AES operation: #TTLS_AES_ENCRYPT or
 *				 #TTLS_AES_DECRYPT.
 * \param input	The 16-Byte buffer holding the input data.
 * \param output   The 16-Byte buffer holding the output data.

 * \return		 \c 0 on success.
 */
int ttls_aes_crypt_ecb(ttls_aes_context *ctx,
					int mode,
					const unsigned char input[16],
					unsigned char output[16]);

#if defined(TTLS_CIPHER_MODE_CBC)
/**
 * \brief  This function performs an AES-CBC encryption or decryption operation
 *		 on full blocks.
 *
 *		 It performs the operation defined in the \p mode
 *		 parameter (encrypt/decrypt), on the input data buffer defined in
 *		 the \p input parameter.
 *
 *		 It can be called as many times as needed, until all the input
 *		 data is processed. ttls_aes_init(), and either
 *		 ttls_aes_setkey_enc() or ttls_aes_setkey_dec() must be called
 *		 before the first call to this API with the same context.
 *
 * \note   This function operates on aligned blocks, that is, the input size
 *		 must be a multiple of the AES block size of 16 Bytes.
 *
 * \note   Upon exit, the content of the IV is updated so that you can
 *		 call the same function again on the next
 *		 block(s) of data and get the same result as if it was
 *		 encrypted in one call. This allows a "streaming" usage.
 *		 If you need to retain the contents of the IV, you should
 *		 either save it manually or use the cipher module instead.
 *
 *
 * \param ctx	  The AES context to use for encryption or decryption.
 * \param mode	 The AES operation: #TTLS_AES_ENCRYPT or
 *				 #TTLS_AES_DECRYPT.
 * \param length   The length of the input data in Bytes. This must be a
 *				 multiple of the block size (16 Bytes).
 * \param iv	   Initialization vector (updated after use).
 * \param input	The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return		 \c 0 on success, or #TTLS_ERR_AES_INVALID_INPUT_LENGTH
 *				 on failure.
 */
int ttls_aes_crypt_cbc(ttls_aes_context *ctx,
					int mode,
					size_t length,
					unsigned char iv[16],
					const unsigned char *input,
					unsigned char *output);
#endif /* TTLS_CIPHER_MODE_CBC */

#if defined(TTLS_CIPHER_MODE_CFB)
/**
 * \brief This function performs an AES-CFB128 encryption or decryption
 *		operation.
 *
 *		It performs the operation defined in the \p mode
 *		parameter (encrypt or decrypt), on the input data buffer
 *		defined in the \p input parameter.
 *
 *		For CFB, you must set up the context with ttls_aes_setkey_enc(),
 *		regardless of whether you are performing an encryption or decryption
 *		operation, that is, regardless of the \p mode parameter. This is
 *		because CFB mode uses the same key schedule for encryption and
 *		decryption.
 *
 * \note  Upon exit, the content of the IV is updated so that you can
 *		call the same function again on the next
 *		block(s) of data and get the same result as if it was
 *		encrypted in one call. This allows a "streaming" usage.
 *		If you need to retain the contents of the
 *		IV, you must either save it manually or use the cipher
 *		module instead.
 *
 *
 * \param ctx	  The AES context to use for encryption or decryption.
 * \param mode	 The AES operation: #TTLS_AES_ENCRYPT or
 *				 #TTLS_AES_DECRYPT.
 * \param length   The length of the input data.
 * \param iv_off   The offset in IV (updated after use).
 * \param iv	   The initialization vector (updated after use).
 * \param input	The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return		 \c 0 on success.
 */
int ttls_aes_crypt_cfb128(ttls_aes_context *ctx,
					   int mode,
					   size_t length,
					   size_t *iv_off,
					   unsigned char iv[16],
					   const unsigned char *input,
					   unsigned char *output);

/**
 * \brief This function performs an AES-CFB8 encryption or decryption
 *		operation.
 *
 *		It performs the operation defined in the \p mode
 *		parameter (encrypt/decrypt), on the input data buffer defined
 *		in the \p input parameter.
 *
 *		Due to the nature of CFB, you must use the same key schedule for
 *		both encryption and decryption operations. Therefore, you must
 *		use the context initialized with ttls_aes_setkey_enc() for
 *		both #TTLS_AES_ENCRYPT and #TTLS_AES_DECRYPT.
 *
 * \note  Upon exit, the content of the IV is updated so that you can
 *		call the same function again on the next
 *		block(s) of data and get the same result as if it was
 *		encrypted in one call. This allows a "streaming" usage.
 *		If you need to retain the contents of the
 *		IV, you should either save it manually or use the cipher
 *		module instead.
 *
 *
 * \param ctx	  The AES context to use for encryption or decryption.
 * \param mode	 The AES operation: #TTLS_AES_ENCRYPT or
 *				 #TTLS_AES_DECRYPT
 * \param length   The length of the input data.
 * \param iv	   The initialization vector (updated after use).
 * \param input	The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return		 \c 0 on success.
 */
int ttls_aes_crypt_cfb8(ttls_aes_context *ctx,
					int mode,
					size_t length,
					unsigned char iv[16],
					const unsigned char *input,
					unsigned char *output);
#endif /*TTLS_CIPHER_MODE_CFB */

#if defined(TTLS_CIPHER_MODE_CTR)
/**
 * \brief	  This function performs an AES-CTR encryption or decryption
 *			 operation.
 *
 *			 This function performs the operation defined in the \p mode
 *			 parameter (encrypt/decrypt), on the input data buffer
 *			 defined in the \p input parameter.
 *
 *			 Due to the nature of CTR, you must use the same key schedule
 *			 for both encryption and decryption operations. Therefore, you
 *			 must use the context initialized with ttls_aes_setkey_enc()
 *			 for both #TTLS_AES_ENCRYPT and #TTLS_AES_DECRYPT.
 *
 * \warning	You must keep the maximum use of your counter in mind.
 *
 * \param ctx			  The AES context to use for encryption or decryption.
 * \param length		   The length of the input data.
 * \param nc_off		   The offset in the current \p stream_block, for
 *						 resuming within the current cipher stream. The
 *						 offset pointer should be 0 at the start of a stream.
 * \param nonce_counter	The 128-bit nonce and counter.
 * \param stream_block	 The saved stream block for resuming. This is
 *						 overwritten by the function.
 * \param input			The buffer holding the input data.
 * \param output		   The buffer holding the output data.
 *
 * \return	 \c 0 on success.
 */
int ttls_aes_crypt_ctr(ttls_aes_context *ctx,
					   size_t length,
					   size_t *nc_off,
					   unsigned char nonce_counter[16],
					   unsigned char stream_block[16],
					   const unsigned char *input,
					   unsigned char *output);
#endif /* TTLS_CIPHER_MODE_CTR */

/**
 * \brief		   Internal AES block encryption function. This is only
 *				  exposed to allow overriding it using
 *				  \c TTLS_AES_ENCRYPT_ALT.
 *
 * \param ctx	   The AES context to use for encryption.
 * \param input	 The plaintext block.
 * \param output	The output (ciphertext) block.
 *
 * \return		  \c 0 on success.
 */
int ttls_internal_aes_encrypt(ttls_aes_context *ctx,
								  const unsigned char input[16],
								  unsigned char output[16]);

/**
 * \brief		   Internal AES block decryption function. This is only
 *				  exposed to allow overriding it using see
 *				  \c TTLS_AES_DECRYPT_ALT.
 *
 * \param ctx	   The AES context to use for decryption.
 * \param input	 The ciphertext block.
 * \param output	The output (plaintext) block.
 *
 * \return		  \c 0 on success.
 */
int ttls_internal_aes_decrypt(ttls_aes_context *ctx,
								  const unsigned char input[16],
								  unsigned char output[16]);

#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		   Deprecated internal AES block encryption function
 *				  without return value.
 *
 * \deprecated	  Superseded by ttls_aes_encrypt_ext() in 2.5.0.
 *
 * \param ctx	   The AES context to use for encryption.
 * \param input	 Plaintext block.
 * \param output	Output (ciphertext) block.
 */
TTLS_DEPRECATED void ttls_aes_encrypt(ttls_aes_context *ctx,
											 const unsigned char input[16],
											 unsigned char output[16]);

/**
 * \brief		   Deprecated internal AES block decryption function
 *				  without return value.
 *
 * \deprecated	  Superseded by ttls_aes_decrypt_ext() in 2.5.0.
 *
 * \param ctx	   The AES context to use for decryption.
 * \param input	 Ciphertext block.
 * \param output	Output (plaintext) block.
 */
TTLS_DEPRECATED void ttls_aes_decrypt(ttls_aes_context *ctx,
											 const unsigned char input[16],
											 unsigned char output[16]);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#ifdef __cplusplus
}
#endif

#else  /* TTLS_AES_ALT */
#include "aes_alt.h"
#endif /* TTLS_AES_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief		  Checkup routine.
 *
 * \return		 \c 0 on success, or \c 1 on failure.
 */
int ttls_aes_self_test(int verbose);

#ifdef __cplusplus
}
#endif

#endif /* aes.h */
