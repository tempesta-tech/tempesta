/**
 * \file xtea.h
 *
 * \brief XTEA block cipher (32-bit)
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
#ifndef TTLS_XTEA_H
#define TTLS_XTEA_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define TTLS_XTEA_ENCRYPT	 1
#define TTLS_XTEA_DECRYPT	 0

#define TTLS_ERR_XTEA_INVALID_INPUT_LENGTH			 -0x0028  /**< The data input has an invalid length. */
#define TTLS_ERR_XTEA_HW_ACCEL_FAILED				  -0x0029  /**< XTEA hardware accelerator failed. */

#if !defined(TTLS_XTEA_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief		  XTEA context structure
 */
typedef struct
{
	uint32_t k[4];	   /*!< key */
}
ttls_xtea_context;

/**
 * \brief		  Initialize XTEA context
 *
 * \param ctx	  XTEA context to be initialized
 */
void ttls_xtea_init(ttls_xtea_context *ctx);

/**
 * \brief		  Clear XTEA context
 *
 * \param ctx	  XTEA context to be cleared
 */
void ttls_xtea_free(ttls_xtea_context *ctx);

/**
 * \brief		  XTEA key schedule
 *
 * \param ctx	  XTEA context to be initialized
 * \param key	  the secret key
 */
void ttls_xtea_setup(ttls_xtea_context *ctx, const unsigned char key[16]);

/**
 * \brief		  XTEA cipher function
 *
 * \param ctx	  XTEA context
 * \param mode	 TTLS_XTEA_ENCRYPT or TTLS_XTEA_DECRYPT
 * \param input	8-byte input block
 * \param output   8-byte output block
 *
 * \return		 0 if successful
 */
int ttls_xtea_crypt_ecb(ttls_xtea_context *ctx,
		int mode,
		const unsigned char input[8],
		unsigned char output[8]);

#if defined(TTLS_CIPHER_MODE_CBC)
/**
 * \brief		  XTEA CBC cipher function
 *
 * \param ctx	  XTEA context
 * \param mode	 TTLS_XTEA_ENCRYPT or TTLS_XTEA_DECRYPT
 * \param length   the length of input, multiple of 8
 * \param iv	   initialization vector for CBC mode
 * \param input	input block
 * \param output   output block
 *
 * \return		 0 if successful,
 *				 TTLS_ERR_XTEA_INVALID_INPUT_LENGTH if the length % 8 != 0
 */
int ttls_xtea_crypt_cbc(ttls_xtea_context *ctx,
		int mode,
		size_t length,
		unsigned char iv[8],
		const unsigned char *input,
		unsigned char *output);
#endif /* TTLS_CIPHER_MODE_CBC */

#ifdef __cplusplus
}
#endif

#else  /* TTLS_XTEA_ALT */
#include "xtea_alt.h"
#endif /* TTLS_XTEA_ALT */

#endif /* xtea.h */
