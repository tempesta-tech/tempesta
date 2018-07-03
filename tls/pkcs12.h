/**
 * \file pkcs12.h
 *
 * \brief PKCS#12 Personal Information Exchange Syntax
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
#ifndef TTLS_PKCS12_H
#define TTLS_PKCS12_H

#include "md.h"
#include "cipher.h"
#include "asn1.h"

#include <stddef.h>

#define TTLS_ERR_PKCS12_BAD_INPUT_DATA				 -0x1F80  /**< Bad input parameters to function. */
#define TTLS_ERR_PKCS12_FEATURE_UNAVAILABLE			-0x1F00  /**< Feature not available, e.g. unsupported encryption scheme. */
#define TTLS_ERR_PKCS12_PBE_INVALID_FORMAT			 -0x1E80  /**< PBE ASN.1 data not as expected. */
#define TTLS_ERR_PKCS12_PASSWORD_MISMATCH			  -0x1E00  /**< Given private key password does not allow for correct decryption. */

#define TTLS_PKCS12_DERIVE_KEY	   1   /**< encryption/decryption key */
#define TTLS_PKCS12_DERIVE_IV		2   /**< initialization vector	 */
#define TTLS_PKCS12_DERIVE_MAC_KEY   3   /**< integrity / MAC key	   */

#define TTLS_PKCS12_PBE_DECRYPT	  0
#define TTLS_PKCS12_PBE_ENCRYPT	  1

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief			PKCS12 Password Based function (encryption / decryption)
 *				   for pbeWithSHAAnd128BitRC4
 *
 * \param pbe_params an ASN1 buffer containing the pkcs-12PbeParams structure
 * \param mode	   either TTLS_PKCS12_PBE_ENCRYPT or TTLS_PKCS12_PBE_DECRYPT
 * \param pwd		the password used (may be NULL if no password is used)
 * \param pwdlen	 length of the password (may be 0)
 * \param input	  the input data
 * \param len		data length
 * \param output	 the output buffer
 *
 * \return		   0 if successful, or a TTLS_ERR_XXX code
 */
int ttls_pkcs12_pbe_sha1_rc4_128(ttls_asn1_buf *pbe_params, int mode,
				 const unsigned char *pwd,  size_t pwdlen,
				 const unsigned char *input, size_t len,
				 unsigned char *output);

/**
 * \brief			PKCS12 Password Based function (encryption / decryption)
 *				   for cipher-based and ttls_md-based PBE's
 *
 * \param pbe_params an ASN1 buffer containing the pkcs-12PbeParams structure
 * \param mode	   either TTLS_PKCS12_PBE_ENCRYPT or TTLS_PKCS12_PBE_DECRYPT
 * \param cipher_type the cipher used
 * \param md_type	 the ttls_md used
 * \param pwd		the password used (may be NULL if no password is used)
 * \param pwdlen	 length of the password (may be 0)
 * \param input	  the input data
 * \param len		data length
 * \param output	 the output buffer
 *
 * \return		   0 if successful, or a TTLS_ERR_XXX code
 */
int ttls_pkcs12_pbe(ttls_asn1_buf *pbe_params, int mode,
				ttls_cipher_type_t cipher_type, ttls_md_type_t md_type,
				const unsigned char *pwd,  size_t pwdlen,
				const unsigned char *input, size_t len,
				unsigned char *output);

/**
 * \brief			The PKCS#12 derivation function uses a password and a salt
 *				   to produce pseudo-random bits for a particular "purpose".
 *
 *				   Depending on the given id, this function can produce an
 *				   encryption/decryption key, an nitialization vector or an
 *				   integrity key.
 *
 * \param data	   buffer to store the derived data in
 * \param datalen	length to fill
 * \param pwd		password to use (may be NULL if no password is used)
 * \param pwdlen	 length of the password (may be 0)
 * \param salt	   salt buffer to use
 * \param saltlen	length of the salt
 * \param ttls_md		 ttls_md type to use during the derivation
 * \param id		 id that describes the purpose (can be TTLS_PKCS12_DERIVE_KEY,
 *				   TTLS_PKCS12_DERIVE_IV or TTLS_PKCS12_DERIVE_MAC_KEY)
 * \param iterations number of iterations
 *
 * \return		  0 if successful, or a MD, BIGNUM type error.
 */
int ttls_pkcs12_derivation(unsigned char *data, size_t datalen,
		   const unsigned char *pwd, size_t pwdlen,
		   const unsigned char *salt, size_t saltlen,
		   ttls_md_type_t ttls_md, int id, int iterations);

#ifdef __cplusplus
}
#endif

#endif /* pkcs12.h */
