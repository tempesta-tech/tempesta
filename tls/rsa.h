/**
 *		Tempesta TLS
 *
 * The RSA public-key cryptosystem.
 *
 * For more information, see
 * 1. Public-Key Cryptography Standards (PKCS) #1 v1.5: RSA Encryption
 * 2. Public-Key Cryptography Standards (PKCS) #1 v2.1: RSA Cryptography
 *    Specifications.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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
#ifndef TTLS_RSA_H
#define TTLS_RSA_H
#include "crypto.h"
#include "bignum.h"

/*
 * RSA Error codes
 */
#define TTLS_ERR_RSA_BAD_INPUT_DATA		-0x4080  /**< Bad input parameters to function. */
#define TTLS_ERR_RSA_INVALID_PADDING				   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define TTLS_ERR_RSA_KEY_CHECK_FAILED				  -0x4200  /**< Key failed to pass the validity check of the library. */
#define TTLS_ERR_RSA_PUBLIC_FAILED		 -0x4280  /**< The public key operation failed. */
#define TTLS_ERR_RSA_PRIVATE_FAILED		-0x4300  /**< The private key operation failed. */
#define TTLS_ERR_RSA_VERIFY_FAILED		 -0x4380  /**< The PKCS#1 verification failed. */
#define TTLS_ERR_RSA_RNG_FAILED			-0x4480 /**< The random generator failed to generate non-zeros. */

/*
 * RSA constants
 */
#define TTLS_RSA_PUBLIC		0 /* Request private key operation. */
#define TTLS_RSA_PRIVATE	1 /* Request public key operation. */

#define TTLS_RSA_PKCS_V15	0 /* Use PKCS-1 v1.5 encoding. */
#define TTLS_RSA_PKCS_V21	1 /* Use PKCS-1 v2.1 encoding. */

/* Identifier for RSA signature operations. */
#define TTLS_RSA_SIGN		1
/* Identifier for RSA encryption and decryption operations. */
#define TTLS_RSA_CRYPT		2

#define TTLS_RSA_SALT_LEN_ANY	-1

/**
 * The RSA context structure.
 *
 * @len		- The size of N in Bytes;
 * @N		- The public modulus;
 * @E		- The public exponent;
 * @D		- The private exponent;
 * @P		- The first prime factor;
 * @Q		- The second prime factor;
 * @DP		- D % (P - 1);
 * @DQ		- D % (Q - 1);
 * @QP		- 1 / (Q % P);
 * @RN		- cached R^2 mod N;
 * @RP		- cached R^2 mod P;
 * @RQ		- cached R^2 mod Q;
 * @Vi		- The cached blinding value;
 * @Vf		- The cached un-blinding value;
 * @padding	- Selects padding mode: #TTLS_RSA_PKCS_V15 for 1.5 padding and
 *		  #TTLS_RSA_PKCS_V21 for OAEP or PSS;
 * @hash_id	- Hash identifier of ttls_md_type_t type, as specified in
 *		  crypto.h for use in the MGF mask generating function used in
 *		  the EME-OAEP and EMSA-PSS encodings;
 */
typedef struct {
	size_t		len;
	TlsMpi		N;
	TlsMpi		E;
	TlsMpi		D;
	TlsMpi		P;
	TlsMpi		Q;
	TlsMpi		DP;
	TlsMpi		DQ;
	TlsMpi		QP;
	TlsMpi		RN;
	TlsMpi		RP;
	TlsMpi		RQ;
	TlsMpi __percpu	*Vi;
	TlsMpi __percpu	*Vf;
	int		padding;
	int		hash_id;
} TlsRSACtx;

void ttls_rsa_init(TlsRSACtx *ctx, int padding, int hash_id);
void ttls_rsa_free(TlsRSACtx *ctx);
int ttls_rsa_import_raw(TlsRSACtx *ctx, unsigned char const *N, size_t N_len,
			unsigned char const *P, size_t P_len,
			unsigned char const *Q, size_t Q_len,
			unsigned char const *D, size_t D_len,
			unsigned char const *E, size_t E_len);

int ttls_rsa_complete(TlsRSACtx *ctx);

/**
 * \brief		  This function exports the core parameters of an RSA key.
 *
 *				 If this function runs successfully, the non-NULL buffers
 *				 pointed to by \p N, \p P, \p Q, \p D, and \p E are fully
 *				 written, with additional unused space filled leading by
 *				 zero Bytes.
 *
 *				 Possible reasons for returning
 *				 #TTLS_ERR_RSA_UNSUPPORTED_OPERATION:<ul>
 *				 <li>An alternative RSA implementation is in use, which
 *				 stores the key externally, and either cannot or should
 *				 not export it into RAM.</li>
 *				 <li>A SW or HW implementation might not support a certain
 *				 deduction. For example, \p P, \p Q from \p N, \p D,
 *				 and \p E if the former are not part of the
 *				 implementation.</li></ul>
 *
 *				 If the function fails due to an unsupported operation,
 *				 the RSA context stays intact and remains usable.
 *
 * \param ctx	  The initialized RSA context.
 * \param N		The MPI to hold the RSA modulus, or NULL.
 * \param P		The MPI to hold the first prime factor of \p N, or NULL.
 * \param Q		The MPI to hold the second prime factor of \p N, or NULL.
 * \param D		The MPI to hold the private exponent, or NULL.
 * \param E		The MPI to hold the public exponent, or NULL.
 *
 * \return		 \c 0 on success,
 *				 #TTLS_ERR_RSA_UNSUPPORTED_OPERATION if exporting the
 *				 requested parameters cannot be done due to missing
 *				 functionality or because of security policies,
 *				 or a non-zero return code on any other failure.
 *
 */
int ttls_rsa_export(const TlsRSACtx *ctx,
			TlsMpi *N, TlsMpi *P, TlsMpi *Q,
			TlsMpi *D, TlsMpi *E);

/**
 * \brief		  This function exports core parameters of an RSA key
 *				 in raw big-endian binary format.
 *
 *				 If this function runs successfully, the non-NULL buffers
 *				 pointed to by \p N, \p P, \p Q, \p D, and \p E are fully
 *				 written, with additional unused space filled leading by
 *				 zero Bytes.
 *
 *				 Possible reasons for returning
 *				 #TTLS_ERR_RSA_UNSUPPORTED_OPERATION:<ul>
 *				 <li>An alternative RSA implementation is in use, which
 *				 stores the key externally, and either cannot or should
 *				 not export it into RAM.</li>
 *				 <li>A SW or HW implementation might not support a certain
 *				 deduction. For example, \p P, \p Q from \p N, \p D,
 *				 and \p E if the former are not part of the
 *				 implementation.</li></ul>
 *				 If the function fails due to an unsupported operation,
 *				 the RSA context stays intact and remains usable.
 *
 * \param ctx	  The initialized RSA context.
 * \param N		The Byte array to store the RSA modulus, or NULL.
 * \param N_len	The size of the buffer for the modulus.
 * \param P		The Byte array to hold the first prime factor of \p N, or
 *				 NULL.
 * \param P_len	The size of the buffer for the first prime factor.
 * \param Q		The Byte array to hold the second prime factor of \p N, or
				   NULL.
 * \param Q_len	The size of the buffer for the second prime factor.
 * \param D		The Byte array to hold the private exponent, or NULL.
 * \param D_len	The size of the buffer for the private exponent.
 * \param E		The Byte array to hold the public exponent, or NULL.
 * \param E_len	The size of the buffer for the public exponent.
 *
 * \note		   The length fields are ignored if the corresponding
 *				 buffer pointers are NULL.
 *
 * \return		 \c 0 on success,
 *				 #TTLS_ERR_RSA_UNSUPPORTED_OPERATION if exporting the
 *				 requested parameters cannot be done due to missing
 *				 functionality or because of security policies,
 *				 or a non-zero return code on any other failure.
 */
int ttls_rsa_export_raw(const TlsRSACtx *ctx,
				unsigned char *N, size_t N_len,
				unsigned char *P, size_t P_len,
				unsigned char *Q, size_t Q_len,
				unsigned char *D, size_t D_len,
				unsigned char *E, size_t E_len);

/**
 * \brief		  This function exports CRT parameters of a private RSA key.
 *
 * \param ctx	  The initialized RSA context.
 * \param DP	   The MPI to hold D modulo P-1, or NULL.
 * \param DQ	   The MPI to hold D modulo Q-1, or NULL.
 * \param QP	   The MPI to hold modular inverse of Q modulo P, or NULL.
 *
 * \return		 \c 0 on success, non-zero error code otherwise.
 *
 * \note		   Alternative RSA implementations not using CRT-parameters
 *				 internally can implement this function based on
 *				 ttls_rsa_deduce_opt().
 *
 */
int ttls_rsa_export_crt(const TlsRSACtx *ctx,
				TlsMpi *DP, TlsMpi *DQ, TlsMpi *QP);

/**
 * \brief		  This function retrieves the length of RSA modulus in Bytes.
 *
 * \param ctx	  The initialized RSA context.
 *
 * \return		 The length of the RSA modulus in Bytes.
 *
 */
size_t ttls_rsa_get_len(const TlsRSACtx *ctx);

int ttls_rsa_check_pubkey(TlsRSACtx *ctx);

int ttls_rsa_pkcs1_sign(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			const unsigned char *hash, size_t hashlen,
			unsigned char *sig);
int ttls_rsa_pkcs1_verify(TlsRSACtx *ctx, ttls_md_type_t md_alg,
			  unsigned int hashlen, const unsigned char *hash,
			  const unsigned char *sig);
int ttls_rsa_rsassa_pss_verify_ext(TlsRSACtx *ctx, ttls_md_type_t md_alg,
				   unsigned int hashlen,
				   const unsigned char *hash,
				   ttls_md_type_t mgf1_hash_id,
				   int expected_salt_len,
				   const unsigned char *sig);

#endif /* rsa.h */
