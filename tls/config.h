/**
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
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
#ifndef TTLS_CONFIG_H
#define TTLS_CONFIG_H

#include <linux/spinlock.h>

/* TODO remove the rest of the mess. */
#define ttls_calloc(n, s)	kzalloc((n) * (s), GFP_ATOMIC)
#define ttls_free(p)		kfree(p)
#define ttls_snprintf		snprintf
#define ttls_printf		pr_info

/**
 * \def TTLS_AES_ALT
 *
 * TTLS__MODULE_NAME__ALT: Uncomment a macro to let mbed TLS use your
 * alternate core implementation of a symmetric crypto, an arithmetic or hash
 * module (e.g. platform specific assembly optimized implementations). Keep
 * in mind that the function prototypes should remain the same.
 *
 * This replaces the whole module. If you only want to replace one of the
 * functions, use one of the TTLS__FUNCTION_NAME__ALT flags.
 *
 * Example: In case you uncomment TTLS_AES_ALT, mbed TLS will no longer
 * provide the "struct ttls_aes_context" definition and omit the base
 * function declarations and implementations. "aes_alt.h" will be included from
 * "aes.h" to include the new function definitions.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * module.
 *
 * \warning   MD2, MD4, MD5, DES and SHA-1 are considered weak and their
 *			use constitutes a security risk. If possible, we recommend
 *			avoiding dependencies on them, and considering stronger message
 *			digests and ciphers instead.
 *
 */
//#define TTLS_AES_ALT
//#define TTLS_BLOWFISH_ALT
//#define TTLS_CAMELLIA_ALT
//#define TTLS_CCM_ALT
//#define TTLS_CMAC_ALT
//#define TTLS_DES_ALT
//#define TTLS_DHM_ALT
//#define TTLS_GCM_ALT
//#define TTLS_MD2_ALT
//#define TTLS_MD4_ALT
//#define TTLS_MD5_ALT
//#define TTLS_RIPEMD160_ALT
//#define TTLS_RSA_ALT
//#define TTLS_SHA1_ALT
//#define TTLS_SHA256_ALT
//#define TTLS_SHA512_ALT
//#define TTLS_XTEA_ALT
/*
 * When replacing the elliptic curve module, pleace consider, that it is
 * implemented with two .c files:
 *	  - ecp.c
 *	  - ecp_curves.c
 * You can replace them very much like all the other TTLS__MODULE_NAME__ALT
 * macros as described above. The only difference is that you have to make sure
 * that you provide functionality for both .c files.
 */
//#define TTLS_ECP_ALT

/**
 * \def TTLS_MD2_PROCESS_ALT
 *
 * TTLS__FUNCTION_NAME__ALT: Uncomment a macro to let mbed TLS use you
 * alternate core implementation of symmetric crypto or hash function. Keep in
 * mind that function prototypes should remain the same.
 *
 * This replaces only one function. The header file from mbed TLS is still
 * used, in contrast to the TTLS__MODULE_NAME__ALT flags.
 *
 * Example: In case you uncomment TTLS_SHA256_PROCESS_ALT, mbed TLS will
 * no longer provide the ttls_sha1_process() function, but it will still provide
 * the other function (using your ttls_sha1_process() function) and the definition
 * of ttls_sha1_context, so your implementation of ttls_sha1_process must be compatible
 * with this definition.
 *
 * \note Because of a signature change, the core AES encryption and decryption routines are
 *	   currently named ttls_aes_internal_encrypt and ttls_aes_internal_decrypt,
 *	   respectively. When setting up alternative implementations, these functions should
 *	   be overriden, but the wrapper functions ttls_aes_decrypt and ttls_aes_encrypt
 *	   must stay untouched.
 *
 * \note If you use the AES_xxx_ALT macros, then is is recommended to also set
 *	   TTLS_AES_ROM_TABLES in order to help the linker garbage-collect the AES
 *	   tables.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * function.
 *
 * \warning   MD2, MD4, MD5, DES and SHA-1 are considered weak and their use
 *			constitutes a security risk. If possible, we recommend avoiding
 *			dependencies on them, and considering stronger message digests
 *			and ciphers instead.
 *
 */
//#define TTLS_MD2_PROCESS_ALT
//#define TTLS_MD4_PROCESS_ALT
//#define TTLS_MD5_PROCESS_ALT
//#define TTLS_RIPEMD160_PROCESS_ALT
//#define TTLS_SHA1_PROCESS_ALT
//#define TTLS_SHA256_PROCESS_ALT
//#define TTLS_SHA512_PROCESS_ALT
//#define TTLS_DES_SETKEY_ALT
//#define TTLS_DES_CRYPT_ECB_ALT
//#define TTLS_DES3_CRYPT_ECB_ALT
//#define TTLS_AES_SETKEY_ENC_ALT
//#define TTLS_AES_SETKEY_DEC_ALT
//#define TTLS_AES_ENCRYPT_ALT
//#define TTLS_AES_DECRYPT_ALT
//#define TTLS_ECDH_GEN_PUBLIC_ALT
//#define TTLS_ECDH_COMPUTE_SHARED_ALT
//#define TTLS_ECDSA_VERIFY_ALT
//#define TTLS_ECDSA_SIGN_ALT
//#define TTLS_ECDSA_GENKEY_ALT

/**
 * \def TTLS_ECP_INTERNAL_ALT
 *
 * Expose a part of the internal interface of the Elliptic Curve Point module.
 *
 * TTLS_ECP__FUNCTION_NAME__ALT: Uncomment a macro to let mbed TLS use your
 * alternative core implementation of elliptic curve arithmetic. Keep in mind
 * that function prototypes should remain the same.
 *
 * This partially replaces one function. The header file from mbed TLS is still
 * used, in contrast to the TTLS_ECP_ALT flag. The original implementation
 * is still present and it is used for group structures not supported by the
 * alternative.
 *
 * Any of these options become available by defining TTLS_ECP_INTERNAL_ALT
 * and implementing the following functions:
 *	  unsigned char ttls_internal_ecp_grp_capable(
 *		  const ttls_ecp_group *grp)
 *	  int  ttls_internal_ecp_init(const ttls_ecp_group *grp)
 *	  void ttls_internal_ecp_deinit(const ttls_ecp_group *grp)
 * The ttls_internal_ecp_grp_capable function should return 1 if the
 * replacement functions implement arithmetic for the given group and 0
 * otherwise.
 * The functions ttls_internal_ecp_init and ttls_internal_ecp_deinit are
 * called before and after each point operation and provide an opportunity to
 * implement optimized set up and tear down instructions.
 *
 * Example: In case you uncomment TTLS_ECP_INTERNAL_ALT and
 * TTLS_ECP_DOUBLE_JAC_ALT, mbed TLS will still provide the ecp_double_jac
 * function, but will use your ttls_internal_ecp_double_jac if the group is
 * supported (your ttls_internal_ecp_grp_capable function returns 1 when
 * receives it as an argument). If the group is not supported then the original
 * implementation is used. The other functions and the definition of
 * ttls_ecp_group and ttls_ecp_point will not change, so your
 * implementation of ttls_internal_ecp_double_jac and
 * ttls_internal_ecp_grp_capable must be compatible with this definition.
 *
 * Uncomment a macro to enable alternate implementation of the corresponding
 * function.
 */
/* Required for all the functions in this section */
//#define TTLS_ECP_INTERNAL_ALT
/* Support for Weierstrass curves with Jacobi representation */
//#define TTLS_ECP_RANDOMIZE_JAC_ALT
//#define TTLS_ECP_ADD_MIXED_ALT
//#define TTLS_ECP_DOUBLE_JAC_ALT
//#define TTLS_ECP_NORMALIZE_JAC_MANY_ALT
//#define TTLS_ECP_NORMALIZE_JAC_ALT
/* Support for curves with Montgomery arithmetic */
//#define TTLS_ECP_DOUBLE_ADD_MXZ_ALT
//#define TTLS_ECP_RANDOMIZE_MXZ_ALT
//#define TTLS_ECP_NORMALIZE_MXZ_ALT

/**
 * \def TTLS_CAMELLIA_SMALL_MEMORY
 *
 * Use less ROM for the Camellia implementation (saves about 768 bytes).
 *
 * Uncomment this macro to use less memory for Camellia.
 */
//#define TTLS_CAMELLIA_SMALL_MEMORY

/**
 * \def TTLS_CIPHER_PADDING_PKCS7
 *
 * TTLS_CIPHER_PADDING_XXX: Uncomment or comment macros to add support for
 * specific padding modes in the cipher layer with cipher modes that support
 * padding (e.g. CBC)
 *
 * If you disable all padding modes, only full blocks can be used with CBC.
 *
 * Enable padding modes in the cipher layer.
 */
#define TTLS_CIPHER_PADDING_PKCS7
#define TTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define TTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define TTLS_CIPHER_PADDING_ZEROS

/**
 * \def TTLS_ECP_NIST_OPTIM
 *
 * Enable specific 'modulo p' routines for each NIST prime.
 * Depending on the prime and architecture, makes operations 4 to 8 times
 * faster on the corresponding curve.
 *
 * Comment this macro to disable NIST curves optimisation.
 */
#define TTLS_ECP_NIST_OPTIM

/**
 * \def TTLS_ECDSA_DETERMINISTIC
 *
 * Enable deterministic ECDSA (RFC 6979).
 * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
 * may result in a compromise of the long-term signing key. This is avoided by
 * the deterministic variant.
 *
 * Requires: TTLS_HMAC_DRBG_C
 *
 * Comment this macro to disable deterministic ECDSA.
 */
#define TTLS_ECDSA_DETERMINISTIC

/**
 * \def TTLS_PK_PARSE_EC_EXTENDED
 *
 * Enhance support for reading EC keys using variants of SEC1 not allowed by
 * RFC 5915 and RFC 5480.
 *
 * Currently this means parsing the SpecifiedECDomain choice of EC
 * parameters (only known groups are supported, not arbitrary domains, to
 * avoid validation issues).
 *
 * Disable if you only need to support RFC 5915 + 5480 key formats.
 */
#define TTLS_PK_PARSE_EC_EXTENDED

/**
 * \def TTLS_GENPRIME
 *
 * Enable the prime-number generation code.
 */
#define TTLS_GENPRIME

/**
 * \def TTLS_ENTROPY_FORCE_SHA256
 *
 * Force the entropy accumulator to use a SHA-256 accumulator instead of the
 * default SHA-512 based one (if both are available).
 *
 * Requires: TTLS_SHA256_C
 *
 * On 32-bit systems SHA-256 can be much faster than SHA-512. Use this option
 * if you have performance concerns.
 *
 * This option is only useful if both TTLS_SHA256_C and
 * TTLS_SHA512_C are defined. Otherwise the available hash module is used.
 */
//#define TTLS_ENTROPY_FORCE_SHA256

/**
 * \def TTLS_PK_RSA_ALT_SUPPORT
 *
 * Support external private RSA keys (eg from a HSM) in the PK layer.
 *
 * Comment this macro to disable support for external private RSA keys.
 */
#define TTLS_PK_RSA_ALT_SUPPORT

/**
 * \def TTLS_RSA_NO_CRT
 *
 * Do not use the Chinese Remainder Theorem
 * for the RSA private operation.
 *
 * Uncomment this macro to disable the use of CRT in RSA.
 *
 */
//#define TTLS_RSA_NO_CRT

/**
 * \def TTLS_SHA256_SMALLER
 *
 * Enable an implementation of SHA-256 that has lower ROM footprint but also
 * lower performance.
 *
 * The default implementation is meant to be a reasonnable compromise between
 * performance and size. This version optimizes more aggressively for size at
 * the expense of performance. Eg on Cortex-M4 it reduces the size of
 * ttls_sha256_process() from ~2KB to ~0.5KB for a performance hit of about
 * 30%.
 *
 * Uncomment to enable the smaller implementation of SHA256.
 */
//#define TTLS_SHA256_SMALLER

/**
 * \def TTLS_DEBUG_ALL
 *
 * Enable the debug messages in SSL module for all issues.
 * Debug messages have been disabled in some places to prevent timing
 * attacks due to (unbalanced) debugging function calls.
 *
 * If you need all error reporting you should enable this during debugging,
 * but remove this for production servers that should log as well.
 *
 * Uncomment this macro to report all debug messages on errors introducing
 * a timing side-channel.
 *
 */
#define TTLS_DEBUG_ALL

/**
 * \def TTLS_EXPORT_KEYS
 *
 * Enable support for exporting key block and master secret.
 * This is required for certain users of TLS, e.g. EAP-TLS.
 *
 * Comment this macro to disable support for key export
 */
#define TTLS_EXPORT_KEYS

/**
 * \def TTLS_X509_ALLOW_EXTENSIONS_NON_V3
 *
 * If set, the X509 parser will not break-off when parsing an X509 certificate
 * and encountering an extension in a v1 or v2 certificate.
 *
 * Uncomment to prevent an error.
 */
//#define TTLS_X509_ALLOW_EXTENSIONS_NON_V3

/**
 * \def TTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
 *
 * If set, the X509 parser will not break-off when parsing an X509 certificate
 * and encountering an unknown critical extension.
 *
 * \warning Depending on your PKI use, enabling this can be a security risk!
 *
 * Uncomment to prevent an error.
 */
//#define TTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION

/**
 * \def TTLS_X509_CHECK_KEY_USAGE
 *
 * Enable verification of the keyUsage extension (CA and leaf certificates).
 *
 * Disabling this avoids problems with mis-issued and/or misused
 * (intermediate) CA and leaf certificates.
 *
 * \warning Depending on your PKI use, disabling this can be a security risk!
 *
 * Comment to skip keyUsage checking for both CA and leaf certificates.
 */
#define TTLS_X509_CHECK_KEY_USAGE

/**
 * \def TTLS_X509_CHECK_EXTENDED_KEY_USAGE
 *
 * Enable verification of the extendedKeyUsage extension (leaf certificates).
 *
 * Disabling this avoids problems with mis-issued and/or misused certificates.
 *
 * \warning Depending on your PKI use, disabling this can be a security risk!
 *
 * Comment to skip extendedKeyUsage checking for certificates.
 */
#define TTLS_X509_CHECK_EXTENDED_KEY_USAGE

/**
 * \def TTLS_X509_RSASSA_PSS_SUPPORT
 *
 * Enable parsing and verification of X.509 certificates, CRLs and CSRS
 * signed with RSASSA-PSS (aka PKCS#1 v2.1).
 *
 * Comment this macro to disallow using RSASSA-PSS in certificates.
 */
#define TTLS_X509_RSASSA_PSS_SUPPORT

/**
 * \def TTLS_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  library/asn1write.c
 * Caller:  library/ecdsa.c
 *		  library/pkwrite.c
 *		  library/x509_create.c
 *		  library/x509write_crt.c
 *		  library/x509write_csr.c
 */
#define TTLS_ASN1_WRITE_C

/**
 * \def TTLS_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  library/base64.c
 * Caller:  library/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define TTLS_BASE64_C

/**
 * \def TTLS_BLOWFISH_C
 *
 * Enable the Blowfish block cipher.
 *
 * Module:  library/blowfish.c
 */
#define TTLS_BLOWFISH_C

/**
 * \def TTLS_CAMELLIA_C
 *
 * Enable the Camellia block cipher.
 *
 * Module:  library/camellia.c
 * Caller:  library/ssl_tls.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *	  TTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *	  TTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
 *	  TTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
 *	  TTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
 *	  TTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
 *	  TTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
 *	  TTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
 *	  TTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *	  TTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *	  TTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *	  TTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
#define TTLS_CAMELLIA_C

/**
 * \def TTLS_CERTS_C
 *
 * Enable the test certificates.
 *
 * Module:  library/certs.c
 * Caller:
 *
 * This module is used for testing (ssl_client/server).
 */
#define TTLS_CERTS_C

/**
 * \def TTLS_CMAC_C
 *
 * Enable the CMAC (Cipher-based Message Authentication Code) mode for block
 * ciphers.
 *
 * Module:  library/cmac.c
 */
#define TTLS_CMAC_C

/**
 * \def TTLS_CTR_DRBG_C
 *
 * Enable the CTR_DRBG AES-256-based random generator.
 *
 * Module:  library/ctr_drbg.c
 * Caller:
 *
 * This module provides the CTR_DRBG AES-256 random number generator.
 */
#define TTLS_CTR_DRBG_C

/**
 * \def TTLS_DHM_C
 *
 * Enable the Diffie-Hellman-Merkle module.
 *
 * Module:  library/dhm.c
 * Caller:  library/ssl_cli.c
 *		  library/ssl_srv.c
 *
 * This module is used by the following key exchanges:
 *	  DHE-RSA, DHE-PSK
 *
 * \warning	Using DHE constitutes a security risk as it
 *			 is not possible to validate custom DH parameters.
 *			 If possible, it is recommended users should consider
 *			 preferring other methods of key exchange.
 *			 See dhm.h for more details.
 *
 */
#define TTLS_DHM_C

/**
 * \def TTLS_ECDH_C
 *
 * Enable the elliptic curve Diffie-Hellman library.
 *
 * Module:  library/ecdh.c
 * Caller:  library/ssl_cli.c
 *		  library/ssl_srv.c
 *
 * This module is used by the following key exchanges:
 *	  ECDHE-ECDSA, ECDHE-RSA, DHE-PSK
 */
#define TTLS_ECDH_C

/**
 * \def TTLS_ECDSA_C
 *
 * Enable the elliptic curve DSA library.
 *
 * Module:  library/ecdsa.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *	  ECDHE-ECDSA
 *
 * Requires: TTLS_ASN1_WRITE_C
 */
#define TTLS_ECDSA_C

/**
 * \def TTLS_ENTROPY_C
 *
 * Enable the platform-specific entropy code.
 *
 * Module:  library/entropy.c
 * Caller:
 *
 * Requires: TTLS_SHA512_C or TTLS_SHA256_C
 *
 * This module provides a generic entropy pool
 */
#define TTLS_ENTROPY_C

/**
 * \def TTLS_HAVEGE_C
 *
 * Enable the HAVEGE random generator.
 *
 * Warning: the HAVEGE random generator is not suitable for virtualized
 *		  environments
 *
 * Warning: the HAVEGE random generator is dependent on timing and specific
 *		  processor traits. It is therefore not advised to use HAVEGE as
 *		  your applications primary random generator or primary entropy pool
 *		  input. As a secondary input to your entropy pool, it IS able add
 *		  the (limited) extra entropy it provides.
 *
 * Module:  library/havege.c
 * Caller:
 *
 * Uncomment to enable the HAVEGE random generator.
 */
//#define TTLS_HAVEGE_C

/**
 * \def TTLS_HMAC_DRBG_C
 *
 * Enable the HMAC_DRBG random generator.
 *
 * Module:  library/hmac_drbg.c
 * Caller:
 *
 * Uncomment to enable the HMAC_DRBG random number geerator.
 */
#define TTLS_HMAC_DRBG_C

/**
 * \def TTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *		  library/pkparse.c
 *		  library/x509_crl.c
 *		  library/x509_crt.c
 *		  library/x509_csr.c
 *
 * Requires: TTLS_BASE64_C
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define TTLS_PEM_PARSE_C

/**
 * \def TTLS_PEM_WRITE_C
 *
 * Enable PEM encoding / writing.
 *
 * Module:  library/pem.c
 * Caller:  library/pkwrite.c
 *		  library/x509write_crt.c
 *		  library/x509write_csr.c
 *
 * Requires: TTLS_BASE64_C
 *
 * This modules adds support for encoding / writing PEM files.
 */
//#define TTLS_PEM_WRITE_C

/**
 * \def TTLS_PK_WRITE_C
 *
 * Enable the generic public (asymetric) key writer.
 *
 * Module:  library/pkwrite.c
 * Caller:  library/x509write.c
 *
 * Uncomment to enable generic public key write functions.
 */
//#define TTLS_PK_WRITE_C

/**
 * \def TTLS_PKCS5_C
 *
 * Enable PKCS#5 functions.
 *
 * Module:  library/pkcs5.c
 *
 * This module adds support for the PKCS#5 functions.
 */
#define TTLS_PKCS5_C

/**
 * \def TTLS_PKCS11_C
 *
 * Enable wrapper for PKCS#11 smartcard support.
 *
 * Module:  library/pkcs11.c
 * Caller:  library/pk.c
 *
 * This module enables SSL/TLS PKCS #11 smartcard support.
 * Requires the presence of the PKCS#11 helper library (libpkcs11-helper)
 */
//#define TTLS_PKCS11_C

/**
 * \def TTLS_PKCS12_C
 *
 * Enable PKCS#12 PBE functions.
 * Adds algorithms for parsing PKCS#8 encrypted private keys
 *
 * Module:  library/pkcs12.c
 * Caller:  library/pkparse.c
 *
 * This module enables PKCS#12 functions.
 */
#define TTLS_PKCS12_C

/**
 * \def TTLS_RIPEMD160_C
 *
 * Enable the RIPEMD-160 hash algorithm.
 *
 * Module:  library/ripemd160.c
 * Caller:  library/md.c
 *
 */
#define TTLS_RIPEMD160_C

/**
 * \def TTLS_SHA256_C
 *
 * Enable the SHA-224 and SHA-256 cryptographic hash algorithms.
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *		  library/md.c
 *		  library/ssl_cli.c
 *		  library/ssl_srv.c
 *		  library/ssl_tls.c
 *
 * This module adds support for SHA-224 and SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define TTLS_SHA256_C

/**
 * \def TTLS_SHA512_C
 *
 * Enable the SHA-384 and SHA-512 cryptographic hash algorithms.
 *
 * Module:  library/sha512.c
 * Caller:  library/entropy.c
 *		  library/md.c
 *		  library/ssl_cli.c
 *		  library/ssl_srv.c
 *
 * This module adds support for SHA-384 and SHA-512.
 */
#define TTLS_SHA512_C

/**
 * \def TTLS_CACHE_C
 *
 * Enable simple SSL cache implementation.
 *
 * Module:  library/ssl_cache.c
 * Caller:
 *
 * Requires: TTLS_CACHE_C
 */
#define TTLS_CACHE_C

/**
 * \def TTLS_TICKET_C
 *
 * Enable an implementation of TLS server-side callbacks for session tickets.
 *
 * Module:  library/ssl_ticket.c
 * Caller:
 */
#define TTLS_TICKET_C

/**
 * \def TTLS_CLI_C
 *
 * Enable the SSL/TLS client code.
 *
 * Module:  library/ssl_cli.c
 * Caller:
 *
 * This module is required for SSL/TLS client support.
 */
//#define TTLS_CLI_C

/**
 * \def TTLS_X509_CRL_PARSE_C
 *
 * Enable X.509 CRL parsing.
 *
 * Module:  library/x509_crl.c
 * Caller:  library/x509_crt.c
 *
 * This module is required for X.509 CRL parsing.
 */
#define TTLS_X509_CRL_PARSE_C

/**
 * \def TTLS_X509_CSR_PARSE_C
 *
 * Enable X.509 Certificate Signing Request (CSR) parsing.
 *
 * Module:  library/x509_csr.c
 * Caller:  library/x509_crt_write.c
 *
 * This module is used for reading X.509 certificate request.
 */
#define TTLS_X509_CSR_PARSE_C

/**
 * \def TTLS_X509_CREATE_C
 *
 * Enable X.509 core for creating certificates.
 *
 * Module:  library/x509_create.c
 *
 * Requires: TTLS_PK_WRITE_C
 *
 * This module is the basis for creating X.509 certificates and CSRs.
 */
//#define TTLS_X509_CREATE_C

/**
 * \def TTLS_X509_CRT_WRITE_C
 *
 * Enable creating X.509 certificates.
 *
 * Module:  library/x509_crt_write.c
 *
 * Requires: TTLS_X509_CREATE_C
 *
 * This module is required for X.509 certificate creation.
 */
//#define TTLS_X509_CRT_WRITE_C

/**
 * \def TTLS_X509_CSR_WRITE_C
 *
 * Enable creating X.509 Certificate Signing Requests (CSR).
 *
 * Module:  library/x509_csr_write.c
 *
 * Requires: TTLS_X509_CREATE_C
 *
 * This module is required for X.509 certificate request writing.
 */
//#define TTLS_X509_CSR_WRITE_C

/**
 * \def TTLS_XTEA_C
 *
 * Enable the XTEA block cipher.
 *
 * Module:  library/xtea.c
 * Caller:
 */
#define TTLS_XTEA_C

/* \} name SECTION: mbed TLS modules */

/**
 * \name SECTION: Module configuration options
 *
 * This section allows for the setting of module specific sizes and
 * configuration options. The default values are already present in the
 * relevant header files and should suffice for the regular use cases.
 *
 * Our advice is to enable options and change their values here
 * only if you have a good reason and know the consequences.
 *
 * Please check the respective header file for documentation on these
 * parameters (to prevent duplicate documentation).
 * \{
 */

/* CTR_DRBG options */
//#define TTLS_CTR_DRBG_ENTROPY_LEN			   48 /**< Amount of entropy used per seed by default (48 with SHA-512, 32 with SHA-256) */
//#define TTLS_CTR_DRBG_RESEED_INTERVAL		10000 /**< Interval before reseed is performed by default */
//#define TTLS_CTR_DRBG_MAX_INPUT				256 /**< Maximum number of additional input bytes */
//#define TTLS_CTR_DRBG_MAX_REQUEST			 1024 /**< Maximum number of requested bytes per call */
//#define TTLS_CTR_DRBG_MAX_SEED_INPUT		   384 /**< Maximum size of (re)seed buffer */

/* HMAC_DRBG options */
//#define TTLS_HMAC_DRBG_RESEED_INTERVAL   10000 /**< Interval before reseed is performed by default */
//#define TTLS_HMAC_DRBG_MAX_INPUT		   256 /**< Maximum number of additional input bytes */
//#define TTLS_HMAC_DRBG_MAX_REQUEST		1024 /**< Maximum number of requested bytes per call */
//#define TTLS_HMAC_DRBG_MAX_SEED_INPUT	  384 /**< Maximum size of (re)seed buffer */

/* ECP options */
//#define TTLS_ECP_MAX_BITS			 521 /**< Maximum bit size of groups */
//#define TTLS_ECP_WINDOW_SIZE			6 /**< Maximum window size used */
//#define TTLS_ECP_FIXED_POINT_OPTIM	  1 /**< Enable fixed-point speed-up */

/* Entropy options */
//#define TTLS_ENTROPY_MAX_SOURCES				20 /**< Maximum number of sources supported */
//#define TTLS_ENTROPY_MAX_GATHER				128 /**< Maximum amount requested from entropy sources */
//#define TTLS_ENTROPY_MIN_HARDWARE			   32 /**< Default minimum number of bytes required for the hardware entropy source ttls_hardware_poll() before entropy is released */

/* Memory buffer allocator options */
//#define TTLS_MEMORY_ALIGN_MULTIPLE	  4 /**< Align on multiples of this value */

/* SSL Cache options */
//#define TTLS_CACHE_DEFAULT_TIMEOUT	   86400 /**< 1 day  */
//#define TTLS_CACHE_DEFAULT_MAX_ENTRIES	  50 /**< Maximum entries in cache */

/* SSL options */
//#define TTLS_DEFAULT_TICKET_LIFETIME	 86400 /**< Lifetime of session tickets (if enabled) */
//#define TTLS_PSK_MAX_LEN			   32 /**< Max size of TLS pre-shared keys, in bytes (default 256 bits) */

/**
 * Complete list of ciphersuites to use, in order of preference.
 *
 * \warning No dependency checking is done on that field! This option can only
 * be used to restrict the set of available ciphersuites. It is your
 * responsibility to make sure the needed modules are active.
 *
 * Use this to save a few hundred bytes of ROM (default ordering of all
 * available ciphersuites) and a few to a few hundred bytes of RAM.
 *
 * The value below is only an example, not the default.
 */
//#define TTLS_CIPHERSUITES TTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

/* X509 options */
//#define TTLS_X509_MAX_INTERMEDIATE_CA   8   /**< Maximum number of intermediate CAs in a verification chain. */
//#define TTLS_X509_MAX_FILE_PATH_LEN	 512 /**< Maximum length of a path/filename string in bytes including the null terminator character ('\0'). */

/**
 * Allow SHA-1 in the default TLS configuration for certificate signing.
 * Without this build-time option, SHA-1 support must be activated explicitly
 * through ttls_conf_cert_profile. Turning on this option is not
 * recommended because of it is possible to generate SHA-1 collisions, however
 * this may be safe for legacy infrastructure where additional controls apply.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *			a security risk. If possible, we recommend avoiding dependencies
 *			on it, and considering stronger message digests instead.
 *
 */
// #define TTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES

/**
 * Allow SHA-1 in the default TLS configuration for TLS 1.2 handshake
 * signature and ciphersuite selection. Without this build-time option, SHA-1
 * support must be activated explicitly through ttls_conf_sig_hashes.
 * The use of SHA-1 in TLS <= 1.1 and in HMAC-SHA-1 is always allowed by
 * default. At the time of writing, there is no practical attack on the use
 * of SHA-1 in handshake signatures, hence this option is turned on by default
 * to preserve compatibility with existing peers, but the general
 * warning applies nonetheless:
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *			a security risk. If possible, we recommend avoiding dependencies
 *			on it, and considering stronger message digests instead.
 *
 */
#define TTLS_TLS_DEFAULT_ALLOW_SHA1_IN_KEY_EXCHANGE

/* CHECK CONFIG. */

#if defined(TTLS_ECDSA_C) &&	(!defined(TTLS_ASN1_WRITE_C))
#error "TTLS_ECDSA_C defined, but not all prerequisites"
#endif

#if defined(TTLS_ENTROPY_C) && (!defined(TTLS_SHA512_C) && !defined(TTLS_SHA256_C))
#error "TTLS_ENTROPY_C defined, but not all prerequisites"
#endif
#if defined(TTLS_ENTROPY_C) && defined(TTLS_SHA512_C) &&		 \
	defined(TTLS_CTR_DRBG_ENTROPY_LEN) && (TTLS_CTR_DRBG_ENTROPY_LEN > 64)
#error "TTLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(TTLS_ENTROPY_C) &&		\
	(!defined(TTLS_SHA512_C) || defined(TTLS_ENTROPY_FORCE_SHA256)) \
	&& defined(TTLS_CTR_DRBG_ENTROPY_LEN) && (TTLS_CTR_DRBG_ENTROPY_LEN > 32)
#error "TTLS_CTR_DRBG_ENTROPY_LEN value too high"
#endif
#if defined(TTLS_ENTROPY_C) && \
	defined(TTLS_ENTROPY_FORCE_SHA256) && !defined(TTLS_SHA256_C)
#error "TTLS_ENTROPY_FORCE_SHA256 defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_RANDOMIZE_JAC_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_RANDOMIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_ADD_MIXED_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_ADD_MIXED_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_DOUBLE_JAC_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_DOUBLE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_NORMALIZE_JAC_MANY_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_NORMALIZE_JAC_MANY_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_NORMALIZE_JAC_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_NORMALIZE_JAC_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_DOUBLE_ADD_MXZ_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_DOUBLE_ADD_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_RANDOMIZE_MXZ_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_RANDOMIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_ECP_NORMALIZE_MXZ_ALT) && !defined(TTLS_ECP_INTERNAL_ALT)
#error "TTLS_ECP_NORMALIZE_MXZ_ALT defined, but not all prerequisites"
#endif

#if defined(TTLS_PEM_PARSE_C) && !defined(TTLS_BASE64_C)
#error "TTLS_PEM_PARSE_C defined, but not all prerequisites"
#endif

#if defined(TTLS_PEM_WRITE_C) && !defined(TTLS_BASE64_C)
#error "TTLS_PEM_WRITE_C defined, but not all prerequisites"
#endif

#if defined(TTLS_X509_CREATE_C) && (!defined(TTLS_ASN1_WRITE_C) ||	   \
	!defined(TTLS_PK_WRITE_C))
#error "TTLS_X509_CREATE_C defined, but not all prerequisites"
#endif

#if defined(TTLS_X509_CRT_WRITE_C) && (!defined(TTLS_X509_CREATE_C))
#error "TTLS_X509_CRT_WRITE_C defined, but not all prerequisites"
#endif

#if defined(TTLS_X509_CSR_WRITE_C) && (!defined(TTLS_X509_CREATE_C))
#error "TTLS_X509_CSR_WRITE_C defined, but not all prerequisites"
#endif

#endif /* TTLS_CONFIG_H */
