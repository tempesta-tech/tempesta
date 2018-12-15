/**
 *		Tempesta TLS
 *
 * Configuration options (set of defines)
 *
 * This set of compile-time options may be used to enable
 * or disable features selectively, and reduce the global
 * memory footprint.
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
#ifndef TTLS_CONFIG_H
#define TTLS_CONFIG_H

#include <linux/slab.h>
#include <linux/spinlock.h>

/* TODO remove the rest of the mess. */
#define ttls_calloc(n, s)	kzalloc((n) * (s), GFP_ATOMIC)
#define ttls_free(p)		kfree(p)

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
//#define TTLS_RSA_ALT
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
 * \def TTLS_*_PROCESS_ALT
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
//#define TTLS_ECDH_GEN_PUBLIC_ALT
//#define TTLS_ECDH_COMPUTE_SHARED_ALT
//#define TTLS_ECDSA_VERIFY_ALT
//#define TTLS_ECDSA_SIGN_ALT

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
 * TODO TTLS_TICKET_C
 *
 * Enable an implementation of TLS server-side callbacks for session tickets.
 *
 * Module:  library/ssl_ticket.c
 */
//#define TTLS_TICKET_C

/**
 * Enable the SSL/TLS client code.
 * This module is required for SSL/TLS client support (#769).
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
//#define TTLS_X509_CRL_PARSE_C

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

#endif /* TTLS_CONFIG_H */
