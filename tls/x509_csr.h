/**
 * \file x509_csr.h
 *
 * \brief X.509 certificate signing request parsing and writing
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
#ifndef TTLS_X509_CSR_H
#define TTLS_X509_CSR_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include "x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures and functions for X.509 Certificate Signing Requests (CSR)
 * \{
 */

/**
 * Certificate Signing Request (CSR) structure.
 */
typedef struct ttls_x509_csr
{
	ttls_x509_buf raw;		   /**< The raw CSR data (DER). */
	ttls_x509_buf cri;		   /**< The raw CertificateRequestInfo body (DER). */

	int version;			/**< CSR version (1=v1). */

	ttls_x509_buf  subject_raw;  /**< The raw subject data (DER). */
	ttls_x509_name subject;	  /**< The parsed subject data (named information object). */

	ttls_pk_context pk;		  /**< Container for the public key context. */

	ttls_x509_buf sig_oid;
	ttls_x509_buf sig;
	ttls_md_type_t sig_md;	   /**< Internal representation of the MD algorithm of the signature algorithm, e.g. TTLS_MD_SHA256 */
	ttls_pk_type_t sig_pk;	   /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. TTLS_PK_RSA */
	void *sig_opts;		 /**< Signature options to be passed to ttls_pk_verify_ext(), e.g. for RSASSA-PSS */
}
ttls_x509_csr;

/**
 * Container for writing a CSR
 */
typedef struct ttls_x509write_csr
{
	ttls_pk_context *key;
	ttls_asn1_named_data *subject;
	ttls_md_type_t md_alg;
	ttls_asn1_named_data *extensions;
}
ttls_x509write_csr;

#if defined(TTLS_X509_CSR_PARSE_C)
/**
 * \brief		  Load a Certificate Signing Request (CSR) in DER format
 *
 * \note		   CSR attributes (if any) are currently silently ignored.
 *
 * \param csr	  CSR context to fill
 * \param buf	  buffer holding the CRL data
 * \param buflen   size of the buffer
 *
 * \return		 0 if successful, or a specific X509 error code
 */
int ttls_x509_csr_parse_der(ttls_x509_csr *csr,
			const unsigned char *buf, size_t buflen);

/**
 * \brief		  Load a Certificate Signing Request (CSR), DER or PEM format
 *
 * \note		   See notes for \c ttls_x509_csr_parse_der()
 *
 * \param csr	  CSR context to fill
 * \param buf	  buffer holding the CRL data
 * \param buflen   size of the buffer
 *				 (including the terminating null byte for PEM data)
 *
 * \return		 0 if successful, or a specific X509 or PEM error code
 */
int ttls_x509_csr_parse(ttls_x509_csr *csr, const unsigned char *buf, size_t buflen);

/**
 * \brief		  Returns an informational string about the
 *				 CSR.
 *
 * \param buf	  Buffer to write to
 * \param size	 Maximum size of buffer
 * \param prefix   A line prefix
 * \param csr	  The X509 CSR to represent
 *
 * \return		 The length of the string written (not including the
 *				 terminated nul byte), or a negative error code.
 */
int ttls_x509_csr_info(char *buf, size_t size, const char *prefix,
				   const ttls_x509_csr *csr);

/**
 * \brief		  Initialize a CSR
 *
 * \param csr	  CSR to initialize
 */
void ttls_x509_csr_init(ttls_x509_csr *csr);

/**
 * \brief		  Unallocate all CSR data
 *
 * \param csr	  CSR to free
 */
void ttls_x509_csr_free(ttls_x509_csr *csr);
#endif /* TTLS_X509_CSR_PARSE_C */

/* \} name */
/* \} addtogroup x509_module */

#if defined(TTLS_X509_CSR_WRITE_C)
/**
 * \brief		   Initialize a CSR context
 *
 * \param ctx	   CSR context to initialize
 */
void ttls_x509write_csr_init(ttls_x509write_csr *ctx);

/**
 * \brief		   Set the subject name for a CSR
 *				  Subject names should contain a comma-separated list
 *				  of OID types and values:
 *				  e.g. "C=UK,O=ARM,CN=mbed TLS Server 1"
 *
 * \param ctx		   CSR context to use
 * \param subject_name  subject name to set
 *
 * \return		  0 if subject name was parsed successfully, or
 *				  a specific error code
 */
int ttls_x509write_csr_set_subject_name(ttls_x509write_csr *ctx,
			const char *subject_name);

/**
 * \brief		   Set the key for a CSR (public key will be included,
 *				  private key used to sign the CSR when writing it)
 *
 * \param ctx	   CSR context to use
 * \param key	   Asymetric key to include
 */
void ttls_x509write_csr_set_key(ttls_x509write_csr *ctx, ttls_pk_context *key);

/**
 * \brief		   Set the MD algorithm to use for the signature
 *				  (e.g. TTLS_MD_SHA1)
 *
 * \param ctx	   CSR context to use
 * \param md_alg	MD algorithm to use
 */
void ttls_x509write_csr_set_md_alg(ttls_x509write_csr *ctx, ttls_md_type_t md_alg);

/**
 * \brief		   Set the Key Usage Extension flags
 *				  (e.g. TTLS_X509_KU_DIGITAL_SIGNATURE | TTLS_X509_KU_KEY_CERT_SIGN)
 *
 * \param ctx	   CSR context to use
 * \param key_usage key usage flags to set
 *
 * \return		  0 if successful, or TTLS_ERR_X509_ALLOC_FAILED
 */
int ttls_x509write_csr_set_key_usage(ttls_x509write_csr *ctx, unsigned char key_usage);

/**
 * \brief		   Set the Netscape Cert Type flags
 *				  (e.g. TTLS_X509_NS_CERT_TYPE_SSL_CLIENT | TTLS_X509_NS_CERT_TYPE_EMAIL)
 *
 * \param ctx		   CSR context to use
 * \param ns_cert_type  Netscape Cert Type flags to set
 *
 * \return		  0 if successful, or TTLS_ERR_X509_ALLOC_FAILED
 */
int ttls_x509write_csr_set_ns_cert_type(ttls_x509write_csr *ctx,
			unsigned char ns_cert_type);

/**
 * \brief		   Generic function to add to or replace an extension in the
 *				  CSR
 *
 * \param ctx	   CSR context to use
 * \param oid	   OID of the extension
 * \param oid_len   length of the OID
 * \param val	   value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return		  0 if successful, or a TTLS_ERR_X509_ALLOC_FAILED
 */
int ttls_x509write_csr_set_extension(ttls_x509write_csr *ctx,
		 const char *oid, size_t oid_len,
		 const unsigned char *val, size_t val_len);

/**
 * \brief		   Free the contents of a CSR context
 *
 * \param ctx	   CSR context to free
 */
void ttls_x509write_csr_free(ttls_x509write_csr *ctx);

/**
 * \brief		   Write a CSR (Certificate Signing Request) to a
 *				  DER structure
 *				  Note: data is written at the end of the buffer! Use the
 *			return value to determine where you should start
 *			using the buffer
 *
 * \param ctx	   CSR to write away
 * \param buf	   buffer to write to
 * \param size	  size of the buffer
 * \param f_rng	 RNG function (for signature, see note)
 * \param p_rng	 RNG parameter
 *
 * \return		  length of data written if successful, or a specific
 *				  error code
 *
 * \note			f_rng may be NULL if RSA is used for signature and the
 *				  signature is made offline (otherwise f_rng is desirable
 *				  for countermeasures against timing attacks).
 *				  ECDSA signatures always require a non-NULL f_rng.
 */
int ttls_x509write_csr_der(ttls_x509write_csr *ctx, unsigned char *buf, size_t size,
		   int (*f_rng)(void *, unsigned char *, size_t),
		   void *p_rng);

#if defined(TTLS_PEM_WRITE_C)
/**
 * \brief		   Write a CSR (Certificate Signing Request) to a
 *				  PEM string
 *
 * \param ctx	   CSR to write away
 * \param buf	   buffer to write to
 * \param size	  size of the buffer
 * \param f_rng	 RNG function (for signature, see note)
 * \param p_rng	 RNG parameter
 *
 * \return		  0 if successful, or a specific error code
 *
 * \note			f_rng may be NULL if RSA is used for signature and the
 *				  signature is made offline (otherwise f_rng is desirable
 *				  for countermeasures against timing attacks).
 *				  ECDSA signatures always require a non-NULL f_rng.
 */
int ttls_x509write_csr_pem(ttls_x509write_csr *ctx, unsigned char *buf, size_t size,
		   int (*f_rng)(void *, unsigned char *, size_t),
		   void *p_rng);
#endif /* TTLS_PEM_WRITE_C */
#endif /* TTLS_X509_CSR_WRITE_C */

#ifdef __cplusplus
}
#endif

#endif /* ttls_x509_csr.h */
