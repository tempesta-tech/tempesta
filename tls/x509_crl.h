/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
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
#ifndef TTLS_X509_CRL_H
#define TTLS_X509_CRL_H

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
 * \name Structures and functions for parsing CRLs
 * \{
 */

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 */
typedef struct ttls_x509_crl_entry
{
	ttls_x509_buf raw;

	ttls_x509_buf serial;

	ttls_x509_time revocation_date;

	ttls_x509_buf entry_ext;

	struct ttls_x509_crl_entry *next;
}
ttls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct ttls_x509_crl
{
	ttls_x509_buf raw;		   /**< The raw certificate data (DER). */
	ttls_x509_buf tbs;		   /**< The raw certificate body (DER). The part that is To Be Signed. */

	int version;			/**< CRL version (1=v1, 2=v2) */
	ttls_x509_buf sig_oid;	   /**< CRL signature type identifier */

	ttls_x509_buf issuer_raw;	/**< The raw issuer data (DER). */

	ttls_x509_name issuer;	   /**< The parsed issuer data (named information object). */

	ttls_x509_time this_update;
	ttls_x509_time next_update;

	ttls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

	ttls_x509_buf crl_ext;

	ttls_x509_buf sig_oid2;
	ttls_x509_buf sig;
	ttls_md_type_t sig_md;		   /**< Internal representation of the MD algorithm of the signature algorithm, e.g. TTLS_MD_SHA256 */
	ttls_pk_type_t sig_pk;		   /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. TTLS_PK_RSA */
	void *sig_opts;			 /**< Signature options to be passed to ttls_pk_verify_ext(), e.g. for RSASSA-PSS */

	struct ttls_x509_crl *next;
}
ttls_x509_crl;

/**
 * \brief		  Parse a DER-encoded CRL and append it to the chained list
 *
 * \param chain	points to the start of the chain
 * \param buf	  buffer holding the CRL data in DER format
 * \param buflen   size of the buffer
 *				 (including the terminating null byte for PEM data)
 *
 * \return		 0 if successful, or a specific X509 or PEM error code
 */
int ttls_x509_crl_parse_der(ttls_x509_crl *chain,
			const unsigned char *buf, size_t buflen);
/**
 * \brief		  Parse one or more CRLs and append them to the chained list
 *
 * \note		   Mutliple CRLs are accepted only if using PEM format
 *
 * \param chain	points to the start of the chain
 * \param buf	  buffer holding the CRL data in PEM or DER format
 * \param buflen   size of the buffer
 *				 (including the terminating null byte for PEM data)
 *
 * \return		 0 if successful, or a specific X509 or PEM error code
 */
int ttls_x509_crl_parse(ttls_x509_crl *chain, const unsigned char *buf, size_t buflen);

/**
 * \brief		  Returns an informational string about the CRL.
 *
 * \param buf	  Buffer to write to
 * \param size	 Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl	  The X509 CRL to represent
 *
 * \return		 The length of the string written (not including the
 *				 terminated nul byte), or a negative error code.
 */
int ttls_x509_crl_info(char *buf, size_t size, const char *prefix,
				   const ttls_x509_crl *crl);

/**
 * \brief		  Initialize a CRL (chain)
 *
 * \param crl	  CRL chain to initialize
 */
void ttls_x509_crl_init(ttls_x509_crl *crl);

/**
 * \brief		  Unallocate all CRL data
 *
 * \param crl	  CRL chain to free
 */
void ttls_x509_crl_free(ttls_x509_crl *crl);

/* \} name */
/* \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* ttls_x509_crl.h */
