/**
 *		Tempesta TLS
 *
 * X.509 certificate revocation list parsing
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#ifndef TTLS_X509_CRL_H
#define TTLS_X509_CRL_H

#include "x509.h"

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 */
typedef struct ttls_x509_crl_entry {
	ttls_x509_buf raw;
	ttls_x509_buf serial;
	ttls_x509_time revocation_date;
	ttls_x509_buf entry_ext;
	struct ttls_x509_crl_entry *next;
}
ttls_x509_crl_entry;

/**
 * Certificate revocation list structure. Every CRL may have multiple entries.
 *
 * @raw;		- The raw certificate data (DER).
 * @tbs;		- The raw certificate body (DER). The part that is
 *			  To Be Signed.
 * @version;		- CRL version (1=v1, 2=v2)
 * @sig_oid;		- CRL signature type identifier
 * @issuer_raw;		- The raw issuer data (DER).
 * @issuer;		- The parsed issuer data (named information object).
 * @this_update;
 * @next_update;
 * @entry;		- The CRL entries containing the certificate revocation
 *			  times for this CA.
 * @crl_ext;
 * @sig_oid2;
 * @sig;
 * @sig_md;		- Internal representation of the MD algorithm of the
 *			  signature algorithm, e.g. TTLS_MD_SHA256
 * @sig_pk;		- Internal representation of the Public Key algorithm
 *			  of the signature algorithm, e.g. TTLS_PK_RSA
 * @*sig_opts;		- Signature options to be passed to ttls_pk_verify_ext(),
 *			  e.g. for RSASSA-PSS

 * @ttls_x509_crl *next;
 */
typedef struct ttls_x509_crl {
	ttls_x509_buf raw;
	ttls_x509_buf tbs;

	int version;
	ttls_x509_buf sig_oid;

	ttls_x509_buf issuer_raw;

	ttls_x509_name issuer;

	ttls_x509_time this_update;
	ttls_x509_time next_update;

	ttls_x509_crl_entry entry;

	ttls_x509_buf crl_ext;

	ttls_x509_buf sig_oid2;
	ttls_x509_buf sig;
	ttls_md_type_t sig_md;
	ttls_pk_type_t sig_pk;
	void *sig_opts;

	struct ttls_x509_crl *next;
}
ttls_x509_crl;


int ttls_x509_crl_parse_der(ttls_x509_crl *chain,
			const unsigned char *buf, size_t buflen);
int ttls_x509_crl_parse(ttls_x509_crl *chain, unsigned char *buf, size_t buflen);

void ttls_x509_crl_init(ttls_x509_crl *crl);
void ttls_x509_crl_free(ttls_x509_crl *crl);

#endif /* ttls_x509_crl.h */
