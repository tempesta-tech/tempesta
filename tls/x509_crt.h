/**
 *		Tempesta TLS
 *
 * X.509 certificate parsing and writing
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2021 Tempesta Technologies, Inc.
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
#ifndef TTLS_X509_CRT_H
#define TTLS_X509_CRT_H

#include "x509.h"
#include "x509_crl.h"

#define TTLS_CERT_LEN_LEN			3

/**
 * Container for an X.509 certificate. The certificate may be chained.
 *
 * @raw			- The raw certificate data (DER) prepended with length.
 * @tbs			- The raw certificate body (DER). The part that is
 *			  To Be Signed.
 * @version		- The X.509 version. (1=v1, 2=v2, 3=v3)
 * @serial		- Unique id for certificate issued by a specific CA.
 * @sig_oid		- Signature algorithm, e.g. sha1RSA.
 * @issuer_raw		- The raw issuer data (DER). Used for quick comparison.
 * @subject_raw		- The raw subject data (DER). Used for quick comparison.
 * @issuer		- The parsed issuer data (named information object).
 * @subject		- The parsed subject data (named information object).
 * @valid_from		- Start time of certificate validity.
 * @valid_to		- End time of certificate validity.
 * @pk			- Container for the public key context.
 * @issuer_id		- Optional X.509 v2/v3 issuer unique identifier.
 * @subject_id		- Optional X.509 v2/v3 subject unique identifier.
 * @v3_ext		- Optional X.509 v3 extensions.
 * @subject_alt_names	- Optional list of Subject Alternative Names
 *			  (Only dNSName supported).
 * @ext_types		- Bit string containing detected and parsed extensions
 * @ca_istrue		- Optional Basic Constraint extension value:
 *			  1 if this certificate belongs to a CA, 0 otherwise.
 * @max_pathlen		- Optional Basic Constraint extension value:
 *			  The maximum path length to the root certificate.
 *			  Path length is 1 higher than RFC 5280 'meaning', so 1+
 * @int key_usage	- Optional key usage extension value: See the values in
 *			  x509.h
 * @ext_key_usage	- Optional list of extended key usage OIDs.
 * @char ns_cert_type	- Optional Netscape certificate type extension value:
 *			  See the values in x509.h
 * @sig			- Signature: hash of the tbs part signed with the
 *			  private key.
 * @sig_md		- Internal representation of the MD algorithm of the
 *			  signature algorithm, e.g. TTLS_MD_SHA256
 * @sig_pk		- Internal representation of the Public Key algorithm
 *			  of the signature algorithm, e.g. TTLS_PK_RSA
 * @*sig_opts		- Signature options to be passed to ttls_pk_verify_ext(),
 *			  e.g. for RSASSA-PSS
 * @TlsX509Crt *next	- Next certificate in the CA-chain.
 */
typedef struct TlsX509Crt {
	ttls_x509_buf raw;
	ttls_x509_buf tbs;

	int version;
	ttls_x509_buf serial;
	ttls_x509_buf sig_oid;

	ttls_x509_buf issuer_raw;
	ttls_x509_buf subject_raw;

	ttls_x509_name issuer;
	ttls_x509_name subject;

	ttls_x509_time valid_from;
	ttls_x509_time valid_to;

	TlsPkCtx pk;

	ttls_x509_buf issuer_id;
	ttls_x509_buf subject_id;
	ttls_x509_buf v3_ext;
	ttls_x509_sequence subject_alt_names;

	int ext_types;
	int ca_istrue;
	int max_pathlen;

	unsigned int key_usage;

	ttls_x509_sequence ext_key_usage;

	unsigned char ns_cert_type;

	ttls_x509_buf sig;
	ttls_md_type_t sig_md;
	ttls_pk_type_t sig_pk;
	void *sig_opts;

	struct TlsX509Crt *next;
} TlsX509Crt;

int ttls_x509_crt_parse_der(TlsX509Crt *chain, const unsigned char *buf,
			    size_t buflen);
int ttls_x509_crt_parse(TlsX509Crt *chain, unsigned char *buf, size_t buflen);

enum {
	TLS_X509_CERT_PROFILE_DEFAULT,
	TLS_X509_CERT_PROFILE_NEXT,
	TLS_X509_CERT_PROFILE_SUITEB
};

int ttls_x509_crt_verify_with_profile(TlsX509Crt *crt,
				      TlsX509Crt *trust_ca,
				      ttls_x509_crl *ca_crl,
				      int profile_id,
				      const char *cn, uint32_t *flags);
/* ttls_x509_crt_verify_with_profile with default profile. */
#define ttls_x509_crt_verify(crt, trust_ca, ca_clrm, cn, flags)			\
	ttls_x509_crt_verify_with_profile((crt), (trust_ca), (ca_clrm),		\
					  TLS_X509_CERT_PROFILE_SUITEB, (cn),	\
					  (flags))

int ttls_x509_crt_check_key_usage(const TlsX509Crt *crt,
				  unsigned int usage);
int ttls_x509_crt_check_extended_key_usage(const TlsX509Crt *crt,
					   const char *usage_oid,
					   size_t usage_len);

TlsX509Crt *ttls_x509_crt_alloc(void);
void ttls_x509_crt_init(TlsX509Crt *crt);
void ttls_x509_crt_free(TlsX509Crt *crt);
void ttls_x509_crt_destroy(TlsX509Crt **crt);

static inline void *
ttls_x509_crt_raw(TlsX509Crt *crt)
{
	return crt->raw.p + TTLS_CERT_LEN_LEN;
}

int ttls_x509_init(void);
void ttls_x509_exit(void);

#endif /* TTLS_X509_CRT_H */
