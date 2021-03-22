/*
 *		Tempesta TLS
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
#ifndef TTLS_X509_H
#define TTLS_X509_H

#include "asn1.h"
#include "pk.h"
#include "rsa.h"

/**
 * Maximum number of intermediate CAs in a verification chain.
 * That is, maximum length of the chain, excluding the end-entity certificate
 * and the trusted root certificate.
 *
 * Set this to a low value to prevent an adversary from making you waste
 * resources verifying an overlong certificate chain.
 */
#define TTLS_X509_MAX_INTERMEDIATE_CA			8

/**
 * X509 Error codes
 */
/* Unavailable feature, e.g. RSA hashing/encryption combination. */
#define TTLS_ERR_X509_FEATURE_UNAVAILABLE		-0x2080
/* The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define TTLS_ERR_X509_INVALID_FORMAT			-0x2180
/* The CRT/CRL/CSR version element is invalid. */
#define TTLS_ERR_X509_INVALID_VERSION			-0x2200
/* The serial tag or value is invalid. */
#define TTLS_ERR_X509_INVALID_SERIAL			-0x2280
/* The algorithm tag or value is invalid. */
#define TTLS_ERR_X509_INVALID_ALG			-0x2300
/* The name tag or value is invalid. */
#define TTLS_ERR_X509_INVALID_NAME			-0x2380
/* The date tag or value is invalid. */
#define TTLS_ERR_X509_INVALID_DATE			-0x2400
/* The signature tag or value invalid. */
#define TTLS_ERR_X509_INVALID_SIGNATURE			-0x2480
/* The extension tag or value is invalid. */
#define TTLS_ERR_X509_INVALID_EXTENSIONS		-0x2500
/* CRT/CRL/CSR has an unsupported version number. */
#define TTLS_ERR_X509_UNKNOWN_VERSION			-0x2580
/* Signature algorithm (oid) is unsupported. */
#define TTLS_ERR_X509_UNKNOWN_SIG_ALG			-0x2600
/* Signature algorithms do not match. (see \c ::TlsX509Crt sig_oid) */
#define TTLS_ERR_X509_SIG_MISMATCH			-0x2680
/* Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define TTLS_ERR_X509_CERT_VERIFY_FAILED		-0x2700
/* Format not recognized as DER or PEM. */
#define TTLS_ERR_X509_CERT_UNKNOWN_FORMAT		-0x2780
/* Input invalid. */
#define TTLS_ERR_X509_BAD_INPUT_DATA			-0x2800
/* Allocation of memory failed. */
#define TTLS_ERR_X509_ALLOC_FAILED			-0x2880
/*
 * A fatal error occurred, eg the chain is too long or the vrfy callback
 * failed.
 */
#define TTLS_ERR_X509_FATAL_ERROR			-0x3000

/*
 * X509 Verify codes
 */
/* The certificate validity has expired. */
#define TTLS_X509_BADCERT_EXPIRED			    0x01
/* The certificate has been revoked (is on a CRL). */
#define TTLS_X509_BADCERT_REVOKED			    0x02
/* The certificate Common Name (CN) does not match with the expected CN. */
#define TTLS_X509_BADCERT_CN_MISMATCH			    0x04
/* The certificate is not correctly signed by the trusted CA. */
#define TTLS_X509_BADCERT_NOT_TRUSTED			    0x08
/* The CRL is not correctly signed by the trusted CA. */
#define TTLS_X509_BADCRL_NOT_TRUSTED			    0x10
/* The CRL is expired. */
#define TTLS_X509_BADCRL_EXPIRED			    0x20
/* Certificate was missing. */
#define TTLS_X509_BADCERT_MISSING			    0x40
/* Other reason (can be used by verify callback) */
#define TTLS_X509_BADCERT_OTHER				  0x0100
/* The certificate validity starts in the future. */
#define TTLS_X509_BADCERT_FUTURE			  0x0200
/* The CRL is from the future */
#define TTLS_X509_BADCRL_FUTURE				  0x0400
/* Usage does not match the keyUsage extension. */
#define TTLS_X509_BADCERT_KEY_USAGE			  0x0800
/* Usage does not match the extendedKeyUsage extension. */
#define TTLS_X509_BADCERT_EXT_KEY_USAGE			  0x1000
/* Usage does not match the nsCertType extension. */
#define TTLS_X509_BADCERT_NS_CERT_TYPE			  0x2000
/* The certificate is signed with an unacceptable hash. */
#define TTLS_X509_BADCERT_BAD_MD			  0x4000
/* The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define TTLS_X509_BADCERT_BAD_PK			  0x8000
/* The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
#define TTLS_X509_BADCERT_BAD_KEY			0x010000
/* The CRL is signed with an unacceptable hash. */
#define TTLS_X509_BADCRL_BAD_MD				0x020000
/* The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define TTLS_X509_BADCRL_BAD_PK				0x040000
/* The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */
#define TTLS_X509_BADCRL_BAD_KEY			0x080000

/*
 * X.509 v3 Key Usage Extension flags
 */
#define TTLS_X509_KU_DIGITAL_SIGNATURE			0x80	/* bit 0 */
#define TTLS_X509_KU_NON_REPUDIATION			0x40	/* bit 1 */
#define TTLS_X509_KU_KEY_ENCIPHERMENT			0x20	/* bit 2 */
#define TTLS_X509_KU_DATA_ENCIPHERMENT			0x10	/* bit 3 */
#define TTLS_X509_KU_KEY_CERT_SIGN			0x04	/* bit 5 */
#define TTLS_X509_KU_CRL_SIGN				0x02	/* bit 6 */
#define TTLS_X509_KU_ENCIPHER_ONLY			0x01	/* bit 7 */
#define TTLS_X509_KU_DECIPHER_ONLY			0x8000	/* bit 8 */

/*
 * X.509 extension types
 *
 * Comments refer to the status for using certificates. Status can be
 * different for writing certificates or reading CRLs or CSRs.
 */
#define TTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER		(1 << 0)
#define TTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER		(1 << 1)
#define TTLS_X509_EXT_KEY_USAGE				(1 << 2)
#define TTLS_X509_EXT_CERTIFICATE_POLICIES		(1 << 3)
#define TTLS_X509_EXT_POLICY_MAPPINGS			(1 << 4)
#define TTLS_X509_EXT_SUBJECT_ALT_NAME			(1 << 5) /* Supported (DNS) */
#define TTLS_X509_EXT_ISSUER_ALT_NAME			(1 << 6)
#define TTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS		(1 << 7)
#define TTLS_X509_EXT_BASIC_CONSTRAINTS			(1 << 8) /* Supported */
#define TTLS_X509_EXT_NAME_CONSTRAINTS			(1 << 9)
#define TTLS_X509_EXT_POLICY_CONSTRAINTS		(1 << 10)
#define TTLS_X509_EXT_EXTENDED_KEY_USAGE		(1 << 11)
#define TTLS_X509_EXT_CRL_DISTRIBUTION_POINTS		(1 << 12)
#define TTLS_X509_EXT_INIHIBIT_ANYPOLICY		(1 << 13)
#define TTLS_X509_EXT_FRESHEST_CRL			(1 << 14)

#define TTLS_X509_EXT_NS_CERT_TYPE			(1 << 16)

/*
 * Storage format identifiers
 * Recognized formats: PEM and DER
 */
#define TTLS_X509_FORMAT_DER				1
#define TTLS_X509_FORMAT_PEM				2

/* Maximum value size of a DN entry */
#define TTLS_X509_MAX_DN_NAME_SIZE			256

/**
 * \name Structures for parsing X.509 certificates, CRLs and CSRs
 */

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef ttls_asn1_buf ttls_x509_buf;

/**
 * Container for ASN1 bit strings.
 */
typedef ttls_asn1_bitstring ttls_x509_bitstring;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef ttls_asn1_named_data ttls_x509_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef ttls_asn1_sequence ttls_x509_sequence;

/**
 * Container for date and time (precision in seconds).
 * @year, @mon, @day	- date;
 * @hour, @min, @sec	- time
 */
typedef struct ttls_x509_time
{
	int year, mon, day;
	int hour, min, sec;
} ttls_x509_time;


int ttls_x509_time_is_past(const ttls_x509_time *to);
int ttls_x509_time_is_future(const ttls_x509_time *from);

/*
 * Internal module functions. You probably do not want to use these unless you
 * know you do.
 */
int ttls_x509_get_name(unsigned char **p, const unsigned char *end,
		       ttls_x509_name *cur);
int ttls_x509_get_alg_null(unsigned char **p, const unsigned char *end,
			   ttls_x509_buf *alg);
int ttls_x509_get_alg(unsigned char **p, const unsigned char *end,
		      ttls_x509_buf *alg, ttls_x509_buf *params);
int ttls_x509_get_rsassa_pss_params(const ttls_x509_buf *params,
				    ttls_md_type_t *md_alg, ttls_md_type_t *mgf_md,
				    int *salt_len);
int ttls_x509_get_sig(unsigned char **p, const unsigned char *end, ttls_x509_buf *sig);
int ttls_x509_get_sig_alg(const ttls_x509_buf *sig_oid, const ttls_x509_buf *sig_params,
			  ttls_md_type_t *md_alg, ttls_pk_type_t *pk_alg,
			  void **sig_opts);
int ttls_x509_get_time(unsigned char **p, const unsigned char *end,
		       ttls_x509_time *t);
int ttls_x509_get_serial(unsigned char **p, const unsigned char *end,
			 ttls_x509_buf *serial);
int ttls_x509_get_ext(unsigned char **p, const unsigned char *end,
		      ttls_x509_buf *ext, int tag);
int ttls_x509_write_sig(unsigned char **p, unsigned char *start,
			const char *oid, size_t oid_len,
			unsigned char *sig, size_t size);

#endif /* x509.h */
