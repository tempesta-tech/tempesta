/*
 *		Tempesta TLS
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
 *
 * This file is part of mbed TLS (https://tls.mbed.org)
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
/* Requested OID is unknown. */
#define TTLS_ERR_X509_UNKNOWN_OID			-0x2100
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
/* Signature algorithms do not match. (see \c ::ttls_x509_crt sig_oid) */
#define TTLS_ERR_X509_SIG_MISMATCH			-0x2680
/* Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define TTLS_ERR_X509_CERT_VERIFY_FAILED		-0x2700
/* Format not recognized as DER or PEM. */
#define TTLS_ERR_X509_CERT_UNKNOWN_FORMAT		-0x2780
/* Input invalid. */
#define TTLS_ERR_X509_BAD_INPUT_DATA			-0x2800
/* Allocation of memory failed. */
#define TTLS_ERR_X509_ALLOC_FAILED			-0x2880
/* Read/write of file failed. */
#define TTLS_ERR_X509_FILE_IO_ERROR			-0x2900
/* Destination buffer is too small. */
#define TTLS_ERR_X509_BUFFER_TOO_SMALL			-0x2980
/*
 * A fatal error occurred, eg the chain is too long or the vrfy callback
 * failed.
 */
#define TTLS_ERR_X509_FATAL_ERROR			-0x3000

/**
 * \name X509 Verify codes
 */
/* Reminder: update x509_crt_verify_strings[] in library/x509_crt.c */
#define TTLS_X509_BADCERT_EXPIRED			 0x01  /**< The certificate validity has expired. */
#define TTLS_X509_BADCERT_REVOKED			 0x02  /**< The certificate has been revoked (is on a CRL). */
#define TTLS_X509_BADCERT_CN_MISMATCH		 0x04  /**< The certificate Common Name (CN) does not match with the expected CN. */
#define TTLS_X509_BADCERT_NOT_TRUSTED		 0x08  /**< The certificate is not correctly signed by the trusted CA. */
#define TTLS_X509_BADCRL_NOT_TRUSTED		  0x10  /**< The CRL is not correctly signed by the trusted CA. */
#define TTLS_X509_BADCRL_EXPIRED			  0x20  /**< The CRL is expired. */
#define TTLS_X509_BADCERT_MISSING			 0x40  /**< Certificate was missing. */
#define TTLS_X509_BADCERT_SKIP_VERIFY		 0x80  /**< Certificate verification was skipped. */
#define TTLS_X509_BADCERT_OTHER			 0x0100  /**< Other reason (can be used by verify callback) */
#define TTLS_X509_BADCERT_FUTURE			0x0200  /**< The certificate validity starts in the future. */
#define TTLS_X509_BADCRL_FUTURE			 0x0400  /**< The CRL is from the future */
#define TTLS_X509_BADCERT_KEY_USAGE		 0x0800  /**< Usage does not match the keyUsage extension. */
#define TTLS_X509_BADCERT_EXT_KEY_USAGE	 0x1000  /**< Usage does not match the extendedKeyUsage extension. */
#define TTLS_X509_BADCERT_NS_CERT_TYPE	  0x2000  /**< Usage does not match the nsCertType extension. */
#define TTLS_X509_BADCERT_BAD_MD			0x4000  /**< The certificate is signed with an unacceptable hash. */
#define TTLS_X509_BADCERT_BAD_PK			0x8000  /**< The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define TTLS_X509_BADCERT_BAD_KEY		 0x010000  /**< The certificate is signed with an unacceptable key (eg bad curve, RSA too short). */
#define TTLS_X509_BADCRL_BAD_MD		   0x020000  /**< The CRL is signed with an unacceptable hash. */
#define TTLS_X509_BADCRL_BAD_PK		   0x040000  /**< The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA). */
#define TTLS_X509_BADCRL_BAD_KEY		  0x080000  /**< The CRL is signed with an unacceptable key (eg bad curve, RSA too short). */

/*
 * X.509 v3 Key Usage Extension flags
 * Reminder: update x509_info_key_usage() when adding new flags.
 */
#define TTLS_X509_KU_DIGITAL_SIGNATURE			(0x80)  /* bit 0 */
#define TTLS_X509_KU_NON_REPUDIATION			  (0x40)  /* bit 1 */
#define TTLS_X509_KU_KEY_ENCIPHERMENT			 (0x20)  /* bit 2 */
#define TTLS_X509_KU_DATA_ENCIPHERMENT			(0x10)  /* bit 3 */
#define TTLS_X509_KU_KEY_AGREEMENT				(0x08)  /* bit 4 */
#define TTLS_X509_KU_KEY_CERT_SIGN				(0x04)  /* bit 5 */
#define TTLS_X509_KU_CRL_SIGN		 (0x02)  /* bit 6 */
#define TTLS_X509_KU_ENCIPHER_ONLY				(0x01)  /* bit 7 */
#define TTLS_X509_KU_DECIPHER_ONLY			  (0x8000)  /* bit 8 */

/*
 * Netscape certificate types
 * (http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html)
 */

#define TTLS_X509_NS_CERT_TYPE_CLIENT		 (0x80)  /* bit 0 */
#define TTLS_X509_NS_CERT_TYPE_SERVER		 (0x40)  /* bit 1 */
#define TTLS_X509_NS_CERT_TYPE_EMAIL			  (0x20)  /* bit 2 */
#define TTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING	 (0x10)  /* bit 3 */
#define TTLS_X509_NS_CERT_TYPE_RESERVED		   (0x08)  /* bit 4 */
#define TTLS_X509_NS_CERT_TYPE_CA			 (0x04)  /* bit 5 */
#define TTLS_X509_NS_CERT_TYPE_EMAIL_CA		   (0x02)  /* bit 6 */
#define TTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA  (0x01)  /* bit 7 */

/*
 * X.509 extension types
 *
 * Comments refer to the status for using certificates. Status can be
 * different for writing certificates or reading CRLs or CSRs.
 */
#define TTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER	(1 << 0)
#define TTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER	  (1 << 1)
#define TTLS_X509_EXT_KEY_USAGE				   (1 << 2)
#define TTLS_X509_EXT_CERTIFICATE_POLICIES		(1 << 3)
#define TTLS_X509_EXT_POLICY_MAPPINGS			 (1 << 4)
#define TTLS_X509_EXT_SUBJECT_ALT_NAME			(1 << 5)	/* Supported (DNS) */
#define TTLS_X509_EXT_ISSUER_ALT_NAME			 (1 << 6)
#define TTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS	 (1 << 7)
#define TTLS_X509_EXT_BASIC_CONSTRAINTS		   (1 << 8)	/* Supported */
#define TTLS_X509_EXT_NAME_CONSTRAINTS			(1 << 9)
#define TTLS_X509_EXT_POLICY_CONSTRAINTS		  (1 << 10)
#define TTLS_X509_EXT_EXTENDED_KEY_USAGE		  (1 << 11)
#define TTLS_X509_EXT_CRL_DISTRIBUTION_POINTS	 (1 << 12)
#define TTLS_X509_EXT_INIHIBIT_ANYPOLICY		  (1 << 13)
#define TTLS_X509_EXT_FRESHEST_CRL				(1 << 14)

#define TTLS_X509_EXT_NS_CERT_TYPE				(1 << 16)

/*
 * Storage format identifiers
 * Recognized formats: PEM and DER
 */
#define TTLS_X509_FORMAT_DER				 1
#define TTLS_X509_FORMAT_PEM				 2

#define TTLS_X509_MAX_DN_NAME_SIZE		 256 /**< Maximum value size of a DN entry */

/**
 * \addtogroup x509_module
 * \{ */

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

/** Container for date and time (precision in seconds). */
typedef struct ttls_x509_time
{
	int year, mon, day;		 /**< Date. */
	int hour, min, sec;		 /**< Time. */
}
ttls_x509_time;

/** \} name Structures for parsing X.509 certificates, CRLs and CSRs */
/** \} addtogroup x509_module */

/**
 * \brief		  Store the certificate DN in printable form into buf;
 *				 no more than size characters will be written.
 *
 * \param buf	  Buffer to write to
 * \param size	 Maximum size of buffer
 * \param dn	   The X509 name to represent
 *
 * \return		 The length of the string written (not including the
 *				 terminated nul byte), or a negative error code.
 */
int ttls_x509_dn_gets(char *buf, size_t size, const ttls_x509_name *dn);

/**
 * \brief		  Store the certificate serial in printable form into buf;
 *				 no more than size characters will be written.
 *
 * \param buf	  Buffer to write to
 * \param size	 Maximum size of buffer
 * \param serial   The X509 serial to represent
 *
 * \return		 The length of the string written (not including the
 *				 terminated nul byte), or a negative error code.
 */
int ttls_x509_serial_gets(char *buf, size_t size, const ttls_x509_buf *serial);

/**
 * \brief		  Check a given ttls_x509_time against the system time
 *				 and tell if it's in the past.
 *
 * \note		   Intended usage is "if (is_past(valid_to)) ERROR".
 *				 Hence the return value of 1 if on internal errors.
 *
 * \param to	   ttls_x509_time to check
 *
 * \return		 1 if the given time is in the past or an error occurred,
 *				 0 otherwise.
 */
int ttls_x509_time_is_past(const ttls_x509_time *to);

/**
 * \brief		  Check a given ttls_x509_time against the system time
 *				 and tell if it's in the future.
 *
 * \note		   Intended usage is "if (is_future(valid_from)) ERROR".
 *				 Hence the return value of 1 if on internal errors.
 *
 * \param from	 ttls_x509_time to check
 *
 * \return		 1 if the given time is in the future or an error
 *			 occurred, 0 otherwise.
 */
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
int ttls_x509_sig_alg_gets(char *buf, size_t size, const ttls_x509_buf *sig_oid,
		   ttls_pk_type_t pk_alg, ttls_md_type_t md_alg,
		   const void *sig_opts);
int ttls_x509_key_size_helper(char *buf, size_t buf_size, const char *name);
int ttls_x509_write_sig(unsigned char **p, unsigned char *start,
		const char *oid, size_t oid_len,
		unsigned char *sig, size_t size);

#define TTLS_X509_SAFE_SNPRINTF			  \
	do {				\
		if (ret < 0 || (size_t) ret >= n)				  \
			return(TTLS_ERR_X509_BUFFER_TOO_SMALL);	\
			\
		n -= (size_t) ret;		  \
		p += (size_t) ret;		  \
	} while (0)

#endif /* x509.h */
