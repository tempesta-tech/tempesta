/**
 *		Tempesta TLS
 *
 * ASN.1 buffer functionality.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
#ifndef __TTLS_ASN1_H__
#define __TTLS_ASN1_H__

#include "bignum.h"

/**
 * ASN1 Error codes
 * These error codes are OR'ed to X509 error codes for higher error granularity.
 */
/* Out of data when parsing an ASN1 data structure. */
#define TTLS_ERR_ASN1_OUT_OF_DATA			-0x0060
/* ASN1 tag was of an unexpected value. */
#define TTLS_ERR_ASN1_UNEXPECTED_TAG			-0x0062
/* Error when trying to determine the length or invalid length. */
#define TTLS_ERR_ASN1_INVALID_LENGTH			-0x0064
/* Actual length differs from expected length. */
#define TTLS_ERR_ASN1_LENGTH_MISMATCH			-0x0066

/**
 * DER constants.
 *
 * These constants comply with the DER encoded ASN.1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into ::ttls_x509_buf.
 */
#define TTLS_ASN1_BOOLEAN				0x01
#define TTLS_ASN1_INTEGER				0x02
#define TTLS_ASN1_BIT_STRING				0x03
#define TTLS_ASN1_OCTET_STRING				0x04
#define TTLS_ASN1_NULL					0x05
#define TTLS_ASN1_OID					0x06
#define TTLS_ASN1_UTF8_STRING				0x0C
#define TTLS_ASN1_SEQUENCE				0x10
#define TTLS_ASN1_SET					0x11
#define TTLS_ASN1_PRINTABLE_STRING			0x13
#define TTLS_ASN1_T61_STRING				0x14
#define TTLS_ASN1_IA5_STRING				0x16
#define TTLS_ASN1_UTC_TIME				0x17
#define TTLS_ASN1_GENERALIZED_TIME			0x18
#define TTLS_ASN1_UNIVERSAL_STRING			0x1C
#define TTLS_ASN1_BMP_STRING				0x1E
#define TTLS_ASN1_PRIMITIVE				0x00
#define TTLS_ASN1_CONSTRUCTED				0x20
#define TTLS_ASN1_CONTEXT_SPECIFIC			0x80

/*
 * Bit masks for each of the components of an ASN.1 tag as specified in
 * ITU X.690 (08/2015), section 8.1 "General rules for encoding",
 * paragraph 8.1.2.2:
 *
 * Bit     8    7   6    5         1
 *	 +-------+-----+------------+
 *	 | Class | P/C | Tag number |
 *	 +-------+-----+------------+
 */
#define TTLS_ASN1_TAG_CLASS_MASK			0xC0
#define TTLS_ASN1_TAG_PC_MASK				0x20
#define TTLS_ASN1_TAG_VALUE_MASK			0x1F

/** Returns the size of the binary string, without the trailing \\0 */
#define TTLS_OID_SIZE(x)	(sizeof(x) - 1)

/**
 * Compares an ttls_asn1_buf structure to a reference OID.
 *
 * Only works for 'defined' oid_str values (TTLS_OID_HMAC_SHA1), you cannot use
 * a 'unsigned char *oid' here!
 */
#define TTLS_OID_CMP(oid_str, oid_buf)					\
	((TTLS_OID_SIZE(oid_str) != (oid_buf)->len) ||			\
	 memcmp((oid_str), (oid_buf)->p, (oid_buf)->len))

#define TTLS_ASN1_CHK_ADD(g, f)						\
do {									\
	if ((ret = f) < 0)						\
		return ret;						\
	else								\
		g += ret;						\
} while (0)

/**
 * Type-length-value structure that allows for ASN1 using DER.
 *
 * @tag		- ASN1 type, e.g. TTLS_ASN1_UTF8_STRING;
 * @len		- ASN1 length, in octets;
 * @p		- ASN1 data, e.g. in ASCII.
 */
typedef struct {
	int		tag;
	size_t		len;
	unsigned char	*p;
} ttls_asn1_buf;

/**
 * Container for ASN1 bit strings.
 *
 * @len		- ASN1 length, in octets;
 * @unused_bits	- Number of unused bits at the end of the string;
 * @p		- Raw ASN1 data for the bit string.
 */
typedef struct {
	size_t		len;
	unsigned char	unused_bits;
	unsigned char	*p;
} ttls_asn1_bitstring;

/**
 * Container for a sequence of ASN.1 items.
 *
 * @buf		- Buffer containing the given ASN.1 item;
 * @next	- The next entry in the sequence.
 */
typedef struct ttls_asn1_sequence
{
	ttls_asn1_buf	buf;
	struct ttls_asn1_sequence *next;
} ttls_asn1_sequence;

/**
 * Container for a sequence or list of 'named' ASN.1 data items.
 *
 * @oid		- The object identifier;
 * @val		- The named value;
 * @next	- The next entry in the sequence;
 * @next_merged	- Merge next item into the current one?
 */
typedef struct ttls_asn1_named_data
{
	ttls_asn1_buf	oid;
	ttls_asn1_buf	val;
	struct ttls_asn1_named_data *next;
	unsigned char	next_merged;
} ttls_asn1_named_data;

int ttls_asn1_get_len(unsigned char **p, const unsigned char *end, size_t *len);
int ttls_asn1_get_tag(unsigned char **p, const unsigned char *end, size_t *len,
		      int tag);
int ttls_asn1_get_bool(unsigned char **p, const unsigned char *end, int *val);
int ttls_asn1_get_int(unsigned char **p, const unsigned char *end, int *val);
int ttls_asn1_get_mpi(unsigned char **p, const unsigned char *end, TlsMpi *X);
int ttls_asn1_get_bitstring(unsigned char **p, const unsigned char *end,
			    ttls_asn1_bitstring *bs);
int ttls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end,
				 size_t *len);
int ttls_asn1_get_sequence_of(unsigned char **p, const unsigned char *end,
			      ttls_asn1_sequence *cur, int tag);
int ttls_asn1_get_alg(unsigned char **p, const unsigned char *end,
		      ttls_asn1_buf *alg, ttls_asn1_buf *params);
int ttls_asn1_get_alg_null(unsigned char **p, const unsigned char *end,
			   ttls_asn1_buf *alg);
int ecdsa_signature_to_asn1(const TlsMpi *r, const TlsMpi *s,
			    unsigned char *sig, size_t *slen);

#endif /* __TTLS_ASN1_H__ */
