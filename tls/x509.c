/*
 *  X.509 common functions for parsing and verification
 *
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
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */
#include "ttls.h"
#include "asn1.h"
#include "certs.h"
#include "oid.h"
#include "pem.h"
#include "x509.h"
#include "x509_crt.h"

#define CHECK(code) if ((ret = code) != 0){ return ret; }
#define CHECK_RANGE(min, max, val) if (val < min || val > max){ return ret; }

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
int ttls_x509_get_serial(unsigned char **p, const unsigned char *end,
		 ttls_x509_buf *serial)
{
	int ret;

	if ((end - *p) < 1)
		return(TTLS_ERR_X509_INVALID_SERIAL +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	if (**p != (TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_PRIMITIVE | 2) &&
		**p !=   TTLS_ASN1_INTEGER)
		return(TTLS_ERR_X509_INVALID_SERIAL +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);

	serial->tag = *(*p)++;

	if ((ret = ttls_asn1_get_len(p, end, &serial->len)) != 0)
		return(TTLS_ERR_X509_INVALID_SERIAL + ret);

	serial->p = *p;
	*p += serial->len;

	return 0;
}

/* Get an algorithm identifier without parameters (eg for signatures)
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *	   algorithm			   OBJECT IDENTIFIER,
 *	   parameters			  ANY DEFINED BY algorithm OPTIONAL  }
 */
int ttls_x509_get_alg_null(unsigned char **p, const unsigned char *end,
		   ttls_x509_buf *alg)
{
	int ret;

	if ((ret = ttls_asn1_get_alg_null(p, end, alg)) != 0)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	return 0;
}

/*
 * Parse an algorithm identifier with (optional) paramaters
 */
int ttls_x509_get_alg(unsigned char **p, const unsigned char *end,
				  ttls_x509_buf *alg, ttls_x509_buf *params)
{
	int ret;

	if ((ret = ttls_asn1_get_alg(p, end, alg, params)) != 0)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	return 0;
}

/*
 * HashAlgorithm ::= AlgorithmIdentifier
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *	  algorithm			   OBJECT IDENTIFIER,
 *	  parameters			  ANY DEFINED BY algorithm OPTIONAL  }
 *
 * For HashAlgorithm, parameters MUST be NULL or absent.
 */
static int x509_get_hash_alg(const ttls_x509_buf *alg, ttls_md_type_t *md_alg)
{
	int ret;
	unsigned char *p;
	const unsigned char *end;
	ttls_x509_buf md_oid;
	size_t len;

	/* Make sure we got a SEQUENCE and setup bounds */
	if (alg->tag != (TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE))
		return(TTLS_ERR_X509_INVALID_ALG +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);

	p = (unsigned char *) alg->p;
	end = p + alg->len;

	if (p >= end)
		return(TTLS_ERR_X509_INVALID_ALG +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	/* Parse md_oid */
	md_oid.tag = *p;

	if ((ret = ttls_asn1_get_tag(&p, end, &md_oid.len, TTLS_ASN1_OID)) != 0)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	md_oid.p = p;
	p += md_oid.len;

	/* Get md_alg from md_oid */
	if ((ret = ttls_oid_get_md_alg(&md_oid, md_alg)) != 0)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	/* Make sure params is absent of NULL */
	if (p == end)
		return 0;

	if ((ret = ttls_asn1_get_tag(&p, end, &len, TTLS_ASN1_NULL)) != 0 || len != 0)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	if (p != end)
		return(TTLS_ERR_X509_INVALID_ALG +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/*
 *	RSASSA-PSS-params  ::=  SEQUENCE  {
 *	   hashAlgorithm	 [0] HashAlgorithm DEFAULT sha1Identifier,
 *	   maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
 *	   saltLength		[2] INTEGER DEFAULT 20,
 *	   trailerField	  [3] INTEGER DEFAULT 1  }
 *	-- Note that the tags in this Sequence are explicit.
 *
 * RFC 4055 (which defines use of RSASSA-PSS in PKIX) states that the value
 * of trailerField MUST be 1, and PKCS#1 v2.2 doesn't even define any other
 * option. Enfore this at parsing time.
 */
int ttls_x509_get_rsassa_pss_params(const ttls_x509_buf *params,
		ttls_md_type_t *md_alg, ttls_md_type_t *mgf_md,
		int *salt_len)
{
	int ret;
	unsigned char *p;
	const unsigned char *end, *end2;
	size_t len;
	ttls_x509_buf alg_id, alg_params;

	/* First set everything to defaults */
	*md_alg = TTLS_MD_SHA1;
	*mgf_md = TTLS_MD_SHA1;
	*salt_len = 20;

	/* Make sure params is a SEQUENCE and setup bounds */
	if (params->tag != (TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE))
		return(TTLS_ERR_X509_INVALID_ALG +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);

	p = (unsigned char *) params->p;
	end = p + params->len;

	if (p == end)
		return 0;

	/*
	 * HashAlgorithm
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
		TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | 0)) == 0)
	{
		end2 = p + len;

		/* HashAlgorithm ::= AlgorithmIdentifier (without parameters) */
		if ((ret = ttls_x509_get_alg_null(&p, end2, &alg_id)) != 0)
			return ret;

		if ((ret = ttls_oid_get_md_alg(&alg_id, md_alg)) != 0)
			return(TTLS_ERR_X509_INVALID_ALG + ret);

		if (p != end2)
			return(TTLS_ERR_X509_INVALID_ALG +
		TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}
	else if (ret != TTLS_ERR_ASN1_UNEXPECTED_TAG)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	if (p == end)
		return 0;

	/*
	 * MaskGenAlgorithm
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
		TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | 1)) == 0)
	{
		end2 = p + len;

		/* MaskGenAlgorithm ::= AlgorithmIdentifier (params = HashAlgorithm) */
		if ((ret = ttls_x509_get_alg(&p, end2, &alg_id, &alg_params)) != 0)
			return ret;

		/* Only MFG1 is recognised for now */
		if (TTLS_OID_CMP(TTLS_OID_MGF1, &alg_id) != 0)
			return(TTLS_ERR_X509_FEATURE_UNAVAILABLE +
		TTLS_ERR_OID_NOT_FOUND);

		/* Parse HashAlgorithm */
		if ((ret = x509_get_hash_alg(&alg_params, mgf_md)) != 0)
			return ret;

		if (p != end2)
			return(TTLS_ERR_X509_INVALID_ALG +
		TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}
	else if (ret != TTLS_ERR_ASN1_UNEXPECTED_TAG)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	if (p == end)
		return 0;

	/*
	 * salt_len
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
		TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | 2)) == 0)
	{
		end2 = p + len;

		if ((ret = ttls_asn1_get_int(&p, end2, salt_len)) != 0)
			return(TTLS_ERR_X509_INVALID_ALG + ret);

		if (p != end2)
			return(TTLS_ERR_X509_INVALID_ALG +
		TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}
	else if (ret != TTLS_ERR_ASN1_UNEXPECTED_TAG)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	if (p == end)
		return 0;

	/*
	 * trailer_field (if present, must be 1)
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
		TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | 3)) == 0)
	{
		int trailer_field;

		end2 = p + len;

		if ((ret = ttls_asn1_get_int(&p, end2, &trailer_field)) != 0)
			return(TTLS_ERR_X509_INVALID_ALG + ret);

		if (p != end2)
			return(TTLS_ERR_X509_INVALID_ALG +
		TTLS_ERR_ASN1_LENGTH_MISMATCH);

		if (trailer_field != 1)
			return(TTLS_ERR_X509_INVALID_ALG);
	}
	else if (ret != TTLS_ERR_ASN1_UNEXPECTED_TAG)
		return(TTLS_ERR_X509_INVALID_ALG + ret);

	if (p != end)
		return(TTLS_ERR_X509_INVALID_ALG +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/*
 *  AttributeTypeAndValue ::= SEQUENCE {
 *	type	 AttributeType,
 *	value	AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_get_attr_type_value(unsigned char **p,
			 const unsigned char *end,
			 ttls_x509_name *cur)
{
	int ret;
	size_t len;
	ttls_x509_buf *oid;
	ttls_x509_buf *val;

	if ((ret = ttls_asn1_get_tag(p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
		return(TTLS_ERR_X509_INVALID_NAME + ret);

	if ((end - *p) < 1)
		return(TTLS_ERR_X509_INVALID_NAME +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	oid = &cur->oid;
	oid->tag = **p;

	if ((ret = ttls_asn1_get_tag(p, end, &oid->len, TTLS_ASN1_OID)) != 0)
		return(TTLS_ERR_X509_INVALID_NAME + ret);

	oid->p = *p;
	*p += oid->len;

	if ((end - *p) < 1)
		return(TTLS_ERR_X509_INVALID_NAME +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	if (**p != TTLS_ASN1_BMP_STRING && **p != TTLS_ASN1_UTF8_STRING	  &&
		**p != TTLS_ASN1_T61_STRING && **p != TTLS_ASN1_PRINTABLE_STRING &&
		**p != TTLS_ASN1_IA5_STRING && **p != TTLS_ASN1_UNIVERSAL_STRING &&
		**p != TTLS_ASN1_BIT_STRING)
		return(TTLS_ERR_X509_INVALID_NAME +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);

	val = &cur->val;
	val->tag = *(*p)++;

	if ((ret = ttls_asn1_get_len(p, end, &val->len)) != 0)
		return(TTLS_ERR_X509_INVALID_NAME + ret);

	val->p = *p;
	*p += val->len;

	cur->next = NULL;

	return 0;
}

/*
 *  Name ::= CHOICE { -- only one possibility for now --
 *	   rdnSequence  RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *	SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *	type	 AttributeType,
 *	value	AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 * The data structure is optimized for the common case where each RDN has only
 * one element, which is represented as a list of AttributeTypeAndValue.
 * For the general case we still use a flat list, but we mark elements of the
 * same set so that they are "merged" together in the functions that consume
 * this list, eg ttls_x509_dn_gets().
 */
int ttls_x509_get_name(unsigned char **p, const unsigned char *end,
				   ttls_x509_name *cur)
{
	int ret;
	size_t set_len;
	const unsigned char *end_set;

	/* don't use recursion, we'd risk stack overflow if not optimized */
	while (1)
	{
		/*
		 * parse SET
		 */
		if ((ret = ttls_asn1_get_tag(p, end, &set_len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SET)) != 0)
			return(TTLS_ERR_X509_INVALID_NAME + ret);

		end_set  = *p + set_len;

		while (1)
		{
			if ((ret = x509_get_attr_type_value(p, end_set, cur)) != 0)
				return ret;

			if (*p == end_set)
				break;

			/* Mark this item as being no the only one in a set */
			cur->next_merged = 1;

			cur->next = ttls_calloc(1, sizeof(ttls_x509_name));

			if (cur->next == NULL)
				return(TTLS_ERR_X509_ALLOC_FAILED);

			cur = cur->next;
		}

		/*
		 * continue until end of SEQUENCE is reached
		 */
		if (*p == end)
			return 0;

		cur->next = ttls_calloc(1, sizeof(ttls_x509_name));

		if (cur->next == NULL)
			return(TTLS_ERR_X509_ALLOC_FAILED);

		cur = cur->next;
	}
}

static int x509_parse_int(unsigned char **p, size_t n, int *res)
{
	*res = 0;

	for (; n > 0; --n)
	{
		if ((**p < '0') || (**p > '9'))
			return (TTLS_ERR_X509_INVALID_DATE);

		*res *= 10;
		*res += (*(*p)++ - '0');
	}

	return 0;
}

static int x509_date_is_valid(const ttls_x509_time *t)
{
	int ret = TTLS_ERR_X509_INVALID_DATE;
	int month_len;

	CHECK_RANGE(0, 9999, t->year);
	CHECK_RANGE(0, 23,   t->hour);
	CHECK_RANGE(0, 59,   t->min );
	CHECK_RANGE(0, 59,   t->sec );

	switch(t->mon)
	{
		case 1: case 3: case 5: case 7: case 8: case 10: case 12:
			month_len = 31;
			break;
		case 4: case 6: case 9: case 11:
			month_len = 30;
			break;
		case 2:
			if ((!(t->year % 4) && t->year % 100) ||
				!(t->year % 400))
				month_len = 29;
			else
				month_len = 28;
			break;
		default:
			return ret;
	}
	CHECK_RANGE(1, month_len, t->day);

	return 0;
}

/*
 * Parse an ASN1_UTC_TIME (yearlen=2) or ASN1_GENERALIZED_TIME (yearlen=4)
 * field.
 */
static int x509_parse_time(unsigned char **p, size_t len, size_t yearlen,
				ttls_x509_time *tm)
{
	int ret;

	/*
	 * Minimum length is 10 or 12 depending on yearlen
	 */
	if (len < yearlen + 8)
		return (TTLS_ERR_X509_INVALID_DATE);
	len -= yearlen + 8;

	/*
	 * Parse year, month, day, hour, minute
	 */
	CHECK(x509_parse_int(p, yearlen, &tm->year));
	if (2 == yearlen)
	{
		if (tm->year < 50)
			tm->year += 100;

		tm->year += 1900;
	}

	CHECK(x509_parse_int(p, 2, &tm->mon));
	CHECK(x509_parse_int(p, 2, &tm->day));
	CHECK(x509_parse_int(p, 2, &tm->hour));
	CHECK(x509_parse_int(p, 2, &tm->min));

	/*
	 * Parse seconds if present
	 */
	if (len >= 2)
	{
		CHECK(x509_parse_int(p, 2, &tm->sec));
		len -= 2;
	}
	else
		return (TTLS_ERR_X509_INVALID_DATE);

	/*
	 * Parse trailing 'Z' if present
	 */
	if (1 == len && 'Z' == **p)
	{
		(*p)++;
		len--;
	}

	/*
	 * We should have parsed all characters at this point
	 */
	if (0 != len)
		return (TTLS_ERR_X509_INVALID_DATE);

	CHECK(x509_date_is_valid(tm));

	return (0);
}

/*
 *  Time ::= CHOICE {
 *	   utcTime		UTCTime,
 *	   generalTime	GeneralizedTime }
 */
int ttls_x509_get_time(unsigned char **p, const unsigned char *end,
			   ttls_x509_time *tm)
{
	int ret;
	size_t len, year_len;
	unsigned char tag;

	if ((end - *p) < 1)
		return(TTLS_ERR_X509_INVALID_DATE +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	tag = **p;

	if (tag == TTLS_ASN1_UTC_TIME)
		year_len = 2;
	else if (tag == TTLS_ASN1_GENERALIZED_TIME)
		year_len = 4;
	else
		return(TTLS_ERR_X509_INVALID_DATE +
				TTLS_ERR_ASN1_UNEXPECTED_TAG);

	(*p)++;
	ret = ttls_asn1_get_len(p, end, &len);

	if (ret != 0)
		return(TTLS_ERR_X509_INVALID_DATE + ret);

	return x509_parse_time(p, len, year_len, tm);
}

int ttls_x509_get_sig(unsigned char **p, const unsigned char *end, ttls_x509_buf *sig)
{
	int ret;
	size_t len;
	int tag_type;

	if ((end - *p) < 1)
		return(TTLS_ERR_X509_INVALID_SIGNATURE +
				TTLS_ERR_ASN1_OUT_OF_DATA);

	tag_type = **p;

	if ((ret = ttls_asn1_get_bitstring_null(p, end, &len)) != 0)
		return(TTLS_ERR_X509_INVALID_SIGNATURE + ret);

	sig->tag = tag_type;
	sig->len = len;
	sig->p = *p;

	*p += len;

	return 0;
}

/*
 * Get signature algorithm from alg OID and optional parameters
 */
int ttls_x509_get_sig_alg(const ttls_x509_buf *sig_oid, const ttls_x509_buf *sig_params,
		  ttls_md_type_t *md_alg, ttls_pk_type_t *pk_alg,
		  void **sig_opts)
{
	int ret;

	if (*sig_opts != NULL)
		return(TTLS_ERR_X509_BAD_INPUT_DATA);

	if ((ret = ttls_oid_get_sig_alg(sig_oid, md_alg, pk_alg)) != 0)
		return(TTLS_ERR_X509_UNKNOWN_SIG_ALG + ret);

	if (*pk_alg == TTLS_PK_RSASSA_PSS)
	{
		ttls_pk_rsassa_pss_options *pss_opts;

		pss_opts = ttls_calloc(1, sizeof(ttls_pk_rsassa_pss_options));
		if (pss_opts == NULL)
			return(TTLS_ERR_X509_ALLOC_FAILED);

		ret = ttls_x509_get_rsassa_pss_params(sig_params,
				  md_alg,
				  &pss_opts->mgf1_hash_id,
				  &pss_opts->expected_salt_len);
		if (ret != 0)
		{
			ttls_free(pss_opts);
			return ret;
		}

		*sig_opts = (void *) pss_opts;
	}
	else
	{
		/* Make sure parameters are absent or NULL */
		if ((sig_params->tag != TTLS_ASN1_NULL && sig_params->tag != 0) ||
			  sig_params->len != 0)
		return(TTLS_ERR_X509_INVALID_ALG);
	}

	return 0;
}

/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!)
 */
int ttls_x509_get_ext(unsigned char **p, const unsigned char *end,
				  ttls_x509_buf *ext, int tag)
{
	int ret;
	size_t len;

	if (*p == end)
		return 0;

	ext->tag = **p;

	if ((ret = ttls_asn1_get_tag(p, end, &ext->len,
			TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | tag)) != 0)
		return ret;

	ext->p = *p;
	end = *p + ext->len;

	/*
	 * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	 *
	 * Extension  ::=  SEQUENCE  {
	 *	  extnID	  OBJECT IDENTIFIER,
	 *	  critical	BOOLEAN DEFAULT FALSE,
	 *	  extnValue   OCTET STRING  }
	 */
	if ((ret = ttls_asn1_get_tag(p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
		return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);

	if (end != *p + len)
		return(TTLS_ERR_X509_INVALID_EXTENSIONS +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int ttls_x509_dn_gets(char *buf, size_t size, const ttls_x509_name *dn)
{
	int ret;
	size_t i, n;
	unsigned char c, merge = 0;
	const ttls_x509_name *name;
	const char *short_name = NULL;
	char s[TTLS_X509_MAX_DN_NAME_SIZE], *p;

	memset(s, 0, sizeof(s));

	name = dn;
	p = buf;
	n = size;

	while (name != NULL)
	{
		if (!name->oid.p)
		{
			name = name->next;
			continue;
		}

		if (name != dn)
		{
			ret = ttls_snprintf(p, n, merge ? " + " : ", ");
			TTLS_X509_SAFE_SNPRINTF;
		}

		ret = ttls_oid_get_attr_short_name(&name->oid, &short_name);

		if (ret == 0)
			ret = ttls_snprintf(p, n, "%s=", short_name);
		else
			ret = ttls_snprintf(p, n, "\?\?=");
		TTLS_X509_SAFE_SNPRINTF;

		for (i = 0; i < name->val.len; i++)
		{
			if (i >= sizeof(s) - 1)
				break;

			c = name->val.p[i];
			if (c < 32 || c == 127 || (c > 128 && c < 160))
				 s[i] = '?';
			else s[i] = c;
		}
		s[i] = '\0';
		ret = ttls_snprintf(p, n, "%s", s);
		TTLS_X509_SAFE_SNPRINTF;

		merge = name->next_merged;
		name = name->next;
	}

	return((int) (size - n));
}

/*
 * Store the serial in printable form into buf; no more
 * than size characters will be written
 */
int ttls_x509_serial_gets(char *buf, size_t size, const ttls_x509_buf *serial)
{
	int ret;
	size_t i, n, nr;
	char *p;

	p = buf;
	n = size;

	nr = (serial->len <= 32)
		? serial->len  : 28;

	for (i = 0; i < nr; i++)
	{
		if (i == 0 && nr > 1 && serial->p[i] == 0x0)
			continue;

		ret = ttls_snprintf(p, n, "%02X%s",
				serial->p[i], (i < nr - 1) ? ":" : "");
		TTLS_X509_SAFE_SNPRINTF;
	}

	if (nr != serial->len)
	{
		ret = ttls_snprintf(p, n, "....");
		TTLS_X509_SAFE_SNPRINTF;
	}

	return((int) (size - n));
}

/*
 * Helper for writing signature algorithms
 */
int ttls_x509_sig_alg_gets(char *buf, size_t size, const ttls_x509_buf *sig_oid,
		   ttls_pk_type_t pk_alg, ttls_md_type_t md_alg,
		   const void *sig_opts)
{
	int ret;
	char *p = buf;
	size_t n = size;
	const char *desc = NULL;

	ret = ttls_oid_get_sig_alg_desc(sig_oid, &desc);
	if (ret != 0)
		ret = ttls_snprintf(p, n, "???" );
	else
		ret = ttls_snprintf(p, n, "%s", desc);
	TTLS_X509_SAFE_SNPRINTF;

	if (pk_alg == TTLS_PK_RSASSA_PSS)
	{
		const ttls_pk_rsassa_pss_options *pss_opts;
		const TlsMdInfo *md_info, *mgf_md_info;

		pss_opts = (const ttls_pk_rsassa_pss_options *) sig_opts;

		md_info = ttls_md_info_from_type(md_alg);
		mgf_md_info = ttls_md_info_from_type(pss_opts->mgf1_hash_id);

		ret = ttls_snprintf(p, n, " (%s, MGF1-%s, 0x%02X)",
				  md_info ? ttls_md_get_name(md_info) : "???",
				  mgf_md_info ? ttls_md_get_name(mgf_md_info) : "???",
				  pss_opts->expected_salt_len);
		TTLS_X509_SAFE_SNPRINTF;
	}

	return((int)(size - n));
}

/*
 * Helper for writing "RSA key size", "EC key size", etc
 */
int ttls_x509_key_size_helper(char *buf, size_t buf_size, const char *name)
{
	char *p = buf;
	size_t n = buf_size;
	int ret;

	ret = ttls_snprintf(p, n, "%s key size", name);
	TTLS_X509_SAFE_SNPRINTF;

	return 0;
}

/*
 * Set the time structure to the current time.
 * Return 0 on success, non-zero on failure.
 */
static void
x509_get_current_time(ttls_x509_time *now)
{
	struct tm t;

	time_to_tm(get_seconds(), 0, &t);

	now->year = t.tm_year + 1900;
	now->mon  = t.tm_mon  + 1;
	now->day  = t.tm_mday;
	now->hour = t.tm_hour;
	now->min  = t.tm_min;
	now->sec  = t.tm_sec;
}

/*
 * Return 0 if before <= after, 1 otherwise
 */
static int x509_check_time(const ttls_x509_time *before, const ttls_x509_time *after)
{
	if (before->year  > after->year)
		return(1);

	if (before->year == after->year &&
		before->mon   > after->mon)
		return(1);

	if (before->year == after->year &&
		before->mon  == after->mon  &&
		before->day   > after->day)
		return(1);

	if (before->year == after->year &&
		before->mon  == after->mon  &&
		before->day  == after->day  &&
		before->hour  > after->hour)
		return(1);

	if (before->year == after->year &&
		before->mon  == after->mon  &&
		before->day  == after->day  &&
		before->hour == after->hour &&
		before->min   > after->min )
		return(1);

	if (before->year == after->year &&
		before->mon  == after->mon  &&
		before->day  == after->day  &&
		before->hour == after->hour &&
		before->min  == after->min  &&
		before->sec   > after->sec )
		return(1);

	return 0;
}

int
ttls_x509_time_is_past(const ttls_x509_time *to)
{
	ttls_x509_time now;

	x509_get_current_time(&now);

	return x509_check_time(&now, to);
}

int
ttls_x509_time_is_future(const ttls_x509_time *from)
{
	ttls_x509_time now;

	x509_get_current_time(&now);

	return x509_check_time(from, &now);
}

/*
 * Checkup routine
 */
int ttls_x509_self_test(int verbose)
{
#if defined(TTLS_CERTS_C)
	int ret;
	uint32_t flags;
	ttls_x509_crt cacert;
	ttls_x509_crt clicert;

	if (verbose != 0)
		ttls_printf("  X.509 certificate load: ");

	ttls_x509_crt_init(&clicert);

	ret = ttls_x509_crt_parse(&clicert, (unsigned char *) ttls_test_cli_crt,
			   ttls_test_cli_crt_len);
	if (ret != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		return ret;
	}

	ttls_x509_crt_init(&cacert);

	ret = ttls_x509_crt_parse(&cacert, (unsigned char *) ttls_test_ca_crt,
			  ttls_test_ca_crt_len);
	if (ret != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		return ret;
	}

	if (verbose != 0)
		ttls_printf("passed\n  X.509 signature verify: ");

	ret = ttls_x509_crt_verify(&clicert, &cacert, NULL, NULL, &flags, NULL, NULL);
	if (ret != 0)
	{
		if (verbose != 0)
			ttls_printf("failed\n");

		return ret;
	}

	if (verbose != 0)
		ttls_printf("passed\n\n");

	ttls_x509_crt_free(&cacert );
	ttls_x509_crt_free(&clicert);

	return 0;
#else
	((void) verbose);
	return 0;
#endif
}
