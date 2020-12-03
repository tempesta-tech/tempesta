/*
 *		Tempesta TLS
 *
 * X.509 certificate parsing and verification.
 *
 * The ITU-T X.509 standard defines a certificate format for PKI.
 *
 * http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 * http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 * http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
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
#include "debug.h"
#include "mpool.h"
#include "x509_crt.h"
#include "oid.h"
#include "pem.h"
#include "tls_internal.h"

/* TODO: #830 start of unused definitions. */
#define TTLS_X509_CRT_VERSION_1			0
#define TTLS_X509_CRT_VERSION_2			1
#define TTLS_X509_CRT_VERSION_3			2
#define TTLS_X509_RFC5280_MAX_SERIAL_LEN	32
#define TTLS_X509_RFC5280_UTC_TIME_LEN		15

/**
 * Container for writing a certificate (CRT)
 *
 */
typedef struct ttls_x509write_cert
{
	int version;
	TlsMpi serial;
	TlsPkCtx *subject_key;
	TlsPkCtx *issuer_key;
	ttls_asn1_named_data *subject;
	ttls_asn1_named_data *issuer;
	ttls_md_type_t md_alg;
	char not_before[TTLS_X509_RFC5280_UTC_TIME_LEN + 1];
	char not_after[TTLS_X509_RFC5280_UTC_TIME_LEN + 1];
	ttls_asn1_named_data *extensions;
}
ttls_x509write_cert;
/* TODO: #830 end unused */

/* Use SLAB for frequent certificate allocations on handshake processing. */
static struct kmem_cache *cert_cache;

/**
 * Build flag from an algorithm/curve identifier (pk, md, ecp)
 * Since 0 is always XXX_NONE, ignore it.
 */
#define TTLS_X509_ID_FLAG(id)   (1 << (id - 1))

/**
 * Security profile for certificate verification. All lists are bitfields,
 * built by ORing flags from TTLS_X509_ID_FLAG().
 *
 * @allowed_mds		- MDs for signatures.
 * @allowed_pks		- PK algs for signatures.
 * @allowed_curves	- Elliptic curves for ECDSA.
 * @rsa_min_bitlen	- Minimum size for RSA keys.
 */
typedef struct
{
	uint32_t allowed_mds;
	uint32_t allowed_pks;
	uint32_t allowed_curves;
	uint32_t rsa_min_bitlen;
}
ttls_x509_crt_profile;

/**
 * Default security profile. Should provide a good balance between security
 * and compatibility with current deployments.
 */
const ttls_x509_crt_profile ttls_x509_crt_profile_default =
{
	/* Only SHA-2 hashes */
	TTLS_X509_ID_FLAG(TTLS_MD_SHA256) |
	TTLS_X509_ID_FLAG(TTLS_MD_SHA384) |
	TTLS_X509_ID_FLAG(TTLS_MD_SHA512),
	0xFFFFFFF, /* Any PK alg	*/
	0xFFFFFFF, /* Any curve	 */
	2048,
};

/**
 * Expected next default profile. Recommended for new deployments.
 * Currently targets a 128-bit security level, except for RSA-2048.
 */
const ttls_x509_crt_profile ttls_x509_crt_profile_next =
{
	/* Hashes from SHA-256 and above */
	TTLS_X509_ID_FLAG(TTLS_MD_SHA256) |
	TTLS_X509_ID_FLAG(TTLS_MD_SHA384) |
	TTLS_X509_ID_FLAG(TTLS_MD_SHA512),
	0xFFFFFFF, /* Any PK alg	*/
	/* Curves at or above 128-bit security level */
	TTLS_X509_ID_FLAG(TTLS_ECP_DP_SECP256R1) |
	TTLS_X509_ID_FLAG(TTLS_ECP_DP_SECP384R1) |
	2048,
};

/**
 * NSA Suite B Profile
 */
const ttls_x509_crt_profile ttls_x509_crt_profile_suiteb =
{
	/* Only SHA-256 and 384 */
	TTLS_X509_ID_FLAG(TTLS_MD_SHA256) |
	TTLS_X509_ID_FLAG(TTLS_MD_SHA384),
	/* Only ECDSA */
	TTLS_X509_ID_FLAG(TTLS_PK_ECDSA) |
	TTLS_X509_ID_FLAG(TTLS_PK_ECKEY),
	/* Only NIST P-256 and P-384 */
	TTLS_X509_ID_FLAG(TTLS_ECP_DP_SECP256R1) |
	TTLS_X509_ID_FLAG(TTLS_ECP_DP_SECP384R1),
	0,
};

/* TODO #830 this will be frequently used in softirq, better to use avx-enabled
 * function here and in x509_memcasecmp(), x509_string_cmp(). But the same
 * code is still possible in the process context on loading server certificates.
 */
static int x509_memcmp(const void *s1, const void *s2, size_t len)
{
	if (in_serving_softirq())
		return memcmp_fast(s1, s2, len);
	return memcmp(s1, s2, len);
}

/**
 * Check md_alg against profile.
 * Return 0 if md_alg acceptable for this profile, -1 otherwise.
 */
static int
x509_profile_check_md_alg(const ttls_x509_crt_profile *profile,
			  ttls_md_type_t md_alg)
{
	if ((profile->allowed_mds & TTLS_X509_ID_FLAG(md_alg)) != 0)
		return 0;

	return -1;
}

/**
 * Check pk_alg against profile.
 * Return 0 if pk_alg acceptable for this profile, -1 otherwise.
 */
static int
x509_profile_check_pk_alg(const ttls_x509_crt_profile *profile,
			  ttls_pk_type_t pk_alg)
{
	if ((profile->allowed_pks & TTLS_X509_ID_FLAG(pk_alg)) != 0)
		return 0;

	return -1;
}

/**
 * Check key against profile.
 * Return 0 if pk_alg acceptable for this profile, -1 otherwise.
 */
static int
x509_profile_check_key(const ttls_x509_crt_profile *profile,
		       ttls_pk_type_t pk_alg, const TlsPkCtx *pk)
{
	if (pk_alg == TTLS_PK_RSA || pk_alg == TTLS_PK_RSASSA_PSS) {
		if (ttls_pk_get_bitlen(pk) >= profile->rsa_min_bitlen)
			return 0;
		return -1;
	}

	if (pk_alg == TTLS_PK_ECDSA
	    || pk_alg == TTLS_PK_ECKEY
	    || pk_alg == TTLS_PK_ECKEY_DH)
	{
		ttls_ecp_group_id gid = ttls_pk_ec(*pk)->grp->id;

		if ((profile->allowed_curves & TTLS_X509_ID_FLAG(gid)) != 0)
			return 0;
		return -1;
	}

	return -1;
}

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int
x509_get_version(unsigned char **p, const unsigned char *end, int *ver)
{
	int ret;
	size_t len;

	ret = ttls_asn1_get_tag(p, end, &len,
				TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED);
	if (unlikely(ret)) {
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG) {
			*ver = 0;
			return 0;
		}
		return ret;
	}

	end = *p + len;

	if ((ret = ttls_asn1_get_int(p, end, ver)))
		return TTLS_ERR_X509_INVALID_VERSION + ret;

	if (*p != end)
		return TTLS_ERR_X509_INVALID_VERSION +
			TTLS_ERR_ASN1_LENGTH_MISMATCH;

	return 0;
}

/*
 *  Validity ::= SEQUENCE {
 *	   notBefore	  Time,
 *	   notAfter	   Time }
 */
static int
x509_get_dates(unsigned char **p, const unsigned char *end,
	       ttls_x509_time *from, ttls_x509_time *to)
{
	int ret;
	size_t len;

	ret = ttls_asn1_get_tag(p, end, &len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (unlikely(ret))
		return TTLS_ERR_X509_INVALID_DATE + ret;

	end = *p + len;

	if ((ret = ttls_x509_get_time(p, end, from)))
		return ret;
	if ((ret = ttls_x509_get_time(p, end, to)))
		return ret;
	if (*p != end)
		return TTLS_ERR_X509_INVALID_DATE +
			TTLS_ERR_ASN1_LENGTH_MISMATCH;

	return 0;
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
static int
x509_get_uid(unsigned char **p, const unsigned char *end, ttls_x509_buf *uid,
	     int n)
{
	int ret;

	if (*p == end)
		return 0;

	uid->tag = **p;

	ret = ttls_asn1_get_tag(p, end, &uid->len,
				TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | n);
	if (unlikely(ret)) {
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
			return 0;
		return ret;
	}

	uid->p = *p;
	*p += uid->len;

	return 0;
}

static int
x509_get_basic_constraints(unsigned char **p, const unsigned char *end,
			   int *ca_istrue, int *max_pathlen)
{
	int ret;
	size_t len;

	/*
	 * BasicConstraints ::= SEQUENCE {
	 *	  cA		  BOOLEAN DEFAULT FALSE,
	 *	  pathLenConstraint	   INTEGER (0..MAX) OPTIONAL }
	 */
	*ca_istrue = 0; /* DEFAULT FALSE */
	*max_pathlen = 0; /* endless */

	ret = ttls_asn1_get_tag(p, end, &len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (unlikely(ret))
		return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

	if (*p == end)
		return 0;

	if ((ret = ttls_asn1_get_bool(p, end, ca_istrue))) {
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
			ret = ttls_asn1_get_int(p, end, ca_istrue);

		if (ret != 0)
			return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

		if (*ca_istrue != 0)
			*ca_istrue = 1;
	}

	if (*p == end)
		return 0;

	if ((ret = ttls_asn1_get_int(p, end, max_pathlen)))
		return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

	if (*p != end)
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
		       TTLS_ERR_ASN1_LENGTH_MISMATCH;

	(*max_pathlen)++;

	return 0;
}

static int
x509_get_ns_cert_type(unsigned char **p, const unsigned char *end,
		      unsigned char *ns_cert_type)
{
	int ret;
	ttls_x509_bitstring bs = { 0, 0, NULL };

	if ((ret = ttls_asn1_get_bitstring(p, end, &bs)))
		return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

	if (bs.len != 1)
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
		       TTLS_ERR_ASN1_INVALID_LENGTH;

	/* Get actual bitstring */
	*ns_cert_type = *bs.p;
	return 0;
}

static int
x509_get_key_usage(unsigned char **p, const unsigned char *end,
		   unsigned int *key_usage)
{
	int ret;
	size_t i;
	ttls_x509_bitstring bs = { 0, 0, NULL };

	if ((ret = ttls_asn1_get_bitstring(p, end, &bs)))
		return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

	if (bs.len < 1)
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
		       TTLS_ERR_ASN1_INVALID_LENGTH;

	/* Get actual bitstring */
	*key_usage = 0;
	for (i = 0; i < bs.len && i < sizeof(unsigned int); i++) {
		*key_usage |= (unsigned int) bs.p[i] << (8*i);
	}

	return 0;
}

/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static int
x509_get_ext_key_usage(unsigned char **p, const unsigned char *end,
		       ttls_x509_sequence *ext_key_usage)
{
	int ret = ttls_asn1_get_sequence_of(p, end, ext_key_usage, TTLS_ASN1_OID);
	if (unlikely(ret))
		return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

	/* Sequence length must be >= 1 */
	if (unlikely(ext_key_usage->buf.p == NULL))
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
		       TTLS_ERR_ASN1_INVALID_LENGTH;

	return 0;
}

/*
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *	  otherName		   [0]	 OtherName,
 *	  rfc822Name		  [1]	 IA5String,
 *	  dNSName			 [2]	 IA5String,
 *	  x400Address		 [3]	 ORAddress,
 *	  directoryName				   [4]	 Name,
 *	  ediPartyName		[5]	 EDIPartyName,
 *	  uniformResourceIdentifier	   [6]	 IA5String,
 *	  iPAddress		   [7]	 OCTET STRING,
 *	  registeredID		[8]	 OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *	  type-id	OBJECT IDENTIFIER,
 *	  value	  [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *	  nameAssigner			[0]	 DirectoryString OPTIONAL,
 *	  partyName			   [1]	 DirectoryString }
 *
 * NOTE: we only parse and use dNSName at this point.
 */
static int
x509_get_subject_alt_name(unsigned char **p, const unsigned char *end,
			  ttls_x509_sequence *subject_alt_name)
{
	int ret;
	size_t len, tag_len;
	ttls_asn1_buf *buf;
	ttls_asn1_sequence *cur = subject_alt_name;

	/* Get main sequence tag */
	ret = ttls_asn1_get_tag(p, end, &len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (unlikely(ret))
		return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

	if (*p + len != end)
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
			TTLS_ERR_ASN1_LENGTH_MISMATCH;

	while (*p < end) {
		unsigned char tag;

		if ((end - *p) < 1)
			return TTLS_ERR_X509_INVALID_EXTENSIONS +
			       TTLS_ERR_ASN1_OUT_OF_DATA;

		tag = **p;
		(*p)++;
		if ((ret = ttls_asn1_get_len(p, end, &tag_len)))
			return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

		if ((tag & TTLS_ASN1_TAG_CLASS_MASK) !=
		    TTLS_ASN1_CONTEXT_SPECIFIC)
		{
			return TTLS_ERR_X509_INVALID_EXTENSIONS
					+ TTLS_ERR_ASN1_UNEXPECTED_TAG;
		}

		/* Skip everything but DNS name */
		if (tag != (TTLS_ASN1_CONTEXT_SPECIFIC | 2)) {
			*p += tag_len;
			continue;
		}

		/* Allocate and assign next pointer */
		if (cur->buf.p) {
			if (cur->next)
				return TTLS_ERR_X509_INVALID_EXTENSIONS;

			cur->next = kzalloc(sizeof(ttls_asn1_sequence),
					    GFP_KERNEL);
			if (!cur->next)
				return -ENOMEM;

			cur = cur->next;
		}

		buf = &(cur->buf);
		buf->tag = tag;
		buf->p = *p;
		buf->len = tag_len;
		*p += buf->len;
	}

	/* Set final sequence entry's next pointer to NULL */
	cur->next = NULL;

	if (*p != end)
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
			TTLS_ERR_ASN1_LENGTH_MISMATCH;

	return 0;
}

/*
 * X.509 v3 extensions
 *
 */
static int
x509_get_crt_ext(unsigned char **p, const unsigned char *end, TlsX509Crt *crt)
{
	int ret;
	size_t len;

	if ((ret = ttls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0) {
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
			return 0;

		return ret;
	}

	while (*p < end)
	{
		unsigned char *end_ext_data, *end_ext_octet;
		/*
		 * Extension  ::=  SEQUENCE  {
		 *	  extnID	  OBJECT IDENTIFIER,
		 *	  critical	BOOLEAN DEFAULT FALSE,
		 *	  extnValue   OCTET STRING  }
		 */
		ttls_x509_buf extn_oid = {0, 0, NULL};
		int is_critical = 0; /* DEFAULT FALSE */
		int ext_type = 0;

		ret = ttls_asn1_get_tag(p, end, &len,
					TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
		if (unlikely(ret))
			return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

		end_ext_data = *p + len;

		/* Get extension ID */
		extn_oid.tag = **p;

		ret = ttls_asn1_get_tag(p, end, &extn_oid.len, TTLS_ASN1_OID);
		if (unlikely(ret))
			return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

		extn_oid.p = *p;
		*p += extn_oid.len;

		if ((end - *p) < 1)
			return TTLS_ERR_X509_INVALID_EXTENSIONS +
					TTLS_ERR_ASN1_OUT_OF_DATA;

		/* Get optional critical */
		if ((ret = ttls_asn1_get_bool(p, end_ext_data, &is_critical))
		    && (ret != TTLS_ERR_ASN1_UNEXPECTED_TAG))
		{
			return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;
		}

		/* Data should be octet string type */
		ret = ttls_asn1_get_tag(p, end_ext_data, &len,
					TTLS_ASN1_OCTET_STRING);
		if (unlikely(ret))
			return TTLS_ERR_X509_INVALID_EXTENSIONS + ret;

		end_ext_octet = *p + len;

		if (end_ext_octet != end_ext_data)
			return TTLS_ERR_X509_INVALID_EXTENSIONS +
					TTLS_ERR_ASN1_LENGTH_MISMATCH;

		/*
		 * Detect supported extensions
		 */
		ret = ttls_oid_get_x509_ext_type(&extn_oid, &ext_type);
		if (unlikely(ret))
		{
			/* No parser found, skip extension */
			*p = end_ext_octet;
			if (is_critical)
				/* Data is marked as critical: fail */
				return TTLS_ERR_X509_INVALID_EXTENSIONS +
					TTLS_ERR_ASN1_UNEXPECTED_TAG;
			continue;
		}

		/* Forbid repeated extensions */
		if (crt->ext_types & ext_type)
			return TTLS_ERR_X509_INVALID_EXTENSIONS;

		crt->ext_types |= ext_type;

		switch(ext_type) {
		case TTLS_X509_EXT_BASIC_CONSTRAINTS:
			/* Parse basic constraints */
			ret = x509_get_basic_constraints(p, end_ext_octet,
							 &crt->ca_istrue,
							 &crt->max_pathlen);
			if (unlikely(ret))
				return ret;
			break;

		case TTLS_X509_EXT_KEY_USAGE:
			/* Parse key usage */
			ret = x509_get_key_usage(p, end_ext_octet,
						 &crt->key_usage);
			if (unlikely(ret))
				return ret;
			break;

		case TTLS_X509_EXT_EXTENDED_KEY_USAGE:
			/* Parse extended key usage */
			ret = x509_get_ext_key_usage(p, end_ext_octet,
						     &crt->ext_key_usage);
			if (unlikely(ret))
				return ret;
			break;

		case TTLS_X509_EXT_SUBJECT_ALT_NAME:
			/* Parse subject alt name */
			ret = x509_get_subject_alt_name(p, end_ext_octet,
							&crt->subject_alt_names);
			if (unlikely(ret))
				return ret;
			break;

		case TTLS_X509_EXT_NS_CERT_TYPE:
			/* Parse netscape certificate type */
			ret = x509_get_ns_cert_type(p, end_ext_octet,
						    &crt->ns_cert_type);
			if (unlikely(ret))
				return ret;
			break;

		default:
			return TTLS_ERR_X509_FEATURE_UNAVAILABLE;
		}
	}

	if (*p != end)
		return TTLS_ERR_X509_INVALID_EXTENSIONS +
				TTLS_ERR_ASN1_LENGTH_MISMATCH;

	return 0;
}

/**
 * Parse and fill a single X.509 certificate in DER format.
 */
static int
x509_crt_parse_der_core(TlsX509Crt *crt, unsigned char *buf, size_t buflen)
{
	int r;
	size_t len;
	unsigned char *p, *end, *crt_end;
	ttls_x509_buf sig_params1, sig_params2, sig_oid2;

	BUG_ON(!crt || !buf);
	memset(&sig_params1, 0, sizeof(ttls_x509_buf));
	memset(&sig_params2, 0, sizeof(ttls_x509_buf));
	memset(&sig_oid2, 0, sizeof(ttls_x509_buf));

	p = (unsigned char*)buf;
	len = buflen;
	end = p + len;

	/*
	 * Certificate  ::=  SEQUENCE  {
	 *   tbsCertificate		TBSCertificate,
	 *   signatureAlgorithm		AlgorithmIdentifier,
	 *   signatureValue		BIT STRING
	 * }
	 */
	r = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT;
	}
	if (len > (size_t)(end - p)) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT
				+ TTLS_ERR_ASN1_LENGTH_MISMATCH;
	}
	crt_end = p + len;

	/*
	 * Create and populate a new buffer for the raw field.
	 * Reuse the buffer, we're responsible to free the pages later.
	 */
	crt->raw.len = crt_end - buf;
	crt->raw.p = p = buf;

	/* Direct pointers to the new buffer. */
	p += crt->raw.len - len;
	end = crt_end = p + len;

	/* TBSCertificate  ::=  SEQUENCE  { */
	crt->tbs.p = p;

	r = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT + r;
	}

	end = p + len;
	crt->tbs.len = end - crt->tbs.p;

	/*
	 * Version ::= INTEGER { v1(0), v2(1), v3(2) }
	 *
	 * CertificateSerialNumber ::= INTEGER
	 *
	 * signature AlgorithmIdentifier
	 */
	if ((r = x509_get_version( &p, end, &crt->version ))
	    || (r = ttls_x509_get_serial(&p, end, &crt->serial))
	    || (r = ttls_x509_get_alg(&p, end, &crt->sig_oid, &sig_params1)))
	{
		ttls_x509_crt_free(crt);
		return r;
	}
	if (crt->version < 0 || crt->version > 2) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_UNKNOWN_VERSION;
	}
	crt->version++;

	r = ttls_x509_get_sig_alg(&crt->sig_oid, &sig_params1, &crt->sig_md,
				  &crt->sig_pk, &crt->sig_opts);
	if (r) {
		ttls_x509_crt_free(crt);
		return r;
	}

	/* issuer Name */
	crt->issuer_raw.p = p;

	r = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT + r;
	}
	if ((r = ttls_x509_get_name(&p, p + len, &crt->issuer))) {
		ttls_x509_crt_free(crt);
		return r;
	}
	crt->issuer_raw.len = p - crt->issuer_raw.p;

	/*
	 * Validity ::= SEQUENCE {
	 *	notBefore	Time,
	 *	notAfter	Time
	 * }
	 */
	r = x509_get_dates(&p, end, &crt->valid_from, &crt->valid_to);
	if (r) {
		ttls_x509_crt_free(crt);
		return r;
	}

	/* subject Name */
	crt->subject_raw.p = p;
	r = ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE);
	if (r) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT + r;
	}
	if (len && (r = ttls_x509_get_name(&p, p + len, &crt->subject))) {
		ttls_x509_crt_free(crt);
		return r;
	}
	crt->subject_raw.len = p - crt->subject_raw.p;

	/* SubjectPublicKeyInfo */
	if ((r = ttls_pk_parse_subpubkey(&p, end, &crt->pk))) {
		ttls_x509_crt_free(crt);
		return r;
	}

	/*
	 *  issuerUniqueID  [1] IMPLICIT UniqueIdentifier OPTIONAL,
	 *		-- If present, version shall be v2 or v3
	 *  subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL,
	 *		-- If present, version shall be v2 or v3
	 *  extensions      [3] EXPLICIT Extensions OPTIONAL
	 *		-- If present, version shall be v3
	 */
	if (crt->version == 2 || crt->version == 3) {
		if ((r = x509_get_uid(&p, end, &crt->issuer_id, 1))) {
			ttls_x509_crt_free(crt);
			return r;
		}
		if ((r = x509_get_uid(&p, end, &crt->subject_id,  2))) {
			ttls_x509_crt_free(crt);
			return r;
		}
	}
	if (crt->version == 3) {
		if ((r = x509_get_crt_ext(&p, end, crt))) {
			ttls_x509_crt_free(crt);
			return r;
		}
	}

	if (p != end) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT
				+ TTLS_ERR_ASN1_LENGTH_MISMATCH;
	}
	end = crt_end;

	/*
	 * }
	 * -- end of TBSCertificate
	 *
	 * signatureAlgorithm	AlgorithmIdentifier,
	 * signatureValue	BIT STRING
	 */
	if ((r = ttls_x509_get_alg(&p, end, &sig_oid2, &sig_params2))) {
		ttls_x509_crt_free(crt);
		return r;
	}
	if (crt->sig_oid.len != sig_oid2.len
	    || x509_memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len)
	    || sig_params1.len != sig_params2.len
	    || (sig_params1.len
		&& x509_memcmp(sig_params1.p, sig_params2.p, sig_params1.len)))
	{
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_SIG_MISMATCH;
	}
	if ((r = ttls_x509_get_sig(&p, end, &crt->sig))) {
		ttls_x509_crt_free(crt);
		return r;
	}

	if (p != end) {
		ttls_x509_crt_free(crt);
		return TTLS_ERR_X509_INVALID_FORMAT
				+ TTLS_ERR_ASN1_LENGTH_MISMATCH;
	}

	return 0;
}

/**
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list.
 */
int
ttls_x509_crt_parse_der(TlsX509Crt *chain, unsigned char *buf, size_t buflen)
{
	int r;
	TlsX509Crt *crt = chain, *prev = NULL;

	BUG_ON(!crt || !buf);

	while (crt->version && crt->next) {
		prev = crt;
		crt = crt->next;
	}
#if DBG_TLS == 3
	print_hex_dump(KERN_INFO, "Binary certificate", DUMP_PREFIX_OFFSET,
		       16, 1, buf, buflen, true);
#endif

	/* Add new certificate on the end of the chain if needed. */
	if (crt->version && !crt->next) {
		crt->next = ttls_x509_crt_alloc();
		if (!crt->next)
			return TTLS_ERR_X509_ALLOC_FAILED;

		prev = crt;
		crt = crt->next;
	}

	if ((r = x509_crt_parse_der_core(crt, buf, buflen))) {
		if (prev)
			prev->next = NULL;
		if (crt != chain)
			kmem_cache_free(cert_cache, crt);
		return r;
	}

	return 0;
}

/**
 * Parse one or more PEM certificates from a buffer and add them to the chained
 * list. @buf is a page cluster reused in the certificates chain. Parses
 * permissively. If some certificates can be parsed, the result is the number
 * of failed certificates it encountered. If none complete correctly, the first
 * error is returned.
 */
int
ttls_x509_crt_parse(TlsX509Crt *chain, unsigned char *buf, size_t buflen)
{
	int success = 0, first_error = 0, total_failed = 0;
	int buf_format = TTLS_X509_FORMAT_DER;

	/* Check for valid input. */
	BUG_ON(!chain || !buf);

	/*
	 * Determine buffer content. Buffer contains either one DER certificate
	 * or one or more PEM certificates.
	 */
	if (buflen && buf[buflen - 1] == '\0'
	    && strstr((const char *)buf, "-----BEGIN CERTIFICATE-----"))
	{
		buf_format = TTLS_X509_FORMAT_PEM;
	}

	if (buf_format == TTLS_X509_FORMAT_DER)
		return ttls_x509_crt_parse_der(chain, buf, buflen);

	if (buf_format == TTLS_X509_FORMAT_PEM) {
		/*
		 * 1 rather than 0 since the terminating NULL byte
		 * is counted in.
		 */
		while (buflen > 1) {
			int r;
			size_t use_len;
			unsigned char *pem_dec;

			/*
			 * If we get there, we know the string is
			 * null-terminated.
			 */
			r = ttls_pem_read_buffer("-----BEGIN CERTIFICATE-----",
						 "-----END CERTIFICATE-----",
						 buf, &use_len);
			if (r > 0) {
				/* Was PEM encoded. */
				pem_dec = buf;
				buflen -= use_len;
				buf += use_len;
			}
			else if (r != TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
				/* PEM header and footer were found. */
				buflen -= use_len;
				buf += use_len;

				if (!first_error)
					first_error = r;
				total_failed++;
				continue;
			}
			else {
				break;
			}

			r = ttls_x509_crt_parse_der(chain, pem_dec, r);
			if (r) {
				/* Quit parsing on a memory error. */
				if (r == TTLS_ERR_X509_ALLOC_FAILED)
					return r;
				if (!first_error)
					first_error = r;
				total_failed++;
				continue;
			}

			success = 1;
		}
	}

	/* Does MPI calculations, so pool context must be freed afterwards. */
	ttls_mpi_pool_cleanup_ctx(0, false);

	if (success)
		return total_failed;
	if (first_error)
		return first_error;
	return TTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
}
EXPORT_SYMBOL(ttls_x509_crt_parse);

struct x509_crt_verify_string {
	int code;
	const char *string;
};

static const struct x509_crt_verify_string x509_crt_verify_strings[] = {
{ TTLS_X509_BADCERT_EXPIRED,		"The certificate validity has expired" },
{ TTLS_X509_BADCERT_REVOKED,		"The certificate has been revoked (is on a CRL)" },
{ TTLS_X509_BADCERT_CN_MISMATCH,	"The certificate Common Name (CN) does not match with the expected CN" },
{ TTLS_X509_BADCERT_NOT_TRUSTED,	"The certificate is not correctly signed by the trusted CA" },
{ TTLS_X509_BADCRL_NOT_TRUSTED,		"The CRL is not correctly signed by the trusted CA" },
{ TTLS_X509_BADCRL_EXPIRED,		"The CRL is expired" },
{ TTLS_X509_BADCERT_MISSING,		"Certificate was missing" },
{ TTLS_X509_BADCERT_SKIP_VERIFY,	"Certificate verification was skipped" },
{ TTLS_X509_BADCERT_OTHER,		"Other reason (can be used by verify callback)" },
{ TTLS_X509_BADCERT_FUTURE,		"The certificate validity starts in the future" },
{ TTLS_X509_BADCRL_FUTURE,		"The CRL is from the future" },
{ TTLS_X509_BADCERT_KEY_USAGE,		"Usage does not match the keyUsage extension" },
{ TTLS_X509_BADCERT_EXT_KEY_USAGE,	"Usage does not match the extendedKeyUsage extension" },
{ TTLS_X509_BADCERT_NS_CERT_TYPE,	"Usage does not match the nsCertType extension" },
{ TTLS_X509_BADCERT_BAD_MD,		"The certificate is signed with an unacceptable hash." },
{ TTLS_X509_BADCERT_BAD_PK,		"The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA)." },
{ TTLS_X509_BADCERT_BAD_KEY,		"The certificate is signed with an unacceptable key (eg bad curve, RSA too short)." },
{ TTLS_X509_BADCRL_BAD_MD,		"The CRL is signed with an unacceptable hash." },
{ TTLS_X509_BADCRL_BAD_PK,		"The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA)." },
{ TTLS_X509_BADCRL_BAD_KEY,		"The CRL is signed with an unacceptable key (eg bad curve, RSA too short)." },
{ 0, NULL }
};

/**
 * Check usage of certificate against keyUsage extension.
 *
 * @crt		- Leaf certificate used.
 * @usage	- Intended usage(s) (eg TTLS_X509_KU_KEY_ENCIPHERMENT
 *		  before using the certificate to perform an RSA key exchange).
 *
 * Except for decipherOnly and encipherOnly, a bit set in the usage argument
 * means this bit MUST be set in the certificate. For decipherOnly and
 * encipherOnly, it means that bit MAY be set.
 *
 * You should only call this function on leaf certificates, on (intermediate)
 * CAs the keyUsage extension is automatically checked by @ttls_x509_crt_verify().
 *
 * @return 0 is these uses of the certificate are allowed,
 * TTLS_ERR_X509_BAD_INPUT_DATA if the keyUsage extension is present but does
 * not match the usage argument.
 */
int
ttls_x509_crt_check_key_usage(const TlsX509Crt *crt,
			      unsigned int usage)
{
	unsigned int usage_must, usage_may;
	unsigned int may_mask = TTLS_X509_KU_ENCIPHER_ONLY
				| TTLS_X509_KU_DECIPHER_ONLY;

	if ((crt->ext_types & TTLS_X509_EXT_KEY_USAGE) == 0)
		return 0;

	usage_must = usage & ~may_mask;

	if (((crt->key_usage & ~may_mask) & usage_must) != usage_must)
		return TTLS_ERR_X509_BAD_INPUT_DATA;

	usage_may = usage & may_mask;

	if (((crt->key_usage & may_mask) | usage_may) != usage_may)
		return TTLS_ERR_X509_BAD_INPUT_DATA;

	return 0;
}

/**
 * Check usage of certificate against extendedKeyUsage. Usually only makes sense
 * on leaf certificates.
 *
 * @crt		- Leaf certificate used.
 * @usage_oid	- Intended usage (eg TTLS_OID_SERVER_AUTH or
 *				  TTLS_OID_CLIENT_AUTH).
 * @usage_len	- Length of usage_oid (eg given by TTLS_OID_SIZE()).
 *
 * @return	- 0 if this use of the certificate is allowed,
 *				  TTLS_ERR_X509_BAD_INPUT_DATA if not.
 */
int
ttls_x509_crt_check_extended_key_usage(const TlsX509Crt *crt,
				       const char *usage_oid,
				       size_t usage_len)
{
	const ttls_x509_sequence *cur;

	/* Extension is not mandatory, absent means no restriction */
	if ((crt->ext_types & TTLS_X509_EXT_EXTENDED_KEY_USAGE) == 0)
		return 0;

	/*
	 * Look for the requested usage (or wildcard ANY) in our list
	 */
	for (cur = &crt->ext_key_usage; cur != NULL; cur = cur->next)
	{
		const ttls_x509_buf *cur_oid = &cur->buf;

		if (cur_oid->len == usage_len &&
		    x509_memcmp(cur_oid->p, usage_oid, usage_len) == 0)
		{
			return 0;
		}

		if (TTLS_OID_CMP(TTLS_OID_ANY_EXTENDED_KEY_USAGE, cur_oid) == 0)
			return 0;
	}

	return TTLS_ERR_X509_BAD_INPUT_DATA;
}

/**
 * Verify the certificate revocation status.
 *
 * @crt		- a certificate to be verified;
 * @crl		- the CRL to verify against;
 *
 * Returns 1 if the certificate is revoked, 0 otherwise.
 */
static int
ttls_x509_crt_is_revoked(const TlsX509Crt *crt, const ttls_x509_crl *crl)
{
	const ttls_x509_crl_entry *cur = &crl->entry;

	while (cur != NULL && cur->serial.len != 0)
	{
		if (crt->serial.len == cur->serial.len &&
		    x509_memcmp(crt->serial.p, cur->serial.p, crt->serial.len) == 0)
		{
			if (ttls_x509_time_is_past(&cur->revocation_date))
				return 1;
		}

		cur = cur->next;
	}

	return 0;
}

/*
 * Check that the given certificate is not revoked according to the CRL.
 * Skip validation is no CRL for the given CA is present.
 */
static int
x509_crt_verifycrl(TlsX509Crt *crt, TlsX509Crt *ca,
		   ttls_x509_crl *crl_list,
		   const ttls_x509_crt_profile *profile)
{
	int flags = 0;
	unsigned char hash[TTLS_MD_MAX_SIZE];
	const TlsMdInfo *md_info;

	if (ca == NULL)
		return flags;

	while (crl_list != NULL)
	{
		if (crl_list->version == 0 ||
		    crl_list->issuer_raw.len != ca->subject_raw.len ||
		    x509_memcmp(crl_list->issuer_raw.p, ca->subject_raw.p,
			   crl_list->issuer_raw.len) != 0)
		{
			crl_list = crl_list->next;
			continue;
		}

		/*
		 * Check if the CA is configured to sign CRLs
		 */
		if (ttls_x509_crt_check_key_usage(ca, TTLS_X509_KU_CRL_SIGN) != 0)
		{
			flags |= TTLS_X509_BADCRL_NOT_TRUSTED;
			break;
		}

		/*
		 * Check if CRL is correctly signed by the trusted CA
		 */
		if (x509_profile_check_md_alg(profile, crl_list->sig_md) != 0)
			flags |= TTLS_X509_BADCRL_BAD_MD;

		if (x509_profile_check_pk_alg(profile, crl_list->sig_pk) != 0)
			flags |= TTLS_X509_BADCRL_BAD_PK;

		md_info = ttls_md_info_from_type(crl_list->sig_md);
		if (md_info == NULL)
		{
			/*
			 * Cannot check 'unknown' hash
			 */
			flags |= TTLS_X509_BADCRL_NOT_TRUSTED;
			break;
		}

		ttls_md(md_info, crl_list->tbs.p, crl_list->tbs.len, hash);

		if (x509_profile_check_key(profile, crl_list->sig_pk, &ca->pk) != 0)
			flags |= TTLS_X509_BADCERT_BAD_KEY;

		if (ttls_pk_verify_ext(crl_list->sig_pk, crl_list->sig_opts, &ca->pk,
				       crl_list->sig_md, hash, ttls_md_get_size(md_info),
				       crl_list->sig.p, crl_list->sig.len) != 0)
		{
			flags |= TTLS_X509_BADCRL_NOT_TRUSTED;
			break;
		}

		/*
		 * Check for validity of CRL (Do not drop out)
		 */
		if (ttls_x509_time_is_past(&crl_list->next_update))
			flags |= TTLS_X509_BADCRL_EXPIRED;

		if (ttls_x509_time_is_future(&crl_list->this_update))
			flags |= TTLS_X509_BADCRL_FUTURE;

		/*
		 * Check if certificate is revoked
		 */
		if (ttls_x509_crt_is_revoked(crt, crl_list))
		{
			flags |= TTLS_X509_BADCERT_REVOKED;
			break;
		}

		crl_list = crl_list->next;
	}

	return flags;
}

/*
 * Like memcmp, but case-insensitive and always returns -1 if different.
 * TODO #830: call tfw_cstricmp() in soft
 */
static int x509_memcasecmp(const void *s1, const void *s2, size_t len)
{
	size_t i;
	unsigned char diff;
	const unsigned char *n1 = s1, *n2 = s2;

	/*
	 * TODO #830
	 * if (in_serving_softirq() && len > 8(?))
	 *	return __tfw_stricmp_avx2(s1, s2, len);
	 * else
	 *	return strncasecmp(s1, s2, len);
	 */

	for (i = 0; i < len; i++)
	{
		diff = n1[i] ^ n2[i];

		if (diff == 0)
			continue;

		if (diff == 32 &&
		    ((n1[i] >= 'a' && n1[i] <= 'z') ||
		     (n1[i] >= 'A' && n1[i] <= 'Z')))
		{
			continue;
		}

		return -1;
	}

	return 0;
}

/*
 * Return 0 if name matches wildcard, -1 otherwise
 */
static int x509_check_wildcard(const char *cn, ttls_x509_buf *name)
{
	size_t i;
	size_t cn_idx = 0, cn_len = strlen(cn);

	if (name->len < 3 || name->p[0] != '*' || name->p[1] != '.')
		return 0;

	for (i = 0; i < cn_len; ++i)
	{
		if (cn[i] == '.')
		{
			cn_idx = i;
			break;
		}
	}

	if (cn_idx == 0)
		return -1;

	if (cn_len - cn_idx == name->len - 1 &&
	    x509_memcasecmp(name->p + 1, cn + cn_idx, name->len - 1) == 0)
	{
		return 0;
	}

	return -1;
}

/*
 * Compare two X.509 strings, case-insensitive, and allowing for some encoding
 * variations (but not all).
 *
 * Return 0 if equal, -1 otherwise.
 */
static int x509_string_cmp(const ttls_x509_buf *a, const ttls_x509_buf *b)
{
	if (a->tag == b->tag &&
	    a->len == b->len &&
	    x509_memcmp(a->p, b->p, b->len) == 0)
	{
		return 0;
	}

	if ((a->tag == TTLS_ASN1_UTF8_STRING || a->tag == TTLS_ASN1_PRINTABLE_STRING) &&
	    (b->tag == TTLS_ASN1_UTF8_STRING || b->tag == TTLS_ASN1_PRINTABLE_STRING) &&
	    a->len == b->len &&
	    x509_memcasecmp(a->p, b->p, b->len) == 0)
	{
		return 0;
	}

	return -1;
}

/*
 * Compare two X.509 Names (aka rdnSequence).
 *
 * See RFC 5280 section 7.1, though we don't implement the whole algorithm:
 * we sometimes return unequal when the full algorithm would return equal,
 * but never the other way. (In particular, we don't do Unicode normalisation
 * or space folding.)
 *
 * Return 0 if equal, -1 otherwise.
 */
static int x509_name_cmp(const ttls_x509_name *a, const ttls_x509_name *b)
{
	/* Avoid recursion, it might not be optimised by the compiler */
	while (a != NULL || b != NULL)
	{
		if (a == NULL || b == NULL)
			return -1;

		/* type */
		if (a->oid.tag != b->oid.tag ||
		    a->oid.len != b->oid.len ||
		    x509_memcmp(a->oid.p, b->oid.p, b->oid.len) != 0)
		{
			return -1;
		}

		/* value */
		if (x509_string_cmp(&a->val, &b->val) != 0)
			return -1;

		/* structure of the list of sets */
		if (a->next_merged != b->next_merged)
			return -1;

		a = a->next;
		b = b->next;
	}

	/* a == NULL == b */
	return 0;
}

/*
 * Check if 'parent' is a suitable parent (signing CA) for 'child'.
 * Return 0 if yes, -1 if not.
 *
 * top means parent is a locally-trusted certificate
 * bottom means child is the end entity cert
 */
static int x509_crt_check_parent(const TlsX509Crt *child,
				 const TlsX509Crt *parent,
				 int top, int bottom)
{
	int need_ca_bit;

	/* Parent must be the issuer */
	if (x509_name_cmp(&child->issuer, &parent->subject) != 0)
		return -1;

	/* Parent must have the basicConstraints CA bit set as a general rule */
	need_ca_bit = 1;

	/* Exception: v1/v2 certificates that are locally trusted. */
	if (top && parent->version < 3)
		need_ca_bit = 0;

	/* Exception: self-signed end-entity certs that are locally trusted. */
	if (top && bottom &&
	    child->raw.len == parent->raw.len &&
	    x509_memcmp(child->raw.p, parent->raw.p, child->raw.len) == 0)
	{
		need_ca_bit = 0;
	}

	if (need_ca_bit && ! parent->ca_istrue)
		return -1;

	if (need_ca_bit &&
	    ttls_x509_crt_check_key_usage(parent, TTLS_X509_KU_KEY_CERT_SIGN) != 0)
	{
		return -1;
	}

	return 0;
}

static int
x509_crt_verify_top(TlsX509Crt *child, TlsX509Crt *trust_ca,
		    ttls_x509_crl *ca_crl, const ttls_x509_crt_profile *profile,
		    int path_cnt, int self_cnt, uint32_t *flags)
{
	uint32_t ca_flags = 0;
	int check_path_cnt;
	unsigned char hash[TTLS_MD_MAX_SIZE];
	const TlsMdInfo *md_info;
	TlsX509Crt *future_past_ca = NULL;

	if (ttls_x509_time_is_past(&child->valid_to))
		*flags |= TTLS_X509_BADCERT_EXPIRED;

	if (ttls_x509_time_is_future(&child->valid_from))
		*flags |= TTLS_X509_BADCERT_FUTURE;

	if (x509_profile_check_md_alg(profile, child->sig_md) != 0)
		*flags |= TTLS_X509_BADCERT_BAD_MD;

	if (x509_profile_check_pk_alg(profile, child->sig_pk) != 0)
		*flags |= TTLS_X509_BADCERT_BAD_PK;

	/*
	 * Child is the top of the chain. Check against the trust_ca list.
	 */
	*flags |= TTLS_X509_BADCERT_NOT_TRUSTED;

	md_info = ttls_md_info_from_type(child->sig_md);
	if (md_info == NULL) {
		/*
		 * Cannot check 'unknown', no need to try any CA
		 */
		trust_ca = NULL;
	}
	else
		ttls_md(md_info, child->tbs.p, child->tbs.len, hash);

	for (/* trust_ca */ ; trust_ca != NULL; trust_ca = trust_ca->next)
	{
		if (x509_crt_check_parent(child, trust_ca, 1, path_cnt == 0) != 0)
			continue;

		check_path_cnt = path_cnt + 1;

		/*
		 * Reduce check_path_cnt to check against if top of the chain is
		 * the same as the trusted CA
		 */
		if (child->subject_raw.len == trust_ca->subject_raw.len &&
		    x509_memcmp(child->subject_raw.p, trust_ca->subject_raw.p,
			   child->issuer_raw.len) == 0)
		{
			check_path_cnt--;
		}

		/* Self signed certificates do not count towards the limit */
		if (trust_ca->max_pathlen > 0 &&
		    trust_ca->max_pathlen < check_path_cnt - self_cnt)
		{
			continue;
		}

		if (ttls_pk_verify_ext(child->sig_pk, child->sig_opts, &trust_ca->pk,
				       child->sig_md, hash, ttls_md_get_size(md_info),
				       child->sig.p, child->sig.len) != 0)
		{
			continue;
		}

		if (ttls_x509_time_is_past(&trust_ca->valid_to) ||
		    ttls_x509_time_is_future(&trust_ca->valid_from))
		{
			if (future_past_ca == NULL)
				future_past_ca = trust_ca;

			continue;
		}

		break;
	}

	if (trust_ca != NULL || (trust_ca = future_past_ca) != NULL) {
		/*
		 * Top of chain is signed by a trusted CA
		 */
		*flags &= ~TTLS_X509_BADCERT_NOT_TRUSTED;

		if (x509_profile_check_key(profile, child->sig_pk, &trust_ca->pk) != 0)
			*flags |= TTLS_X509_BADCERT_BAD_KEY;
	}

	/*
	 * If top of chain is not the same as the trusted CA send a verify request
	 * to the callback for any issues with validity and CRL presence for the
	 * trusted CA certificate.
	 */
	if (trust_ca != NULL &&
	    (child->subject_raw.len != trust_ca->subject_raw.len ||
	     x509_memcmp(child->subject_raw.p, trust_ca->subject_raw.p,
		    child->issuer_raw.len) != 0))
	{
		/* Check trusted CA's CRL for the chain's top crt */
		*flags |= x509_crt_verifycrl(child, trust_ca, ca_crl, profile);

		if (ttls_x509_time_is_past(&trust_ca->valid_to))
			ca_flags |= TTLS_X509_BADCERT_EXPIRED;

		if (ttls_x509_time_is_future(&trust_ca->valid_from))
			ca_flags |= TTLS_X509_BADCERT_FUTURE;
	}

	*flags |= ca_flags;

	return 0;
}

static int
x509_crt_verify_child(TlsX509Crt *child, TlsX509Crt *parent,
		      TlsX509Crt *trust_ca, ttls_x509_crl *ca_crl,
		      const ttls_x509_crt_profile *profile,
		      int path_cnt, int self_cnt, uint32_t *flags)
{
	int ret;
	uint32_t parent_flags = 0;
	unsigned char hash[TTLS_MD_MAX_SIZE];
	TlsX509Crt *grandparent;
	const TlsMdInfo *md_info;

	/* Counting intermediate self signed certificates */
	if ((path_cnt != 0) && x509_name_cmp(&child->issuer, &child->subject) == 0)
		self_cnt++;

	/* path_cnt is 0 for the first intermediate CA */
	if (1 + path_cnt > TTLS_X509_MAX_INTERMEDIATE_CA) {
		/* return immediately as the goal is to avoid unbounded recursion */
		return TTLS_ERR_X509_FATAL_ERROR;
	}

	if (ttls_x509_time_is_past(&child->valid_to))
		*flags |= TTLS_X509_BADCERT_EXPIRED;

	if (ttls_x509_time_is_future(&child->valid_from))
		*flags |= TTLS_X509_BADCERT_FUTURE;

	if (x509_profile_check_md_alg(profile, child->sig_md) != 0)
		*flags |= TTLS_X509_BADCERT_BAD_MD;

	if (x509_profile_check_pk_alg(profile, child->sig_pk) != 0)
		*flags |= TTLS_X509_BADCERT_BAD_PK;

	md_info = ttls_md_info_from_type(child->sig_md);
	if (md_info == NULL)
	{
		/*
		 * Cannot check 'unknown' hash
		 */
		T_WARN("certificate uses unsupported hash %d\n", child->sig_md);
		*flags |= TTLS_X509_BADCERT_NOT_TRUSTED;
	}
	else
	{
		ttls_md(md_info, child->tbs.p, child->tbs.len, hash);

		if (x509_profile_check_key(profile, child->sig_pk, &parent->pk) != 0)
			*flags |= TTLS_X509_BADCERT_BAD_KEY;

		if (ttls_pk_verify_ext(child->sig_pk, child->sig_opts, &parent->pk,
				       child->sig_md, hash, ttls_md_get_size(md_info),
				       child->sig.p, child->sig.len) != 0)
		{
			*flags |= TTLS_X509_BADCERT_NOT_TRUSTED;
		}
	}

	/* Check trusted CA's CRL for the given crt */
	*flags |= x509_crt_verifycrl(child, parent, ca_crl, profile);

	/* Look for a grandparent in trusted CAs */
	for (grandparent = trust_ca;
	     grandparent != NULL;
	     grandparent = grandparent->next)
	{
		if (x509_crt_check_parent(parent, grandparent,
					  0, path_cnt == 0) == 0)
			break;
	}

	if (grandparent != NULL)
	{
		ret = x509_crt_verify_top(parent, grandparent, ca_crl, profile,
					  path_cnt + 1, self_cnt, &parent_flags);
		if (ret != 0)
			return ret;
	}
	else
	{
		/* Look for a grandparent upwards the chain */
		for (grandparent = parent->next;
		     grandparent != NULL;
		     grandparent = grandparent->next)
		{
			/* +2 because the current step is not yet accounted for
			 * and because max_pathlen is one higher than it should be.
			 * Also self signed certificates do not count to the limit. */
			if (grandparent->max_pathlen > 0 &&
			    grandparent->max_pathlen < 2 + path_cnt - self_cnt)
			{
				continue;
			}

			if (x509_crt_check_parent(parent, grandparent,
						  0, path_cnt == 0) == 0)
				break;
		}

		/* Is our parent part of the chain or at the top? */
		if (grandparent != NULL)
		{
			ret = x509_crt_verify_child(parent, grandparent,
						    trust_ca, ca_crl, profile,
						    path_cnt + 1, self_cnt,
						    &parent_flags);
			if (ret != 0)
				return ret;
		}
		else
		{
			ret = x509_crt_verify_top(parent, trust_ca, ca_crl,
						  profile, path_cnt + 1,
						  self_cnt, &parent_flags);
			if (ret != 0)
				return ret;
		}
	}

	*flags |= parent_flags;

	return 0;
}

/**
 * Verify the certificate signature according to profile.
 *
 * It is your responsibility to provide up-to-date CRLs for all trusted CAs.
 * If no CRL is provided for the CA that was used to sign the certificate,
 * CRL verification is skipped silently, that is *without* setting any flag.
 *
 * @crt		- a certificate (chain) to be verified;
 * @trust_ca	- the list of trusted CAs;
 * @ca_crl	- the list of CRLs for trusted CAs (see note above);
 * @cn		- expected Common Name (can be set to NULL if the CN must
 *		  not be verified);
 * @flags	- result of the verification
 *
 * @return:
 * - 0 (and flags set to 0) if the chain was verified and valid,
 * - TTLS_ERR_X509_CERT_VERIFY_FAILED if the chain was verified, but found to
 *   be invalid, @flags will have one or more TTLS_X509_BADCERT_XXX or
 *   TTLS_X509_BADCRL_XXX flags set,
 * - another error (and flags set to 0xffffffff) in case of a fatal error
 *   encountered during the verification process.
 */
int
ttls_x509_crt_verify_with_profile(TlsX509Crt *crt,
				  TlsX509Crt *trust_ca,
				  ttls_x509_crl *ca_crl,
				  int profile_id,
				  const char *cn, uint32_t *flags)
{
	size_t cn_len;
	int ret;
	int pathlen = 0, selfsigned = 0;
	TlsX509Crt *parent;
	ttls_x509_name *name;
	ttls_x509_sequence *cur = NULL;
	ttls_pk_type_t pk_type;
	const ttls_x509_crt_profile *profile;

	switch (profile_id) {
	case TLS_X509_CERT_PROFILE_NEXT:
		profile = &ttls_x509_crt_profile_next;
		break;
	case TLS_X509_CERT_PROFILE_SUITEB:
		profile = &ttls_x509_crt_profile_suiteb;
		break;
	default:
		profile = &ttls_x509_crt_profile_default;
		break;
	}

	*flags = 0;

	if (cn != NULL)
	{
		name = &crt->subject;
		cn_len = strlen(cn);

		if (crt->ext_types & TTLS_X509_EXT_SUBJECT_ALT_NAME)
		{
			cur = &crt->subject_alt_names;

			while (cur != NULL)
			{
				if (cur->buf.len == cn_len
				    && !x509_memcasecmp(cn, cur->buf.p, cn_len))
					break;

				if (cur->buf.len > 2
				    && !x509_memcmp(cur->buf.p, "*.", 2)
				    && !x509_check_wildcard(cn, &cur->buf))
					break;

				cur = cur->next;
			}

			if (cur == NULL)
				*flags |= TTLS_X509_BADCERT_CN_MISMATCH;
		}
		else
		{
			while (name != NULL)
			{
				if (!TTLS_OID_CMP(TTLS_OID_AT_CN, &name->oid)) {
					if (name->val.len == cn_len
					    && !x509_memcasecmp(name->val.p, cn,
								cn_len))
						break;

					if (name->val.len > 2
					    && !x509_memcmp(name->val.p, "*.", 2)
					    && !x509_check_wildcard(cn,
								    &name->val))
						break;
				}

				name = name->next;
			}

			if (name == NULL)
				*flags |= TTLS_X509_BADCERT_CN_MISMATCH;
		}
	}

	/* Check the type and size of the key */
	pk_type = ttls_pk_get_type(&crt->pk);

	if (x509_profile_check_pk_alg(profile, pk_type) != 0)
		*flags |= TTLS_X509_BADCERT_BAD_PK;

	if (x509_profile_check_key(profile, pk_type, &crt->pk) != 0)
		*flags |= TTLS_X509_BADCERT_BAD_KEY;

	/* Look for a parent in trusted CAs */
	for (parent = trust_ca; parent != NULL; parent = parent->next)
	{
		if (x509_crt_check_parent(crt, parent, 0, pathlen == 0) == 0)
			break;
	}

	if (parent != NULL)
	{
		ret = x509_crt_verify_top(crt, parent, ca_crl, profile, pathlen,
					  selfsigned, flags);
		if (ret != 0)
			goto exit;
	}
	else
	{
		/* Look for a parent upwards the chain */
		for (parent = crt->next; parent != NULL; parent = parent->next)
			if (x509_crt_check_parent(crt, parent, 0, pathlen == 0) == 0)
				break;

		/* Are we part of the chain or at the top? */
		if (parent != NULL)
		{
			ret = x509_crt_verify_child(crt, parent, trust_ca,
						    ca_crl, profile, pathlen,
						    selfsigned, flags);
			if (ret != 0)
				goto exit;
		}
		else
		{
			ret = x509_crt_verify_top(crt, trust_ca, ca_crl,
						  profile, pathlen, selfsigned,
						  flags);
			if (ret != 0)
				goto exit;
		}
	}

exit:
	/* prevent misuse of the vrfy callback - VERIFY_FAILED would be ignored by
	 * the SSL module for authmode optional, but non-zero return from the
	 * callback means a fatal error so it shouldn't be ignored */
	if (ret == TTLS_ERR_X509_CERT_VERIFY_FAILED)
		ret = TTLS_ERR_X509_FATAL_ERROR;

	if (ret != 0)
	{
		*flags = (uint32_t) -1;
		return ret;
	}

	if (*flags != 0)
		return TTLS_ERR_X509_CERT_VERIFY_FAILED;

	return 0;
}

TlsX509Crt *
ttls_x509_crt_alloc(void)
{
	/*
	 * Certificates are always manually zerised before deallocation,
	 * avoid GFP_ZERO flag here.
	 */
	TlsX509Crt *crt = kmem_cache_alloc(cert_cache, GFP_ATOMIC);
	if (crt)
		ttls_bzero_safe(crt, sizeof(TlsX509Crt));
	return crt;
}

/*
 * Init certificate. Safe for process context.
 */
void
ttls_x509_crt_init(TlsX509Crt *crt)
{
	memset(crt, 0, sizeof(TlsX509Crt));
}
EXPORT_SYMBOL(ttls_x509_crt_init);

/**
 * Unallocate all certificate data. Caller is responsible to deallocate @crt
 * on its own.
 */
void
ttls_x509_crt_free(TlsX509Crt *crt)
{
	TlsX509Crt *cert_cur = crt, *cert_prv;
	ttls_x509_name *name_cur, *name_prv;
	ttls_x509_sequence *seq_cur, *seq_prv;

	if (!crt)
		return;

	do {
		ttls_pk_free(&cert_cur->pk);
		kfree(cert_cur->sig_opts);

		name_cur = cert_cur->issuer.next;
		while (name_cur) {
			name_prv = name_cur;
			name_cur = name_cur->next;
			ttls_bzero_safe(name_prv, sizeof(ttls_x509_name));
			kfree(name_prv);
		}

		name_cur = cert_cur->subject.next;
		while (name_cur) {
			name_prv = name_cur;
			name_cur = name_cur->next;
			ttls_bzero_safe(name_prv, sizeof(ttls_x509_name));
			kfree(name_prv);
		}

		seq_cur = cert_cur->ext_key_usage.next;
		while (seq_cur) {
			seq_prv = seq_cur;
			seq_cur = seq_cur->next;
			ttls_bzero_safe(seq_prv, sizeof(ttls_x509_sequence));
			kfree(seq_prv);
		}

		seq_cur = cert_cur->subject_alt_names.next;
		while (seq_cur) {
			seq_prv = seq_cur;
			seq_cur = seq_cur->next;
			ttls_bzero_safe(seq_prv, sizeof(ttls_x509_sequence));
			kfree(seq_prv);
		}

		if (cert_cur->raw.p) {
			ttls_bzero_safe(cert_cur->raw.p, cert_cur->raw.len);
			/*
			 * It's a user responsibility to free the certificate
			 * pages.
			 */
		}

		cert_cur = cert_cur->next;
	} while (cert_cur);

	cert_cur = crt;
	do {
		cert_prv = cert_cur;
		cert_cur = cert_cur->next;

		ttls_bzero_safe(cert_prv, sizeof(TlsX509Crt));
		if (cert_prv != crt)
			kmem_cache_free(cert_cache, cert_prv);
	} while (cert_cur);

}
EXPORT_SYMBOL(ttls_x509_crt_free);

void
ttls_x509_crt_destroy(TlsX509Crt **crt)
{
	if (!*crt)
		return;
	ttls_x509_crt_free(*crt);

	if ((*crt)->raw.p && (*crt)->raw.len) {
		__free_pages(virt_to_page((*crt)->raw.p),
			     get_order((*crt)->raw.len));
	}
	ttls_bzero_safe(*crt, sizeof(TlsX509Crt));
	kmem_cache_free(cert_cache, *crt);
	*crt = NULL;
}

int
ttls_x509_init(void)
{
	cert_cache = kmem_cache_create("tls_cert_cache", sizeof(TlsX509Crt),
				       0, 0, NULL);
	if (!cert_cache)
		return -ENOMEM;
	return 0;
}

void
ttls_x509_exit(void)
{
	kmem_cache_destroy(cert_cache);
}
