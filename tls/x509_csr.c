/*
 *  X.509 Certificate Signing Request (CSR) parsing
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
#include "config.h"

#if defined(TTLS_X509_CSR_PARSE_C)

#include "x509_csr.h"
#include "oid.h"
#if defined(TTLS_PEM_PARSE_C)
#include "pem.h"
#endif

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version(unsigned char **p,
							 const unsigned char *end,
							 int *ver)
{
	int ret;

	if ((ret = ttls_asn1_get_int(p, end, ver)) != 0)
	{
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
		{
			*ver = 0;
			return 0;
		}

		return(TTLS_ERR_X509_INVALID_VERSION + ret);
	}

	return 0;
}

/*
 * Parse a CSR in DER format
 */
int ttls_x509_csr_parse_der(ttls_x509_csr *csr,
						const unsigned char *buf, size_t buflen)
{
	int ret;
	size_t len;
	unsigned char *p, *end;
	ttls_x509_buf sig_params;

	memset(&sig_params, 0, sizeof(ttls_x509_buf));

	/*
	 * Check for valid input
	 */
	if (csr == NULL || buf == NULL || buflen == 0)
		return(TTLS_ERR_X509_BAD_INPUT_DATA);

	ttls_x509_csr_init(csr);

	/*
	 * first copy the raw DER data
	 */
	p = ttls_calloc(1, len = buflen);

	if (p == NULL)
		return(TTLS_ERR_X509_ALLOC_FAILED);

	memcpy(p, buf, buflen);

	csr->raw.p = p;
	csr->raw.len = len;
	end = p + len;

	/*
	 *  CertificationRequest ::= SEQUENCE {
	 *	   certificationRequestInfo CertificationRequestInfo,
	 *	   signatureAlgorithm AlgorithmIdentifier,
	 *	   signature		  BIT STRING
	 *  }
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_INVALID_FORMAT);
	}

	if (len != (size_t) (end - p))
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}

	/*
	 *  CertificationRequestInfo ::= SEQUENCE {
	 */
	csr->cri.p = p;

	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_INVALID_FORMAT + ret);
	}

	end = p + len;
	csr->cri.len = end - csr->cri.p;

	/*
	 *  Version  ::=  INTEGER {  v1(0) }
	 */
	if ((ret = x509_csr_get_version(&p, end, &csr->version)) != 0)
	{
		ttls_x509_csr_free(csr);
		return ret;
	}

	if (csr->version != 0)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_UNKNOWN_VERSION);
	}

	csr->version++;

	/*
	 *  subject			   Name
	 */
	csr->subject_raw.p = p;

	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_INVALID_FORMAT + ret);
	}

	if ((ret = ttls_x509_get_name(&p, p + len, &csr->subject)) != 0)
	{
		ttls_x509_csr_free(csr);
		return ret;
	}

	csr->subject_raw.len = p - csr->subject_raw.p;

	/*
	 *  subjectPKInfo SubjectPublicKeyInfo
	 */
	if ((ret = ttls_pk_parse_subpubkey(&p, end, &csr->pk)) != 0)
	{
		ttls_x509_csr_free(csr);
		return ret;
	}

	/*
	 *  attributes	[0] Attributes
	 *
	 *  The list of possible attributes is open-ended, though RFC 2985
	 *  (PKCS#9) defines a few in section 5.4. We currently don't support any,
	 *  so we just ignore them. This is a safe thing to do as the worst thing
	 *  that could happen is that we issue a certificate that does not match
	 *  the requester's expectations - this cannot cause a violation of our
	 *  signature policies.
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_CONTEXT_SPECIFIC)) != 0)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_INVALID_FORMAT + ret);
	}

	p += len;

	end = csr->raw.p + csr->raw.len;

	/*
	 *  signatureAlgorithm   AlgorithmIdentifier,
	 *  signature			BIT STRING
	 */
	if ((ret = ttls_x509_get_alg(&p, end, &csr->sig_oid, &sig_params)) != 0)
	{
		ttls_x509_csr_free(csr);
		return ret;
	}

	if ((ret = ttls_x509_get_sig_alg(&csr->sig_oid, &sig_params,
								  &csr->sig_md, &csr->sig_pk,
								  &csr->sig_opts)) != 0)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_UNKNOWN_SIG_ALG);
	}

	if ((ret = ttls_x509_get_sig(&p, end, &csr->sig)) != 0)
	{
		ttls_x509_csr_free(csr);
		return ret;
	}

	if (p != end)
	{
		ttls_x509_csr_free(csr);
		return(TTLS_ERR_X509_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}

	return 0;
}

/*
 * Parse a CSR, allowing for PEM or raw DER encoding
 */
int ttls_x509_csr_parse(ttls_x509_csr *csr, const unsigned char *buf, size_t buflen)
{
#if defined(TTLS_PEM_PARSE_C)
	int ret;
	size_t use_len;
	ttls_pem_context pem;
#endif

	/*
	 * Check for valid input
	 */
	if (csr == NULL || buf == NULL || buflen == 0)
		return(TTLS_ERR_X509_BAD_INPUT_DATA);

#if defined(TTLS_PEM_PARSE_C)
	ttls_pem_init(&pem);

	/* Avoid calling ttls_pem_read_buffer() on non-null-terminated string */
	if (buf[buflen - 1] != '\0')
		ret = TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
	else
		ret = ttls_pem_read_buffer(&pem,
							   "-----BEGIN CERTIFICATE REQUEST-----",
							   "-----END CERTIFICATE REQUEST-----",
							   buf, NULL, 0, &use_len);

	if (ret == 0)
	{
		/*
		 * Was PEM encoded, parse the result
		 */
		if ((ret = ttls_x509_csr_parse_der(csr, pem.buf, pem.buflen)) != 0)
			return ret;

		ttls_pem_free(&pem);
		return 0;
	}
	else if (ret != TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT)
	{
		ttls_pem_free(&pem);
		return ret;
	}
	else
#endif /* TTLS_PEM_PARSE_C */
	return(ttls_x509_csr_parse_der(csr, buf, buflen));
}

#define BEFORE_COLON	14
#define BC			  "14"
/*
 * Return an informational string about the CSR.
 */
int ttls_x509_csr_info(char *buf, size_t size, const char *prefix,
				   const ttls_x509_csr *csr)
{
	int ret;
	size_t n;
	char *p;
	char key_size_str[BEFORE_COLON];

	p = buf;
	n = size;

	ret = ttls_snprintf(p, n, "%sCSR version   : %d",
							   prefix, csr->version);
	TTLS_X509_SAFE_SNPRINTF;

	ret = ttls_snprintf(p, n, "\n%ssubject name  : ", prefix);
	TTLS_X509_SAFE_SNPRINTF;
	ret = ttls_x509_dn_gets(p, n, &csr->subject);
	TTLS_X509_SAFE_SNPRINTF;

	ret = ttls_snprintf(p, n, "\n%ssigned using  : ", prefix);
	TTLS_X509_SAFE_SNPRINTF;

	ret = ttls_x509_sig_alg_gets(p, n, &csr->sig_oid, csr->sig_pk, csr->sig_md,
							 csr->sig_opts);
	TTLS_X509_SAFE_SNPRINTF;

	if ((ret = ttls_x509_key_size_helper(key_size_str, BEFORE_COLON,
									  ttls_pk_get_name(&csr->pk))) != 0)
	{
		return ret;
	}

	ret = ttls_snprintf(p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str,
						  (int) ttls_pk_get_bitlen(&csr->pk));
	TTLS_X509_SAFE_SNPRINTF;

	return((int) (size - n));
}

/*
 * Initialize a CSR
 */
void ttls_x509_csr_init(ttls_x509_csr *csr)
{
	memset(csr, 0, sizeof(ttls_x509_csr));
}

/*
 * Unallocate all CSR data
 */
void ttls_x509_csr_free(ttls_x509_csr *csr)
{
	ttls_x509_name *name_cur;
	ttls_x509_name *name_prv;

	if (csr == NULL)
		return;

	ttls_pk_free(&csr->pk);

#if defined(TTLS_X509_RSASSA_PSS_SUPPORT)
	ttls_free(csr->sig_opts);
#endif

	name_cur = csr->subject.next;
	while (name_cur != NULL)
	{
		name_prv = name_cur;
		name_cur = name_cur->next;
		ttls_zeroize(name_prv, sizeof(ttls_x509_name));
		ttls_free(name_prv);
	}

	if (csr->raw.p != NULL)
	{
		ttls_zeroize(csr->raw.p, csr->raw.len);
		ttls_free(csr->raw.p);
	}

	ttls_zeroize(csr, sizeof(ttls_x509_csr));
}

#endif /* TTLS_X509_CSR_PARSE_C */
