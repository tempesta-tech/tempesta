/**
 *		Tempesta TLS
 *
 * X.509 Certidicate Revocation List (CRL) parsing
 *
 * The ITU-T X.509 standard defines a certificate format for PKI.
 *
 * http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 * http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 * http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#include "x509_crl.h"
#include "oid.h"
#include "pem.h"
#include "tls_internal.h"

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1)  }
 */
static int x509_crl_get_version(unsigned char **p,
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
 * X.509 CRL v2 extensions
 *
 * We currently don't parse any extension's content, but we do check that the
 * list of extensions is well-formed and abort on critical extensions (that
 * are unsupported as we don't support any extension so far)
 */
static int x509_get_crl_ext(unsigned char **p,
				 const unsigned char *end,
				 ttls_x509_buf *ext)
{
	int ret;

	/*
	 * crlExtensions		   [0]  EXPLICIT Extensions OPTIONAL
	 *				  -- if present, version MUST be v2
	 */
	if ((ret = ttls_x509_get_ext(p, end, ext, 0)) != 0)
	{
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
			return 0;

		return ret;
	}

	while (*p < end)
	{
		/*
		 * Extension  ::=  SEQUENCE  {
		 *	  extnID	  OBJECT IDENTIFIER,
		 *	  critical	BOOLEAN DEFAULT FALSE,
		 *	  extnValue   OCTET STRING  }
		 */
		int is_critical = 0;
		const unsigned char *end_ext_data;
		size_t len;

		/* Get enclosing sequence tag */
		if ((ret = ttls_asn1_get_tag(p, end, &len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
			return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);

		end_ext_data = *p + len;

		/* Get OID (currently ignored) */
		if ((ret = ttls_asn1_get_tag(p, end_ext_data, &len,
				  TTLS_ASN1_OID)) != 0)
		{
			return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);
		}
		*p += len;

		/* Get optional critical */
		if ((ret = ttls_asn1_get_bool(p, end_ext_data,
				   &is_critical)) != 0 &&
			(ret != TTLS_ERR_ASN1_UNEXPECTED_TAG))
		{
			return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);
		}

		/* Data should be octet string type */
		if ((ret = ttls_asn1_get_tag(p, end_ext_data, &len,
				TTLS_ASN1_OCTET_STRING)) != 0)
			return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);

		/* Ignore data so far and just check its length */
		*p += len;
		if (*p != end_ext_data)
			return(TTLS_ERR_X509_INVALID_EXTENSIONS +
		TTLS_ERR_ASN1_LENGTH_MISMATCH);

		/* Abort on (unsupported) critical extensions */
		if (is_critical)
			return(TTLS_ERR_X509_INVALID_EXTENSIONS +
		TTLS_ERR_ASN1_UNEXPECTED_TAG);
	}

	if (*p != end)
		return(TTLS_ERR_X509_INVALID_EXTENSIONS +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/*
 * X.509 CRL v2 entry extensions (no extensions parsed yet.)
 */
static int x509_get_crl_entry_ext(unsigned char **p,
				 const unsigned char *end,
				 ttls_x509_buf *ext)
{
	int ret;
	size_t len = 0;

	/* OPTIONAL */
	if (end <= *p)
		return 0;

	ext->tag = **p;
	ext->p = *p;

	/*
	 * Get CRL-entry extension sequence header
	 * crlEntryExtensions	  Extensions OPTIONAL  -- if present, MUST be v2
	 */
	if ((ret = ttls_asn1_get_tag(p, end, &ext->len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
		{
			ext->p = NULL;
			return 0;
		}
		return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);
	}

	end = *p + ext->len;

	if (end != *p + ext->len)
		return(TTLS_ERR_X509_INVALID_EXTENSIONS +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	while (*p < end)
	{
		if ((ret = ttls_asn1_get_tag(p, end, &len,
				TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
			return(TTLS_ERR_X509_INVALID_EXTENSIONS + ret);

		*p += len;
	}

	if (*p != end)
		return(TTLS_ERR_X509_INVALID_EXTENSIONS +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/*
 * X.509 CRL Entries
 */
static int x509_get_entries(unsigned char **p,
				 const unsigned char *end,
				 ttls_x509_crl_entry *entry)
{
	int ret;
	size_t entry_len;
	ttls_x509_crl_entry *cur_entry = entry;

	if (*p == end)
		return 0;

	if ((ret = ttls_asn1_get_tag(p, end, &entry_len,
			TTLS_ASN1_SEQUENCE | TTLS_ASN1_CONSTRUCTED)) != 0)
	{
		if (ret == TTLS_ERR_ASN1_UNEXPECTED_TAG)
			return 0;

		return ret;
	}

	end = *p + entry_len;

	while (*p < end)
	{
		size_t len2;
		const unsigned char *end2;

		if ((ret = ttls_asn1_get_tag(p, end, &len2,
				TTLS_ASN1_SEQUENCE | TTLS_ASN1_CONSTRUCTED)) != 0)
		{
			return ret;
		}

		cur_entry->raw.tag = **p;
		cur_entry->raw.p = *p;
		cur_entry->raw.len = len2;
		end2 = *p + len2;

		if ((ret = ttls_x509_get_serial(p, end2, &cur_entry->serial)) != 0)
			return ret;

		if ((ret = ttls_x509_get_time(p, end2,
		   &cur_entry->revocation_date)) != 0)
			return ret;

		if ((ret = x509_get_crl_entry_ext(p, end2,
		&cur_entry->entry_ext)) != 0)
			return ret;

		if (*p < end)
		{
			cur_entry->next = kzalloc(sizeof(ttls_x509_crl_entry),
						  GFP_KERNEL);

			if (cur_entry->next == NULL)
				return(TTLS_ERR_X509_ALLOC_FAILED);

			cur_entry = cur_entry->next;
		}
	}

	return 0;
}

/**
 * Parse a DER-encoded CRL and append it to the chained list
 *
 * @chain	- points to the start of the chain;
 * @buf		- buffer holding the CRL data in DER format;
 * @buflen	- size of the buffer (including the terminating null byte for
 *		  PEM data);
 *
 * Return 0 if successful, or a specific X509 or PEM error code
 */
int
ttls_x509_crl_parse_der(ttls_x509_crl *chain,
			const unsigned char *buf, size_t buflen)
{
	int ret;
	size_t len;
	unsigned char *p = NULL, *end = NULL;
	ttls_x509_buf sig_params1, sig_params2, sig_oid2;
	ttls_x509_crl *crl = chain;

	/*
	 * Check for valid input
	 */
	if (crl == NULL || buf == NULL)
		return(TTLS_ERR_X509_BAD_INPUT_DATA);

	memset(&sig_params1, 0, sizeof(ttls_x509_buf));
	memset(&sig_params2, 0, sizeof(ttls_x509_buf));
	memset(&sig_oid2, 0, sizeof(ttls_x509_buf));

	/*
	 * Add new CRL on the end of the chain if needed.
	 */
	while (crl->version != 0 && crl->next != NULL)
		crl = crl->next;

	if (crl->version != 0 && crl->next == NULL)
	{
		crl->next = kzalloc(sizeof(ttls_x509_crl), GFP_KERNEL);

		if (crl->next == NULL)
		{
			ttls_x509_crl_free(crl);
			return(TTLS_ERR_X509_ALLOC_FAILED);
		}

		ttls_x509_crl_init(crl->next);
		crl = crl->next;
	}

	/*
	 * Copy raw DER-encoded CRL
	 */
	if (buflen == 0)
		return(TTLS_ERR_X509_INVALID_FORMAT);

	p = kmalloc(buflen, GFP_KERNEL);
	if (p == NULL)
		return(TTLS_ERR_X509_ALLOC_FAILED);

	memcpy(p, buf, buflen);

	crl->raw.p = p;
	crl->raw.len = buflen;

	end = p + buflen;

	/*
	 * CertificateList  ::=  SEQUENCE  {
	 *	  tbsCertList		  TBSCertList,
	 *	  signatureAlgorithm   AlgorithmIdentifier,
	 *	  signatureValue	   BIT STRING  }
	 */
	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_INVALID_FORMAT);
	}

	if (len != (size_t) (end - p))
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}

	/*
	 * TBSCertList  ::=  SEQUENCE  {
	 */
	crl->tbs.p = p;

	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_INVALID_FORMAT + ret);
	}

	end = p + len;
	crl->tbs.len = end - crl->tbs.p;

	/*
	 * Version  ::=  INTEGER  OPTIONAL {  v1(0), v2(1)  }
	 *			   -- if present, MUST be v2
	 *
	 * signature			AlgorithmIdentifier
	 */
	if ((ret = x509_crl_get_version(&p, end, &crl->version)) != 0 ||
		(ret = ttls_x509_get_alg(&p, end, &crl->sig_oid, &sig_params1)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	if (crl->version < 0 || crl->version > 1)
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_UNKNOWN_VERSION);
	}

	crl->version++;

	if ((ret = ttls_x509_get_sig_alg(&crl->sig_oid, &sig_params1,
		  &crl->sig_md, &crl->sig_pk,
		  &crl->sig_opts)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	/*
	 * issuer			   Name
	 */
	crl->issuer_raw.p = p;

	if ((ret = ttls_asn1_get_tag(&p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_INVALID_FORMAT + ret);
	}

	if ((ret = ttls_x509_get_name(&p, p + len, &crl->issuer)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	crl->issuer_raw.len = p - crl->issuer_raw.p;

	/*
	 * thisUpdate		  Time
	 * nextUpdate		  Time OPTIONAL
	 */
	if ((ret = ttls_x509_get_time(&p, end, &crl->this_update)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	if ((ret = ttls_x509_get_time(&p, end, &crl->next_update)) != 0)
	{
		if (ret != (TTLS_ERR_X509_INVALID_DATE +
			TTLS_ERR_ASN1_UNEXPECTED_TAG) &&
			ret != (TTLS_ERR_X509_INVALID_DATE +
			TTLS_ERR_ASN1_OUT_OF_DATA))
		{
			ttls_x509_crl_free(crl);
			return ret;
		}
	}

	/*
	 * revokedCertificates	SEQUENCE OF SEQUENCE   {
	 *	  userCertificate		CertificateSerialNumber,
	 *	  revocationDate		 Time,
	 *	  crlEntryExtensions	 Extensions OPTIONAL
	 *		   -- if present, MUST be v2
	 *			} OPTIONAL
	 */
	if ((ret = x509_get_entries(&p, end, &crl->entry)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	/*
	 * crlExtensions		  EXPLICIT Extensions OPTIONAL
	 *				  -- if present, MUST be v2
	 */
	if (crl->version == 2)
	{
		ret = x509_get_crl_ext(&p, end, &crl->crl_ext);

		if (ret != 0)
		{
			ttls_x509_crl_free(crl);
			return ret;
		}
	}

	if (p != end)
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}

	end = crl->raw.p + crl->raw.len;

	/*
	 *  signatureAlgorithm   AlgorithmIdentifier,
	 *  signatureValue	   BIT STRING
	 */
	if ((ret = ttls_x509_get_alg(&p, end, &sig_oid2, &sig_params2)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	if (crl->sig_oid.len != sig_oid2.len ||
		memcmp(crl->sig_oid.p, sig_oid2.p, crl->sig_oid.len) != 0 ||
		sig_params1.len != sig_params2.len ||
		(sig_params1.len != 0 &&
		  memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0))
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_SIG_MISMATCH);
	}

	if ((ret = ttls_x509_get_sig(&p, end, &crl->sig)) != 0)
	{
		ttls_x509_crl_free(crl);
		return ret;
	}

	if (p != end)
	{
		ttls_x509_crl_free(crl);
		return(TTLS_ERR_X509_INVALID_FORMAT +
				TTLS_ERR_ASN1_LENGTH_MISMATCH);
	}

	return 0;
}

/**
 * Parse one or more CRLs and add them to the chained list. Multiple CRLs are
 * accepted only if using PEM format.
 *
 * @chain	- points to the start of the chain;
 * @buf		- buffer holding the CRL data in PEM or DER format;
 * @buflen	- size of the buffer (including the terminating null byte for
 *		  PEM data)
 *
 * Return 0 if successful, or a specific X509 or PEM error code.
 *
 * BEWARE @buf is overwritten by the PEM decoder.
 */
int
ttls_x509_crl_parse(ttls_x509_crl *chain, unsigned char *buf, size_t buflen)
{
	int r, dec_len, is_pem = 0;
	size_t use_len;

	if (!chain || !buf)
		return TTLS_ERR_X509_BAD_INPUT_DATA;

	do {
		/*
		 * Avoid calling ttls_pem_read_buffer() on non-null-terminated
		 * string.
		 */
		if (!buflen || buf[buflen - 1] != '\0')
			r = TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
		else
			r = ttls_pem_read_buffer("-----BEGIN X509 CRL-----",
						 "-----END X509 CRL-----",
						 buf, &use_len);

		if (r > 0) {
			/* Was PEM encoded. */
			is_pem = 1;
			dec_len = r;
			buflen -= use_len;

			if ((r = ttls_x509_crl_parse_der(chain, buf, dec_len)))
				return r;
		}
		else if (is_pem) {
			return r;
		}

		buf += use_len;
	}
	/*
	 * In the PEM case, buflen is 1 at the end, for the terminated NULL
	 * byte. And a valid CRL cannot be less than 1 byte anyway.
	 */
	while (is_pem && buflen > 1);

	if (is_pem)
		return 0;
	return ttls_x509_crl_parse_der(chain, buf, buflen);
}

/**
 * Initialize a CRL chain
 */
void ttls_x509_crl_init(ttls_x509_crl *crl)
{
	memset(crl, 0, sizeof(ttls_x509_crl));
}

/**
 * Unallocate all CRL data
 */
void ttls_x509_crl_free(ttls_x509_crl *crl)
{
	ttls_x509_crl *crl_cur = crl;
	ttls_x509_crl *crl_prv;
	ttls_x509_name *name_cur;
	ttls_x509_name *name_prv;
	ttls_x509_crl_entry *entry_cur;
	ttls_x509_crl_entry *entry_prv;

	if (crl == NULL)
		return;

	do
	{
		kfree(crl_cur->sig_opts);

		name_cur = crl_cur->issuer.next;
		while (name_cur != NULL)
		{
			name_prv = name_cur;
			name_cur = name_cur->next;
			ttls_bzero_safe(name_prv, sizeof(ttls_x509_name));
			kfree(name_prv);
		}

		entry_cur = crl_cur->entry.next;
		while (entry_cur != NULL)
		{
			entry_prv = entry_cur;
			entry_cur = entry_cur->next;
			ttls_bzero_safe(entry_prv, sizeof(ttls_x509_crl_entry));
			kfree(entry_prv);
		}

		if (crl_cur->raw.p != NULL)
		{
			ttls_bzero_safe(crl_cur->raw.p, crl_cur->raw.len);
			kfree(crl_cur->raw.p);
		}

		crl_cur = crl_cur->next;
	}
	while (crl_cur != NULL);

	crl_cur = crl;
	do
	{
		crl_prv = crl_cur;
		crl_cur = crl_cur->next;

		ttls_bzero_safe(crl_prv, sizeof(ttls_x509_crl));
		if (crl_prv != crl)
			kfree(crl_prv);
	}
	while (crl_cur != NULL);
}
