/*
 *  X.509 Certificate Signing Request writing
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
 * References:
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */
#include "config.h"

#if defined(TTLS_X509_CSR_WRITE_C)

#include "x509_csr.h"
#include "oid.h"
#include "asn1write.h"
#if defined(TTLS_PEM_WRITE_C)
#include "pem.h"
#endif

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

void ttls_x509write_csr_init(ttls_x509write_csr *ctx)
{
	memset(ctx, 0, sizeof(ttls_x509write_csr));
}

void ttls_x509write_csr_free(ttls_x509write_csr *ctx)
{
	ttls_asn1_free_named_data_list(&ctx->subject);
	ttls_asn1_free_named_data_list(&ctx->extensions);

	ttls_zeroize(ctx, sizeof(ttls_x509write_csr));
}

void ttls_x509write_csr_set_md_alg(ttls_x509write_csr *ctx, ttls_md_type_t md_alg)
{
	ctx->md_alg = md_alg;
}

void ttls_x509write_csr_set_key(ttls_x509write_csr *ctx, ttls_pk_context *key)
{
	ctx->key = key;
}

int ttls_x509write_csr_set_subject_name(ttls_x509write_csr *ctx,
									const char *subject_name)
{
	return ttls_x509_string_to_names(&ctx->subject, subject_name);
}

int ttls_x509write_csr_set_extension(ttls_x509write_csr *ctx,
								 const char *oid, size_t oid_len,
								 const unsigned char *val, size_t val_len)
{
	return ttls_x509_set_extension(&ctx->extensions, oid, oid_len,
							   0, val, val_len);
}

int ttls_x509write_csr_set_key_usage(ttls_x509write_csr *ctx, unsigned char key_usage)
{
	unsigned char buf[4];
	unsigned char *c;
	int ret;

	c = buf + 4;

	if ((ret = ttls_asn1_write_bitstring(&c, buf, &key_usage, 7)) != 4)
		return ret;

	ret = ttls_x509write_csr_set_extension(ctx, TTLS_OID_KEY_USAGE,
									   TTLS_OID_SIZE(TTLS_OID_KEY_USAGE),
									   buf, 4);
	if (ret != 0)
		return ret;

	return 0;
}

int ttls_x509write_csr_set_ns_cert_type(ttls_x509write_csr *ctx,
									unsigned char ns_cert_type)
{
	unsigned char buf[4];
	unsigned char *c;
	int ret;

	c = buf + 4;

	if ((ret = ttls_asn1_write_bitstring(&c, buf, &ns_cert_type, 8)) != 4)
		return ret;

	ret = ttls_x509write_csr_set_extension(ctx, TTLS_OID_NS_CERT_TYPE,
									   TTLS_OID_SIZE(TTLS_OID_NS_CERT_TYPE),
									   buf, 4);
	if (ret != 0)
		return ret;

	return 0;
}

int ttls_x509write_csr_der(ttls_x509write_csr *ctx, unsigned char *buf, size_t size,
					   int (*f_rng)(void *, unsigned char *, size_t),
					   void *p_rng)
{
	int ret;
	const char *sig_oid;
	size_t sig_oid_len = 0;
	unsigned char *c, *c2;
	unsigned char hash[64];
	unsigned char sig[TTLS_MPI_MAX_SIZE];
	unsigned char tmp_buf[2048];
	size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
	size_t len = 0;
	ttls_pk_type_t pk_alg;

	/*
	 * Prepare data to be signed in tmp_buf
	 */
	c = tmp_buf + sizeof(tmp_buf);

	TTLS_ASN1_CHK_ADD(len, ttls_x509_write_extensions(&c, tmp_buf, ctx->extensions));

	if (len)
	{
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
														TTLS_ASN1_SEQUENCE));

		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
														TTLS_ASN1_SET));

		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_oid(&c, tmp_buf, TTLS_OID_PKCS9_CSR_EXT_REQ,
										  TTLS_OID_SIZE(TTLS_OID_PKCS9_CSR_EXT_REQ)));

		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
														TTLS_ASN1_SEQUENCE));
	}

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
													TTLS_ASN1_CONTEXT_SPECIFIC));

	TTLS_ASN1_CHK_ADD(pub_len, ttls_pk_write_pubkey_der(ctx->key,
												tmp_buf, c - tmp_buf));
	c -= pub_len;
	len += pub_len;

	/*
	 *  Subject  ::=  Name
	 */
	TTLS_ASN1_CHK_ADD(len, ttls_x509_write_names(&c, tmp_buf, ctx->subject));

	/*
	 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_int(&c, tmp_buf, 0));

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
													TTLS_ASN1_SEQUENCE));

	/*
	 * Prepare signature
	 */
	ttls_md(ttls_md_info_from_type(ctx->md_alg), c, len, hash);

	if ((ret = ttls_pk_sign(ctx->key, ctx->md_alg, hash, 0, sig, &sig_len,
								 f_rng, p_rng)) != 0)
	{
		return ret;
	}

	if (ttls_pk_can_do(ctx->key, TTLS_PK_RSA))
		pk_alg = TTLS_PK_RSA;
	else if (ttls_pk_can_do(ctx->key, TTLS_PK_ECDSA))
		pk_alg = TTLS_PK_ECDSA;
	else
		return(TTLS_ERR_X509_INVALID_ALG);

	if ((ret = ttls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
												&sig_oid, &sig_oid_len)) != 0)
	{
		return ret;
	}

	/*
	 * Write data to output buffer
	 */
	c2 = buf + size;
	TTLS_ASN1_CHK_ADD(sig_and_oid_len, ttls_x509_write_sig(&c2, buf,
										sig_oid, sig_oid_len, sig, sig_len));

	if (len > (size_t)(c2 - buf))
		return(TTLS_ERR_ASN1_BUF_TOO_SMALL);

	c2 -= len;
	memcpy(c2, c, len);

	len += sig_and_oid_len;
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c2, buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c2, buf, TTLS_ASN1_CONSTRUCTED |
												 TTLS_ASN1_SEQUENCE));

	return((int) len);
}

#define PEM_BEGIN_CSR		   "-----BEGIN CERTIFICATE REQUEST-----\n"
#define PEM_END_CSR			 "-----END CERTIFICATE REQUEST-----\n"

#if defined(TTLS_PEM_WRITE_C)
int ttls_x509write_csr_pem(ttls_x509write_csr *ctx, unsigned char *buf, size_t size,
					   int (*f_rng)(void *, unsigned char *, size_t),
					   void *p_rng)
{
	int ret;
	unsigned char output_buf[4096];
	size_t olen = 0;

	if ((ret = ttls_x509write_csr_der(ctx, output_buf, sizeof(output_buf),
								   f_rng, p_rng)) < 0)
	{
		return ret;
	}

	if ((ret = ttls_pem_write_buffer(PEM_BEGIN_CSR, PEM_END_CSR,
								  output_buf + sizeof(output_buf) - ret,
								  ret, buf, size, &olen)) != 0)
	{
		return ret;
	}

	return 0;
}
#endif /* TTLS_PEM_WRITE_C */

#endif /* TTLS_X509_CSR_WRITE_C */
