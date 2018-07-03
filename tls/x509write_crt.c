/*
 *  X.509 certificate writing
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
 * - certificates: RFC 5280, updated by RFC 6818
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */
#include "config.h"

#if defined(TTLS_X509_CRT_WRITE_C)

#include "x509_crt.h"
#include "oid.h"
#include "asn1write.h"
#include "sha1.h"
#if defined(TTLS_PEM_WRITE_C)
#include "pem.h"
#endif /* TTLS_PEM_WRITE_C */

/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}

void ttls_x509write_crt_init(ttls_x509write_cert *ctx)
{
	memset(ctx, 0, sizeof(ttls_x509write_cert));

	ttls_mpi_init(&ctx->serial);
	ctx->version = TTLS_X509_CRT_VERSION_3;
}

void ttls_x509write_crt_free(ttls_x509write_cert *ctx)
{
	ttls_mpi_free(&ctx->serial);

	ttls_asn1_free_named_data_list(&ctx->subject);
	ttls_asn1_free_named_data_list(&ctx->issuer);
	ttls_asn1_free_named_data_list(&ctx->extensions);

	ttls_zeroize(ctx, sizeof(ttls_x509write_cert));
}

void ttls_x509write_crt_set_version(ttls_x509write_cert *ctx, int version)
{
	ctx->version = version;
}

void ttls_x509write_crt_set_md_alg(ttls_x509write_cert *ctx, ttls_md_type_t md_alg)
{
	ctx->md_alg = md_alg;
}

void ttls_x509write_crt_set_subject_key(ttls_x509write_cert *ctx, ttls_pk_context *key)
{
	ctx->subject_key = key;
}

void ttls_x509write_crt_set_issuer_key(ttls_x509write_cert *ctx, ttls_pk_context *key)
{
	ctx->issuer_key = key;
}

int ttls_x509write_crt_set_subject_name(ttls_x509write_cert *ctx,
			const char *subject_name)
{
	return ttls_x509_string_to_names(&ctx->subject, subject_name);
}

int ttls_x509write_crt_set_issuer_name(ttls_x509write_cert *ctx,
		   const char *issuer_name)
{
	return ttls_x509_string_to_names(&ctx->issuer, issuer_name);
}

int ttls_x509write_crt_set_serial(ttls_x509write_cert *ctx, const ttls_mpi *serial)
{
	int ret;

	if ((ret = ttls_mpi_copy(&ctx->serial, serial)) != 0)
		return ret;

	return 0;
}

int ttls_x509write_crt_set_validity(ttls_x509write_cert *ctx, const char *not_before,
		const char *not_after)
{
	if (strlen(not_before) != TTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
		strlen(not_after)  != TTLS_X509_RFC5280_UTC_TIME_LEN - 1)
	{
		return(TTLS_ERR_X509_BAD_INPUT_DATA);
	}
	strncpy(ctx->not_before, not_before, TTLS_X509_RFC5280_UTC_TIME_LEN);
	strncpy(ctx->not_after , not_after , TTLS_X509_RFC5280_UTC_TIME_LEN);
	ctx->not_before[TTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
	ctx->not_after[TTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

	return 0;
}

int ttls_x509write_crt_set_extension(ttls_x509write_cert *ctx,
		 const char *oid, size_t oid_len,
		 int critical,
		 const unsigned char *val, size_t val_len)
{
	return ttls_x509_set_extension(&ctx->extensions, oid, oid_len,
				   critical, val, val_len);
}

int ttls_x509write_crt_set_basic_constraints(ttls_x509write_cert *ctx,
				 int is_ca, int max_pathlen)
{
	int ret;
	unsigned char buf[9];
	unsigned char *c = buf + sizeof(buf);
	size_t len = 0;

	memset(buf, 0, sizeof(buf));

	if (is_ca && max_pathlen > 127)
		return(TTLS_ERR_X509_BAD_INPUT_DATA);

	if (is_ca)
	{
		if (max_pathlen >= 0)
		{
			TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_int(&c, buf, max_pathlen));
		}
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_bool(&c, buf, 1));
	}

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, buf, TTLS_ASN1_CONSTRUCTED |
			TTLS_ASN1_SEQUENCE));

	return ttls_x509write_crt_set_extension(ctx, TTLS_OID_BASIC_CONSTRAINTS,
				TTLS_OID_SIZE(TTLS_OID_BASIC_CONSTRAINTS),
				0, buf + sizeof(buf) - len, len);
}

int ttls_x509write_crt_set_key_usage(ttls_x509write_cert *ctx,
				 unsigned int key_usage)
{
	unsigned char buf[4], ku;
	unsigned char *c;
	int ret;

	/* We currently only support 7 bits, from 0x80 to 0x02 */
	if ((key_usage & ~0xfe) != 0)
		return(TTLS_ERR_X509_FEATURE_UNAVAILABLE);

	c = buf + 4;
	ku = (unsigned char) key_usage;

	if ((ret = ttls_asn1_write_bitstring(&c, buf, &ku, 7)) != 4)
		return ret;

	ret = ttls_x509write_crt_set_extension(ctx, TTLS_OID_KEY_USAGE,
			   TTLS_OID_SIZE(TTLS_OID_KEY_USAGE),
			   1, buf, 4);
	if (ret != 0)
		return ret;

	return 0;
}

int ttls_x509write_crt_set_ns_cert_type(ttls_x509write_cert *ctx,
			unsigned char ns_cert_type)
{
	unsigned char buf[4];
	unsigned char *c;
	int ret;

	c = buf + 4;

	if ((ret = ttls_asn1_write_bitstring(&c, buf, &ns_cert_type, 8)) != 4)
		return ret;

	ret = ttls_x509write_crt_set_extension(ctx, TTLS_OID_NS_CERT_TYPE,
			   TTLS_OID_SIZE(TTLS_OID_NS_CERT_TYPE),
			   0, buf, 4);
	if (ret != 0)
		return ret;

	return 0;
}

static int x509_write_time(unsigned char **p, unsigned char *start,
				const char *t, size_t size)
{
	int ret;
	size_t len = 0;

	/*
	 * write TTLS_ASN1_UTC_TIME if year < 2050 (2 bytes shorter)
	 */
	if (t[0] == '2' && t[1] == '0' && t[2] < '5')
	{
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_raw_buffer(p, start,
		 (const unsigned char *) t + 2,
		 size - 2));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(p, start, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(p, start, TTLS_ASN1_UTC_TIME));
	}
	else
	{
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_raw_buffer(p, start,
			  (const unsigned char *) t,
			  size));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(p, start, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(p, start, TTLS_ASN1_GENERALIZED_TIME));
	}

	return((int) len);
}

int ttls_x509write_crt_der(ttls_x509write_cert *ctx, unsigned char *buf, size_t size,
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
	size_t sub_len = 0, pub_len = 0, sig_and_oid_len = 0, sig_len;
	size_t len = 0;
	ttls_pk_type_t pk_alg;

	/*
	 * Prepare data to be signed in tmp_buf
	 */
	c = tmp_buf + sizeof(tmp_buf);

	/* Signature algorithm needed in TBS, and later for actual signature */

	/* There's no direct way of extracting a signature algorithm
	 * (represented as an element of ttls_pk_type_t) from a PK instance. */
	if (ttls_pk_can_do(ctx->issuer_key, TTLS_PK_RSA))
		pk_alg = TTLS_PK_RSA;
	else if (ttls_pk_can_do(ctx->issuer_key, TTLS_PK_ECDSA))
		pk_alg = TTLS_PK_ECDSA;
	else
		return(TTLS_ERR_X509_INVALID_ALG);

	if ((ret = ttls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
				  &sig_oid, &sig_oid_len)) != 0)
	{
		return ret;
	}

	/*
	 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	 */

	/* Only for v3 */
	if (ctx->version == TTLS_X509_CRT_VERSION_3)
	{
		TTLS_ASN1_CHK_ADD(len, ttls_x509_write_extensions(&c, tmp_buf, ctx->extensions));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
					   TTLS_ASN1_SEQUENCE));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONTEXT_SPECIFIC |
					   TTLS_ASN1_CONSTRUCTED | 3));
	}

	/*
	 *  SubjectPublicKeyInfo
	 */
	TTLS_ASN1_CHK_ADD(pub_len, ttls_pk_write_pubkey_der(ctx->subject_key,
			tmp_buf, c - tmp_buf));
	c -= pub_len;
	len += pub_len;

	/*
	 *  Subject  ::=  Name
	 */
	TTLS_ASN1_CHK_ADD(len, ttls_x509_write_names(&c, tmp_buf, ctx->subject));

	/*
	 *  Validity ::= SEQUENCE {
	 *	   notBefore	  Time,
	 *	   notAfter	   Time }
	 */
	sub_len = 0;

	TTLS_ASN1_CHK_ADD(sub_len, x509_write_time(&c, tmp_buf, ctx->not_after,
		TTLS_X509_RFC5280_UTC_TIME_LEN));

	TTLS_ASN1_CHK_ADD(sub_len, x509_write_time(&c, tmp_buf, ctx->not_before,
		TTLS_X509_RFC5280_UTC_TIME_LEN));

	len += sub_len;
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, sub_len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
				TTLS_ASN1_SEQUENCE));

	/*
	 *  Issuer  ::=  Name
	 */
	TTLS_ASN1_CHK_ADD(len, ttls_x509_write_names(&c, tmp_buf, ctx->issuer));

	/*
	 *  Signature   ::=  AlgorithmIdentifier
	 */
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_algorithm_identifier(&c, tmp_buf,
		   sig_oid, strlen(sig_oid), 0));

	/*
	 *  Serial   ::=  INTEGER
	 */
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_mpi(&c, tmp_buf, &ctx->serial));

	/*
	 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 */

	/* Can be omitted for v1 */
	if (ctx->version != TTLS_X509_CRT_VERSION_1)
	{
		sub_len = 0;
		TTLS_ASN1_CHK_ADD(sub_len, ttls_asn1_write_int(&c, tmp_buf, ctx->version));
		len += sub_len;
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, sub_len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONTEXT_SPECIFIC |
					   TTLS_ASN1_CONSTRUCTED | 0));
	}

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, tmp_buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, tmp_buf, TTLS_ASN1_CONSTRUCTED |
				   TTLS_ASN1_SEQUENCE));

	/*
	 * Make signature
	 */
	if ((ret = ttls_md(ttls_md_info_from_type(ctx->md_alg), c,
				len, hash)) != 0)
	{
		return ret;
	}

	if ((ret = ttls_pk_sign(ctx->issuer_key, ctx->md_alg, hash, 0, sig, &sig_len,
			 f_rng, p_rng)) != 0)
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

#define PEM_BEGIN_CRT		   "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT			 "-----END CERTIFICATE-----\n"

#if defined(TTLS_PEM_WRITE_C)
int ttls_x509write_crt_pem(ttls_x509write_cert *crt, unsigned char *buf, size_t size,
		   int (*f_rng)(void *, unsigned char *, size_t),
		   void *p_rng)
{
	int ret;
	unsigned char output_buf[4096];
	size_t olen = 0;

	if ((ret = ttls_x509write_crt_der(crt, output_buf, sizeof(output_buf),
		   f_rng, p_rng)) < 0)
	{
		return ret;
	}

	if ((ret = ttls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
		  output_buf + sizeof(output_buf) - ret,
		  ret, buf, size, &olen)) != 0)
	{
		return ret;
	}

	return 0;
}
#endif /* TTLS_PEM_WRITE_C */

#endif /* TTLS_X509_CRT_WRITE_C */
