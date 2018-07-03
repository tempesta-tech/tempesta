/*
 *  Public Key layer for writing key files and structures
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
#include "config.h"

#if defined(TTLS_PK_WRITE_C)

#include "pk.h"
#include "asn1write.h"
#include "oid.h"
#include "rsa.h"
#include "ecp.h"
#if defined(TTLS_ECDSA_C)
#include "ecdsa.h"
#endif
#if defined(TTLS_PEM_WRITE_C)
#include "pem.h"
#endif

/*
 *  RSAPublicKey ::= SEQUENCE {
 *	  modulus		   INTEGER,  -- n
 *	  publicExponent	INTEGER   -- e
 *  }
 */
static int pk_write_rsa_pubkey(unsigned char **p, unsigned char *start,
		ttls_rsa_context *rsa)
{
	int ret;
	size_t len = 0;
	ttls_mpi T;

	ttls_mpi_init(&T);

	/* Export E */
	if ((ret = ttls_rsa_export(rsa, NULL, NULL, NULL, NULL, &T)) != 0 ||
		 (ret = ttls_asn1_write_mpi(p, start, &T)) < 0)
		goto end_of_export;
	len += ret;

	/* Export N */
	if ((ret = ttls_rsa_export(rsa, &T, NULL, NULL, NULL, NULL)) != 0 ||
		 (ret = ttls_asn1_write_mpi(p, start, &T)) < 0)
		goto end_of_export;
	len += ret;

end_of_export:

	ttls_mpi_free(&T);
	if (ret < 0)
		return ret;

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(p, start, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(p, start, TTLS_ASN1_CONSTRUCTED |
			 TTLS_ASN1_SEQUENCE));

	return((int) len);
}

/*
 * EC public key is an EC point
 */
static int pk_write_ec_pubkey(unsigned char **p, unsigned char *start,
				   ttls_ecp_keypair *ec)
{
	int ret;
	size_t len = 0;
	unsigned char buf[TTLS_ECP_MAX_PT_LEN];

	if ((ret = ttls_ecp_point_write_binary(&ec->grp, &ec->Q,
				TTLS_ECP_PF_UNCOMPRESSED,
				&len, buf, sizeof(buf))) != 0)
	{
		return ret;
	}

	if (*p < start || (size_t)(*p - start) < len)
		return(TTLS_ERR_ASN1_BUF_TOO_SMALL);

	*p -= len;
	memcpy(*p, buf, len);

	return((int) len);
}

/*
 * ECParameters ::= CHOICE {
 *   namedCurve		 OBJECT IDENTIFIER
 * }
 */
static int pk_write_ec_param(unsigned char **p, unsigned char *start,
				  ttls_ecp_keypair *ec)
{
	int ret;
	size_t len = 0;
	const char *oid;
	size_t oid_len;

	if ((ret = ttls_oid_get_oid_by_ec_grp(ec->grp.id, &oid, &oid_len)) != 0)
		return ret;

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_oid(p, start, oid, oid_len));

	return((int) len);
}

int ttls_pk_write_pubkey(unsigned char **p, unsigned char *start,
				 const ttls_pk_context *key)
{
	int ret;
	size_t len = 0;

	if (ttls_pk_get_type(key) == TTLS_PK_RSA)
		TTLS_ASN1_CHK_ADD(len, pk_write_rsa_pubkey(p, start, ttls_pk_rsa(*key)));
	else
	if (ttls_pk_get_type(key) == TTLS_PK_ECKEY)
		TTLS_ASN1_CHK_ADD(len, pk_write_ec_pubkey(p, start, ttls_pk_ec(*key)));
	else
		return(TTLS_ERR_PK_FEATURE_UNAVAILABLE);

	return((int) len);
}

int ttls_pk_write_pubkey_der(ttls_pk_context *key, unsigned char *buf, size_t size)
{
	int ret;
	unsigned char *c;
	size_t len = 0, par_len = 0, oid_len;
	const char *oid;

	c = buf + size;

	TTLS_ASN1_CHK_ADD(len, ttls_pk_write_pubkey(&c, buf, key));

	if (c - buf < 1)
		return(TTLS_ERR_ASN1_BUF_TOO_SMALL);

	/*
	 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
	 *	   algorithm			AlgorithmIdentifier,
	 *	   subjectPublicKey	 BIT STRING }
	 */
	*--c = 0;
	len += 1;

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, buf, TTLS_ASN1_BIT_STRING));

	if ((ret = ttls_oid_get_oid_by_pk_alg(ttls_pk_get_type(key),
			   &oid, &oid_len)) != 0)
	{
		return ret;
	}

	if (ttls_pk_get_type(key) == TTLS_PK_ECKEY)
	{
		TTLS_ASN1_CHK_ADD(par_len, pk_write_ec_param(&c, buf, ttls_pk_ec(*key)));
	}

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_algorithm_identifier(&c, buf, oid, oid_len,
					par_len));

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, buf, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, buf, TTLS_ASN1_CONSTRUCTED |
			TTLS_ASN1_SEQUENCE));

	return((int) len);
}

int ttls_pk_write_key_der(ttls_pk_context *key, unsigned char *buf, size_t size)
{
	int ret;
	unsigned char *c = buf + size;
	size_t len = 0;

	if (ttls_pk_get_type(key) == TTLS_PK_RSA)
	{
		ttls_mpi T; /* Temporary holding the exported parameters */
		ttls_rsa_context *rsa = ttls_pk_rsa(*key);

		/*
		 * Export the parameters one after another to avoid simultaneous copies.
		 */

		ttls_mpi_init(&T);

		/* Export QP */
		if ((ret = ttls_rsa_export_crt(rsa, NULL, NULL, &T)) != 0 ||
			(ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export DQ */
		if ((ret = ttls_rsa_export_crt(rsa, NULL, &T, NULL)) != 0 ||
			(ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export DP */
		if ((ret = ttls_rsa_export_crt(rsa, &T, NULL, NULL)) != 0 ||
			(ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export Q */
		if ((ret = ttls_rsa_export(rsa, NULL, NULL,
				 &T, NULL, NULL)) != 0 ||
			 (ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export P */
		if ((ret = ttls_rsa_export(rsa, NULL, &T,
				 NULL, NULL, NULL)) != 0 ||
			 (ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export D */
		if ((ret = ttls_rsa_export(rsa, NULL, NULL,
				 NULL, &T, NULL)) != 0 ||
			 (ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export E */
		if ((ret = ttls_rsa_export(rsa, NULL, NULL,
				 NULL, NULL, &T)) != 0 ||
			 (ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

		/* Export N */
		if ((ret = ttls_rsa_export(rsa, &T, NULL,
				 NULL, NULL, NULL)) != 0 ||
			 (ret = ttls_asn1_write_mpi(&c, buf, &T)) < 0)
			goto end_of_export;
		len += ret;

	end_of_export:

		ttls_mpi_free(&T);
		if (ret < 0)
			return ret;

		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_int(&c, buf, 0));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c,
		   buf, TTLS_ASN1_CONSTRUCTED |
		   TTLS_ASN1_SEQUENCE));
	}
	else
	if (ttls_pk_get_type(key) == TTLS_PK_ECKEY)
	{
		ttls_ecp_keypair *ec = ttls_pk_ec(*key);
		size_t pub_len = 0, par_len = 0;

		/*
		 * RFC 5915, or SEC1 Appendix C.4
		 *
		 * ECPrivateKey ::= SEQUENCE {
		 *	  version		INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
		 *	  privateKey	 OCTET STRING,
		 *	  parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
		 *	  publicKey  [1] BIT STRING OPTIONAL
		 *	}
		 */

		/* publicKey */
		TTLS_ASN1_CHK_ADD(pub_len, pk_write_ec_pubkey(&c, buf, ec));

		if (c - buf < 1)
			return(TTLS_ERR_ASN1_BUF_TOO_SMALL);
		*--c = 0;
		pub_len += 1;

		TTLS_ASN1_CHK_ADD(pub_len, ttls_asn1_write_len(&c, buf, pub_len));
		TTLS_ASN1_CHK_ADD(pub_len, ttls_asn1_write_tag(&c, buf, TTLS_ASN1_BIT_STRING));

		TTLS_ASN1_CHK_ADD(pub_len, ttls_asn1_write_len(&c, buf, pub_len));
		TTLS_ASN1_CHK_ADD(pub_len, ttls_asn1_write_tag(&c, buf,
				TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | 1));
		len += pub_len;

		/* parameters */
		TTLS_ASN1_CHK_ADD(par_len, pk_write_ec_param(&c, buf, ec));

		TTLS_ASN1_CHK_ADD(par_len, ttls_asn1_write_len(&c, buf, par_len));
		TTLS_ASN1_CHK_ADD(par_len, ttls_asn1_write_tag(&c, buf,
				TTLS_ASN1_CONTEXT_SPECIFIC | TTLS_ASN1_CONSTRUCTED | 0));
		len += par_len;

		/* privateKey: write as MPI then fix tag */
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_mpi(&c, buf, &ec->d));
		*c = TTLS_ASN1_OCTET_STRING;

		/* version */
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_int(&c, buf, 1));

		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(&c, buf, len));
		TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(&c, buf, TTLS_ASN1_CONSTRUCTED |
				TTLS_ASN1_SEQUENCE));
	}
	else
		return(TTLS_ERR_PK_FEATURE_UNAVAILABLE);

	return((int) len);
}

#if defined(TTLS_PEM_WRITE_C)

#define PEM_BEGIN_PUBLIC_KEY	"-----BEGIN PUBLIC KEY-----\n"
#define PEM_END_PUBLIC_KEY	  "-----END PUBLIC KEY-----\n"

#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA	 "-----END RSA PRIVATE KEY-----\n"
#define PEM_BEGIN_PRIVATE_KEY_EC	"-----BEGIN EC PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_EC	  "-----END EC PRIVATE KEY-----\n"

/*
 * Max sizes of key per types. Shown as tag + len (+ content).
 */

/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {		  1 + 3
 *	   algorithm			AlgorithmIdentifier,  1 + 1 (sequence)
 *			+ 1 + 1 + 9 (rsa oid)
 *			+ 1 + 1 (params null)
 *	   subjectPublicKey	 BIT STRING }		  1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {		 1 + 3
 *	  modulus		   INTEGER,  -- n			1 + 3 + MPI_MAX + 1
 *	  publicExponent	INTEGER   -- e			1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_PUB_DER_MAX_BYTES   38 + 2 * TTLS_MPI_MAX_SIZE

/*
 * RSA private keys:
 *  RSAPrivateKey ::= SEQUENCE {		1 + 3
 *	  version		   Version,				  1 + 1 + 1
 *	  modulus		   INTEGER,				  1 + 3 + MPI_MAX + 1
 *	  publicExponent	INTEGER,				  1 + 3 + MPI_MAX + 1
 *	  privateExponent   INTEGER,				  1 + 3 + MPI_MAX + 1
 *	  prime1			INTEGER,				  1 + 3 + MPI_MAX / 2 + 1
 *	  prime2			INTEGER,				  1 + 3 + MPI_MAX / 2 + 1
 *	  exponent1		 INTEGER,				  1 + 3 + MPI_MAX / 2 + 1
 *	  exponent2		 INTEGER,				  1 + 3 + MPI_MAX / 2 + 1
 *	  coefficient	   INTEGER,				  1 + 3 + MPI_MAX / 2 + 1
 *	  otherPrimeInfos   OtherPrimeInfos OPTIONAL  0 (not supported)
 *  }
 */
#define MPI_MAX_SIZE_2		  TTLS_MPI_MAX_SIZE / 2 + \
		TTLS_MPI_MAX_SIZE % 2
#define RSA_PRV_DER_MAX_BYTES   47 + 3 * TTLS_MPI_MAX_SIZE \
		   + 5 * MPI_MAX_SIZE_2

/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {	  1 + 2
 *	algorithm		 AlgorithmIdentifier,	1 + 1 (sequence)
 *		+ 1 + 1 + 7 (ec oid)
 *		+ 1 + 1 + 9 (namedCurve oid)
 *	subjectPublicKey  BIT STRING			  1 + 2 + 1			   [1]
 *		+ 1 (point format)		[1]
 *		+ 2 * ECP_MAX (coords)	[1]
 *  }
 */
#define ECP_PUB_DER_MAX_BYTES   30 + 2 * TTLS_ECP_MAX_BYTES

/*
 * EC private keys:
 * ECPrivateKey ::= SEQUENCE {				  1 + 2
 *	  version		INTEGER ,				1 + 1 + 1
 *	  privateKey	 OCTET STRING,			1 + 1 + ECP_MAX
 *	  parameters [0] ECParameters OPTIONAL,   1 + 1 + (1 + 1 + 9)
 *	  publicKey  [1] BIT STRING OPTIONAL	  1 + 2 + [1] above
 *	}
 */
#define ECP_PRV_DER_MAX_BYTES   29 + 3 * TTLS_ECP_MAX_BYTES

#define PUB_DER_MAX_BYTES   RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
				RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES
#define PRV_DER_MAX_BYTES   RSA_PRV_DER_MAX_BYTES > ECP_PRV_DER_MAX_BYTES ? \
				RSA_PRV_DER_MAX_BYTES : ECP_PRV_DER_MAX_BYTES

int ttls_pk_write_pubkey_pem(ttls_pk_context *key, unsigned char *buf, size_t size)
{
	int ret;
	unsigned char output_buf[PUB_DER_MAX_BYTES];
	size_t olen = 0;

	if ((ret = ttls_pk_write_pubkey_der(key, output_buf,
			 sizeof(output_buf))) < 0)
	{
		return ret;
	}

	if ((ret = ttls_pem_write_buffer(PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
		  output_buf + sizeof(output_buf) - ret,
		  ret, buf, size, &olen)) != 0)
	{
		return ret;
	}

	return 0;
}

int ttls_pk_write_key_pem(ttls_pk_context *key, unsigned char *buf, size_t size)
{
	int ret;
	unsigned char output_buf[PRV_DER_MAX_BYTES];
	const char *begin, *end;
	size_t olen = 0;

	if ((ret = ttls_pk_write_key_der(key, output_buf, sizeof(output_buf))) < 0)
		return ret;

	if (ttls_pk_get_type(key) == TTLS_PK_RSA)
	{
		begin = PEM_BEGIN_PRIVATE_KEY_RSA;
		end = PEM_END_PRIVATE_KEY_RSA;
	}
	else
	if (ttls_pk_get_type(key) == TTLS_PK_ECKEY)
	{
		begin = PEM_BEGIN_PRIVATE_KEY_EC;
		end = PEM_END_PRIVATE_KEY_EC;
	}
	else
		return(TTLS_ERR_PK_FEATURE_UNAVAILABLE);

	if ((ret = ttls_pem_write_buffer(begin, end,
		  output_buf + sizeof(output_buf) - ret,
		  ret, buf, size, &olen)) != 0)
	{
		return ret;
	}

	return 0;
}
#endif /* TTLS_PEM_WRITE_C */

#endif /* TTLS_PK_WRITE_C */
