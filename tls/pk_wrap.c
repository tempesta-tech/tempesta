/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer: wrapper functions.
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
 */
#include "pk_internal.h"
#include "rsa.h"
#include "ecp.h"
#include "ecdsa.h"

static int rsa_can_do(ttls_pk_type_t type)
{
	return(type == TTLS_PK_RSA ||
			type == TTLS_PK_RSASSA_PSS);
}

static size_t rsa_get_bitlen(const void *ctx)
{
	const ttls_rsa_context * rsa = (const ttls_rsa_context *) ctx;
	return(8 * ttls_rsa_get_len(rsa));
}

static int rsa_verify_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   const unsigned char *sig, size_t sig_len)
{
	int ret;
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;
	size_t rsa_len = ttls_rsa_get_len(rsa);

	if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	if (sig_len < rsa_len)
		return(TTLS_ERR_RSA_VERIFY_FAILED);

	if ((ret = ttls_rsa_pkcs1_verify(rsa, TTLS_RSA_PUBLIC, md_alg,
		  (unsigned int) hash_len, hash, sig)) != 0)
		return ret;

	if (sig_len > rsa_len)
		return(TTLS_ERR_PK_SIG_LEN_MISMATCH);

	return 0;
}

static int rsa_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len)
{
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;

	if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	*sig_len = ttls_rsa_get_len(rsa);

	return(ttls_rsa_pkcs1_sign(rsa, TTLS_RSA_PRIVATE,
				md_alg, (unsigned int) hash_len, hash, sig));
}

static int rsa_decrypt_wrap(void *ctx,
		const unsigned char *input, size_t ilen,
		unsigned char *output, size_t *olen, size_t osize)
{
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;

	if (ilen != ttls_rsa_get_len(rsa))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	return(ttls_rsa_pkcs1_decrypt(rsa,
				TTLS_RSA_PRIVATE, olen, input, output, osize));
}

static int rsa_encrypt_wrap(void *ctx,
		const unsigned char *input, size_t ilen,
		unsigned char *output, size_t *olen, size_t osize)
{
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;
	*olen = ttls_rsa_get_len(rsa);

	if (*olen > osize)
		return(TTLS_ERR_RSA_OUTPUT_TOO_LARGE);

	return(ttls_rsa_pkcs1_encrypt(rsa, TTLS_RSA_PUBLIC,
			   ilen, input, output));
}

static int rsa_check_pair_wrap(const void *pub, const void *prv)
{
	return(ttls_rsa_check_pub_priv((const ttls_rsa_context *) pub,
		(const ttls_rsa_context *) prv));
}

static void *rsa_alloc_wrap(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_rsa_context));

	if (ctx != NULL)
		ttls_rsa_init((ttls_rsa_context *) ctx, 0, 0);

	return(ctx);
}

static void rsa_free_wrap(void *ctx)
{
	ttls_rsa_free((ttls_rsa_context *) ctx);
	ttls_free(ctx);
}

static void rsa_debug(const void *ctx, ttls_pk_debug_item *items)
{
	items->type = TTLS_PK_DEBUG_MPI;
	items->name = "rsa.N";
	items->value = &(((ttls_rsa_context *) ctx)->N);

	items++;

	items->type = TTLS_PK_DEBUG_MPI;
	items->name = "rsa.E";
	items->value = &(((ttls_rsa_context *) ctx)->E);
}

const ttls_pk_info_t ttls_rsa_info = {
	TTLS_PK_RSA,
	"RSA",
	rsa_get_bitlen,
	rsa_can_do,
	rsa_verify_wrap,
	rsa_sign_wrap,
	rsa_decrypt_wrap,
	rsa_encrypt_wrap,
	rsa_check_pair_wrap,
	rsa_alloc_wrap,
	rsa_free_wrap,
	rsa_debug,
};

/*
 * Generic EC key
 */
static int eckey_can_do(ttls_pk_type_t type)
{
	return(type == TTLS_PK_ECKEY ||
			type == TTLS_PK_ECKEY_DH ||
			type == TTLS_PK_ECDSA);
}

static size_t eckey_get_bitlen(const void *ctx)
{
	return(((ttls_ecp_keypair *) ctx)->grp.pbits);
}

/* Forward declarations */
static int ecdsa_verify_wrap(void *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash, size_t hash_len,
		   const unsigned char *sig, size_t sig_len);

static int ecdsa_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len);

static int eckey_verify_wrap(void *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash, size_t hash_len,
		   const unsigned char *sig, size_t sig_len)
{
	int ret;
	ttls_ecdsa_context ecdsa;

	ttls_ecdsa_init(&ecdsa);

	if ((ret = ttls_ecdsa_from_keypair(&ecdsa, ctx)) == 0)
		ret = ecdsa_verify_wrap(&ecdsa, md_alg, hash, hash_len, sig, sig_len);

	ttls_ecdsa_free(&ecdsa);

	return ret;
}

static int eckey_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len)
{
	int ret;
	ttls_ecdsa_context ecdsa;

	ttls_ecdsa_init(&ecdsa);

	if ((ret = ttls_ecdsa_from_keypair(&ecdsa, ctx)) == 0)
		ret = ecdsa_sign_wrap(&ecdsa, md_alg, hash, hash_len, sig, sig_len);

	ttls_ecdsa_free(&ecdsa);

	return ret;
}

static int eckey_check_pair(const void *pub, const void *prv)
{
	return(ttls_ecp_check_pub_priv((const ttls_ecp_keypair *) pub,
		(const ttls_ecp_keypair *) prv));
}

static void *eckey_alloc_wrap(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_ecp_keypair));

	if (ctx != NULL)
		ttls_ecp_keypair_init(ctx);

	return(ctx);
}

static void eckey_free_wrap(void *ctx)
{
	ttls_ecp_keypair_free((ttls_ecp_keypair *) ctx);
	ttls_free(ctx);
}

static void eckey_debug(const void *ctx, ttls_pk_debug_item *items)
{
	items->type = TTLS_PK_DEBUG_ECP;
	items->name = "eckey.Q";
	items->value = &(((ttls_ecp_keypair *) ctx)->Q);
}

const ttls_pk_info_t ttls_eckey_info = {
	TTLS_PK_ECKEY,
	"EC",
	eckey_get_bitlen,
	eckey_can_do,
	eckey_verify_wrap,
	eckey_sign_wrap,
	NULL,
	NULL,
	eckey_check_pair,
	eckey_alloc_wrap,
	eckey_free_wrap,
	eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do(ttls_pk_type_t type)
{
	return(type == TTLS_PK_ECKEY ||
			type == TTLS_PK_ECKEY_DH);
}

const ttls_pk_info_t ttls_eckeydh_info = {
	TTLS_PK_ECKEY_DH,
	"EC_DH",
	eckey_get_bitlen,		 /* Same underlying key structure */
	eckeydh_can_do,
	NULL,
	NULL,
	NULL,
	NULL,
	eckey_check_pair,
	eckey_alloc_wrap,	   /* Same underlying key structure */
	eckey_free_wrap,		/* Same underlying key structure */
	eckey_debug,			/* Same underlying key structure */
};

static int ecdsa_can_do(ttls_pk_type_t type)
{
	return(type == TTLS_PK_ECDSA);
}

static int ecdsa_verify_wrap(void *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash, size_t hash_len,
		   const unsigned char *sig, size_t sig_len)
{
	int ret;
	((void) md_alg);

	ret = ttls_ecdsa_read_signature((ttls_ecdsa_context *) ctx,
		hash, hash_len, sig, sig_len);

	if (ret == TTLS_ERR_ECP_SIG_LEN_MISMATCH)
		return(TTLS_ERR_PK_SIG_LEN_MISMATCH);

	return ret;
}

static int
ecdsa_sign_wrap(void *ctx, ttls_md_type_t md_alg,
		const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t *sig_len)
{
	return ttls_ecdsa_write_signature((ttls_ecdsa_context *)ctx,
					  hash, hash_len, sig, sig_len);
}

static void *
ecdsa_alloc_wrap(void)
{
	ttls_ecdsa_context *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx)
		ttls_ecdsa_init(ctx);

	return ctx;
}

static void
ecdsa_free_wrap(void *ctx)
{
	ttls_ecdsa_free((ttls_ecdsa_context *)ctx);
	kfree(ctx);
}

const ttls_pk_info_t ttls_ecdsa_info = {
	TTLS_PK_ECDSA,
	"ECDSA",
	eckey_get_bitlen,	/* Compatible key structures */
	ecdsa_can_do,
	ecdsa_verify_wrap,
	ecdsa_sign_wrap,
	NULL,
	NULL,
	eckey_check_pair,	/* Compatible key structures */
	ecdsa_alloc_wrap,
	ecdsa_free_wrap,
	eckey_debug,		/* Compatible key structures */
};
