/*
 *  Public Key abstraction layer: wrapper functions
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
#include "pk_internal.h"
/* Even if RSA not activated, for the sake of RSA-alt */
#include "rsa.h"
#include "ecp.h"

#if defined(TTLS_ECDSA_C)
#include "ecdsa.h"
#endif

#if defined(TTLS_PK_RSA_ALT_SUPPORT)
/* Implementation that should never be optimized out by the compiler */
static void ttls_zeroize(void *v, size_t n) {
	volatile unsigned char *p = v; while (n--) *p++ = 0;
}
#endif

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

	if ((ret = ttls_rsa_pkcs1_verify(rsa, NULL, NULL,
								  TTLS_RSA_PUBLIC, md_alg,
								  (unsigned int) hash_len, hash, sig)) != 0)
		return ret;

	if (sig_len > rsa_len)
		return(TTLS_ERR_PK_SIG_LEN_MISMATCH);

	return 0;
}

static int rsa_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len,
				   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;

	if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	*sig_len = ttls_rsa_get_len(rsa);

	return(ttls_rsa_pkcs1_sign(rsa, f_rng, p_rng, TTLS_RSA_PRIVATE,
				md_alg, (unsigned int) hash_len, hash, sig));
}

static int rsa_decrypt_wrap(void *ctx,
					const unsigned char *input, size_t ilen,
					unsigned char *output, size_t *olen, size_t osize,
					int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;

	if (ilen != ttls_rsa_get_len(rsa))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	return(ttls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
				TTLS_RSA_PRIVATE, olen, input, output, osize));
}

static int rsa_encrypt_wrap(void *ctx,
					const unsigned char *input, size_t ilen,
					unsigned char *output, size_t *olen, size_t osize,
					int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	ttls_rsa_context * rsa = (ttls_rsa_context *) ctx;
	*olen = ttls_rsa_get_len(rsa);

	if (*olen > osize)
		return(TTLS_ERR_RSA_OUTPUT_TOO_LARGE);

	return(ttls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng, TTLS_RSA_PUBLIC,
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

#if defined(TTLS_ECDSA_C)
/* Forward declarations */
static int ecdsa_verify_wrap(void *ctx, ttls_md_type_t md_alg,
					   const unsigned char *hash, size_t hash_len,
					   const unsigned char *sig, size_t sig_len);

static int ecdsa_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len,
				   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

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
				   unsigned char *sig, size_t *sig_len,
				   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	int ret;
	ttls_ecdsa_context ecdsa;

	ttls_ecdsa_init(&ecdsa);

	if ((ret = ttls_ecdsa_from_keypair(&ecdsa, ctx)) == 0)
		ret = ecdsa_sign_wrap(&ecdsa, md_alg, hash, hash_len, sig, sig_len,
							   f_rng, p_rng);

	ttls_ecdsa_free(&ecdsa);

	return ret;
}

#endif /* TTLS_ECDSA_C */

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
#if defined(TTLS_ECDSA_C)
	eckey_verify_wrap,
	eckey_sign_wrap,
#else
	NULL,
	NULL,
#endif
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

#if defined(TTLS_ECDSA_C)
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

static int ecdsa_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len,
				   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	return(ttls_ecdsa_write_signature((ttls_ecdsa_context *) ctx,
				md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng));
}

static void *ecdsa_alloc_wrap(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_ecdsa_context));

	if (ctx != NULL)
		ttls_ecdsa_init((ttls_ecdsa_context *) ctx);

	return(ctx);
}

static void ecdsa_free_wrap(void *ctx)
{
	ttls_ecdsa_free((ttls_ecdsa_context *) ctx);
	ttls_free(ctx);
}

const ttls_pk_info_t ttls_ecdsa_info = {
	TTLS_PK_ECDSA,
	"ECDSA",
	eckey_get_bitlen,	 /* Compatible key structures */
	ecdsa_can_do,
	ecdsa_verify_wrap,
	ecdsa_sign_wrap,
	NULL,
	NULL,
	eckey_check_pair,   /* Compatible key structures */
	ecdsa_alloc_wrap,
	ecdsa_free_wrap,
	eckey_debug,		/* Compatible key structures */
};
#endif /* TTLS_ECDSA_C */

#if defined(TTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do(ttls_pk_type_t type)
{
	return(type == TTLS_PK_RSA);
}

static size_t rsa_alt_get_bitlen(const void *ctx)
{
	const ttls_rsa_alt_context *rsa_alt = (const ttls_rsa_alt_context *) ctx;

	return(8 * rsa_alt->key_len_func(rsa_alt->key));
}

static int rsa_alt_sign_wrap(void *ctx, ttls_md_type_t md_alg,
				   const unsigned char *hash, size_t hash_len,
				   unsigned char *sig, size_t *sig_len,
				   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	ttls_rsa_alt_context *rsa_alt = (ttls_rsa_alt_context *) ctx;

	if (UINT_MAX < hash_len)
		return(TTLS_ERR_PK_BAD_INPUT_DATA);

	*sig_len = rsa_alt->key_len_func(rsa_alt->key);

	return(rsa_alt->sign_func(rsa_alt->key, f_rng, p_rng, TTLS_RSA_PRIVATE,
				md_alg, (unsigned int) hash_len, hash, sig));
}

static int rsa_alt_decrypt_wrap(void *ctx,
					const unsigned char *input, size_t ilen,
					unsigned char *output, size_t *olen, size_t osize,
					int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
	ttls_rsa_alt_context *rsa_alt = (ttls_rsa_alt_context *) ctx;

	((void) f_rng);
	((void) p_rng);

	if (ilen != rsa_alt->key_len_func(rsa_alt->key))
		return(TTLS_ERR_RSA_BAD_INPUT_DATA);

	return(rsa_alt->decrypt_func(rsa_alt->key,
				TTLS_RSA_PRIVATE, olen, input, output, osize));
}

static int rsa_alt_check_pair(const void *pub, const void *prv)
{
	unsigned char sig[TTLS_MPI_MAX_SIZE];
	unsigned char hash[32];
	size_t sig_len = 0;
	int ret;

	if (rsa_alt_get_bitlen(prv) != rsa_get_bitlen(pub))
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);

	memset(hash, 0x2a, sizeof(hash));

	if ((ret = rsa_alt_sign_wrap((void *) prv, TTLS_MD_NONE,
								   hash, sizeof(hash),
								   sig, &sig_len, NULL, NULL)) != 0)
	{
		return ret;
	}

	if (rsa_verify_wrap((void *) pub, TTLS_MD_NONE,
						 hash, sizeof(hash), sig, sig_len) != 0)
	{
		return(TTLS_ERR_RSA_KEY_CHECK_FAILED);
	}

	return 0;
}

static void *rsa_alt_alloc_wrap(void)
{
	void *ctx = ttls_calloc(1, sizeof(ttls_rsa_alt_context));

	if (ctx != NULL)
		memset(ctx, 0, sizeof(ttls_rsa_alt_context));

	return(ctx);
}

static void rsa_alt_free_wrap(void *ctx)
{
	ttls_zeroize(ctx, sizeof(ttls_rsa_alt_context));
	ttls_free(ctx);
}

const ttls_pk_info_t ttls_rsa_alt_info = {
	TTLS_PK_RSA_ALT,
	"RSA-alt",
	rsa_alt_get_bitlen,
	rsa_alt_can_do,
	NULL,
	rsa_alt_sign_wrap,
	rsa_alt_decrypt_wrap,
	NULL,
	rsa_alt_check_pair,
	rsa_alt_alloc_wrap,
	rsa_alt_free_wrap,
	NULL,
};

#endif /* TTLS_PK_RSA_ALT_SUPPORT */
