/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer.
 *
 * Based on mbed TLS, https://tls.mbed.org.
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
#include "pk.h"
#include "rsa.h"
#include "tls_internal.h"
#include "ecp.h"
#include "ecdsa.h"

extern int ttls_ecdsa_write_signature(TlsEcpKeypair *ctx,
				      const unsigned char *hash, size_t hlen,
				      unsigned char *sig, size_t *slen);
extern int ttls_ecdsa_read_signature(TlsEcpKeypair *ctx,
				     const unsigned char *hash, size_t hlen,
				     const unsigned char *sig, size_t slen);

static int
rsa_can_do(ttls_pk_type_t type)
{
	return type == TTLS_PK_RSA || type == TTLS_PK_RSASSA_PSS;
}

static size_t
rsa_get_bitlen(const void *ctx)
{
	const TlsRSACtx * rsa = (const TlsRSACtx *)ctx;
	return 8 * ttls_rsa_get_len(rsa);
}

static int
rsa_verify_wrap(void *ctx, ttls_md_type_t md_alg, const unsigned char *hash,
		size_t hash_len, const unsigned char *sig, size_t sig_len)
{
	TlsRSACtx *rsa = (TlsRSACtx *)ctx;

	if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
		return TTLS_ERR_PK_BAD_INPUT_DATA;
	if (sig_len != ttls_rsa_get_len(rsa))
		return TTLS_ERR_PK_SIG_LEN_MISMATCH;

	return ttls_rsa_pkcs1_verify(rsa, md_alg, (unsigned int)hash_len, hash,
				     sig);
}

static int
rsa_sign_wrap(void *ctx, ttls_md_type_t md_alg, const unsigned char *hash,
	      size_t hash_len, unsigned char *sig, size_t *sig_len)
{
	TlsRSACtx * rsa = (TlsRSACtx *)ctx;

	if (WARN_ON_ONCE(md_alg == TTLS_MD_NONE || UINT_MAX < hash_len))
		return -EINVAL;

	*sig_len = ttls_rsa_get_len(rsa);

	return ttls_rsa_pkcs1_sign(rsa, md_alg, hash, sig);
}

static void *
rsa_alloc_wrap(void)
{
	TlsRSACtx *ctx;

	might_sleep();

	if ((ctx = ttls_mpi_pool_alloc(sizeof(*ctx), GFP_KERNEL)))
		ttls_rsa_init(ctx, 0, 0);

	return ctx;
}

static void
rsa_free_wrap(void *ctx)
{
	ttls_mpi_pool_free(ctx);
}

/*
 * EC key restricted to ECDH
 */
static int
eckeydh_can_do(ttls_pk_type_t type)
{
	return type == TTLS_PK_ECKEY || type == TTLS_PK_ECKEY_DH;
}

static int
ecdsa_can_do(ttls_pk_type_t type)
{
	return type == TTLS_PK_ECDSA;
}

static int
ecdsa_verify_wrap(void *ctx, ttls_md_type_t md_alg __attribute__((unused)),
		  const unsigned char *hash, size_t hash_len,
		  const unsigned char *sig, size_t sig_len)
{
	int r = ttls_ecdsa_read_signature((TlsEcpKeypair *)ctx, hash, hash_len,
					  sig, sig_len);
	if (r == TTLS_ERR_ECP_SIG_LEN_MISMATCH)
		return TTLS_ERR_PK_SIG_LEN_MISMATCH;
	return r;
}

static int
ecdsa_sign_wrap(void *ctx,
		ttls_md_type_t md_alg __attribute__((unused)),
		const unsigned char *hash, size_t hash_len,
		unsigned char *sig, size_t *sig_len)
{
	return ttls_ecdsa_write_signature((TlsEcpKeypair *)ctx,
					  hash, hash_len, sig, sig_len);
}

/*
 * Generic EC key
 */
static int
eckey_can_do(ttls_pk_type_t type)
{
	return type == TTLS_PK_ECKEY || type == TTLS_PK_ECKEY_DH ||
	       type == TTLS_PK_ECDSA;
}

static size_t
eckey_get_bitlen(const void *ctx)
{
	return ((TlsEcpKeypair *)ctx)->grp.pbits;
}

static void *
eckey_alloc_wrap(void)
{
	TlsEcpKeypair *ctx;

	might_sleep();

	if ((ctx = ttls_mpi_pool_alloc(sizeof(*ctx), GFP_KERNEL)))
		ttls_ecp_keypair_init(ctx);

	return ctx;
}

static void
eckey_free_wrap(void *ctx)
{
	ttls_mpi_pool_free(ctx);
}

const TlsPkInfo ttls_rsa_info = {
	TTLS_PK_RSA,
	"RSA",
	rsa_get_bitlen,
	rsa_can_do,
	rsa_verify_wrap,
	rsa_sign_wrap,
	rsa_alloc_wrap,
	rsa_free_wrap,
};

const TlsPkInfo ttls_eckeydh_info = {
	TTLS_PK_ECKEY_DH,
	"EC_DH",
	eckey_get_bitlen,
	eckeydh_can_do,
	NULL,
	NULL,
	eckey_alloc_wrap,
	eckey_free_wrap,
};

const TlsPkInfo ttls_ecdsa_info = {
	TTLS_PK_ECDSA,
	"ECDSA",
	eckey_get_bitlen,
	ecdsa_can_do,
	ecdsa_verify_wrap,
	ecdsa_sign_wrap,
	eckey_alloc_wrap,
	eckey_free_wrap,
};

const TlsPkInfo ttls_eckey_info = {
	TTLS_PK_ECKEY,
	"EC",
	eckey_get_bitlen,
	eckey_can_do,
	ecdsa_verify_wrap,
	ecdsa_sign_wrap,
	eckey_alloc_wrap,
	eckey_free_wrap,
};

void
ttls_pk_init(TlsPkCtx *ctx)
{
	ctx->pk_info = NULL;
	ctx->pk_ctx = NULL;
}
EXPORT_SYMBOL(ttls_pk_init);

#define TTLS_PK_ARGS_SANITY_CHECK(fname)				\
do {									\
	if (unlikely(!ctx || !ctx->pk_info))				\
		return TTLS_ERR_PK_BAD_INPUT_DATA;			\
	if (unlikely(!ctx->pk_info->fname##_func ))			\
		return TTLS_ERR_PK_TYPE_MISMATCH;			\
} while (0)

void
ttls_pk_free(TlsPkCtx *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return;
	ctx->pk_info->ctx_free_func(ctx->pk_ctx);
}
EXPORT_SYMBOL(ttls_pk_free);

const TlsPkInfo *
ttls_pk_info_from_type(ttls_pk_type_t pk_type)
{
	switch (pk_type) {
	case TTLS_PK_RSA:
		return &ttls_rsa_info;
	case TTLS_PK_ECKEY:
		return &ttls_eckey_info;
	case TTLS_PK_ECKEY_DH:
		return &ttls_eckeydh_info;
	case TTLS_PK_ECDSA:
		return &ttls_ecdsa_info;
	default:
		return NULL;
	}
}

/**
 * Executes the allocation and initialization callback specific for a
 * particular public key algorithm. The callback allocates the context in a new
 * MPI memory pool.
 */
int
ttls_pk_setup(TlsPkCtx *ctx, const TlsPkInfo *info)
{
	might_sleep();
	BUG_ON(!ctx || !info || ctx->pk_info);

	T_DBG("setup pk context for %s(%d) key\n", info->name, info->type);
	if (!(ctx->pk_ctx = info->ctx_alloc_func()))
		return TTLS_ERR_PK_ALLOC_FAILED;
	ctx->pk_info = info;

	return 0;
}

/**
 * Tell if a PK can do the operations of the given type.
 */
int
ttls_pk_can_do(const TlsPkCtx *ctx, ttls_pk_type_t type)
{
	/* null or NONE context can't do anything */
	if (WARN_ON_ONCE(!ctx || !ctx->pk_info))
		return 0;

	return ctx->pk_info->can_do(type);
}

static inline int
pk_hashlen_helper(ttls_md_type_t md_alg, size_t *hash_len)
{
	const TlsMdInfo *md_info;

	if (*hash_len)
		return 0;

	if (!(md_info = ttls_md_info_from_type(md_alg)))
		return -1;
	*hash_len = ttls_md_get_size(md_info);

	return 0;
}

/**
 * Verify a signature.
 */
int
ttls_pk_verify(TlsPkCtx *ctx, ttls_md_type_t md_alg,
	       const unsigned char *hash, size_t hash_len,
	       const unsigned char *sig, size_t sig_len)
{
	TTLS_PK_ARGS_SANITY_CHECK(verify);
	if (unlikely(pk_hashlen_helper(md_alg, &hash_len)))
		return TTLS_ERR_PK_BAD_INPUT_DATA;

	return ctx->pk_info->verify_func(ctx->pk_ctx, md_alg, hash, hash_len,
					 sig, sig_len);
}

/**
 * Verify a signature with options.
 */
int
ttls_pk_verify_ext(ttls_pk_type_t type, const void *options,
		   TlsPkCtx *ctx, ttls_md_type_t md_alg,
		   const unsigned char *hash, size_t hash_len,
		   const unsigned char *sig, size_t sig_len)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return TTLS_ERR_PK_BAD_INPUT_DATA;
	if (!ttls_pk_can_do(ctx, type))
		return TTLS_ERR_PK_TYPE_MISMATCH;

	if (type == TTLS_PK_RSASSA_PSS) {
		int r;
		const ttls_pk_rsassa_pss_options *pss_opts;

		if (md_alg == TTLS_MD_NONE && UINT_MAX < hash_len)
			return TTLS_ERR_PK_BAD_INPUT_DATA;
		if (!options)
			return TTLS_ERR_PK_BAD_INPUT_DATA;

		pss_opts = (const ttls_pk_rsassa_pss_options *)options;

		if (sig_len < ttls_pk_get_len(ctx))
			return TTLS_ERR_RSA_VERIFY_FAILED;

		r = ttls_rsa_rsassa_pss_verify_ext(ttls_pk_rsa(*ctx),
						   md_alg,
						   (unsigned int)hash_len,
						   hash,
						   pss_opts->mgf1_hash_id,
						   pss_opts->expected_salt_len,
						   sig);
		if (r)
			return r;
		if (sig_len > ttls_pk_get_len(ctx))
			return TTLS_ERR_PK_SIG_LEN_MISMATCH;
		return 0;
	}

	/* General case: no options */
	if (options)
		return TTLS_ERR_PK_BAD_INPUT_DATA;

	return ttls_pk_verify(ctx, md_alg, hash, hash_len, sig, sig_len);
}

/**
 * Make a signature.
 */
int
ttls_pk_sign(TlsPkCtx *ctx, ttls_md_type_t md_alg,
	     const unsigned char *hash, size_t hash_len,
	     unsigned char *sig, size_t *sig_len)
{
	TTLS_PK_ARGS_SANITY_CHECK(sign);
	if (unlikely(pk_hashlen_helper(md_alg, &hash_len)))
		return TTLS_ERR_PK_BAD_INPUT_DATA;

	return ctx->pk_info->sign_func(ctx->pk_ctx, md_alg, hash, hash_len,
				       sig, sig_len);
}

/**
 * Get key size in bits.
 */
size_t
ttls_pk_get_bitlen(const TlsPkCtx *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return 0;
	return ctx->pk_info->get_bitlen(ctx->pk_ctx);
}

/**
 * Access the PK type.
 */
ttls_pk_type_t
ttls_pk_get_type(const TlsPkCtx *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return TTLS_PK_NONE;
	return ctx->pk_info->type;
}
