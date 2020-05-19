/*
 *		Tempesta TLS
 *
 * Public Key abstraction layer.
 *
 * References:
 *
 * 1. ECDSA (SEC1): http://www.secg.org/index.php?action=secg,docs_secg
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
#include "tls_internal.h"
#include "ecp.h"
#include "mpool.h"
#include "pk.h"
#include "rsa.h"

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

	if (WARN_ON_ONCE(md_alg == TTLS_MD_NONE))
		return -EINVAL;

	*sig_len = ttls_rsa_get_len(rsa);

	return ttls_rsa_pkcs1_sign(rsa, md_alg, hash, hash_len, sig);
}

static void *
rsa_alloc_wrap(void)
{
	TlsMpiPool *mp;
	TlsRSACtx *ctx;

	might_sleep();

	if (!(mp = ttls_mpi_pool_create(TTLS_MPOOL_ORDER, GFP_KERNEL)))
		return NULL;

	if ((ctx = ttls_mpool_alloc_data(mp, sizeof(*ctx))))
		ttls_rsa_init(ctx, 0, 0);

	return ctx;
}

static void
rsa_free_wrap(void *ctx)
{
	ttls_rsa_free(ctx);
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

/**
 * Read and check signature.
 *
 * If the bitlength of the message hash is larger than the bitlength of the
 * group order, then the hash is truncated as defined in Standards for
 * Efficient Cryptography Group (SECG): SEC1 Elliptic Curve Cryptography,
 * section 4.1.4, step 3.
 */
static int
ecdsa_verify_wrap(void *ctx, ttls_md_type_t md_alg __attribute__((unused)),
		  const unsigned char *hash, size_t hash_len,
		  const unsigned char *sig, size_t sig_len)
{
	TlsEcpKeypair *eck = ctx;
	unsigned char *p = (unsigned char *)sig;
	const unsigned char *end = sig + sig_len;
	size_t len;
	TlsMpi *r, *s;

	if (WARN_ON_ONCE(!eck->grp->ecdsa_verify))
		return -EINVAL;

	r = ttls_mpi_alloc_stack_init(0);
	s = ttls_mpi_alloc_stack_init(0);

	if (ttls_asn1_get_tag(&p, end, &len,
			      TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE))
		return -EIO;
	if (p + len != end)
		return -EIO;

	if (ttls_asn1_get_mpi(&p, end, r)
	    || ttls_asn1_get_mpi(&p, end, s))
		return -EIO;
	if (unlikely(p != end))
		return TTLS_ERR_ECP_SIG_LEN_MISMATCH;

	return eck->grp->ecdsa_verify(hash, hash_len, &eck->Q, r, s);
}

static int
ecdsa_sign_wrap(void *ctx, ttls_md_type_t md_alg __attribute__((unused)),
		const unsigned char *hash, size_t hash_len, unsigned char *sig,
		size_t *sig_len)
{
	TlsEcpKeypair *eck = ctx;

	if (WARN_ON_ONCE(!eck->grp->ecdsa_sign))
		return -EINVAL;

	return eck->grp->ecdsa_sign(&eck->d, hash, hash_len, sig, sig_len);
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
	return ((TlsEcpKeypair *)ctx)->grp->bits;
}

static void *
eckey_alloc_wrap(void)
{
	TlsMpiPool *mp;
	TlsEcpKeypair *ctx;

	might_sleep();

	if (!(mp = ttls_mpi_pool_create(TTLS_MPOOL_ORDER, GFP_KERNEL)))
		return NULL;

	if ((ctx = ttls_mpool_alloc_data(mp, sizeof(*ctx))))
		ttls_ecp_keypair_init(ctx);

	return ctx;
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
	NULL
};

const TlsPkInfo ttls_ecdsa_info = {
	TTLS_PK_ECDSA,
	"ECDSA",
	eckey_get_bitlen,
	ecdsa_can_do,
	ecdsa_verify_wrap,
	ecdsa_sign_wrap,
	eckey_alloc_wrap,
	NULL
};

const TlsPkInfo ttls_eckey_info = {
	TTLS_PK_ECKEY,
	"EC",
	eckey_get_bitlen,
	eckey_can_do,
	ecdsa_verify_wrap,
	ecdsa_sign_wrap,
	eckey_alloc_wrap,
	NULL
};

void
ttls_pk_init(TlsPkCtx *ctx)
{
	ctx->pk_info = NULL;
	ctx->pk_ctx = NULL;
}
EXPORT_SYMBOL(ttls_pk_init);

void
ttls_pk_free(TlsPkCtx *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return;

	if (ctx->pk_info->ctx_free_func)
		ctx->pk_info->ctx_free_func(ctx->pk_ctx);

	ttls_mpi_pool_free(ctx->pk_ctx);
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

/**
 * Verify a signature.
 */
int
ttls_pk_verify(TlsPkCtx *ctx, ttls_md_type_t md_alg, const unsigned char *hash,
	       const unsigned char *sig, size_t sig_len)
{
	size_t hash_len = ttls_md_get_size(ttls_md_info_from_type(md_alg));

	BUG_ON(!ctx || !ctx->pk_info || !ctx->pk_info->verify_func);

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

	return ttls_pk_verify(ctx, md_alg, hash, sig, sig_len);
}

/**
 * Make a signature.
 */
int
ttls_pk_sign(TlsPkCtx *ctx, ttls_md_type_t md_alg, const unsigned char *hash,
	     unsigned char *sig, size_t *sig_len)
{
	size_t hash_len = ttls_md_get_size(ttls_md_info_from_type(md_alg));

	BUG_ON(!ctx || !ctx->pk_info || !ctx->pk_info->sign_func);

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

ttls_pk_type_t
ttls_pk_get_type(const TlsPkCtx *ctx)
{
	if (unlikely(!ctx || !ctx->pk_info))
		return TTLS_PK_NONE;
	return ctx->pk_info->type;
}
