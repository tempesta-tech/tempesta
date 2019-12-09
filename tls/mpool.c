/*
 *		Tempesta TLS
 *
 * MPI memory pool based on PK exchange type (profile).
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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
#include "bignum.h"

/**
 * MPI memory pool.
 *
 * Tempesta TLS handshake happens in softirq non-preemptable context, so we can
 * keep per-cpu memory pool for all temporary MPIs required for a particilar
 * handshake step taken on a CPU. The memory pool is cleaned and freed after
 * each handshake step.
 *
 * The pool also used for MPI profiles (see below) to initialize a profile
 * implicitly for MPI math. Dynamically allocated pages are used instead of
 * static per-cpu ones.
 *
 * @order	- page order of the underneath memory area;
 * @curr	- offset of free memory area for MPI allocations.
 */
typedef struct {
	unsigned int		order;
	unsigned int		curr;
} TlsMpiPool;

/**
 * MPI memory profile.
 *
 * TLS handshakes uses public key cryptography calculations executing a lot
 * of MPI operations, so temporal MPIs are required and many MPIs change their
 * sizes. To avoid dynamic memory allocations we use the MPI profiles -
 * pregenerated set of initialized MPIs which are just copied in single shot on
 * a handshake. An MPI profile contains all the memory required to perform all
 * PK computations for a perticular handshake type (RSA, EC etc).
 * The PK type is determined at Vhost certificate loading and a new static MPI
 * profile is created if necessary.
 *
 * MPI profile uses MPI pool to allocate required MPIs. The whole pool content
 * is copied as is on a handshake key exchange.
 *
 * @pool	- the memory area containing initialized MPIs;
 */
typedef struct {
	TlsMpiPool	*pool;
} TlsMpiProfile;

/**
 * Profile types.
 * Different PK profiles may share the same memory region.
 */
typedef enum {
	TTLS_MPI_PROFILE_ECDH,
	TTLS_MPI_PROFILE_DHM,
	TTLS_MPI_PROFILE_ECDHE_SECP256,
	TTLS_MPI_PROFILE_ECDHE_SECP384,
	__TTLS_MPI_PROFILES_N,
	__TTLS_MPI_PROFILES_INVALID = __TTLS_MPI_PROFILES_N
} ttls_mpi_profile_t;

#define MCTX_ORDER		0 /* one page for temporary MPIs */
#define MPI_POOL_DATA(mp)	((void *)((char *)(mp) + sizeof(TlsMpiPool)))
#define MPI_POOL_FREE_PTR(mp)	((void *)((char *)(mp) + sizeof(TlsMpiPool) \
					  + mp->curr))
#define MPI_PROFILE_SZ(p)	((p)->pool->curr + size(TlsMpiPool))

/*
 * Static memory profiles for all types of crypto handshakes.
 * MPIs from the pool live during the whole handshake process.
 */
static TlsMpiProfile mpi_profiles[__TTLS_MPI_PROFILES_N] ____cacheline_aligned;
/*
 * Memory pool for temporal (stack allocated) MPIs which are used only during
 * one call of the TLS handshake state machine.
 */
static DEFINE_PER_CPU(TlsMpiPool *, g_tmp_mpool);

/**
 * Return a pointer to an MPI pool of one of the two types:
 * 1. current handshake profile;
 * 2. temporary per-cpu pool for stack allocated MPIs.
 */
static TlsMpiPool *
__mpi_pool(void *addr)
{
	unsigned long a = (unsigned long)addr;
	unsigned long sp = (unsigned long)&a;

	/* Maximum kernel stack size is 2 pages. */
	if (sp < a && a < sp + 2 * PAGE_SIZE)
		return *this_cpu_ptr(&g_tmp_mpool);
	return (TlsMpiPool *)(a & ~PAGE_MASK);
}

/**
 * Allocate space for a new MPI within a pool.
 */
static
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n)
{
	void *ptr;
	TlsMpiPool *mp = __mpi_pool(x);

	if (WARN_ON_ONCE(sizeof(*mp) + mp->size + n > PAGE_SIZE))
		return -ENOMEM;

	ptr = MPI_POOL_FREE_PTR(mp);
	BUG_ON(x >= ptr);
	mp->curr += n;

	return (unsigned long)ptr - (unsigned long)x;
}

/**
 * Cleanup current CPU memory pool for temporary MPIs.
 */
void
ttls_mpi_pool_cleanup_ctx(void)
{
	TlsMpiPool *mp = *this_cpu_ptr(&g_tmp_mpool);
	void *data = MPI_POOL_DATA(mp);

	BUG_ON(mp->mem_alloc < data);
	BUG_ON(mp->curr > mp->size);

	bzero_fast(data, mp->curr);
	mp->curr = 0;
}

/**
 * Free MPI memory pool storing the crypto context @ctx and return the freed
 * memory to the buddy allocator.
 */
void
ttls_mpi_pool_free(void *ctx)
{
	TlsMpiPool *mp = (TlsMpiPool *)ctx - 1;

	WARN_ON((PAGE_SIZE << mp->order) / 2 > mp->curr,
		"Too large MPI pool was allocated (order=%u used=%u)\n",
		mp->order, mp->curr);

	bzero_fast(mp, mp->curr);
	free_pages((unsigned long)mp, mp->order);
}

/**
 * Allocate and initialize a new MPI pool.
 *
 * If @n == 0, then only one page (the minimum allocation) is allocated.
 */
void *
ttls_mpi_pool_alloc(size_t n, gfp_t gfp_mask)
{
	TlsMpiPool *mp;
	unsigned int order = n ? get_order(n + sizeof(*mp)) : 0;

	mp = (TlsMpiPool *)__get_free_pages(gfp_mask | __GFP_ZERO, order);
	if (!mp)
		return NULL;

	mp->order = order;
	mp->curr = sizeof(TlsMpiPool);

	return MPI_POOL_DATA(mp);
}

/**
 * Should we template the profile with ID @pid for the key @pkey from a vhost's
 * certificate?
 */
static bool
ttls_mpi_profile_for_cert(int pid, const TlsPkCtx *pkey)
{
	switch (pkey->pk_info->type) {
	case TTLS_PK_ECKEY:
	case TTLS_PK_ECKEY_DH:
	case TTLS_PK_ECDSA:
		switch (pid) {
		/* ECDH uses curve from the private key. */
		case TTLS_MPI_PROFILE_ECDH:
		/* Preset curves for ECDHE, see ttls_preset_curves. */
		case TTLS_MPI_PROFILE_ECDHE_SECP256:
		case TTLS_MPI_PROFILE_ECDHE_SECP384:
			return true;
		default:
			return false;
		}
		return false;
	case TTLS_PK_RSA:
	case TTLS_PK_RSASSA_PSS:
		switch (pid) {
		case TTLS_MPI_PROFILE_DHM:
			return true;
		default:
			return false;
		}
	default:
		T_ERR("Cannot match a memory profile %d to PK %d\n",
		      i, pkey->pk_info->type);
	}
	return false;
}

static TlsMpiPool *
ttls_mpi_profile_create_ec(const TlsPkCtx *pkey, ttls_mpi_profile_t pid)
{
	int r;
	size_t n_sz;
	TlsMpiPool *mp;
	TlsECDHCtx *ecdh_ctx;
	TlsEcpGrp *grp;
	TlsEcpKeypair *key = ttls_pk_ec(*pkey);

	if (!(mp = ttls_mpi_pool_alloc(0, GFP_KERNEL | __GFP_ZERO)))
		return NULL;
	mp->curr += sizeof(*ecdx_ctx);
	ecdh_ctx = MPI_POOL_DATA(mp);
	grp = &ecdh_ctx->grp;

	/* See ttls_mpi_profile_for_cert() for the cases description. */
	switch (pid) {
	case TTLS_MPI_PROFILE_ECDH:
		r = ttls_ecdh_get_params(ecdh_ctx, pkey, TTLS_ECDH_OURS);
		if (r) {
			T_DBG("cannot get ECDH params from a certificate, %d\n",
			      r);
			return NULL;
		}
	case TTLS_MPI_PROFILE_ECDHE_SECP256:
		r = ttls_ecp_group_load(&ecdh_ctx->grp, TTLS_ECP_DP_SECP256R1);
		if (r) {
			T_DBG("cannot load Secp256r1 ECP group, %d\n", r);
			goto err;
		}
		/*
		 * Allocate memory for the MPIs set in ttls_ecp_gen_keypair()
		 * called from ttls_ecdh_make_params().
		 *
		 * TODO #1064 I don't understand the math enough, so I set the Q
		 * size as double d size for now.
		 */
		n_sz = CHARS_TO_LIMBS((grp->nbits + 7) / 8);
		if (__mpi_alloc(&ecdh_ctx->d, n_sz)
		    || __mpi_alloc(&ecdh_ctx->Q, n_sz * 2))
			return -ENOMEM;
	case TTLS_MPI_PROFILE_ECDHE_SECP384:
		r = ttls_ecp_group_load(&ecdh_ctx->grp, TTLS_ECP_DP_SECP384R1);
		if (r) {
			T_DBG("cannot load Secp384r1 ECP group, %d\n", r);
			goto err;
		}
		n_sz = CHARS_TO_LIMBS((grp->nbits + 7) / 8);
		if (__mpi_alloc(&ecdh_ctx->d, n_sz)
		    || __mpi_alloc(&ecdh_ctx->Q, n_sz * 2))
			return -ENOMEM;
	default:
		WARN_ONCE(1, "There is no EC profile for id %d\n", pid);
		return NULL;
	}

	/* Init the temporary point to be used in ttls_ecdh_compute_shared(). */
	ttls_ecp_point_init(&ecdh_ctx->_P);

	/*
	 * Prepare precomputed points to use them in ecp_mul_comb().
	 * Different curves require different size of T - comput the maximum
	 * number of items to fit all the curves - that's fine on vhost
	 * initialization stage.
	 */
	n_sz = (ecdh_ctx->grp.nbits + TTLS_ECP_WINDOW_ORDER - 1)
		/ TTLS_ECP_WINDOW_ORDER;
	if (ecp_precompute_comb(&ecdh_ctx->grp, &ecdh_ctx->grp.T,
				&ecdh_ctx->grp.G, TTLS_ECP_WINDOW_ORDER, n_sz))
		return NULL;

	return mp;
}

static TlsMpiPool *
ttls_mpi_profile_create_dh(const TlsPkCtx *pkey, ttls_mpi_profile_t pid)
{
	int r;
	TlsMpiPool *mp;
	TlsDHMCtx *dhm_ctx;

	if (!(mp = ttls_mpi_pool_alloc(0, GFP_KERNEL | __GFP_ZERO)))
		return NULL;
	mp->curr += sizeof(*dhm_ctx);
	dhm_ctx = MPI_POOL_DATA(mp);

	/*
	 * Set DHM prime modulus and generator defined in NSA Suite B
	 * (257 bytes).
	 */
	r = ttls_mpi_read_binary(&dhm_ctx->P, TTLS_DHM_RFC3526_MODP_2048_P_BIN,
				 sizeof(TTLS_DHM_RFC3526_MODP_2048_P_BIN));
	if (r)
		return NULL;
	r = ttls_mpi_read_binary(&dhm_ctx->G, TTLS_DHM_RFC3526_MODP_2048_G_BIN,
				 sizeof(TTLS_DHM_RFC3526_MODP_2048_G_BIN));
	if (r)
		return NULL;
	dhm_ctx->len = ttls_mpi_size(&dhm_ctx->P);

	return mp;
}

/**
 * Allocate, if necessary, new MPI memory profiles for the certificate @crt
 * and all supported ciphersuites.
 */
int
ttls_mpi_profile_set(ttls_x509_crt *crt)
{
	static bool has_empty_profile = true;
	TlsMpiPool *mp;
	const TlsPkCtx *pkey = crt->pk;
	int i, r, n;

	might_sleep();

	/*
	 * All the profiles are filled by previous vhost certificates.
	 * This optimization is crucial for massive vhost configurations.
	 */
	if (!has_empty_profile)
		return 0;

	for (i = 0, n = 0; i < __TTLS_MPI_PROFILES_N; ++i) {
		if (mpi_profiles[i].profile) {
			++n;
			continue; /* already initialized */
		}
		if (!ttls_mpi_profile_for_cert(i, pkey))
			continue;

		switch (pkey->pk_info->type) {
		case TTLS_PK_ECKEY:
		case TTLS_PK_ECKEY_DH:
		case TTLS_PK_ECDSA:
			if (!(mp = ttls_mpi_profile_create_ec(pkey, i)))
				return -EINVAL;
			break;
		case TTLS_PK_RSA:
			if (!(mp = ttls_mpi_profile_create_dh(pkey, i)))
				return -EINVAL;
			break;
		default:
			T_ERR("Cannot create a memory profile for a PK %d\n",
			      pkey->pk_info->type);
		}
		mpi_profiles[i].profile = mp;

		++n;
	}
	if (n == __TTLS_MPI_PROFILES_N)
		has_empty_profile = false;

	return 0;
}
EXPORT_SYMBOL(ttls_mpi_profile_set);

static int
__mpi_profile_clone(ttls_mpi_profile_id id)
{
	char *ptr;
	size_t p_sz;
	TlsMpiPool *prof;
	TlsHandshake *hs = tls->hs;

	prof = mpi_profiles[id].pool;
	if (WARN_ON_ONCE(!prof)) {
		T_WARN("Try to do ECDH handshake w/o a profile\n");
		return -ENOENT;
	}

	p_sz = MPI_PROFILE_SZ(prof);
	ptr = pg_skb_alloc(p_sz, GFP_ATOMIC, NUMA_NO_NODE);
	if (WARN_ON_ONCE(!ptr))
		return -ENOMEM;

	memcpy_fast(ptr, prof->pool, p_sz);
	hs->crypto_ctx = MPI_POOL_DATA(ptr);

	return 0;
}

/**
 * Determines the appropriate MPI memory profile and initizes ready to use MPI
 * context for the handshake.
 */
int
ttls_mpi_profile_clone(TlsCtx *tls)
{
	int r;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;

	if (ttls_ciphersuite_uses_ecdh(ci))
		return __mpi_profile_clone(TTLS_MPI_PROFILE_ECDH);

	if (ttls_ciphersuite_uses_ecdhe(ci)) {
		const TlsEcpCurveInfo **curve = NULL;
		const ttls_ecp_group_id *gid = ttls_preset_curves;
		ttls_mpi_profile_t pid = __TTLS_MPI_PROFILES_INVALID;

		/* Match our preference list against the offered curves */
		for ( ; *gid != TTLS_ECP_DP_NONE; gid++)
			for (curve = tls->hs->curves; *curve; curve++)
				if ((*curve)->grp_id == *gid)
					goto curve_found;
curve_found:
		if (!curve || !*curve) {
			T_WARN("No matching curve for ECDHE key exchange\n");
			r = -EINVAL;
			goto err;
		}
		T_DBG("ECDHE curve: %s\n", (*curve)->name);

		if ((*curve)->grp_id == TTLS_ECP_DP_SECP256R1) {
			pid = TTLS_MPI_PROFILE_ECDHE_SECP256;
		}
		else if ((*curve)->grp_id == TTLS_ECP_DP_SECP384R1) {
			pid = TTLS_MPI_PROFILE_ECDHE_SECP384;
		}

		return __mpi_profile_clone(pid);
	}

	if (ttls_ciphersuite_uses_dhe(ci))
		return __mpi_profile_clone(TTLS_MPI_PROFILE_ECDH);

	T_WARN("Try clonning a ciphersuite (%d) w/o a profile\n",
	       ci->key_exchange);
	return -EINVAL;
}

/**
 * Clear and free a cloned profile when a handshake completes.
 *
 * @ctx	- the crypto context, placed just after the pool descriptor.
 */
void
ttls_mpi_profile_free(void *ctx)
{
	TlsMpiPool *mp = (TlsMpiPool *)ctx - 1;

	bzero_fast(mp, mp->curr + sizeof(TlsMpiPool));
	put_page(virt_to_page(hs->crypto_ctx));
}

void
ttls_mpool_exit(void)
{
	int i;
	TlsMpiPool *mp;

	for (i = 0; i < __TTLS_MPI_PROFILES_N; ++i) {
		mp = mpi_profiles[i].pool;
		if (mp) {
			memset(MPI_POOL_DATA(*mp), 0, mp->curr);
			free_pages((unsigned long)mp, mp->order);
		}
	}

	for_each_possible_cpu(i) {
		/*
		 * No need to zeroize the pool memory - the last softirq context
		 * using it already cleared it.
		 */
		mp = *per_cpu_ptr(&g_tmp_pool, i);
		free_pages((unsigned long)mp, MCTX_ORDER);
	}
}

int __init
ttls_mpool_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		TlsMpiPool **mp = per_cpu_ptr(&g_tmp_pool, cpu);
		*mp = (TlsMpiPool *)__get_free_pages(GFP_KERNEL| __GFP_ZERO,
						     MCTX_ORDER);
		if (!*mp)
			goto err_cleanup;
	}

	return 0;
err_cleanup:
	ttls_mpool_exit();
	return -ENOMEM;
}
