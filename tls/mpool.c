/*
 *		Tempesta TLS
 *
 * MPI memory pool based on PK exchange type (profile).
 *
 * TLS handshakes uses public key cryptography calculations executing a lot
 * of MPI operations, so temporal MPIs are required and many MPIs change their
 * sizes. To avoid dynamic memory allocations we use the MPI profiles -
 * pregenerated set of initialized MPIs which are just copied in single shot on
 * a handshake. An MPI profile contains all the memory required to perform all
 * PK computations for a perticular handshake type (RSA, EC etc).
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
#include <linux/preempt.h>

#include "bignum.h"
#include "ciphersuites.h"
#include "dhm.h"
#include "ecp.h"
#include "tls_internal.h"

#define MCTX_ORDER		0 /* one page for temporary MPIs */
#define MPI_POOL_DATA(mp)	((void *)((char *)(mp) + sizeof(TlsMpiPool)))
#define MPI_POOL_FREE_PTR(mp)	((void *)((char *)(mp) + mp->curr))
#define MPI_PROFILE_SZ(mp)	(mp)->curr

/*
 * Memory pool for temporal (stack allocated) MPIs which are used only during
 * one call of the TLS handshake state machine.
 *
 * Using the pools in process (configuration) context requires to disable
 * preemption.
 */
static DEFINE_PER_CPU(TlsMpiPool *, g_tmp_mpool);

/**
 * Return a pointer to an MPI pool of one of the following types:
 * 1. static cipher suite memory profile;
 * 2. temporary per-cpu pool for stack allocated MPIs (softirq);
 * 3. current handshake profile cloned from (1) (softirq).
 */
static TlsMpiPool *
__mpi_pool(void *addr)
{
	TlsMpiPool *mp;
	const char *mp_name;
	unsigned long a = (unsigned long)addr;
	unsigned long sp = (unsigned long)&a;

	/*
	 * On configuration phase (process context) we fill cipher suite
	 * profiles, so these pools are the first to check.
	 */
	if ((mp = ttls_ciphersuite_addr_mp(addr))) {
		mp_name = "ciphersuite";
		goto check;
	}

	/* Maximum kernel stack size is 2 pages. */
	if (sp < a && a < sp + 2 * PAGE_SIZE) {
		mp = *this_cpu_ptr(&g_tmp_mpool);
		mp_name = "temporary";
		goto check;
	}

	/* FIXME need a safer determination of the pool address. */
	mp = (TlsMpiPool *)(a & ~((PAGE_SIZE << MCTX_ORDER) - 1));
	mp_name = "handshake";

check:
	if (unlikely((unsigned long)MPI_POOL_FREE_PTR(mp) <= (unsigned long)addr
		     || (unsigned long)mp + sizeof(*mp) > a
		     || mp->curr > (PAGE_SIZE << mp->order)))
	{
		T_ERR("Bad MPI address %p in pool %p (%s, order=%u curr=%u)\n",
		      addr, mp, mp_name, mp->order, mp->curr);
		BUG();
	}
	return mp;
}

void *
__mpool_alloc_data(TlsMpiPool *mp, size_t n)
{
	void *ptr = MPI_POOL_FREE_PTR(mp);

	if (WARN_ON_ONCE(mp->curr + n > (PAGE_SIZE << mp->order)))
		return NULL;
	mp->curr += n;

	return ptr;
}

/**
 * Allocate space for a new MPI within a pool.
 */
int
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n)
{
	void *ptr = __mpool_alloc_data(__mpi_pool(x), n);

	if (!ptr)
		return -ENOMEM;

	return (int)((unsigned long)ptr - (unsigned long)x);
}

void *
ttls_mpool_alloc_stck(size_t n)
{
	return __mpool_alloc_data(*this_cpu_ptr(&g_tmp_mpool), n);
}

/**
 * Cleanup current CPU memory pool for temporary MPIs.
 *
 * We do not zeroize configuration pool after each vhost reconfiguration -
 * the data is stored in memory anyway. We zeroize the memory only on the system
 * stop, when the memory is returned to the buddy allocator.
 */
void
ttls_mpi_pool_cleanup_ctx(bool zero)
{
	TlsMpiPool *mp = *this_cpu_ptr(&g_tmp_mpool);

	BUG_ON(mp->curr > (PAGE_SIZE << mp->order));

	if (zero)
		ttls_bzero_safe(MPI_POOL_DATA(mp), mp->curr - sizeof(*mp));
	mp->curr = sizeof(TlsMpiPool);
}

/**
 * Free MPI memory pool storing the crypto context @ctx and return the freed
 * memory to the buddy allocator.
 */
void
ttls_mpi_pool_free(void *ctx)
{
	TlsMpiPool *mp = (TlsMpiPool *)ctx - 1;

	WARN((PAGE_SIZE << mp->order) / 2 > mp->curr,
	     "Too large MPI pool was allocated (order=%u used=%u)\n",
	     mp->order, mp->curr);

	bzero_fast(MPI_POOL_DATA(mp), mp->curr - sizeof(*mp));
	free_pages((unsigned long)mp, mp->order);
}

/**
 * Allocate and initialize a new MPI pool.
 *
 * If @n == 0, then only one page (the minimum allocation) is allocated.
 */
void *
__mpi_pool_alloc(size_t n, gfp_t gfp_mask)
{
	TlsMpiPool *mp;
	unsigned int order = n ? get_order(n + sizeof(*mp)) : MCTX_ORDER;

	mp = (TlsMpiPool *)__get_free_pages(gfp_mask | __GFP_ZERO, order);
	if (!mp)
		return NULL;

	mp->order = order;
	mp->curr = sizeof(TlsMpiPool);

	return mp;
}

void *
ttls_mpi_pool_alloc(size_t n, gfp_t gfp_mask)
{
	TlsMpiPool *mp = __mpi_pool_alloc(n, gfp_mask);
	if (!mp)
		return NULL;
	return MPI_POOL_DATA(mp);
}

static int
ttls_mpi_profile_create_ec(TlsMpiPool *mp, ttls_ecp_group_id ec)
{
	int r;
	size_t n_sz;
	TlsECDHCtx *ecdh_ctx;
	TlsEcpGrp *grp;

	mp->curr += sizeof(*ecdh_ctx);
	ecdh_ctx = MPI_POOL_DATA(mp);
	grp = &ecdh_ctx->grp;

	switch (ec) {
	case TTLS_ECP_DP_SECP256R1:
		if ((r = ttls_ecp_group_load(&ecdh_ctx->grp, ec))) {
			T_DBG("cannot load Secp256r1 ECP group, %d\n", r);
			return r;
		}
		/*
		 * Allocate memory for the MPIs set in ttls_ecp_gen_keypair()
		 * called from ttls_ecdh_make_params().
		 *
		 * TODO #1064 set Q MPIs to proper size.
		 */
		n_sz = CHARS_TO_LIMBS((grp->nbits + 7) / 8);
		if (__mpi_alloc(&ecdh_ctx->d, n_sz))
			return -ENOMEM;
		break;
	case TTLS_ECP_DP_SECP384R1:
		if ((r = ttls_ecp_group_load(&ecdh_ctx->grp, ec))) {
			T_DBG("cannot load Secp384r1 ECP group, %d\n", r);
			return r;
		}
		n_sz = CHARS_TO_LIMBS((grp->nbits + 7) / 8);
		if (__mpi_alloc(&ecdh_ctx->d, n_sz))
			return -ENOMEM;
		break;
	default:
		WARN_ONCE(1, "There is no EC profile for %d\n", ec);
		return -EINVAL;
	}

	/* Init the temporary point to be used in ttls_ecdh_compute_shared(). */
	ttls_ecp_point_init(&ecdh_ctx->p_tmp);

	/*
	 * Prepare precomputed points to use them in ecp_mul_comb().
	 * Different curves require different size of T - comput the maximum
	 * number of items to fit all the curves - that's fine on vhost
	 * initialization stage.
	 */
	n_sz = (ecdh_ctx->grp.nbits + TTLS_ECP_WINDOW_ORDER - 1)
		/ TTLS_ECP_WINDOW_ORDER;
	if (ecp_precompute_comb(&ecdh_ctx->grp, ecdh_ctx->grp.T,
				&ecdh_ctx->grp.G, TTLS_ECP_WINDOW_ORDER, n_sz))
		return -EDOM;

	return 0;
}

static int
ttls_mpi_profile_create_dh(TlsMpiPool *mp)
{
	mp->curr += sizeof(TlsDHMCtx);

	return ttls_dhm_load(MPI_POOL_DATA(mp));
}

/**
 * Allocate MPI memory profiles for all the defined cipher suites and
 * preset elliptic curves.
 */
static int
ttls_mpi_profile_set(TlsCiphersuite *cs)
{
	int r = 0;
	ttls_ecp_group_id ec;
	TlsMpiPool *mp;

	/* Static ciphersuite profiles are always here. */
	BUG_ON(!cs->mpi_profile[0]);
	/* Nothing to do if the profile is already initialized. */
	if (cs->mpi_profile[0]->curr > sizeof(TlsMpiPool))
		return 0;

	preempt_disable();

	switch (cs->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		for (ec = __TTLS_ECP_DP_FIRST; ec < __TTLS_ECP_DP_N; ++ec) {
			mp = cs->mpi_profile[ec];
			if ((r = ttls_mpi_profile_create_ec(mp, ec)))
				goto cleanup;
		}
		break;
	case TTLS_KEY_EXCHANGE_DHE_RSA:
		mp = cs->mpi_profile[0];
		if ((r = ttls_mpi_profile_create_dh(mp)))
			goto cleanup;
		break;
	default:
		T_ERR("Cannot create a memory profile for %s\n", cs->name);
		r = -EINVAL;
	}

cleanup:
	preempt_enable();
	return r;
}

static int
__mpi_profile_clone(TlsCtx *tls, ttls_ecp_group_id ec)
{
	char *ptr;
	size_t p_sz;
	TlsMpiPool *mp;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;
	TlsHandshake *hs = tls->hs;

	mp = ci->mpi_profile[ec];
	if (WARN_ON_ONCE(!mp)) {
		T_WARN("Try to do %s handshake w/o an MPI profile\n",
		       ci->name);
		return -ENOENT;
	}

	p_sz = MPI_PROFILE_SZ(mp);
	/* TODO #1064 doesn't it make sense to use full pages? */
	ptr = pg_skb_alloc(p_sz, GFP_ATOMIC, NUMA_NO_NODE);
	if (WARN_ON_ONCE(!ptr))
		return -ENOMEM;

	memcpy_fast(ptr, mp, p_sz);
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
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;
	const TlsEcpCurveInfo **curve = NULL;
	const ttls_ecp_group_id *gid = ttls_preset_curves;

	switch (ci->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
		/* Match our preference list against the offered curves */
		for ( ; *gid != TTLS_ECP_DP_NONE; gid++)
			for (curve = tls->hs->curves; *curve; curve++)
				if ((*curve)->grp_id == *gid)
					goto curve_found;
curve_found:
		if (!curve || !*curve) {
			T_WARN("No matching curve for ECDHE key exchange\n");
			return -EINVAL;
		}
		T_DBG("ECDHE curve: %s\n", (*curve)->name);

		return __mpi_profile_clone(tls, (*curve)->grp_id);

	case TTLS_KEY_EXCHANGE_DHE_RSA:
		return __mpi_profile_clone(tls, 0);

	default:
		T_WARN("Try clonning a ciphersuite %s w/o a profile\n",
			ci->name);
		return -EINVAL;
	}
}

void
ttls_mpool_exit(void)
{
	int i;
	TlsMpiPool *mp;

	for_each_possible_cpu(i) {
		mp = *per_cpu_ptr(&g_tmp_mpool, i);
		ttls_bzero_safe(MPI_POOL_DATA(mp), mp->curr - sizeof(*mp));
		free_pages((unsigned long)mp, MCTX_ORDER);
	}
}

int __init
ttls_mpool_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		TlsMpiPool **mp = per_cpu_ptr(&g_tmp_mpool, cpu);
		if (!(*mp = __mpi_pool_alloc(0, GFP_KERNEL)))
			goto err_cleanup;
	}

	if (ttls_ciphersuite_for_all(ttls_mpi_profile_set))
		goto err_cleanup;

	return 0;
err_cleanup:
	ttls_mpool_exit();
	return -ENOMEM;
}
