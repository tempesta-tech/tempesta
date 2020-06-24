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
 * PK computations for a particular handshake type (RSA, EC etc).
 *
 * Tempesta TLS handshake happens in softirq non-preemptable context, so we can
 * keep per-cpu memory pool for all temporary MPIs required for a particular
 * handshake step taken on a CPU. The memory pool is cleaned and freed after
 * each handshake step.
 *
 * The pool also used for MPI profiles (see below) to initialize a profile
 * implicitly for MPI math. Dynamically allocated pages are used instead of
 * static per-cpu ones.
 *
 * Copyright (C) 2019-2020 Tempesta Technologies, Inc.
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
#include "mpool.h"

#define MPI_POOL_DATA(mp)	((void *)((char *)(mp) + sizeof(TlsMpiPool)))
#define MPI_POOL_FREE_PTR(mp)	((void *)((char *)(mp) + (mp)->curr))
#define MPI_POOL_SZ(mp)		(PAGE_SIZE << (mp)->order)
#define MPI_POOL_END(mp)	((void *)((char *)(mp) + MPI_POOL_SZ(mp)))
#define MPI_POOL_SZ_ALIGN(n)	(((n) + CIL - 1) & ~LMASK)
#define MPI_PROFILE_SZ(mp)	(mp)->curr
/* PK and RSA 4096 are memory greedy, so standard 4 pages stack isn't enough. */
#define __MPOOL_STACK_ORDER	3
/* Do our best to keep per-handshake MPI pools as tiny as possible. */
#define __MPOOL_HS_ORDER	0

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
TlsMpiPool *
ttls_mpool(void *addr)
{
	TlsMpiPool *mp;
	const char *mp_name;
	const unsigned long a = (unsigned long)addr;

	/*
	 * On configuration phase (process context) we fill cipher suite
	 * profiles, so these pools are the first to check.
	 */
	if ((mp = ttls_ciphersuite_addr_mp(addr))) {
		mp_name = "ciphersuite";
		goto check;
	}

	mp = *this_cpu_ptr(&g_tmp_mpool);
	mp_name = "temporary";
	if ((unsigned long)mp < a
	    && a < (unsigned long)mp + (PAGE_SIZE << mp->order))
		goto check;

	/* See ttls_mpi_pool_create() for alignment guarantees. */
	mp = (TlsMpiPool *)(a & ~((PAGE_SIZE << __MPOOL_HS_ORDER) - 1));
	mp_name = "handshake";

check:
	if (unlikely((unsigned long)MPI_POOL_FREE_PTR(mp) <= a
		     || (unsigned long)mp + sizeof(*mp) > a
		     || (unsigned long)MPI_POOL_END(mp) <= a
		     || mp->curr > MPI_POOL_SZ(mp)))
	{
		T_ERR("Bad MPI address %pK in pool %pK (%s, order=%u curr=%u)\n",
		      addr, mp, mp_name, mp->order, mp->curr);
		BUG();
	}
	return mp;
}

void *
ttls_mpool_alloc_data(TlsMpiPool *mp, size_t n)
{
	void *ptr = MPI_POOL_FREE_PTR(mp);

	if (unlikely(mp->curr + n > MPI_POOL_SZ(mp))) {
		T_ERR("Not enough space in pool %pK (order=%u curr=%u)"
		      " to grow for %lu bytes", mp, mp->order, mp->curr, n);
		BUG();
	}

	mp->curr += MPI_POOL_SZ_ALIGN(n);

	return ptr;
}

/**
 * Allocate limbs space for the MPI within a pool, where the MPI was allocated.
 */
int
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n)
{
	unsigned short *ptr;
	TlsMpiPool *mp = ttls_mpool(x);

	ptr = ttls_mpool_alloc_data(mp, n);

	return (int)((unsigned long)ptr - (unsigned long)x);
}

void *
ttls_mpool_alloc_stack(size_t n)
{
	return ttls_mpool_alloc_data(*this_cpu_ptr(&g_tmp_mpool), n);
}

/**
 * Cleanup current CPU memory pool for temporary MPIs: partially, up to @addr,
 * if it's non zero, or fully otherwise.
 *
 * The function call is semantically similar to moving RSP register, but the
 * function call (1) is more expensive and (2) provides memory zeroing.
 * ttls_mpool_alloc_data() with this function should be used for large MPI
 * allocations, when the small kernel stack can be overrun.
 */
void
ttls_mpi_pool_cleanup_ctx(unsigned long addr, bool zero)
{
	TlsMpiPool *mp = *this_cpu_ptr(&g_tmp_mpool);
	unsigned long clean_off, m = (unsigned long)mp;

	/* The tail part must be cleaned up with ttls_mpool_shrink_tailtmp(). */
	if (WARN(addr && (addr < m || addr >= (unsigned long)MPI_POOL_END(mp)),
		 "Try to cleanup bad address %lx on MPI pool %pK\n",
		 addr, mp))
		return;

	clean_off = addr ? addr - m : sizeof(TlsMpiPool);
	if (zero)
		ttls_bzero_safe((char *)mp + clean_off, mp->curr - clean_off);
	mp->curr = clean_off;
}

/**
 * Free MPI memory pool storing the crypto context @ctx and return the freed
 * memory to the buddy allocator.
 */
void
ttls_mpi_pool_free(void *ctx)
{
	TlsMpiPool *mp = (TlsMpiPool *)ctx - 1;

	if (mp->order && MPI_POOL_SZ(mp) / 2 > mp->curr)
		T_WARN("Too large MPI pool was allocated (order=%u used=%u)\n",
		       mp->order, mp->curr);

	bzero_fast(MPI_POOL_DATA(mp), mp->curr - sizeof(*mp));
	WARN_ON_ONCE((unsigned long)mp & ((PAGE_SIZE << mp->order) - 1));
	free_pages((unsigned long)mp, mp->order);
}

/**
 * Allocate and initialize a new MPI pool.
 *
 * Memory pools are allocated directly from the buddy allocator, i.e. buddies
 * with order higher than 1 are allocated with addresses aligned to
 * (PAGE_SIZE << order).
 *
 * If @n == 0, then only one page (the minimum allocation) is allocated.
 */
TlsMpiPool *
ttls_mpi_pool_create(size_t order, gfp_t gfp_mask)
{
	TlsMpiPool *mp;
	unsigned long addr;

	if (!(addr = __get_free_pages(gfp_mask | __GFP_ZERO, order)))
		return NULL;
	WARN_ON_ONCE(addr & ((PAGE_SIZE << order) - 1));

	mp = (TlsMpiPool *)addr;
	mp->order = order;
	mp->curr = sizeof(*mp);

	return mp;
}

static int
ttls_mpi_profile_create_ec(TlsMpiPool *mp, ttls_ecp_group_id ec)
{
	size_t n_sz;
	TlsECDHCtx *ctx;
	const TlsEcpGrp *g;

	if (unlikely(!(g = ttls_ecp_group_lookup(ec))))
		return -EINVAL;

	/* Reserve space for the public key point X and Y coordinates. */
	if (!(ctx = ttls_mpool_alloc_data(mp, sizeof(*ctx)
					      + BITS_TO_CHARS(g->bits) * 2)))
		return -ENOMEM;

	/*
	 * Initialize the context group pointer - it will be copied as is by
	 * all the cloned MPI profiles, so they will use this group.
	 */
	ctx->grp = g;

	/* Init the temporary point to be used in ttls_ecdh_compute_shared(). */
	ttls_ecp_point_init(&ctx->z);
	/*
	 * Allocate memory for the MPIs set in ttls_ecp_gen_keypair()
	 * called from ttls_ecdh_make_params().
	 */
	n_sz = CHARS_TO_LIMBS((ctx->grp->bits + 7) / 8);
	ttls_mpi_alloc(&ctx->d, n_sz);
	ttls_mpi_alloc(&ctx->Q.X, n_sz * 2);
	ttls_mpi_alloc(&ctx->Q.Y, n_sz * 2);
	ttls_mpi_alloc(&ctx->Q.Z, n_sz * 2);
	ttls_mpi_alloc(&ctx->z.Z, n_sz * 2);

	return 0;
}

static void
ttls_mpi_profile_create_dh(TlsMpiPool *mp)
{
	TlsDHMCtx *dhm = ttls_mpool_alloc_data(mp, sizeof(*dhm));

	/*
	 * TODO #1335: use a reference to the profile constant data as it's
	 * done for EC in __mpi_profile_load_ec().
	 */

	ttls_dhm_load(dhm);
}

/**
 * Allocate MPI memory profiles for all the defined cipher suites and
 * preset elliptic curves.
 */
static int
ttls_mpi_profile_set(TlsCiphersuite *cs)
{
	int r = 0, e;
	TlsMpiPool *mp;

	/* Static ciphersuite profiles are always here. */
	BUG_ON(!cs->mpi_profile[0]);
	/* Nothing to do if the profile is already initialized. */
	if (cs->mpi_profile[0]->curr > sizeof(TlsMpiPool))
		return 0;

	kernel_fpu_begin();

	/*
	 * The ciphersuite memory profiles are from static memory, so
	 * all the areas are zeroized.
	 */
	switch (cs->key_exchange) {
	case TTLS_KEY_EXCHANGE_ECDHE_RSA:
	case TTLS_KEY_EXCHANGE_ECDHE_ECDSA:
		/* 0'th curve is NONE, so count from -1. */
		for (e = 0; e < __TTLS_ECP_DP_N - 1; ++e) {
			mp = cs->mpi_profile[e];
			if ((r = ttls_mpi_profile_create_ec(mp, e + 1)))
				goto cleanup;
		}
		break;
	case TTLS_KEY_EXCHANGE_DHE_RSA:
		mp = cs->mpi_profile[0];
		ttls_mpi_profile_create_dh(mp);
		break;
	default:
		T_ERR("Cannot create a memory profile for %s\n", cs->name);
		r = -EINVAL;
	}

cleanup:
	kernel_fpu_end();
	return r;
}

/**
 * Create a new per-handshake MPI pool and clone an MPI profile into it.
 */
static int
__mpi_profile_clone(TlsCtx *tls, int ec)
{
	char *ptr;
	TlsMpiPool *mp;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;
	TlsHandshake *hs = tls->hs;

	BUG_ON(ec < 0 || ec >= __TTLS_ECP_DP_N);

	mp = ci->mpi_profile[ec];
	if (!mp) {
		T_WARN("Try to do %s handshake w/o an MPI profile\n",
		       ci->name);
		return -ENOENT;
	}
	if (WARN_ON_ONCE(MPI_PROFILE_SZ(mp) > (PAGE_SIZE << __MPOOL_HS_ORDER))) {
		T_WARN("Too large TLS handshake crypto profile\n");
		return -ENOMEM;
	}

	ptr = (char *)__get_free_pages(GFP_ATOMIC, __MPOOL_HS_ORDER);
	if (WARN_ON_ONCE(!ptr))
		return -ENOMEM;

	memcpy_fast(ptr, mp, MPI_PROFILE_SZ(mp));
	hs->crypto_ctx = MPI_POOL_DATA(ptr);

	/*
	 * Adjust the cloned memory pool order, which can be smaller than
	 * the original.
	 */
	mp = (TlsMpiPool *)ptr;
	mp->order = __MPOOL_HS_ORDER;

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

		return __mpi_profile_clone(tls, (*curve)->grp_id - 1);

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
		free_pages((unsigned long)mp, mp->order);
	}
}

int __init
ttls_mpool_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		TlsMpiPool **mp = per_cpu_ptr(&g_tmp_mpool, cpu);
		if (!(*mp = ttls_mpi_pool_create(__MPOOL_STACK_ORDER,
						 GFP_KERNEL)))
			goto err_cleanup;
	}

	if (ttls_ciphersuite_for_all(ttls_mpi_profile_set))
		goto err_cleanup;

	return 0;
err_cleanup:
	ttls_mpool_exit();
	return -ENOMEM;
}
