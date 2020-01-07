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
#define MPI_POOL_FREE_PTR(mp)	((void *)((char *)(mp) + mp->curr))
#define MPI_POOL_TAIL_PTR(mp)	((void *)((char *)(mp) + mp->curr_tail))
#define MPI_PROFILE_SZ(mp)	(mp)->curr
/* PK is memory greedy, so standard 2 pages stack isn't enough. */
#define __MPOOL_STACK_ORDER	2

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
	unsigned long sp = (unsigned long)&a;

	/*
	 * On configuration phase (process context) we fill cipher suite
	 * profiles, so these pools are the first to check.
	 */
	if ((mp = ttls_ciphersuite_addr_mp(addr))) {
		mp_name = "ciphersuite";
		goto check;
	}

	/*
	 * If @addr (some MPI) was allocated on stack, then prohibit any
	 * pool operations - TlsMpi->_off is unable to handle too far pointers.
	 *
	 * Maximum kernel stack size is 2 pages.
	 */
	if (WARN_ON_ONCE(sp < a && a < sp + 2 * PAGE_SIZE))
		return NULL;

	mp = *this_cpu_ptr(&g_tmp_mpool);
	mp_name = "temporary";
	if ((unsigned long)mp < a
	    && a < (unsigned long)mp + (PAGE_SIZE << mp->order))
		goto check;

	/* See ttls_mpi_pool_alloc() for alignment guarantees. */
	mp = (TlsMpiPool *)(a & ~((PAGE_SIZE << TTLS_MPOOL_ORDER) - 1));
	mp_name = "handshake";

check:
	if (unlikely(((unsigned long)MPI_POOL_FREE_PTR(mp) <= a
		      && (unsigned long)MPI_POOL_TAIL_PTR(mp) > a)
		     || (unsigned long)mp + sizeof(*mp) > a
		     || (unsigned long)mp + (PAGE_SIZE << mp->order) <= a
		     || mp->curr > (PAGE_SIZE << mp->order)
		     || mp->curr_tail > (PAGE_SIZE << mp->order)))
	{
		T_ERR("Bad MPI address %pK in pool %pK (%s, order=%u curr=%u"
		      " curr_tail=%u)\n",
		      addr, mp, mp_name, mp->order, mp->curr, mp->curr_tail);
		BUG();
	}
	return mp;
}

void *
ttls_mpool_alloc_data(TlsMpiPool *mp, size_t n)
{
	void *ptr = MPI_POOL_FREE_PTR(mp);

	if (WARN(mp->curr + n > mp->curr_tail,
		 "Not enough space in pool %pK (order=%u curr=%u curr_tail=%u)"
		 " to grow for %lu bytes",
		 mp, mp->order, mp->curr, mp->curr_tail, n))
		return NULL;

	mp->curr += n;

	return ptr;
}

/**
 * Allocate limbs space for the MPI within a pool, where the MPI was allocated.
 */
int
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n, bool tail)
{
	unsigned short *ptr;
	TlsMpiPool *mp = ttls_mpool(x);

	if (!mp)
		return -ENOMEM;

	if (!tail) {
		if (!(ptr = ttls_mpool_alloc_data(mp, n)))
			return -ENOMEM;
		return (int)((unsigned long)ptr - (unsigned long)x);
	}

	/*
	 * For the tail allocation (shrinkable memory area) we need to
	 * remember the MPI address and the allocation size to be able to fix
	 * _off on ttls_mpool_shrink_tailtmp().
	 */
	if (WARN(mp->curr + n > mp->curr_tail,
		 "Not enough tail space in pool %pK (order=%u curr=%u"
		 " curr_tail=%u) to grow for %lu bytes",
		 mp, mp->order, mp->curr, mp->curr_tail, n))
		return -ENOSPC;

	mp->curr_tail -= n + sizeof(short) * 2;
	ptr = MPI_POOL_TAIL_PTR(mp);
	*ptr++ = (unsigned short)((unsigned long)x - (unsigned long)mp);
	*ptr++ = (unsigned short)n;

	return (unsigned long)ptr - (unsigned long)x;
}

void *
ttls_mpool_alloc_stck(size_t n)
{
	return ttls_mpool_alloc_data(*this_cpu_ptr(&g_tmp_mpool), n);
}

/**
 * Cleanup current CPU memory pool for temporary MPIs: partilly, up to @addr,
 * if it's non zero, or fully otherwise.
 *
 * The function call is semantically similar to moving RSP register, but the
 * funcation call (1) i more expensive and (2) provides memory zeroing.
 * ttls_mpool_alloc_data() with this function should be used for large MPI
 * allocations, when the small kernel stack can be overrun.
 */
void
ttls_mpi_pool_cleanup_ctx(unsigned long addr, bool zero)
{
	TlsMpiPool *mp = *this_cpu_ptr(&g_tmp_mpool);
	unsigned long clean_off, m = (unsigned long)mp;

	if (WARN(mp->curr > (mp->curr_tail),
		 "MPI pool %pK overran before cleanup, curr=%u curr_tail=%u"
		 " order=%u\n", mp, mp->curr, mp->curr_tail, mp->order))
		return;

	/* The tail part must be cleaned up with ttls_mpool_shrink_tailtmp(). */
	if (WARN(addr && (addr < m || addr > m + mp->curr_tail),
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

	if (mp->order && (PAGE_SIZE << mp->order) / 2 > mp->curr)
		T_WARN("Too large MPI pool was allocated (order=%u used=%ld)\n",
		       mp->order,
		       mp->curr + (PAGE_SIZE << mp->order) - mp->curr_tail);

	bzero_fast(MPI_POOL_DATA(mp), mp->curr - sizeof(*mp));
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
ttls_mpi_pool_alloc(size_t order, gfp_t gfp_mask)
{
	TlsMpiPool *mp;
	unsigned long addr;

	if (!(addr = __get_free_pages(gfp_mask | __GFP_ZERO, order)))
		return NULL;
	WARN_ON_ONCE(addr & ((PAGE_SIZE << order) - 1));

	mp = (TlsMpiPool *)addr;
	mp->order = order;
	mp->curr = sizeof(TlsMpiPool);
	mp->curr_tail = PAGE_SIZE << order;

	return mp;
}

/**
 * Alloc the ECP vector at once and initialize it by hands - this is quite
 * hot place. The memory will be immediately reclaimed without MPI fixups, so
 * don't bother with MPI limbs descriptors as ttls_mpi_pool_alloc_mpi() does
 * this.
 *
 * ecp_double_jac() may require more than 1 limb for Z coordinate, so we have
 * to provide enough space.
 */
TlsEcpPoint *
ttls_mpool_ecp_create_tmp_T(int n, const TlsEcpPoint *P)
{
	int i, off;
	TlsEcpPoint *T;
	TlsMpiPool *mp = *this_cpu_ptr(&g_tmp_mpool);
	size_t x_sz = P->X.used * 2, y_sz = P->Y.used * 2, z_sz = P->X.used;
	size_t x_off = x_sz * CIL - sizeof(TlsMpi);
	size_t y_off = y_sz * CIL - sizeof(TlsMpi);
	size_t z_off = z_sz * CIL - sizeof(TlsMpi);
	size_t tot_sz = (sizeof(TlsEcpPoint) + (x_sz + y_sz + z_sz) * CIL) * n;

	if (WARN(mp->curr + tot_sz > mp->curr_tail,
		 "Not enough tail space in pool %pK (order=%u curr=%u"
		 " curr_tail=%u) to grow for %lu bytes",
		 mp, mp->order, mp->curr, mp->curr_tail, tot_sz))
		return NULL;

	mp->curr_tail -= tot_sz;
	T = MPI_POOL_TAIL_PTR(mp);

	for (off = sizeof(TlsEcpPoint) * n, i = 0; i < n; ++i) {
		T[i].X.s = 0;
		T[i].X.used = 0;
		T[i].X.limbs = x_sz;
		T[i].X._off = off;
		off += x_off;

		T[i].Y.s = 0;
		T[i].Y.used = 0;
		T[i].Y.limbs = y_sz;
		T[i].Y._off = off;
		off += y_off;

		T[i].Z.s = 0;
		T[i].Z.used = 0;
		T[i].Z.limbs = z_sz;
		T[i].Z._off = off;
		off += z_off;
	}
	WARN_ON_ONCE(off + (n * 3) * sizeof(TlsMpi) != tot_sz);

	return T;
}

/**
 * The memory pool shrinking is required in two cases:
 * 1. for the pool to be used as a memory profile to minimize size of clonned
 *    pools;
 * 2. mixed stack allocations in runtime, when long-living objects are allocated
 *    on the stack after large short-living objects (e.g. R in ecp_mul_comb() is
 *    allocated after T[]->Z) and this isn't trivial to reclaim memory occuped
 *    by the long living objects.
 * The first case is supposed to be handled with accurate shrinking with fixing
 * reclaimed MPIs. In the secind case we know precisely that the short-livin
 * objects aren't required and we reclaim this by just moving the tail pointer.
 */
void
ttls_mpool_shrink_tailtmp(TlsMpiPool *mp, bool fix_refs)
{
	size_t mp_sz = PAGE_SIZE << mp->order;

	if (unlikely(fix_refs)) {
		struct mpi_desc_t {
			unsigned short	off;
			unsigned short	len;
		} *md;

		for (md = MPI_POOL_TAIL_PTR(mp);
		     (unsigned long)md < (unsigned long)mp + mp_sz;
		     md = (struct mpi_desc_t *)((char *)(md + 1) + md->len))
		{
			TlsMpi *x = (TlsMpi *)((char *)mp + md->off);

			BUG_ON(md->off > mp->curr_tail
			       || md->off < sizeof(*mp));
			BUG_ON(md->len > mp_sz
			       || md->len + mp->curr_tail > mp_sz);
			BUG_ON(md->len % CIL);

			x->s = 0;
			x->limbs = 0;
			x->used = 0;
			x->_off = 0;
		}
		bzero_fast(MPI_POOL_TAIL_PTR(mp), mp_sz - mp->curr_tail);
	}

	mp->curr_tail = mp_sz;
}

static int
__mpi_profile_load_ec(TlsMpiPool *mp, TlsECDHCtx *ctx, unsigned char w,
		      ttls_ecp_group_id ec)
{
	int r;
	size_t n_sz;
	TlsEcpGrp *grp = &ctx->grp;

	if ((r = ttls_ecp_group_load(&ctx->grp, ec))) {
		T_DBG("cannot load Secp256r1 ECP group, %d\n",
		      ec == TTLS_ECP_DP_SECP256R1 ? "Secp256r1" :
		      ec == TTLS_ECP_DP_SECP384R1 ? "Secp384r1" : "unknown",
		      r);
		return r;
	}

	/* Init the temporary point to be used in ttls_ecdh_compute_shared(). */
	ttls_ecp_point_init(&ctx->p_tmp);

	/*
	 * Allocate memory for the MPIs set in ttls_ecp_gen_keypair()
	 * called from ttls_ecdh_make_params().
	 */
	n_sz = CHARS_TO_LIMBS((grp->nbits + 7) / 8);
	if (ttls_mpi_alloc(&ctx->d, n_sz)
	    || ttls_mpi_alloc(&ctx->Q.X, n_sz * 2)
	    || ttls_mpi_alloc(&ctx->Q.Y, n_sz * 2)
	    || ttls_mpi_alloc(&ctx->Q.Z, n_sz * 2)
	    || ttls_mpi_alloc(&ctx->p_tmp.Z, n_sz * 2))
		return -ENOMEM;

	/* Prepare precomputed points to use them in ecp_mul_comb(). */
	n_sz = (ctx->grp.nbits + w - 1) / w;
	if (ecp_precompute_comb(&ctx->grp, ctx->grp.T, &ctx->grp.G, w, n_sz))
		return -EDOM;

	ttls_mpool_shrink_tailtmp(mp, true);

	return 0;
}

static int
ttls_mpi_profile_create_ec(TlsMpiPool *mp, ttls_ecp_group_id ec)
{
	int r;
	TlsECDHCtx *ecdh_ctx;

	if (!(ecdh_ctx = ttls_mpool_alloc_data(mp, sizeof(*ecdh_ctx))))
		return -ENOMEM;

	switch (ec) {
	case TTLS_ECP_DP_SECP256R1:
		if ((r = __mpi_profile_load_ec(mp, ecdh_ctx, 5, ec)))
			return r;
		break;
	case TTLS_ECP_DP_SECP384R1:
		if ((r = __mpi_profile_load_ec(mp, ecdh_ctx, 6, ec)))
			return r;
		break;
	case TTLS_ECP_DP_CURVE25519:
		/* TODO #1031 nothing to do yet. */
		return 0;
	default:
		WARN_ONCE(1, "There is no EC profile for %d\n", ec);
		return -EINVAL;
	}

	return 0;
}

static int
ttls_mpi_profile_create_dh(TlsMpiPool *mp)
{
	TlsDHMCtx *dhm;

	if (!(dhm = ttls_mpool_alloc_data(mp, sizeof(*dhm))))
		return -ENOMEM;

	return ttls_dhm_load(dhm);
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
		if ((r = ttls_mpi_profile_create_dh(mp)))
			goto cleanup;
		break;
	default:
		T_ERR("Cannot create a memory profile for %s\n", cs->name);
		r = -EINVAL;
	}

cleanup:
	kernel_fpu_end();
	return r;
}

static int
__mpi_profile_clone(TlsCtx *tls, int ec)
{
	char *ptr;
	size_t order;
	TlsMpiPool *mp;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;
	TlsHandshake *hs = tls->hs;

	BUG_ON(ec < 0 || ec >= __TTLS_ECP_DP_N);

	mp = ci->mpi_profile[ec];
	if (WARN_ON_ONCE(!mp)) {
		T_WARN("Try to do %s handshake w/o an MPI profile\n",
		       ci->name);
		return -ENOENT;
	}

	order = get_order(MPI_PROFILE_SZ(mp));
	ptr = (char *)__get_free_pages(GFP_ATOMIC, order);
	if (WARN_ON_ONCE(!ptr))
		return -ENOMEM;

	memcpy_fast(ptr, mp, MPI_PROFILE_SZ(mp));
	hs->crypto_ctx = MPI_POOL_DATA(ptr);

	/*
	 * Adjust the cloned memory pool order, which can be smaller than
	 * the original.
	 */
	mp = (TlsMpiPool *)ptr;
	mp->order = order;
	mp->curr_tail = PAGE_SIZE << order;

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
		free_pages((unsigned long)mp, TTLS_MPOOL_ORDER);
	}
}

int __init
ttls_mpool_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		TlsMpiPool **mp = per_cpu_ptr(&g_tmp_mpool, cpu);
		if (!(*mp = ttls_mpi_pool_alloc(__MPOOL_STACK_ORDER,
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
