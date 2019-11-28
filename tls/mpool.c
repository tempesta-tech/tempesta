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
 * MPI memory profile.
 *
 * TLS handshakes uses public key cryptography calculations executing a lot
 * of MPI operations, so temporal MPIs are required and many MPIs change their
 * sizes. To avoid dynamic memory allocations we use the MPI profiles -
 * statically pregenerated set of initialized MPIs which are just copied in
 * single shot on a handshake. An MPI profile contains all the memory required
 * to perform all PK computations for a perticular handshake type (RSA, EC etc).
 * The PK type is determined at Vhost certificate loading and a new static MPI
 * profile is created if necessary.
 *
 * @curr	- offset of free memory area for MPI allocations;
 * @size	- size of the profile to allocate and copy for a particular
 *		  handshake;
 */
typedef struct tls_mpi_profile_t {
	void				*mem_alloc;
	size_t				size;
} TlsMpiPool;

/**
 * MPI memory profile is determined by the certificate key type and size and
 * choosen ciphersuite.
 */
typedef struct {
	TlsMpiPool		*profile;
} TlsMpiPDesc;

/* Profile types. */
typedef enum {
	TTLS_MPI_PROFILE_ECDH,
	TTLS_MPI_PROFILE_DHM,
	TTLS_MPI_PROFILE_ECDHE_SECP256,
	TTLS_MPI_PROFILE_ECDHE_SECP384,
	TTLS_MPI_PROFILE_ECDHE_SECP521,
	TTLS_MPI_PROFILE_ECDHE_BP256,
	TTLS_MPI_PROFILE_ECDHE_BP384,
	TTLS_MPI_PROFILE_ECDHE_BP521,
	__TTLS_MPI_PROFILES_N
} ttls_mpi_profile_t;

#define MPI_POOL_DATA(mp)	((void *)((char *)(mp) + sizeof(TlsMpiPool)))
#define MPI_POOL_FREE_PTR(mp)	((void *)((char *)(mp) + sizeof(TlsMpiPool) \
					  + mp->curr))

/*
 * Static memory profiles for all types of crypto handshakes.
 * MPIs from the pool live during the whole handshake process.
 */
static TlsMpiPDesc mpi_profiles[__TTLS_MPI_PROFILES_N] ____cacheline_aligned;
/*
 * Memory pool for temporal (stack allocated) MPIs which are used only during
 * one call of the TLS handshake state machine.
 */
static DEFINE_PER_CPU(TlsMpiPool *, g_tmp_mpool);

void
ttls_mpi_profile_init_mpi(TlsMpiPool *mp)
{
	mp->next = NULL;
	mp->mem_alloc = 0;
	mp->size = 0;
}

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

static
ttls_mpi_profile_alloc_mpi(TlsMpi *x, size_t n)
{
	void *ptr;
	TlsMpiPool *mp = __mpi_profile(x);

	if (WARN_ON_ONCE(sizeof(*mp) + mp->size + n > PAGE_SIZE))
		return -ENOMEM;

	ptr = MPI_POOL_FREE_PTR(mp);
	BUG_ON(x >= ptr);
	mp->curr += n;
	mp->size += n; // TODO do we need the size?

	return (unsigned long)ptr - (unsigned long)x;
}

/**
 * Cleanup current CPU memory pool for temporary MPIs.
 */
void
ttls_mpi_cleanup_ctx(void)
{
	TlsMpiPool *mp = *this_cpu_ptr(&g_tmp_mpool);
	void *data = MPI_POOL_DATA(mp);

	BUG_ON(mp->mem_alloc < data);
	BUG_ON(mp->curr > mp->size);

	bzero_fast(data, mp->curr);
	mp->curr = 0;
}

static bool
ttls_mpi_profile_for_cert(int pid, const TlsPkCtx *pkey)
{
	/* TODO #1064 implement the proper switch cases. */
	switch (pkey->pk_info->type) {
	case TTLS_PK_ECKEY:
		if (id == TTLS_MPI_PROFILE_ECDH)
			return true;
		return false;
	case TTLS_PK_ECKEY_DH:
		return false;
	case TTLS_PK_ECDSA:
		return false;
	case TTLS_PK_RSA:
		return false;
	default:
		T_ERR("Cannot match a memory profile %d to PK %d\n",
		      i, pkey->pk_info->type);
	}
	return false;
}

static TlsMpiPool *
ttls_mpi_profile_create_ec(const TlsPkCtx *pkey)
{
	int r;
	TlsMpiPool *mp;
	TlsECDHCtx *ecdh_ctx;

	mp = (TlsMpiPool *)__get_free_pages(GFP_KERNEL| __GFP_ZERO, 0);
	if (!mp)
		return NULL;
	ecdh_ctx = MPI_POOL_DATA(mp);

	r = ttls_ecdh_get_params(ecdh_ctx, ttls_pk_ec(*pkey), TTLS_ECDH_OURS);
	if (r) {
		T_DBG("cannot get ECDH params from a certificate, %d\n", r);
		return NULL;
	}

	// TODO in progress: ECDH path in ttls_parse_client_key_exchange() ->
	// ttls_ecdh_calc_secret() -> ecp_check_pubkey_sw()

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

		if (!mp) {
			switch (pkey->pk_info->type) {
			case TTLS_PK_ECKEY:
			case TTLS_PK_ECKEY_DH:
			case TTLS_PK_ECDSA:
				if (!(mp = ttls_mpi_profile_create_ec(pkey)))
					return -EINVAL;
				break;
			case TTLS_PK_RSA:
				/* TODO #1064. */
				ttls_dhm_init(&hs->dhm_ctx);
				break;
			default:
				T_ERR("Cannot create a memory profile"
				      " for a PK %d\n", pkey->pk_info->type);
			}
		}
		mpi_profiles[i].profile = mp;

		++n;
	}
	if (n == __TTLS_MPI_PROFILES_N)
		has_empty_profile = false;

	return 0;
}
EXPORT_SYMBOL(ttls_mpi_profile_set);

/**
 * Determines the appropriate MPI memory profile and initizes ready to use MPI
 * context for the handshake.
 */
int
ttls_mpi_profile_alloc(TlsCtx *tls)
{
	TlsHandshake *hs = tls->hs;
	TlsMpiPool *prof = tls->peer_conf->mpi_prof;
	const TlsCiphersuite *ci = tls->xfrm.ciphersuite_info;

	// TODO #1064: copy the 2K data, extend prof if necessary

	if (ttls_ciphersuite_uses_ecdh(ci) ||
	    ttls_ciphersuite_uses_ecdhe(ci))
	{

	} else {

	}

	return 0;
}

void
ttls_mpool_exit(void)
{
	int i;

	for (i = 0; i < __TTLS_MPI_PROFILES_N; ++i) {
		if (mpi_profiles[i].profile)
			free_pages(mpi_profiles[i].profile, 0);
	}

	for_each_possible_cpu(i) {
		TlsMpiPool **ptr = per_cpu_ptr(&g_tmp_pool, i);
		memset(MPI_POOL_DATA(*ptr), 0, (*ptr)->curr);
		free_pages(*ptr, 0);
	}
}

int __init
ttls_mpool_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		TlsMpiPool **mp = per_cpu_ptr(&g_tmp_pool, cpu);
		*mp = (TlsMpiPool *)__get_free_pages(GFP_KERNEL| __GFP_ZERO, 0);
		if (!*mp)
			goto err_cleanup;
	}

	return 0;
err_cleanup:
	ttls_mpool_exit();
	return -ENOMEM;
}
