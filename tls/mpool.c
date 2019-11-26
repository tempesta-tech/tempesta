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

/**
 * MPI memory profile is determined by the certificate key type and size and
 * choosen ciphersuite.
 */
typedef struct {
	TlsMpiProfile		*profile;
} TlsMpiPDesc;

static TlsMpiPDesc mpi_profiles[__TTLS_MPI_PROFILES_N] ____cacheline_aligned;

void
ttls_mpi_profile_init_mpi(TlsMpiProfile *mp)
{
	mp->next = NULL;
	mp->mem_alloc = MPI_PROFILE_DATA(mp);
	mp->size = 0;
}

static int
ttls_mpi_profile_alloc_mpi(TlsMpi *x, size_t n)
{
	void *ptr;
	TlsMpiProfile *mp = MPI_PROFILE(x);

	if (WARN_ON_ONCE(sizeof(*mp) + mp->size + n > PAGE_SIZE))
		return -ENOMEM;

	ptr = mp->mem_alloc;
	BUG_ON(x >= ptr);
	mp->mem_alloc = (void *)((unsigned long)ptr + n);
	mp->size += n;

	return (unsigned long)ptr - (unsigned long)x;
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

static TlsMpiProfile *
ttls_mpi_profile_create_ec(const TlsPkCtx *pkey)
{
	TlsMpiProfile *mp;
	TlsECDHCtx *ecdh_ctx;

	mp = (TlsMpiProfile *)__get_free_pages(GFP_KERNEL| __GFP_ZERO, 0);
	if (!mp)
		return -ENOMEM;

	TlsECDHCtx *ecdh_ctx = MPI_PROFILE_DATA(mp);

	mp_sz += sizeof(TlsECDHCtx);

	// TODO ECDH + each supported cureve for ECDHE + DHM

	r = ttls_ecdh_get_params(ecdh_ctx, ttls_pk_ec(*pkey), TTLS_ECDH_OURS);
	if (r)
		T_DBG("cannot get ECDH params from a certificate, %d\n", r);

	// TODO in progress: ECDH path in ttls_write_server_key_exchange()

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
	TlsMpiProfile *mp;
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
	TlsMpiProfile *prof = tls->peer_conf->mpi_prof;
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
ttls_mpi_profile_exit(void)
{
	int i;

	for (i = 0; i < __TTLS_MPI_PROFILES_N; ++i) {
		if (mpi_profiles[i].profile)
			free_pages(mpi_profiles[i].profile, 0);
	}
}
