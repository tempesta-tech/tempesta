/**
 *		Tempesta TLS mocks for the unit tests
 *
 * Copyright (C) 2021 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#define NO_RSA_FUNC
#include "ttls_mocks.h"

/*
 * md_* mocks are required for RSA tests.
 */

void
ttls_md_init(TlsMdCtx *ctx)
{
}

void
ttls_md_free(TlsMdCtx *ctx)
{
}

int
ttls_md_finish(TlsMdCtx *ctx, unsigned char *output)
{
	switch (ctx->md_info->type) {
	case TTLS_MODE_NONE:
		BUG();
	case TTLS_MD_SHA256:
		memset(output, 0, 32);
		return 0;
	case TTLS_MD_SHA384:
		memset(output, 0, 48);
		return 0;
	case TTLS_MD_SHA512:
		memset(output, 0, 64);
		return 0;
	}
	return 0;
}

int
ttls_md(const TlsMdInfo *md_info, const unsigned char *input,
		   size_t ilen, unsigned char *output)
{
	return 0;
}

int
ttls_md_setup(TlsMdCtx *ctx, const TlsMdInfo *md_info, int hmac)
{
	return 0;
}

const TlsMdInfo *
ttls_md_info_from_type(ttls_md_type_t md_type)
{
	static struct shash_alg shash = {
		.digestsize = 32,
	};
	static const TlsMdInfo md_info = {
		.type = TTLS_MD_SHA256,
		.alg_hash = &shash.base,
	};
	return &md_info;
}

int
ttls_md_starts(TlsMdCtx *ctx)
{
	return 0;
}

int
ttls_md_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen)
{
	return 0;
}

int
ttls_oid_get_oid_by_md(ttls_md_type_t md_alg, const char **oid, size_t *olen)
{
	static const char OID[1] = {0};

	*oid = OID;
	*olen = 1;

	return 0;
}

void __attribute__((weak))
ttls_mpi_pool_cleanup_ctx(unsigned long addr, bool zero)
{
	BUG();
}

int __attribute__((weak))
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n)
{
	BUG();
}

void __attribute__((weak))
ttls_mpi_pool_free(void *ctx)
{
	BUG();
}

TlsMpiPool * __attribute__((weak))
ttls_mpool(void *addr)
{
	BUG();
}
