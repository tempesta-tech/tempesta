/*
 *		Tempesta TLS
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
#ifndef __TFW_MPOOL_H__
#define __TFW_MPOOL_H__

#include "tls_internal.h"

TlsMpiPool *ttls_mpool(void *addr);
void *ttls_mpool_alloc_stack(size_t n);
void *ttls_mpool_alloc_data(TlsMpiPool *mp, size_t n);
int ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n);
TlsMpiPool *ttls_mpi_pool_create(size_t order, gfp_t gfp_mask);
void ttls_mpi_pool_free(void *ctx);
int ttls_mpi_profile_clone(TlsCtx *tls);
void ttls_mpi_pool_cleanup_ctx(unsigned long addr, bool zero);

int ttls_mpool_init(void);
void ttls_mpool_exit(void);

#endif /* __TFW_MPOOL_H__ */
