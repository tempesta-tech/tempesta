/*
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
#ifndef TTLS_DEBUG_H
#define TTLS_DEBUG_H

#include "ttls.h"
#include "ecp.h"

#ifndef BANNER
#define BANNER	"tls"
#endif
#include "lib/log.h"

#if defined(DEBUG) && (DEBUG == 3)

#define TTLS_DEBUG_MPI(text, X)						\
	ttls_debug_print_mpi(tls, __FILE__, __LINE__, text, X)

#define TTLS_DEBUG_ECP(text, X)						\
	ttls_debug_print_ecp(tls, __FILE__, __LINE__, text, X)

#define TTLS_DEBUG_CRT(text, crt)					\
	ttls_debug_print_crt(tls, __FILE__, __LINE__, text, crt)

void ttls_debug_print_mpi(const ttls_context *tls, const char *file, int line,
			  const char *text, const ttls_mpi *X);
void ttls_debug_print_ecp(const ttls_context *tls, const char *file, int line,
			  const char *text, const ttls_ecp_point *X);
void ttls_debug_print_crt(const ttls_context *tls, const char *file, int line,
			  const char *text, const ttls_x509_crt *crt);
void ttls_dbg_print_scatterlist(const char *str, struct scatterlist *sg,
				unsigned int sgn, unsigned int off,
				unsigned int len);

#else

#define TTLS_DEBUG_MPI(text, X)		do { } while (0)
#define TTLS_DEBUG_ECP(text, X)		do { } while (0)
#define TTLS_DEBUG_CRT(text, crt)	do { } while (0)

#endif

#endif /* debug.h */

