/*
 *		Tempesta TLS
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
 *
 * Based on mbed TLS, https://tls.mbed.org.
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

/* Affects only TempestaTLS internal debug symbols. */
#if DBG_TLS == 0
#undef DEBUG
#endif

#ifndef BANNER
#define BANNER	"tls"
#endif
#include "lib/log.h"

#ifdef DEBUG

void __log_mpis(size_t n, const char *msg, ...);
void ttls_debug_print_crt(const char *file, int line, const char *msg,
			  const ttls_x509_crt *crt);

#define T_DBG_MPI1(msg, x1)		__log_mpis(1, msg, #x1, x1)
#define T_DBG_MPI2(msg, x1, x2)		__log_mpis(2, msg, #x1, x1, #x2, x2)
#define T_DBG_MPI3(msg, x1, x2, x3)					\
	__log_mpis(3, msg, #x1, x1, #x2, x2, #x3, x3)
#define T_DBG_MPI4(msg, x1, x2, x3, x4)					\
	__log_mpis(3, msg, #x1, x1, #x2, x2, #x3, x3, #x4, x4)

/* Print MPIs and data structures containing MPIs on higest debug level only. */
#if DEBUG == 3

#define T_DBG_ECP(msg, x)		__log_mpis(2, msg, (x)->X, (x)->Y)

#define T_DBG_CRT(text, crt)						\
	ttls_debug_print_crt(__FILE__, __LINE__, text, crt)

/*
 * Make the things repeatable, simple and INSECURE on largest debug level -
 * this helps to debug TLS (thanks to reproducible records payload), but
 * must not be used in any security sensitive installations.
 */
static inline void
ttls_rnd(void *buf, size_t len)
{
	memset(buf, 0x55, len);
}

unsigned long ttls_time_debug(void);

#define ttls_time()		ttls_time_debug()

#endif /* highest debug level */
#else /* no debugging at all */

#define T_DBG_MPI1(...)
#define T_DBG_MPI2(...)
#define T_DBG_MPI3(...)
#define T_DBG_MPI4(...)
#define T_DBG_ECP(msg, x)
#define T_DBG_CRT(text, crt)

#define ttls_time()		get_seconds()
#define ttls_rnd(buf, len)	get_random_bytes_arch(buf, len)
#endif

#endif /* TTLS_DEBUG_H */
