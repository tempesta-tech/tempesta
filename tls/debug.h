/**
 *		Tempesta TLS
 *
 * Copyright (C) 2020-2022 Tempesta Technologies, Inc.
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
#ifndef __TTLS_DEBUG_H__
#define __TTLS_DEBUG_H__

/*
 * Affects only TempestaTLS internal debug symbols.
 * Note that pr_debug() depends on DEBUG definition, so
 * always include this file frist!
 */
#undef DEBUG
#if DBG_TLS > 0
#define DEBUG DBG_TLS
#endif
#ifndef BANNER
#define BANNER	"tls"
#endif

#include "lib/log.h"

#define TTLS_LOG_WITH_PEER(tls, fmt, log, ...)				\
do {									\
	if ((tls)->sk->sk_family == AF_INET)				\
		log("[%pI4] " fmt, &(tls)->sk->sk_daddr, ##__VA_ARGS__);\
	else								\
		log("[%pI6c] " fmt, &(tls)->sk->sk_v6_daddr, ##__VA_ARGS__);\
} while (0)

#define TTLS_ERR(tls, fmt, ...)						\
	TTLS_LOG_WITH_PEER(tls, fmt, T_ERR, ##__VA_ARGS__)
#define TTLS_WARN(tls, fmt, ...)					\
	TTLS_LOG_WITH_PEER(tls, fmt, T_WARN, ##__VA_ARGS__)
#define TTLS_LOG(tls, fmt, ...)						\
	TTLS_LOG_WITH_PEER(tls, fmt, T_LOG, ##__VA_ARGS__)

#endif /* __TTLS_DEBUG_H__ */
