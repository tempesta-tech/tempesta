/**
 *		Tempesta TLS
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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

#define TTLS_LOG_WITH_PEER(tls, action_expr)			\
do {								\
	struct sockaddr_storage _tls_peer_ss;			\
	struct sockaddr_storage *_tls_peer_sa = &_tls_peer_ss;	\
	if (ttls_extract_peer_addr(tls, _tls_peer_sa))		\
		_tls_peer_sa = NULL;				\
	action_expr;						\
} while (0)

#define TTLS_PEER_FMT "[c=%pISp] "
#define TTLS_ERR(tls, fmt, ...) TTLS_LOG_WITH_PEER(tls, \
	T_ERR(TTLS_PEER_FMT fmt, _tls_peer_sa, ##__VA_ARGS__))
#define TTLS_WARN(tls, fmt, ...) TTLS_LOG_WITH_PEER(tls, \
	T_WARN(TTLS_PEER_FMT fmt, _tls_peer_sa, ##__VA_ARGS__))
#define TTLS_LOG(tls, fmt, ...) TTLS_LOG_WITH_PEER(tls, \
	T_LOG(TTLS_PEER_FMT fmt, _tls_peer_sa, ##__VA_ARGS__))

#endif /* __TTLS_DEBUG_H__ */
