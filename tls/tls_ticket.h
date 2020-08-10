/**
 *		Tempesta TLS
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#ifndef TTLS_TICKET_H
#define TTLS_TICKET_H

#include "crypto.h"

int ttls_ticket_write(TlsCtx *ctx, unsigned char *buf,
		      size_t buf_sz, size_t *tlen,
		      uint32_t *ticket_lifetime);
int ttls_ticket_parse(TlsCtx *ctx, unsigned char *buf, size_t len);

int ttls_tickets_configure(TlsPeerCfg *cfg, unsigned long lifetime,
			   const char *secret_str, size_t len,
			   const char *vhost_name, size_t vn_len);
int ttls_tickets_clean(TlsPeerCfg *cfg);
int ttls_tickets_init(void);
void ttls_tickets_exit(void);

#endif /* ssl_ticket.h */
