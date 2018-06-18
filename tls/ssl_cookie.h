/**
 * \file ssl_cookie.h
 *
 * \brief DTLS cookie callbacks implementation
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef TTLS_SSL_COOKIE_H
#define TTLS_SSL_COOKIE_H

#include "ttls.h"

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */
#ifndef TTLS_SSL_COOKIE_TIMEOUT
#define TTLS_SSL_COOKIE_TIMEOUT	 60 /**< Default expiration delay of DTLS cookies, in seconds */
#endif

/* \} name SECTION: Module settings */

/**
 * \brief		  Context for the default cookie functions.
 */
typedef struct
{
	ttls_md_context_t	hmac_ctx;   /*!< context for the HMAC portion   */
	unsigned long   serial;	 /*!< serial number for expiration   */
	unsigned long   timeout;	/*!< timeout delay, in seconds */
	spinlock_t mutex;
} ttls_ssl_cookie_ctx;

/**
 * \brief		  Initialize cookie context
 */
void ttls_ssl_cookie_init(ttls_ssl_cookie_ctx *ctx);

/**
 * \brief		  Setup cookie context (generate keys)
 */
int ttls_ssl_cookie_setup(ttls_ssl_cookie_ctx *ctx,
					  int (*f_rng)(void *, unsigned char *, size_t),
					  void *p_rng);

/**
 * \brief		  Set expiration delay for cookies
 *				 (Default TTLS_SSL_COOKIE_TIMEOUT)
 *
 * \param ctx	  Cookie contex
 * \param delay	Delay, in seconds if.
 *				 0 to disable expiration (NOT recommended)
 */
void ttls_ssl_cookie_set_timeout(ttls_ssl_cookie_ctx *ctx, unsigned long delay);

/**
 * \brief		  Free cookie context
 */
void ttls_ssl_cookie_free(ttls_ssl_cookie_ctx *ctx);

/**
 * \brief		  Generate cookie, see \c ttls_ssl_cookie_write_t
 */
ttls_ssl_cookie_write_t ttls_ssl_cookie_write;

/**
 * \brief		  Verify cookie, see \c ttls_ssl_cookie_write_t
 */
ttls_ssl_cookie_check_t ttls_ssl_cookie_check;

#endif /* ssl_cookie.h */
