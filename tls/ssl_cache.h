/**
 * \file ssl_cache.h
 *
 * \brief SSL session cache implementation
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
#ifndef TTLS_SSL_CACHE_H
#define TTLS_SSL_CACHE_H

#include "ttls.h"

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(TTLS_SSL_CACHE_DEFAULT_TIMEOUT)
#define TTLS_SSL_CACHE_DEFAULT_TIMEOUT	   86400   /*!< 1 day  */
#endif

#if !defined(TTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES)
#define TTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES	  50   /*!< Maximum entries in cache */
#endif

typedef struct ttls_ssl_cache_context ttls_ssl_cache_context;
typedef struct ttls_ssl_cache_entry ttls_ssl_cache_entry;

/**
 * \brief   This structure is used for storing cache entries
 */
struct ttls_ssl_cache_entry
{
	time_t timestamp;		   /*!< entry timestamp	*/
	TtlsSess session;		/*!< entry session	  */
	ttls_x509_buf peer_cert;		 /*!< entry peer_cert	*/
	ttls_ssl_cache_entry *next;	  /*!< chain pointer	  */
};

/**
 * \brief Cache context
 */
struct ttls_ssl_cache_context
{
	ttls_ssl_cache_entry *chain;	 /*!< start of the chain	 */
	int timeout;				/*!< cache entry timeout	*/
	int max_entries;			/*!< maximum entries		*/
	spinlock_t mutex;	/*!< mutex				  */
};

/**
 * \brief		  Initialize an SSL cache context
 *
 * \param cache	SSL cache context
 */
void ttls_ssl_cache_init(ttls_ssl_cache_context *cache);

/**
 * \brief		  Cache get callback implementation
 *
 * \param data	 SSL cache context
 * \param session  session to retrieve entry for
 */
int ttls_ssl_cache_get(void *data, TtlsSess *session);

/**
 * \brief		  Cache set callback implementation
 *
 * \param data	 SSL cache context
 * \param session  session to store entry for
 */
int ttls_ssl_cache_set(void *data, const TtlsSess *session);

/**
 * \brief		  Set the cache timeout
 *				 (Default: TTLS_SSL_CACHE_DEFAULT_TIMEOUT (1 day))
 *
 *				 A timeout of 0 indicates no timeout.
 *
 * \param cache	SSL cache context
 * \param timeout  cache entry timeout in seconds
 */
void ttls_ssl_cache_set_timeout(ttls_ssl_cache_context *cache, int timeout);

/**
 * \brief		  Set the maximum number of cache entries
 *				 (Default: TTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES (50))
 *
 * \param cache	SSL cache context
 * \param max	  cache entry maximum
 */
void ttls_ssl_cache_set_max_entries(ttls_ssl_cache_context *cache, int max);

/**
 * \brief		  Free referenced items in a cache context and clear memory
 *
 * \param cache	SSL cache context
 */
void ttls_ssl_cache_free(ttls_ssl_cache_context *cache);

#endif /* ssl_cache.h */
