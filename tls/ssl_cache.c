/*
 *  SSL session cache implementation
 *
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
/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SSL_CACHE_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include "ssl_cache.h"

#include <string.h>

void mbedtls_ssl_cache_init( mbedtls_ssl_cache_context *cache )
{
    memset( cache, 0, sizeof( mbedtls_ssl_cache_context ) );

    cache->timeout = MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT;
    cache->max_entries = MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES;
    spin_lock_init( &cache->mutex );
}

int mbedtls_ssl_cache_get( void *data, mbedtls_ssl_session *session )
{
    int ret = 1;
    time_t t = mbedtls_time( NULL );
    mbedtls_ssl_cache_context *cache = (mbedtls_ssl_cache_context *) data;
    mbedtls_ssl_cache_entry *cur, *entry;

    spin_lock( &cache->mutex );

    cur = cache->chain;
    entry = NULL;

    while( cur != NULL )
    {
        entry = cur;
        cur = cur->next;

        if( cache->timeout != 0 &&
            (int) ( t - entry->timestamp ) > cache->timeout )
            continue;

        if( session->ciphersuite != entry->session.ciphersuite ||
            session->compression != entry->session.compression ||
            session->id_len != entry->session.id_len )
            continue;

        if( memcmp( session->id, entry->session.id,
                    entry->session.id_len ) != 0 )
            continue;

        memcpy( session->master, entry->session.master, 48 );

        session->verify_result = entry->session.verify_result;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
        /*
         * Restore peer certificate (without rest of the original chain)
         */
        if( entry->peer_cert.p != NULL )
        {
            if( ( session->peer_cert = mbedtls_calloc( 1,
                                 sizeof(mbedtls_x509_crt) ) ) == NULL )
            {
                ret = 1;
                goto exit;
            }

            mbedtls_x509_crt_init( session->peer_cert );
            if( mbedtls_x509_crt_parse( session->peer_cert, entry->peer_cert.p,
                                entry->peer_cert.len ) != 0 )
            {
                mbedtls_free( session->peer_cert );
                session->peer_cert = NULL;
                ret = 1;
                goto exit;
            }
        }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

        ret = 0;
        goto exit;
    }

exit:
    spin_unlock( &cache->mutex );

    return( ret );
}

int mbedtls_ssl_cache_set( void *data, const mbedtls_ssl_session *session )
{
    int ret = 1;
    time_t t = mbedtls_time( NULL ), oldest = 0;
    mbedtls_ssl_cache_entry *old = NULL;
    mbedtls_ssl_cache_context *cache = (mbedtls_ssl_cache_context *) data;
    mbedtls_ssl_cache_entry *cur, *prv;
    int count = 0;

    spin_lock( &cache->mutex );

    cur = cache->chain;
    prv = NULL;

    while( cur != NULL )
    {
        count++;

        if( cache->timeout != 0 &&
            (int) ( t - cur->timestamp ) > cache->timeout )
        {
            cur->timestamp = t;
            break; /* expired, reuse this slot, update timestamp */
        }

        if( memcmp( session->id, cur->session.id, cur->session.id_len ) == 0 )
            break; /* client reconnected, keep timestamp for session id */

        if( oldest == 0 || cur->timestamp < oldest )
        {
            oldest = cur->timestamp;
            old = cur;
        }

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
        /*
         * Reuse oldest entry if max_entries reached
         */
        if( count >= cache->max_entries )
        {
            if( old == NULL )
            {
                ret = 1;
                goto exit;
            }

            cur = old;
        }
        else
        {
            /*
             * max_entries not reached, create new entry
             */
            cur = mbedtls_calloc( 1, sizeof(mbedtls_ssl_cache_entry) );
            if( cur == NULL )
            {
                ret = 1;
                goto exit;
            }

            if( prv == NULL )
                cache->chain = cur;
            else
                prv->next = cur;
        }

        cur->timestamp = t;
    }

    memcpy( &cur->session, session, sizeof( mbedtls_ssl_session ) );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /*
     * If we're reusing an entry, free its certificate first
     */
    if( cur->peer_cert.p != NULL )
    {
        mbedtls_free( cur->peer_cert.p );
        memset( &cur->peer_cert, 0, sizeof(mbedtls_x509_buf) );
    }

    /*
     * Store peer certificate
     */
    if( session->peer_cert != NULL )
    {
        cur->peer_cert.p = mbedtls_calloc( 1, session->peer_cert->raw.len );
        if( cur->peer_cert.p == NULL )
        {
            ret = 1;
            goto exit;
        }

        memcpy( cur->peer_cert.p, session->peer_cert->raw.p,
                session->peer_cert->raw.len );
        cur->peer_cert.len = session->peer_cert->raw.len;

        cur->session.peer_cert = NULL;
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    ret = 0;

exit:
    spin_unlock( &cache->mutex );

    return( ret );
}

void mbedtls_ssl_cache_set_timeout( mbedtls_ssl_cache_context *cache, int timeout )
{
    if( timeout < 0 ) timeout = 0;

    cache->timeout = timeout;
}

void mbedtls_ssl_cache_set_max_entries( mbedtls_ssl_cache_context *cache, int max )
{
    if( max < 0 ) max = 0;

    cache->max_entries = max;
}

void mbedtls_ssl_cache_free( mbedtls_ssl_cache_context *cache )
{
    mbedtls_ssl_cache_entry *cur, *prv;

    cur = cache->chain;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        mbedtls_ssl_session_free( &prv->session );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
        mbedtls_free( prv->peer_cert.p );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

        mbedtls_free( prv );
    }

    cache->chain = NULL;
}

#endif /* MBEDTLS_SSL_CACHE_C */
