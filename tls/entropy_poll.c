/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ENTROPY_C)

#include "entropy.h"
#include "entropy_poll.h"

#include <string.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#if defined(MBEDTLS_HAVEGE_C)
#include "havege.h"
#endif
#if defined(MBEDTLS_ENTROPY_NV_SEED)
#include "platform.h"
#endif

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)

#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32)
#error "Platform entropy sources only work on Unix and Windows, see MBEDTLS_NO_PLATFORM_ENTROPY in config.h"
#endif

#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */

#if defined(MBEDTLS_TEST_NULL_ENTROPY)
int mbedtls_null_entropy_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    ((void) data);
    ((void) output);
    *olen = 0;

    if( len < sizeof(unsigned char) )
        return( 0 );

    *olen = sizeof(unsigned char);

    return( 0 );
}
#endif

int mbedtls_hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    unsigned long timer = get_cycles();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);

    return( 0 );
}

#if defined(MBEDTLS_HAVEGE_C)
int mbedtls_havege_poll( void *data,
                 unsigned char *output, size_t len, size_t *olen )
{
    mbedtls_havege_state *hs = (mbedtls_havege_state *) data;
    *olen = 0;

    if( mbedtls_havege_random( hs, output, len ) != 0 )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    *olen = len;

    return( 0 );
}
#endif /* MBEDTLS_HAVEGE_C */

#if defined(MBEDTLS_ENTROPY_NV_SEED)
int mbedtls_nv_seed_poll( void *data,
                          unsigned char *output, size_t len, size_t *olen )
{
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    ((void) data);

    memset( buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE );

    if( mbedtls_nv_seed_read( buf, MBEDTLS_ENTROPY_BLOCK_SIZE ) < 0 )
      return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    if( len < use_len )
      use_len = len;

    memcpy( output, buf, use_len );
    *olen = use_len;

    return( 0 );
}
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#endif /* MBEDTLS_ENTROPY_C */
