/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_TIMING_C)
#include <linux/string.h>
#include "timing.h"
#endif
#if defined(MBEDTLS_HAVEGE_C)
#include "havege.h"
#endif

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>
#include <wincrypt.h>

int mbedtls_platform_entropy_poll( void *data, unsigned char *output, size_t len,
                           size_t *olen )
{
    HCRYPTPROV provider;
    ((void) data);
    *olen = 0;

    if( CryptAcquireContext( &provider, NULL, NULL,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) == FALSE )
    {
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    if( CryptGenRandom( provider, (DWORD) len, output ) == FALSE )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    CryptReleaseContext( provider, 0 );
    *olen = len;

    return( 0 );
}
#else /* _WIN32 && !EFIX64 && !EFI32 */

/*
 * Test for Linux getrandom() support.
 * Since there is no wrapper in the libc yet, use the generic syscall wrapper
 * available in GNU libc and compatible libc's (eg uClibc).
 */
#if defined(__linux__) && defined(__GLIBC__)
#include <unistd.h>
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define HAVE_GETRANDOM

static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
    /* MemSan cannot understand that the syscall writes to the buffer */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset( buf, 0, buflen );
#endif
#endif

    return( syscall( SYS_getrandom, buf, buflen, flags ) );
}

#include <sys/utsname.h>
/* Check if version is at least 3.17.0 */
static int check_version_3_17_plus( void )
{
    int minor;
    struct utsname un;
    const char *ver;

    /* Get version information */
    uname(&un);
    ver = un.release;

    /* Check major version; assume a single digit */
    if( ver[0] < '3' || ver[0] > '9' || ver [1] != '.' )
        return( -1 );

    if( ver[0] - '0' > 3 )
        return( 0 );

    /* Ok, so now we know major == 3, check minor.
     * Assume 1 or 2 digits. */
    if( ver[2] < '0' || ver[2] > '9' )
        return( -1 );

    minor = ver[2] - '0';

    if( ver[3] >= '0' && ver[3] <= '9' )
        minor = 10 * minor + ver[3] - '0';
    else if( ver [3] != '.' )
        return( -1 );

    if( minor < 17 )
        return( -1 );

    return( 0 );
}
static int has_getrandom = -1;
#endif /* SYS_getrandom */
#endif /* __linux__ */

#include <stdio.h>

int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
    FILE *file;
    size_t read_len;
    ((void) data);

#if defined(HAVE_GETRANDOM)
    if( has_getrandom == -1 )
        has_getrandom = ( check_version_3_17_plus() == 0 );

    if( has_getrandom )
    {
        int ret;

        if( ( ret = getrandom_wrapper( output, len, 0 ) ) < 0 )
            return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

        *olen = ret;
        return( 0 );
    }
#endif /* HAVE_GETRANDOM */

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    read_len = fread( output, 1, len, file );
    if( read_len != len )
    {
        fclose( file );
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
    *olen = len;

    return( 0 );
}
#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */

#if defined(MBEDTLS_TIMING_C)
int mbedtls_hardclock_poll( void *data,
                    unsigned char *output, size_t len, size_t *olen )
{
    unsigned long timer = mbedtls_timing_hardclock();
    ((void) data);
    *olen = 0;

    if( len < sizeof(unsigned long) )
        return( 0 );

    memcpy( output, &timer, sizeof(unsigned long) );
    *olen = sizeof(unsigned long);

    return( 0 );
}
#endif /* MBEDTLS_TIMING_C */

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

#endif /* MBEDTLS_ENTROPY_C */
