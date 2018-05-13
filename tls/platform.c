/*
 *  Platform abstraction layer
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_PLATFORM_C)

#include "platform.h"

#if defined(MBEDTLS_PLATFORM_MEMORY)
#if !defined(MBEDTLS_PLATFORM_STD_CALLOC)
static void *platform_calloc_uninit( size_t n, size_t size )
{
	((void) n);
	((void) size);
	return( NULL );
}

#define MBEDTLS_PLATFORM_STD_CALLOC   platform_calloc_uninit
#endif /* !MBEDTLS_PLATFORM_STD_CALLOC */

#if !defined(MBEDTLS_PLATFORM_STD_FREE)
static void platform_free_uninit( void *ptr )
{
	((void) ptr);
}

#define MBEDTLS_PLATFORM_STD_FREE	 platform_free_uninit
#endif /* !MBEDTLS_PLATFORM_STD_FREE */

void * (*mbedtls_calloc)( size_t, size_t ) = MBEDTLS_PLATFORM_STD_CALLOC;
void (*mbedtls_free)( void * )	 = MBEDTLS_PLATFORM_STD_FREE;

int mbedtls_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
							  void (*free_func)( void * ) )
{
	mbedtls_calloc = calloc_func;
	mbedtls_free = free_func;
	return( 0 );
}
#endif /* MBEDTLS_PLATFORM_MEMORY */

#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_SNPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_snprintf_uninit( char * s, size_t n,
									 const char * format, ... )
{
	((void) s);
	((void) n);
	((void) format);
	return( 0 );
}

#define MBEDTLS_PLATFORM_STD_SNPRINTF	platform_snprintf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_SNPRINTF */

int (*mbedtls_snprintf)( char * s, size_t n,
						  const char * format,
						  ... ) = MBEDTLS_PLATFORM_STD_SNPRINTF;

int mbedtls_platform_set_snprintf( int (*snprintf_func)( char * s, size_t n,
												 const char * format,
												 ... ) )
{
	mbedtls_snprintf = snprintf_func;
	return( 0 );
}
#endif /* MBEDTLS_PLATFORM_SNPRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_PRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_PRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_printf_uninit( const char *format, ... )
{
	((void) format);
	return( 0 );
}

#define MBEDTLS_PLATFORM_STD_PRINTF	platform_printf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_PRINTF */

int (*mbedtls_printf)( const char *, ... ) = MBEDTLS_PLATFORM_STD_PRINTF;

int mbedtls_platform_set_printf( int (*printf_func)( const char *, ... ) )
{
	mbedtls_printf = printf_func;
	return( 0 );
}
#endif /* MBEDTLS_PLATFORM_PRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_FPRINTF)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static int platform_fprintf_uninit( FILE *stream, const char *format, ... )
{
	((void) stream);
	((void) format);
	return( 0 );
}

#define MBEDTLS_PLATFORM_STD_FPRINTF   platform_fprintf_uninit
#endif /* !MBEDTLS_PLATFORM_STD_FPRINTF */

int (*mbedtls_fprintf)( FILE *, const char *, ... ) =
										MBEDTLS_PLATFORM_STD_FPRINTF;

int mbedtls_platform_set_fprintf( int (*fprintf_func)( FILE *, const char *, ... ) )
{
	mbedtls_fprintf = fprintf_func;
	return( 0 );
}
#endif /* MBEDTLS_PLATFORM_FPRINTF_ALT */

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_EXIT)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static void platform_exit_uninit( int status )
{
	((void) status);
}

#define MBEDTLS_PLATFORM_STD_EXIT   platform_exit_uninit
#endif /* !MBEDTLS_PLATFORM_STD_EXIT */

void (*mbedtls_exit)( int status ) = MBEDTLS_PLATFORM_STD_EXIT;

int mbedtls_platform_set_exit( void (*exit_func)( int status ) )
{
	mbedtls_exit = exit_func;
	return( 0 );
}
#endif /* MBEDTLS_PLATFORM_EXIT_ALT */

#if defined(MBEDTLS_PLATFORM_TIME_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_TIME)
/*
 * Make dummy function to prevent NULL pointer dereferences
 */
static time_t platform_time_uninit( mbedtls_time_t* timer )
{
	((void) timer);
	return( 0 );
}

#define MBEDTLS_PLATFORM_STD_TIME   platform_time_uninit
#endif /* !MBEDTLS_PLATFORM_STD_TIME */

time_t (*mbedtls_time)( mbedtls_time_t* timer ) = MBEDTLS_PLATFORM_STD_TIME;

int mbedtls_platform_set_time( time_t (*time_func)( mbedtls_time_t* timer ) )
{
	mbedtls_time = time_func;
	return( 0 );
}
#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#if !defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)
/*
 * Placeholder platform setup that does nothing by default
 */
int mbedtls_platform_setup( mbedtls_platform_context *ctx )
{
	(void)ctx;

	return( 0 );
}

/*
 * Placeholder platform teardown that does nothing by default
 */
void mbedtls_platform_teardown( mbedtls_platform_context *ctx )
{
	(void)ctx;
}
#endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT */

#endif /* MBEDTLS_PLATFORM_C */
