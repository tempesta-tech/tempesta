/**
 * \file platform.h
 *
 * \brief The Mbed TLS platform abstraction layer.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H

#include "config.h"

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#if !defined(MBEDTLS_PLATFORM_STD_EXIT)
#define MBEDTLS_PLATFORM_STD_EXIT	  exit /**< The default \c exit function to use. */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_EXIT_SUCCESS)
#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS /**< The default exit value to use. */
#endif
#if !defined(MBEDTLS_PLATFORM_STD_EXIT_FAILURE)
#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE /**< The default exit value to use. */
#endif
#else /* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */
#if defined(MBEDTLS_PLATFORM_STD_MEM_HDR)
#include MBEDTLS_PLATFORM_STD_MEM_HDR
#endif
#endif /* MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */


/* \} name SECTION: Module settings */

/*
 * The function pointers for calloc and free
 */
#if defined(MBEDTLS_PLATFORM_MEMORY)
#if defined(MBEDTLS_PLATFORM_FREE_MACRO) && \
	defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
#define mbedtls_free	   MBEDTLS_PLATFORM_FREE_MACRO
#define mbedtls_calloc	 MBEDTLS_PLATFORM_CALLOC_MACRO
#else
/* For size_t */
#include <stddef.h>
extern void * (*mbedtls_calloc)(size_t n, size_t size);
extern void (*mbedtls_free)(void *ptr);

/**
 * \brief   This function allows configuring custom memory-management functions.
 *
 * \param calloc_func   The \c calloc function implementation.
 * \param free_func	 The \c free function implementation.
 *
 * \return			  \c 0.
 */
int mbedtls_platform_set_calloc_free(void * (*calloc_func)(size_t, size_t),
							  void (*free_func)(void *));
#endif /* MBEDTLS_PLATFORM_FREE_MACRO && MBEDTLS_PLATFORM_CALLOC_MACRO */
#else /* !MBEDTLS_PLATFORM_MEMORY */
#define mbedtls_free	   free
#define mbedtls_calloc	 calloc
#endif /* MBEDTLS_PLATFORM_MEMORY && !MBEDTLS_PLATFORM_{FREE,CALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
/* We need FILE * */
#include <stdio.h>
extern int (*mbedtls_fprintf)(FILE *stream, const char *format, ...);

/**
 * \brief   This function allows configuring a custom \p fprintf function pointer.
 *
 * \param fprintf_func   The \c fprintf function implementation.
 *
 * \return			   \c 0.
 */
int mbedtls_platform_set_fprintf(int (*fprintf_func)(FILE *stream, const char *,
											   ...));
#else
#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO)
#define mbedtls_fprintf	MBEDTLS_PLATFORM_FPRINTF_MACRO
#else
#define mbedtls_fprintf	fprintf
#endif /* MBEDTLS_PLATFORM_FPRINTF_MACRO */
#endif /* MBEDTLS_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for snprintf
 *
 * The snprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(_WIN32)
/* For Windows (inc. MSYS2), we provide our own fixed implementation */
int mbedtls_platform_win32_snprintf(char *s, size_t n, const char *fmt, ...);
#endif

/*
 * The function pointers for exit
 */
#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
extern void (*mbedtls_exit)(int status);

/**
 * \brief   This function allows configuring a custom \c exit function
 *		  pointer.
 *
 * \param exit_func   The \c exit function implementation.
 *
 * \return  \c 0 on success.
 */
int mbedtls_platform_set_exit(void (*exit_func)(int status));
#else
#if defined(MBEDTLS_PLATFORM_EXIT_MACRO)
#define mbedtls_exit   MBEDTLS_PLATFORM_EXIT_MACRO
#else
#define mbedtls_exit   exit
#endif /* MBEDTLS_PLATFORM_EXIT_MACRO */
#endif /* MBEDTLS_PLATFORM_EXIT_ALT */

/*
 * The default exit values
 */
#if defined(MBEDTLS_PLATFORM_STD_EXIT_SUCCESS)
#define MBEDTLS_EXIT_SUCCESS MBEDTLS_PLATFORM_STD_EXIT_SUCCESS
#else
#define MBEDTLS_EXIT_SUCCESS 0
#endif
#if defined(MBEDTLS_PLATFORM_STD_EXIT_FAILURE)
#define MBEDTLS_EXIT_FAILURE MBEDTLS_PLATFORM_STD_EXIT_FAILURE
#else
#define MBEDTLS_EXIT_FAILURE 1
#endif

/**
 * \brief   The platform context structure.
 *
 * \note	This structure may be used to assist platform-specific
 *		  setup or teardown operations.
 */
typedef struct {
	char dummy; /**< Placeholder member, as empty structs are not portable. */
}
mbedtls_platform_context;

/**
 * \brief   This function performs any platform initialization operations.
 *
 * \param   ctx	 The Mbed TLS context.
 *
 * \return  \c 0 on success.
 *
 * \note	This function is intended to allow platform-specific initialization,
 *		  and should be called before any other library functions. Its
 *		  implementation is platform-specific, and unless
 *		  platform-specific code is provided, it does nothing.
 *
 *		  Its use and whether it is necessary to call it is dependent on the
 *		  platform.
 */
int mbedtls_platform_setup(mbedtls_platform_context *ctx);
/**
 * \brief   This function performs any platform teardown operations.
 *
 * \param   ctx	 The Mbed TLS context.
 *
 * \note	This function should be called after every other Mbed TLS module
 *		  has been correctly freed using the appropriate free function.
 *		  Its implementation is platform-specific, and unless
 *		  platform-specific code is provided, it does nothing.
 *
 *		  Its use and whether it is necessary to call it is dependent on the
 *		  platform.
 */
void mbedtls_platform_teardown(mbedtls_platform_context *ctx);

#endif /* platform.h */
