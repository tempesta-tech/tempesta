/*
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
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
#ifndef TTLS_DEBUG_H
#define TTLS_DEBUG_H

#include "ttls.h"
#include "ecp.h"

#define BANNER	"tls"
#include "lib/log.h"

#if defined(DEBUG) && (DEBUG == 3)

#define TTLS_DEBUG_STRIP_PARENS(...)   __VA_ARGS__

#define TTLS_DEBUG_MSG(level, args)		\
	ttls_debug_print_msg(ssl, level, __FILE__, __LINE__,		\
			     TTLS_DEBUG_STRIP_PARENS args)

#define TTLS_DEBUG_RET(level, text, ret)				\
	ttls_debug_print_ret(ssl, level, __FILE__, __LINE__, text, ret)

#define TTLS_DEBUG_BUF(level, text, buf, len)			\
	ttls_debug_print_buf(ssl, level, __FILE__, __LINE__, text, buf, len)

#define TTLS_DEBUG_MPI(level, text, X)				\
	ttls_debug_print_mpi(ssl, level, __FILE__, __LINE__, text, X)

#define TTLS_DEBUG_ECP(level, text, X)				\
	ttls_debug_print_ecp(ssl, level, __FILE__, __LINE__, text, X)

#define TTLS_DEBUG_CRT(level, text, crt)				\
	ttls_debug_print_crt(ssl, level, __FILE__, __LINE__, text, crt)

/**
 * \brief   Set the threshold error level to handle globally all debug output.
 *		  Debug messages that have a level over the threshold value are
 *		  discarded.
 *		  (Default value: 0 = No debug)
 *
 * \param threshold	 theshold level of messages to filter on. Messages at a
 *		  higher level will be discarded.
 *			  - Debug levels
 *				  - 0 No debug
 *				  - 1 Error
 *				  - 2 State change
 *				  - 3 Informational
 *				  - 4 Verbose
 */
void ttls_debug_set_threshold(int threshold);

/**
 * \brief	Print a message to the debug output. This function is always used
 *		  through the TTLS_DEBUG_MSG() macro, which supplies the ssl
 *		  context, file and line number parameters.
 *
 * \param ssl	   SSL context
 * \param level	 error level of the debug message
 * \param file	  file the message has occurred in
 * \param line	  line number the message has occurred at
 * \param format	format specifier, in printf format
 * \param ...	   variables used by the format specifier
 *
 * \attention	   This function is intended for INTERNAL usage within the
 *				  library only.
 */
void ttls_debug_print_msg(const ttls_context *ssl, int level,
			  const char *file, int line,
			  const char *format, ...);

/**
 * \brief   Print the return value of a function to the debug output. This
 *		  function is always used through the TTLS_DEBUG_RET() macro,
 *		  which supplies the ssl context, file and line number parameters.
 *
 * \param ssl	   SSL context
 * \param level	 error level of the debug message
 * \param file	  file the error has occurred in
 * \param line	  line number the error has occurred in
 * \param text	  the name of the function that returned the error
 * \param ret	   the return code value
 *
 * \attention	   This function is intended for INTERNAL usage within the
 *				  library only.
 */
void ttls_debug_print_ret(const ttls_context *ssl, int level,
			  const char *file, int line,
			  const char *text, int ret);

/**
 * \brief   Output a buffer of size len bytes to the debug output. This function
 *		  is always used through the TTLS_DEBUG_BUF() macro,
 *		  which supplies the ssl context, file and line number parameters.
 *
 * \param ssl	   SSL context
 * \param level	 error level of the debug message
 * \param file	  file the error has occurred in
 * \param line	  line number the error has occurred in
 * \param text	  a name or label for the buffer being dumped. Normally the
 *				  variable or buffer name
 * \param buf	   the buffer to be outputted
 * \param len	   length of the buffer
 *
 * \attention	   This function is intended for INTERNAL usage within the
 *				  library only.
 */
void ttls_debug_print_buf(const ttls_context *ssl, int level,
			  const char *file, int line, const char *text,
			  const unsigned char *buf, size_t len);

/**
 * \brief   Print a MPI variable to the debug output. This function is always
 *		  used through the TTLS_DEBUG_MPI() macro, which supplies the
 *		  ssl context, file and line number parameters.
 *
 * \param ssl	   SSL context
 * \param level	 error level of the debug message
 * \param file	  file the error has occurred in
 * \param line	  line number the error has occurred in
 * \param text	  a name or label for the MPI being output. Normally the
 *				  variable name
 * \param X		 the MPI variable
 *
 * \attention	   This function is intended for INTERNAL usage within the
 *				  library only.
 */
void ttls_debug_print_mpi(const ttls_context *ssl, int level,
			  const char *file, int line,
			  const char *text, const ttls_mpi *X);

/**
 * \brief   Print an ECP point to the debug output. This function is always
 *		  used through the TTLS_DEBUG_ECP() macro, which supplies the
 *		  ssl context, file and line number parameters.
 *
 * \param ssl	   SSL context
 * \param level	 error level of the debug message
 * \param file	  file the error has occurred in
 * \param line	  line number the error has occurred in
 * \param text	  a name or label for the ECP point being output. Normally the
 *				  variable name
 * \param X		 the ECP point
 *
 * \attention	   This function is intended for INTERNAL usage within the
 *				  library only.
 */
void ttls_debug_print_ecp(const ttls_context *ssl, int level,
			  const char *file, int line,
			  const char *text, const ttls_ecp_point *X);

/**
 * \brief   Print a X.509 certificate structure to the debug output. This
 *		  function is always used through the TTLS_DEBUG_CRT() macro,
 *		  which supplies the ssl context, file and line number parameters.
 *
 * \param ssl	   SSL context
 * \param level	 error level of the debug message
 * \param file	  file the error has occurred in
 * \param line	  line number the error has occurred in
 * \param text	  a name or label for the certificate being output
 * \param crt	   X.509 certificate structure
 *
 * \attention	   This function is intended for INTERNAL usage within the
 *				  library only.
 */
void ttls_debug_print_crt(const ttls_context *ssl, int level,
			  const char *file, int line,
			  const char *text, const ttls_x509_crt *crt);

/**
 * Print data in hex format from scatter list @sg starting at offset @off and
 * of length @len.
 */
void ttls_dbg_print_scatterlist(const char *str, struct scatterlist *sg,
				unsigned int sgn, unsigned int off,
				unsigned int len);

#else

#define TTLS_DEBUG_MSG(level, args)
#define TTLS_DEBUG_RET(level, text, ret)
#define TTLS_DEBUG_BUF(level, text, buf, len)
#define TTLS_DEBUG_MPI(level, text, X)
#define TTLS_DEBUG_ECP(level, text, X)
#define TTLS_DEBUG_CRT(level, text, crt)

#define T_DBG3_SL(str, sg, off, len)

#endif

#endif /* debug.h */

