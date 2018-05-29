/**
 * \file ripemd160.h
 *
 * \brief RIPE MD-160 message digest
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
#ifndef TTLS_RIPEMD160_H
#define TTLS_RIPEMD160_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define TTLS_ERR_RIPEMD160_HW_ACCEL_FAILED			 -0x0031  /**< RIPEMD160 hardware accelerator failed */

#if !defined(TTLS_RIPEMD160_ALT)

/**
 * \brief		  RIPEMD-160 context structure
 */
typedef struct
{
	uint32_t total[2];		  /*!< number of bytes processed  */
	uint32_t state[5];		  /*!< intermediate digest state  */
	unsigned char buffer[64];   /*!< data block being processed */
}
ttls_ripemd160_context;

/**
 * \brief		  Initialize RIPEMD-160 context
 *
 * \param ctx	  RIPEMD-160 context to be initialized
 */
void ttls_ripemd160_init(ttls_ripemd160_context *ctx);

/**
 * \brief		  Clear RIPEMD-160 context
 *
 * \param ctx	  RIPEMD-160 context to be cleared
 */
void ttls_ripemd160_free(ttls_ripemd160_context *ctx);

/**
 * \brief		  Clone (the state of) an RIPEMD-160 context
 *
 * \param dst	  The destination context
 * \param src	  The context to be cloned
 */
void ttls_ripemd160_clone(ttls_ripemd160_context *dst,
						const ttls_ripemd160_context *src);

/**
 * \brief		  RIPEMD-160 context setup
 *
 * \param ctx	  context to be initialized
 *
 * \return		 0 if successful
 */
int ttls_ripemd160_starts_ret(ttls_ripemd160_context *ctx);

/**
 * \brief		  RIPEMD-160 process buffer
 *
 * \param ctx	  RIPEMD-160 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 *
 * \return		 0 if successful
 */
int ttls_ripemd160_update_ret(ttls_ripemd160_context *ctx,
								  const unsigned char *input,
								  size_t ilen);

/**
 * \brief		  RIPEMD-160 final digest
 *
 * \param ctx	  RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 *
 * \return		 0 if successful
 */
int ttls_ripemd160_finish_ret(ttls_ripemd160_context *ctx,
								  unsigned char output[20]);

/**
 * \brief		  RIPEMD-160 process data block (internal use only)
 *
 * \param ctx	  RIPEMD-160 context
 * \param data	 buffer holding one block of data
 *
 * \return		 0 if successful
 */
int ttls_internal_ripemd160_process(ttls_ripemd160_context *ctx,
										const unsigned char data[64]);

#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		  RIPEMD-160 context setup
 *
 * \deprecated	 Superseded by ttls_ripemd160_starts_ret() in 2.7.0
 *
 * \param ctx	  context to be initialized
 */
TTLS_DEPRECATED void ttls_ripemd160_starts(
											ttls_ripemd160_context *ctx);

/**
 * \brief		  RIPEMD-160 process buffer
 *
 * \deprecated	 Superseded by ttls_ripemd160_update_ret() in 2.7.0
 *
 * \param ctx	  RIPEMD-160 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 */
TTLS_DEPRECATED void ttls_ripemd160_update(
												ttls_ripemd160_context *ctx,
												const unsigned char *input,
												size_t ilen);

/**
 * \brief		  RIPEMD-160 final digest
 *
 * \deprecated	 Superseded by ttls_ripemd160_finish_ret() in 2.7.0
 *
 * \param ctx	  RIPEMD-160 context
 * \param output   RIPEMD-160 checksum result
 */
TTLS_DEPRECATED void ttls_ripemd160_finish(
												ttls_ripemd160_context *ctx,
												unsigned char output[20]);

/**
 * \brief		  RIPEMD-160 process data block (internal use only)
 *
 * \deprecated	 Superseded by ttls_internal_ripemd160_process() in 2.7.0
 *
 * \param ctx	  RIPEMD-160 context
 * \param data	 buffer holding one block of data
 */
TTLS_DEPRECATED void ttls_ripemd160_process(
											ttls_ripemd160_context *ctx,
											const unsigned char data[64]);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#else  /* TTLS_RIPEMD160_ALT */
#include "ripemd160_alt.h"
#endif /* TTLS_RIPEMD160_ALT */

/**
 * \brief		  Output = RIPEMD-160(input buffer)
 *
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 * \param output   RIPEMD-160 checksum result
 *
 * \return		 0 if successful
 */
int ttls_ripemd160_ret(const unsigned char *input,
						   size_t ilen,
						   unsigned char output[20]);

#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		  Output = RIPEMD-160(input buffer)
 *
 * \deprecated	 Superseded by ttls_ripemd160_ret() in 2.7.0
 *
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 * \param output   RIPEMD-160 checksum result
 */
TTLS_DEPRECATED void ttls_ripemd160(const unsigned char *input,
										   size_t ilen,
										   unsigned char output[20]);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#endif /* ttls_ripemd160.h */
