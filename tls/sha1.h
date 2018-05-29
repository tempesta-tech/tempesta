/**
 * \file sha1.h
 *
 * \brief The SHA-1 cryptographic hash function.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *			a security risk. We recommend considering stronger message
 *			digests instead.
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
#ifndef TTLS_SHA1_H
#define TTLS_SHA1_H

#include "config.h"

#define TTLS_ERR_SHA1_HW_ACCEL_FAILED				  -0x0035  /**< SHA-1 hardware accelerator failed */

#if !defined(TTLS_SHA1_ALT)
// Regular implementation
//

/**
 * \brief		  The SHA-1 context structure.
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
typedef struct
{
	uint32_t total[2];		  /*!< The number of Bytes processed.  */
	uint32_t state[5];		  /*!< The intermediate digest state.  */
	unsigned char buffer[64];   /*!< The data block being processed. */
}
ttls_sha1_context;

/**
 * \brief		  This function initializes a SHA-1 context.
 *
 * \param ctx	  The SHA-1 context to initialize.
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_sha1_init(ttls_sha1_context *ctx);

/**
 * \brief		  This function clears a SHA-1 context.
 *
 * \param ctx	  The SHA-1 context to clear.
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_sha1_free(ttls_sha1_context *ctx);

/**
 * \brief		  This function clones the state of a SHA-1 context.
 *
 * \param dst	  The destination context.
 * \param src	  The context to clone.
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_sha1_clone(ttls_sha1_context *dst,
						 const ttls_sha1_context *src);

/**
 * \brief		  This function starts a SHA-1 checksum calculation.
 *
 * \param ctx	  The context to initialize.
 *
 * \return		 \c 0 if successful
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_sha1_starts_ret(ttls_sha1_context *ctx);

/**
 * \brief		  This function feeds an input buffer into an ongoing SHA-1
 *				 checksum calculation.
 *
 * \param ctx	  The SHA-1 context.
 * \param input	The buffer holding the input data.
 * \param ilen	 The length of the input data.
 *
 * \return		 \c 0 if successful
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_sha1_update_ret(ttls_sha1_context *ctx,
							 const unsigned char *input,
							 size_t ilen);

/**
 * \brief		  This function finishes the SHA-1 operation, and writes
 *				 the result to the output buffer.
 *
 * \param ctx	  The SHA-1 context.
 * \param output   The SHA-1 checksum result.
 *
 * \return		 \c 0 if successful
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_sha1_finish_ret(ttls_sha1_context *ctx,
							 unsigned char output[20]);

/**
 * \brief		  SHA-1 process data block (internal use only)
 *
 * \param ctx	  SHA-1 context
 * \param data	 The data block being processed.
 *
 * \return		 \c 0 if successful
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_internal_sha1_process(ttls_sha1_context *ctx,
								   const unsigned char data[64]);

#else  /* TTLS_SHA1_ALT */
#include "sha1_alt.h"
#endif /* TTLS_SHA1_ALT */

/**
 * \brief		  This function calculates the SHA-1 checksum of a buffer.
 *
 *				 The function allocates the context, performs the
 *				 calculation, and frees the context.
 *
 *				 The SHA-1 result is calculated as
 *				 output = SHA-1(input buffer).
 *
 * \param input	The buffer holding the input data.
 * \param ilen	 The length of the input data.
 * \param output   The SHA-1 checksum result.
 *
 * \return		 \c 0 if successful
 *
 * \warning		SHA-1 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_sha1_ret(const unsigned char *input,
					  size_t ilen,
					  unsigned char output[20]);

#endif /* ttls_sha1.h */
