/**
 * \file sha256.h
 *
 * \brief The SHA-224 and SHA-256 cryptographic hash function.
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
#ifndef TTLS_SHA256_H
#define TTLS_SHA256_H

#include "config.h"

#define TTLS_ERR_SHA256_HW_ACCEL_FAILED				-0x0037  /**< SHA-256 hardware accelerator failed */

#if !defined(TTLS_SHA256_ALT)
// Regular implementation
//

/**
 * \brief		  The SHA-256 context structure.
 *
 *				 The structure is used both for SHA-256 and for SHA-224
 *				 checksum calculations. The choice between these two is
 *				 made in the call to ttls_sha256_starts_ret().
 */
typedef struct
{
	uint32_t total[2];		  /*!< The number of Bytes processed.  */
	uint32_t state[8];		  /*!< The intermediate digest state.  */
	unsigned char buffer[64];   /*!< The data block being processed. */
	int is224;				  /*!< Determines which function to use.
									 <ul><li>0: Use SHA-256.</li>
									 <li>1: Use SHA-224.</li></ul> */
}
ttls_sha256_context;

/**
 * \brief		  This function initializes a SHA-256 context.
 *
 * \param ctx	  The SHA-256 context to initialize.
 */
void ttls_sha256_init(ttls_sha256_context *ctx);

/**
 * \brief		  This function clears a SHA-256 context.
 *
 * \param ctx	  The SHA-256 context to clear.
 */
void ttls_sha256_free(ttls_sha256_context *ctx);

/**
 * \brief		  This function clones the state of a SHA-256 context.
 *
 * \param dst	  The destination context.
 * \param src	  The context to clone.
 */
void ttls_sha256_clone(ttls_sha256_context *dst,
						   const ttls_sha256_context *src);

/**
 * \brief		  This function starts a SHA-224 or SHA-256 checksum
 *				 calculation.
 *
 * \param ctx	  The context to initialize.
 * \param is224	Determines which function to use.
 *				 <ul><li>0: Use SHA-256.</li>
 *				 <li>1: Use SHA-224.</li></ul>
 *
 * \return		 \c 0 on success.
 */
int ttls_sha256_starts_ret(ttls_sha256_context *ctx, int is224);

/**
 * \brief		  This function feeds an input buffer into an ongoing
 *				 SHA-256 checksum calculation.
 *
 * \param ctx	  SHA-256 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 *
 * \return		 \c 0 on success.
 */
int ttls_sha256_update_ret(ttls_sha256_context *ctx,
							   const unsigned char *input,
							   size_t ilen);

/**
 * \brief		  This function finishes the SHA-256 operation, and writes
 *				 the result to the output buffer.
 *
 * \param ctx	  The SHA-256 context.
 * \param output   The SHA-224 or SHA-256 checksum result.
 *
 * \return		 \c 0 on success.
 */
int ttls_sha256_finish_ret(ttls_sha256_context *ctx,
							   unsigned char output[32]);

/**
 * \brief		  This function processes a single data block within
 *				 the ongoing SHA-256 computation. This function is for
 *				 internal use only.
 *
 * \param ctx	  The SHA-256 context.
 * \param data	 The buffer holding one block of data.
 *
 * \return		 \c 0 on success.
 */
int ttls_internal_sha256_process(ttls_sha256_context *ctx,
									 const unsigned char data[64]);

#else  /* TTLS_SHA256_ALT */
#include "sha256_alt.h"
#endif /* TTLS_SHA256_ALT */

/**
 * \brief		  This function calculates the SHA-224 or SHA-256
 *				 checksum of a buffer.
 *
 *				 The function allocates the context, performs the
 *				 calculation, and frees the context.
 *
 *				 The SHA-256 result is calculated as
 *				 output = SHA-256(input buffer).
 *
 * \param input	The buffer holding the input data.
 * \param ilen	 The length of the input data.
 * \param output   The SHA-224 or SHA-256 checksum result.
 * \param is224	Determines which function to use.
 *				 <ul><li>0: Use SHA-256.</li>
 *				 <li>1: Use SHA-224.</li></ul>
 */
int ttls_sha256_ret(const unsigned char *input,
						size_t ilen,
						unsigned char output[32],
						int is224);

#endif /* ttls_sha256.h */
