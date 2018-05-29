/**
 * \file sha512.h
 *
 * \brief The SHA-384 and SHA-512 cryptographic hash function.
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
#ifndef TTLS_SHA512_H
#define TTLS_SHA512_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define TTLS_ERR_SHA512_HW_ACCEL_FAILED				-0x0039  /**< SHA-512 hardware accelerator failed */

#if !defined(TTLS_SHA512_ALT)
// Regular implementation
//

/**
 * \brief		  The SHA-512 context structure.
 *
 *				 The structure is used both for SHA-384 and for SHA-512
 *				 checksum calculations. The choice between these two is
 *				 made in the call to ttls_sha512_starts_ret().
 */
typedef struct
{
	uint64_t total[2];		  /*!< The number of Bytes processed. */
	uint64_t state[8];		  /*!< The intermediate digest state. */
	unsigned char buffer[128];  /*!< The data block being processed. */
	int is384;				  /*!< Determines which function to use.
								 *   <ul><li>0: Use SHA-512.</li>
								 *   <li>1: Use SHA-384.</li></ul> */
}
ttls_sha512_context;

/**
 * \brief		  This function initializes a SHA-512 context.
 *
 * \param ctx	  The SHA-512 context to initialize.
 */
void ttls_sha512_init(ttls_sha512_context *ctx);

/**
 * \brief		  This function clears a SHA-512 context.
 *
 * \param ctx	  The SHA-512 context to clear.
 */
void ttls_sha512_free(ttls_sha512_context *ctx);

/**
 * \brief		  This function clones the state of a SHA-512 context.
 *
 * \param dst	  The destination context.
 * \param src	  The context to clone.
 */
void ttls_sha512_clone(ttls_sha512_context *dst,
						   const ttls_sha512_context *src);

/**
 * \brief		  This function starts a SHA-384 or SHA-512 checksum
 *				 calculation.
 *
 * \param ctx	  The SHA-512 context to initialize.
 * \param is384	Determines which function to use.
 *				 <ul><li>0: Use SHA-512.</li>
 *				 <li>1: Use SHA-384.</li></ul>
 *
 * \return		 \c 0 on success.
 */
int ttls_sha512_starts_ret(ttls_sha512_context *ctx, int is384);

/**
 * \brief		  This function feeds an input buffer into an ongoing
 *				 SHA-512 checksum calculation.
 *
 * \param ctx	  The SHA-512 context.
 * \param input	The buffer holding the input data.
 * \param ilen	 The length of the input data.
 *
 * \return		 \c 0 on success.
 */
int ttls_sha512_update_ret(ttls_sha512_context *ctx,
					const unsigned char *input,
					size_t ilen);

/**
 * \brief		  This function finishes the SHA-512 operation, and writes
 *				 the result to the output buffer. This function is for
 *				 internal use only.
 *
 * \param ctx	  The SHA-512 context.
 * \param output   The SHA-384 or SHA-512 checksum result.
 *
 * \return		 \c 0 on success.
 */
int ttls_sha512_finish_ret(ttls_sha512_context *ctx,
							   unsigned char output[64]);

/**
 * \brief		  This function processes a single data block within
 *				 the ongoing SHA-512 computation.
 *
 * \param ctx	  The SHA-512 context.
 * \param data	 The buffer holding one block of data.
 *
 * \return		 \c 0 on success.
 */
int ttls_internal_sha512_process(ttls_sha512_context *ctx,
									 const unsigned char data[128]);
#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		  This function starts a SHA-384 or SHA-512 checksum
 *				 calculation.
 *
 * \deprecated	 Superseded by ttls_sha512_starts_ret() in 2.7.0
 *
 * \param ctx	  The SHA-512 context to initialize.
 * \param is384	Determines which function to use.
 *				 <ul><li>0: Use SHA-512.</li>
 *				 <li>1: Use SHA-384.</li></ul>
 */
TTLS_DEPRECATED void ttls_sha512_starts(ttls_sha512_context *ctx,
											   int is384);

/**
 * \brief		  This function feeds an input buffer into an ongoing
 *				 SHA-512 checksum calculation.
 *
 * \deprecated	 Superseded by ttls_sha512_update_ret() in 2.7.0
 *
 * \param ctx	  The SHA-512 context.
 * \param input	The buffer holding the data.
 * \param ilen	 The length of the input data.
 */
TTLS_DEPRECATED void ttls_sha512_update(ttls_sha512_context *ctx,
											   const unsigned char *input,
											   size_t ilen);

/**
 * \brief		  This function finishes the SHA-512 operation, and writes
 *				 the result to the output buffer.
 *
 * \deprecated	 Superseded by ttls_sha512_finish_ret() in 2.7.0
 *
 * \param ctx	  The SHA-512 context.
 * \param output   The SHA-384 or SHA-512 checksum result.
 */
TTLS_DEPRECATED void ttls_sha512_finish(ttls_sha512_context *ctx,
											   unsigned char output[64]);

/**
 * \brief		  This function processes a single data block within
 *				 the ongoing SHA-512 computation. This function is for
 *				 internal use only.
 *
 * \deprecated	 Superseded by ttls_internal_sha512_process() in 2.7.0
 *
 * \param ctx	  The SHA-512 context.
 * \param data	 The buffer holding one block of data.
 */
TTLS_DEPRECATED void ttls_sha512_process(
											ttls_sha512_context *ctx,
											const unsigned char data[128]);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#else  /* TTLS_SHA512_ALT */
#include "sha512_alt.h"
#endif /* TTLS_SHA512_ALT */

/**
 * \brief		  This function calculates the SHA-512 or SHA-384
 *				 checksum of a buffer.
 *
 *				 The function allocates the context, performs the
 *				 calculation, and frees the context.
 *
 *				 The SHA-512 result is calculated as
 *				 output = SHA-512(input buffer).
 *
 * \param input	The buffer holding the input data.
 * \param ilen	 The length of the input data.
 * \param output   The SHA-384 or SHA-512 checksum result.
 * \param is384	Determines which function to use.
 *				 <ul><li>0: Use SHA-512.</li>
 *				 <li>1: Use SHA-384.</li></ul>
 *
 * \return		 \c 0 on success.
 */
int ttls_sha512_ret(const unsigned char *input,
						size_t ilen,
						unsigned char output[64],
						int is384);

#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		  This function calculates the SHA-512 or SHA-384
 *				 checksum of a buffer.
 *
 *				 The function allocates the context, performs the
 *				 calculation, and frees the context.
 *
 *				 The SHA-512 result is calculated as
 *				 output = SHA-512(input buffer).
 *
 * \deprecated	 Superseded by ttls_sha512_ret() in 2.7.0
 *
 * \param input	The buffer holding the data.
 * \param ilen	 The length of the input data.
 * \param output   The SHA-384 or SHA-512 checksum result.
 * \param is384	Determines which function to use.
 *				 <ul><li>0: Use SHA-512.</li>
 *				 <li>1: Use SHA-384.</li></ul>
 */
TTLS_DEPRECATED void ttls_sha512(const unsigned char *input,
										size_t ilen,
										unsigned char output[64],
										int is384);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#endif /* ttls_sha512.h */
