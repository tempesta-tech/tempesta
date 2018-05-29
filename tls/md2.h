/**
 * \file md2.h
 *
 * \brief MD2 message digest algorithm (hash function)
 *
 * \warning MD2 is considered a weak message digest and its use constitutes a
 *		  security risk. We recommend considering stronger message digests
 *		  instead.
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
 *
 */
#ifndef TTLS_MD2_H
#define TTLS_MD2_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>

#define TTLS_ERR_MD2_HW_ACCEL_FAILED				   -0x002B  /**< MD2 hardware accelerator failed */

#if !defined(TTLS_MD2_ALT)
// Regular implementation
//

/**
 * \brief		  MD2 context structure
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
typedef struct
{
	unsigned char cksum[16];	/*!< checksum of the data block */
	unsigned char state[48];	/*!< intermediate digest state  */
	unsigned char buffer[16];   /*!< data block being processed */
	size_t left;				/*!< amount of data in buffer   */
}
ttls_md2_context;

/**
 * \brief		  Initialize MD2 context
 *
 * \param ctx	  MD2 context to be initialized
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md2_init(ttls_md2_context *ctx);

/**
 * \brief		  Clear MD2 context
 *
 * \param ctx	  MD2 context to be cleared
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md2_free(ttls_md2_context *ctx);

/**
 * \brief		  Clone (the state of) an MD2 context
 *
 * \param dst	  The destination context
 * \param src	  The context to be cloned
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md2_clone(ttls_md2_context *dst,
						const ttls_md2_context *src);

/**
 * \brief		  MD2 context setup
 *
 * \param ctx	  context to be initialized
 *
 * \return		 0 if successful
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md2_starts_ret(ttls_md2_context *ctx);

/**
 * \brief		  MD2 process buffer
 *
 * \param ctx	  MD2 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 *
 * \return		 0 if successful
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md2_update_ret(ttls_md2_context *ctx,
							const unsigned char *input,
							size_t ilen);

/**
 * \brief		  MD2 final digest
 *
 * \param ctx	  MD2 context
 * \param output   MD2 checksum result
 *
 * \return		 0 if successful
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md2_finish_ret(ttls_md2_context *ctx,
							unsigned char output[16]);

/**
 * \brief		  MD2 process data block (internal use only)
 *
 * \param ctx	  MD2 context
 *
 * \return		 0 if successful
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_internal_md2_process(ttls_md2_context *ctx);

#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		  MD2 context setup
 *
 * \deprecated	 Superseded by ttls_md2_starts_ret() in 2.7.0
 *
 * \param ctx	  context to be initialized
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
TTLS_DEPRECATED void ttls_md2_starts(ttls_md2_context *ctx);

/**
 * \brief		  MD2 process buffer
 *
 * \deprecated	 Superseded by ttls_md2_update_ret() in 2.7.0
 *
 * \param ctx	  MD2 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
TTLS_DEPRECATED void ttls_md2_update(ttls_md2_context *ctx,
											const unsigned char *input,
											size_t ilen);

/**
 * \brief		  MD2 final digest
 *
 * \deprecated	 Superseded by ttls_md2_finish_ret() in 2.7.0
 *
 * \param ctx	  MD2 context
 * \param output   MD2 checksum result
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
TTLS_DEPRECATED void ttls_md2_finish(ttls_md2_context *ctx,
											unsigned char output[16]);

/**
 * \brief		  MD2 process data block (internal use only)
 *
 * \deprecated	 Superseded by ttls_internal_md2_process() in 2.7.0
 *
 * \param ctx	  MD2 context
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
TTLS_DEPRECATED void ttls_md2_process(ttls_md2_context *ctx);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#else  /* TTLS_MD2_ALT */
#include "md2_alt.h"
#endif /* TTLS_MD2_ALT */

/**
 * \brief		  Output = MD2(input buffer)
 *
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 * \param output   MD2 checksum result
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md2_ret(const unsigned char *input,
					 size_t ilen,
					 unsigned char output[16]);

#if !defined(TTLS_DEPRECATED_REMOVED)
#if defined(TTLS_DEPRECATED_WARNING)
#define TTLS_DEPRECATED	  __attribute__((deprecated))
#else
#define TTLS_DEPRECATED
#endif
/**
 * \brief		  Output = MD2(input buffer)
 *
 * \deprecated	 Superseded by ttls_md2_ret() in 2.7.0
 *
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 * \param output   MD2 checksum result
 *
 * \warning		MD2 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
TTLS_DEPRECATED void ttls_md2(const unsigned char *input,
									 size_t ilen,
									 unsigned char output[16]);

#undef TTLS_DEPRECATED
#endif /* !TTLS_DEPRECATED_REMOVED */

#endif /* ttls_md2.h */
