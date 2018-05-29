/**
 * \file md4.h
 *
 * \brief MD4 message digest algorithm (hash function)
 *
 * \warning MD4 is considered a weak message digest and its use constitutes a
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
#ifndef TTLS_MD4_H
#define TTLS_MD4_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define TTLS_ERR_MD4_HW_ACCEL_FAILED				   -0x002D  /**< MD4 hardware accelerator failed */

#if !defined(TTLS_MD4_ALT)
// Regular implementation
//

/**
 * \brief		  MD4 context structure
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
typedef struct
{
	uint32_t total[2];		  /*!< number of bytes processed  */
	uint32_t state[4];		  /*!< intermediate digest state  */
	unsigned char buffer[64];   /*!< data block being processed */
}
ttls_md4_context;

/**
 * \brief		  Initialize MD4 context
 *
 * \param ctx	  MD4 context to be initialized
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md4_init(ttls_md4_context *ctx);

/**
 * \brief		  Clear MD4 context
 *
 * \param ctx	  MD4 context to be cleared
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md4_free(ttls_md4_context *ctx);

/**
 * \brief		  Clone (the state of) an MD4 context
 *
 * \param dst	  The destination context
 * \param src	  The context to be cloned
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md4_clone(ttls_md4_context *dst,
						const ttls_md4_context *src);

/**
 * \brief		  MD4 context setup
 *
 * \param ctx	  context to be initialized
 *
 * \return		 0 if successful
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 */
int ttls_md4_starts_ret(ttls_md4_context *ctx);

/**
 * \brief		  MD4 process buffer
 *
 * \param ctx	  MD4 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 *
 * \return		 0 if successful
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md4_update_ret(ttls_md4_context *ctx,
							const unsigned char *input,
							size_t ilen);

/**
 * \brief		  MD4 final digest
 *
 * \param ctx	  MD4 context
 * \param output   MD4 checksum result
 *
 * \return		 0 if successful
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md4_finish_ret(ttls_md4_context *ctx,
							unsigned char output[16]);

/**
 * \brief		  MD4 process data block (internal use only)
 *
 * \param ctx	  MD4 context
 * \param data	 buffer holding one block of data
 *
 * \return		 0 if successful
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_internal_md4_process(ttls_md4_context *ctx,
								  const unsigned char data[64]);

#else  /* TTLS_MD4_ALT */
#include "md4_alt.h"
#endif /* TTLS_MD4_ALT */

/**
 * \brief		  Output = MD4(input buffer)
 *
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 * \param output   MD4 checksum result
 *
 * \return		 0 if successful
 *
 * \warning		MD4 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md4_ret(const unsigned char *input,
					 size_t ilen,
					 unsigned char output[16]);

#endif /* ttls_md4.h */
