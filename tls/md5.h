/**
 * \file md5.h
 *
 * \brief MD5 message digest algorithm (hash function)
 *
 * \warning   MD5 is considered a weak message digest and its use constitutes a
 *			security risk. We recommend considering stronger message
 *			digests instead.
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
#ifndef TTLS_MD5_H
#define TTLS_MD5_H

#include "config.h"

#define TTLS_ERR_MD5_HW_ACCEL_FAILED				   -0x002F  /**< MD5 hardware accelerator failed */

#if !defined(TTLS_MD5_ALT)
// Regular implementation
//

/**
 * \brief		  MD5 context structure
 *
 * \warning		MD5 is considered a weak message digest and its use
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
ttls_md5_context;

/**
 * \brief		  Initialize MD5 context
 *
 * \param ctx	  MD5 context to be initialized
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md5_init(ttls_md5_context *ctx);

/**
 * \brief		  Clear MD5 context
 *
 * \param ctx	  MD5 context to be cleared
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md5_free(ttls_md5_context *ctx);

/**
 * \brief		  Clone (the state of) an MD5 context
 *
 * \param dst	  The destination context
 * \param src	  The context to be cloned
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
void ttls_md5_clone(ttls_md5_context *dst,
						const ttls_md5_context *src);

/**
 * \brief		  MD5 context setup
 *
 * \param ctx	  context to be initialized
 *
 * \return		 0 if successful
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md5_starts_ret(ttls_md5_context *ctx);

/**
 * \brief		  MD5 process buffer
 *
 * \param ctx	  MD5 context
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 *
 * \return		 0 if successful
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md5_update_ret(ttls_md5_context *ctx,
							const unsigned char *input,
							size_t ilen);

/**
 * \brief		  MD5 final digest
 *
 * \param ctx	  MD5 context
 * \param output   MD5 checksum result
 *
 * \return		 0 if successful
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md5_finish_ret(ttls_md5_context *ctx,
							unsigned char output[16]);

/**
 * \brief		  MD5 process data block (internal use only)
 *
 * \param ctx	  MD5 context
 * \param data	 buffer holding one block of data
 *
 * \return		 0 if successful
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_internal_md5_process(ttls_md5_context *ctx,
								  const unsigned char data[64]);

#else  /* TTLS_MD5_ALT */
#include "md5_alt.h"
#endif /* TTLS_MD5_ALT */

/**
 * \brief		  Output = MD5(input buffer)
 *
 * \param input	buffer holding the data
 * \param ilen	 length of the input data
 * \param output   MD5 checksum result
 *
 * \return		 0 if successful
 *
 * \warning		MD5 is considered a weak message digest and its use
 *				 constitutes a security risk. We recommend considering
 *				 stronger message digests instead.
 *
 */
int ttls_md5_ret(const unsigned char *input,
					 size_t ilen,
					 unsigned char output[16]);

#endif /* ttls_md5.h */
