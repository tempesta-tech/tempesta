/**
 * \file entropy.h
 *
 * \brief Entropy accumulator implementation
 */
/*
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
#ifndef TTLS_ENTROPY_H
#define TTLS_ENTROPY_H

#if !defined(TTLS_CONFIG_FILE)
#include "config.h"
#else
#include TTLS_CONFIG_FILE
#endif

#include <stddef.h>

#if defined(TTLS_SHA512_C) && !defined(TTLS_ENTROPY_FORCE_SHA256)
#include "sha512.h"
#define TTLS_ENTROPY_SHA512_ACCUMULATOR
#else
#if defined(TTLS_SHA256_C)
#define TTLS_ENTROPY_SHA256_ACCUMULATOR
#include "sha256.h"
#endif
#endif

#if defined(TTLS_HAVEGE_C)
#include "havege.h"
#endif

#define TTLS_ERR_ENTROPY_SOURCE_FAILED				 -0x003C  /**< Critical entropy source failure. */
#define TTLS_ERR_ENTROPY_MAX_SOURCES				   -0x003E  /**< No more sources can be added. */
#define TTLS_ERR_ENTROPY_NO_SOURCES_DEFINED			-0x0040  /**< No sources have been added to poll. */
#define TTLS_ERR_ENTROPY_NO_STRONG_SOURCE			  -0x003D  /**< No strong sources have been added to poll. */
#define TTLS_ERR_ENTROPY_FILE_IO_ERROR				 -0x003F  /**< Read/write error in file. */

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(TTLS_ENTROPY_MAX_SOURCES)
#define TTLS_ENTROPY_MAX_SOURCES	 20	  /**< Maximum number of sources supported */
#endif

#if !defined(TTLS_ENTROPY_MAX_GATHER)
#define TTLS_ENTROPY_MAX_GATHER	  128	 /**< Maximum amount requested from entropy sources */
#endif

/* \} name SECTION: Module settings */

#if defined(TTLS_ENTROPY_SHA512_ACCUMULATOR)
#define TTLS_ENTROPY_BLOCK_SIZE	  64	  /**< Block size of entropy accumulator (SHA-512) */
#else
#define TTLS_ENTROPY_BLOCK_SIZE	  32	  /**< Block size of entropy accumulator (SHA-256) */
#endif

#define TTLS_ENTROPY_MAX_SEED_SIZE   1024	/**< Maximum size of seed we read from seed file */
#define TTLS_ENTROPY_SOURCE_MANUAL   TTLS_ENTROPY_MAX_SOURCES

#define TTLS_ENTROPY_SOURCE_STRONG   1	   /**< Entropy source is strong   */
#define TTLS_ENTROPY_SOURCE_WEAK	 0	   /**< Entropy source is weak	 */

/**
 * \brief		   Entropy poll callback pointer
 *
 * \param data	  Callback-specific data pointer
 * \param output	Data to fill
 * \param len	   Maximum size to provide
 * \param olen	  The actual amount of bytes put into the buffer (Can be 0)
 *
 * \return		  0 if no critical failures occurred,
 *				  TTLS_ERR_ENTROPY_SOURCE_FAILED otherwise
 */
typedef int (*ttls_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len,
							size_t *olen);

/**
 * \brief		   Entropy source state
 */
typedef struct
{
	ttls_entropy_f_source_ptr	f_source;   /**< The entropy source callback */
	void *		  p_source;   /**< The callback data pointer */
	size_t		  size;	   /**< Amount received in bytes */
	size_t		  threshold;  /**< Minimum bytes required before release */
	int			 strong;	 /**< Is the source strong? */
}
ttls_entropy_source_state;

/**
 * \brief		   Entropy context structure
 */
typedef struct
{
	int accumulator_started;
#if defined(TTLS_ENTROPY_SHA512_ACCUMULATOR)
	ttls_sha512_context  accumulator;
#else
	ttls_sha256_context  accumulator;
#endif
	int			 source_count;
	ttls_entropy_source_state	source[TTLS_ENTROPY_MAX_SOURCES];
#if defined(TTLS_HAVEGE_C)
	ttls_havege_state	havege_data;
#endif
	spinlock_t mutex;	/*!< mutex				  */
}
ttls_entropy_context;

/**
 * \brief		   Initialize the context
 *
 * \param ctx	   Entropy context to initialize
 */
void ttls_entropy_init(ttls_entropy_context *ctx);

/**
 * \brief		   Free the data in the context
 *
 * \param ctx	   Entropy context to free
 */
void ttls_entropy_free(ttls_entropy_context *ctx);

/**
 * \brief		   Adds an entropy source to poll
 *
 * \param ctx	   Entropy context
 * \param f_source  Entropy function
 * \param p_source  Function data
 * \param threshold Minimum required from source before entropy is released
 *				  (with ttls_entropy_func()) (in bytes)
 * \param strong	TTLS_ENTROPY_SOURCE_STRONG or
 *				  MBEDTSL_ENTROPY_SOURCE_WEAK.
 *				  At least one strong source needs to be added.
 *				  Weaker sources (such as the cycle counter) can be used as
 *				  a complement.
 *
 * \return		  0 if successful or TTLS_ERR_ENTROPY_MAX_SOURCES
 */
int ttls_entropy_add_source(ttls_entropy_context *ctx,
						ttls_entropy_f_source_ptr f_source, void *p_source,
						size_t threshold, int strong);

/**
 * \brief		   Trigger an extra gather poll for the accumulator
 *
 * \param ctx	   Entropy context
 *
 * \return		  0 if successful, or TTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int ttls_entropy_gather(ttls_entropy_context *ctx);

/**
 * \brief		   Retrieve entropy from the accumulator
 *				  (Maximum length: TTLS_ENTROPY_BLOCK_SIZE)
 *
 * \param data	  Entropy context
 * \param output	Buffer to fill
 * \param len	   Number of bytes desired, must be at most TTLS_ENTROPY_BLOCK_SIZE
 *
 * \return		  0 if successful, or TTLS_ERR_ENTROPY_SOURCE_FAILED
 */
int ttls_entropy_func(void *data, unsigned char *output, size_t len);

/**
 * \brief		   Add data to the accumulator manually
 *
 * \param ctx	   Entropy context
 * \param data	  Data to add
 * \param len	   Length of data
 *
 * \return		  0 if successful
 */
int ttls_entropy_update_manual(ttls_entropy_context *ctx,
						   const unsigned char *data, size_t len);

#endif /* entropy.h */
