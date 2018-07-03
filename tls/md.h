 /**
 * \file md.h
 *
 * \brief The generic message-digest wrapper.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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

#ifndef TTLS_MD_H
#define TTLS_MD_H

#include "config.h"

#define TTLS_ERR_MD_FEATURE_UNAVAILABLE				-0x5080  /**< The selected feature is not available. */
#define TTLS_ERR_MD_BAD_INPUT_DATA		 -0x5100  /**< Bad input parameters to function. */
#define TTLS_ERR_MD_ALLOC_FAILED		   -0x5180  /**< Failed to allocate memory. */
#define TTLS_ERR_MD_FILE_IO_ERROR		  -0x5200  /**< Opening or reading of file failed. */
#define TTLS_ERR_MD_HW_ACCEL_FAILED		-0x5280  /**< MD hardware accelerator failed. */

/**
 * \brief	 Enumeration of supported message digests
 *
 * \warning   MD2, MD4, MD5 and SHA-1 are considered weak message digests and
 *			their use constitutes a security risk. We recommend considering
 *			stronger message digests instead.
 *
 */
typedef enum {
	TTLS_MD_NONE=0,
	TTLS_MD_MD2,
	TTLS_MD_MD4,
	TTLS_MD_MD5,
	TTLS_MD_SHA1,
	TTLS_MD_SHA224,
	TTLS_MD_SHA256,
	TTLS_MD_SHA384,
	TTLS_MD_SHA512,
	TTLS_MD_RIPEMD160,
} ttls_md_type_t;

#define TTLS_MD_MAX_SIZE		 64  /* longest known is SHA512 */

/**
 * Opaque struct defined in md_internal.h.
 */
typedef struct ttls_md_info_t ttls_md_info_t;

/**
 * The generic message-digest context.
 */
typedef struct {
	/** Information about the associated message digest. */
	const ttls_md_info_t *md_info;

	/** The digest-specific context. */
	void *md_ctx;

	/** The HMAC part of the context. */
	void *hmac_ctx;
} ttls_md_context_t;

/**
 * \brief		   This function returns the list of digests supported by the
 *				  generic digest module.
 *
 * \return		  A statically allocated array of digests. Each element
 *				  in the returned list is an integer belonging to the
 *				  message-digest enumeration #ttls_md_type_t.
 *				  The last entry is 0.
 */
const int *ttls_md_list(void);

/**
 * \brief		   This function returns the message-digest information
 *				  associated with the given digest name.
 *
 * \param md_name   The name of the digest to search for.
 *
 * \return		  The message-digest information associated with \p md_name,
 *				  or NULL if not found.
 */
const ttls_md_info_t *ttls_md_info_from_string(const char *md_name);

/**
 * \brief		   This function returns the message-digest information
 *				  associated with the given digest type.
 *
 * \param md_type   The type of digest to search for.
 *
 * \return		  The message-digest information associated with \p md_type,
 *				  or NULL if not found.
 */
const ttls_md_info_t *ttls_md_info_from_type(ttls_md_type_t md_type);

/**
 * \brief		   This function initializes a message-digest context without
 *				  binding it to a particular message-digest algorithm.
 *
 *				  This function should always be called first. It prepares the
 *				  context for ttls_md_setup() for binding it to a
 *				  message-digest algorithm.
 */
void ttls_md_init(ttls_md_context_t *ctx);

/**
 * \brief		   This function clears the internal structure of \p ctx and
 *				  frees any embedded internal structure, but does not free
 *				  \p ctx itself.
 *
 *				  If you have called ttls_md_setup() on \p ctx, you must
 *				  call ttls_md_free() when you are no longer using the
 *				  context.
 *				  Calling this function if you have previously
 *				  called ttls_md_init() and nothing else is optional.
 *				  You must not call this function if you have not called
 *				  ttls_md_init().
 */
void ttls_md_free(ttls_md_context_t *ctx);

/**
 * \brief		   This function selects the message digest algorithm to use,
 *				  and allocates internal structures.
 *
 *				  It should be called after ttls_md_init() or
 *				  ttls_md_free(). Makes it necessary to call
 *				  ttls_md_free() later.
 *
 * \param ctx	   The context to set up.
 * \param md_info   The information structure of the message-digest algorithm
 *				  to use.
 * \param hmac	  <ul><li>0: HMAC is not used. Saves some memory.</li>
 *				  <li>non-zero: HMAC is used with this context.</li></ul>
 *
 * \returns		 \c 0 on success,
 *				  #TTLS_ERR_MD_BAD_INPUT_DATA on parameter failure, or
 *				  #TTLS_ERR_MD_ALLOC_FAILED on memory allocation failure.
 */
int ttls_md_setup(ttls_md_context_t *ctx, const ttls_md_info_t *md_info, int hmac);

/**
 * \brief		   This function clones the state of an message-digest
 *				  context.
 *
 * \note			You must call ttls_md_setup() on \c dst before calling
 *				  this function.
 *
 * \note			The two contexts must have the same type,
 *				  for example, both are SHA-256.
 *
 * \warning		 This function clones the message-digest state, not the
 *				  HMAC state.
 *
 * \param dst	   The destination context.
 * \param src	   The context to be cloned.
 *
 * \return		  \c 0 on success,
 *				  #TTLS_ERR_MD_BAD_INPUT_DATA on parameter failure.
 */
int ttls_md_clone(ttls_md_context_t *dst,
		  const ttls_md_context_t *src);

/**
 * \brief		   This function extracts the message-digest size from the
 *				  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *				  to use.
 *
 * \return		  The size of the message-digest output in Bytes.
 */
unsigned char ttls_md_get_size(const ttls_md_info_t *md_info);

/**
 * \brief		   This function extracts the message-digest type from the
 *				  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *				  to use.
 *
 * \return		  The type of the message digest.
 */
ttls_md_type_t ttls_md_get_type(const ttls_md_info_t *md_info);

/**
 * \brief		   This function extracts the message-digest name from the
 *				  message-digest information structure.
 *
 * \param md_info   The information structure of the message-digest algorithm
 *				  to use.
 *
 * \return		  The name of the message digest.
 */
const char *ttls_md_get_name(const ttls_md_info_t *md_info);

/**
 * \brief		   This function starts a message-digest computation.
 *
 *				  You must call this function after setting up the context
 *				  with ttls_md_setup(), and before passing data with
 *				  ttls_md_update().
 *
 * \param ctx	   The generic message-digest context.
 *
 * \returns		 \c 0 on success, #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_starts(ttls_md_context_t *ctx);

/**
 * \brief		   This function feeds an input buffer into an ongoing
 *				  message-digest computation.
 *
 *				  You must call ttls_md_starts() before calling this
 *				  function. You may call this function multiple times.
 *				  Afterwards, call ttls_md_finish().
 *
 * \param ctx	   The generic message-digest context.
 * \param input	 The buffer holding the input data.
 * \param ilen	  The length of the input data.
 *
 * \returns		 \c 0 on success, #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_update(ttls_md_context_t *ctx, const unsigned char *input, size_t ilen);

/**
 * \brief		   This function finishes the digest operation,
 *				  and writes the result to the output buffer.
 *
 *				  Call this function after a call to ttls_md_starts(),
 *				  followed by any number of calls to ttls_md_update().
 *				  Afterwards, you may either clear the context with
 *				  ttls_md_free(), or call ttls_md_starts() to reuse
 *				  the context for another digest operation with the same
 *				  algorithm.
 *
 * \param ctx	   The generic message-digest context.
 * \param output	The buffer for the generic message-digest checksum result.
 *
 * \returns		 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_finish(ttls_md_context_t *ctx, unsigned char *output);

/**
 * \brief		  This function calculates the message-digest of a buffer,
 *				 with respect to a configurable message-digest algorithm
 *				 in a single call.
 *
 *				 The result is calculated as
 *				 Output = message_digest(input buffer).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *				 to use.
 * \param input	The buffer holding the data.
 * \param ilen	 The length of the input data.
 * \param output   The generic message-digest checksum result.
 *
 * \returns		\c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				 parameter verification fails.
 */
int ttls_md(const ttls_md_info_t *md_info, const unsigned char *input, size_t ilen,
		unsigned char *output);

/**
 * \brief		   This function sets the HMAC key and prepares to
 *				  authenticate a new message.
 *
 *				  Call this function after ttls_md_setup(), to use
 *				  the MD context for an HMAC calculation, then call
 *				  ttls_md_hmac_update() to provide the input data, and
 *				  ttls_md_hmac_finish() to get the HMAC value.
 *
 * \param ctx	   The message digest context containing an embedded HMAC
 *				  context.
 * \param key	   The HMAC secret key.
 * \param keylen	The length of the HMAC key in Bytes.
 *
 * \returns		 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_hmac_starts(ttls_md_context_t *ctx, const unsigned char *key,
		size_t keylen);

/**
 * \brief		   This function feeds an input buffer into an ongoing HMAC
 *				  computation.
 *
 *				  Call ttls_md_hmac_starts() or ttls_md_hmac_reset()
 *				  before calling this function.
 *				  You may call this function multiple times to pass the
 *				  input piecewise.
 *				  Afterwards, call ttls_md_hmac_finish().
 *
 * \param ctx	   The message digest context containing an embedded HMAC
 *				  context.
 * \param input	 The buffer holding the input data.
 * \param ilen	  The length of the input data.
 *
 * \returns		 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_hmac_update(ttls_md_context_t *ctx, const unsigned char *input,
		size_t ilen);

/**
 * \brief		   This function finishes the HMAC operation, and writes
 *				  the result to the output buffer.
 *
 *				  Call this function after ttls_md_hmac_starts() and
 *				  ttls_md_hmac_update() to get the HMAC value. Afterwards
 *				  you may either call ttls_md_free() to clear the context,
 *				  or call ttls_md_hmac_reset() to reuse the context with
 *				  the same HMAC key.
 *
 * \param ctx	   The message digest context containing an embedded HMAC
 *				  context.
 * \param output	The generic HMAC checksum result.
 *
 * \returns		 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_hmac_finish(ttls_md_context_t *ctx, unsigned char *output);

/**
 * \brief		   This function prepares to authenticate a new message with
 *				  the same key as the previous HMAC operation.
 *
 *				  You may call this function after ttls_md_hmac_finish().
 *				  Afterwards call ttls_md_hmac_update() to pass the new
 *				  input.
 *
 * \param ctx	   The message digest context containing an embedded HMAC
 *				  context.
 *
 * \returns		 \c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				  parameter verification fails.
 */
int ttls_md_hmac_reset(ttls_md_context_t *ctx);

/**
 * \brief		  This function calculates the full generic HMAC
 *				 on the input buffer with the provided key.
 *
 *				 The function allocates the context, performs the
 *				 calculation, and frees the context.
 *
 *				 The HMAC result is calculated as
 *				 output = generic HMAC(hmac key, input buffer).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *				 to use.
 * \param key	  The HMAC secret key.
 * \param keylen   The length of the HMAC secret key in Bytes.
 * \param input	The buffer holding the input data.
 * \param ilen	 The length of the input data.
 * \param output   The generic HMAC result.
 *
 * \returns		\c 0 on success, or #TTLS_ERR_MD_BAD_INPUT_DATA if
 *				 parameter verification fails.
 */
int ttls_md_hmac(const ttls_md_info_t *md_info, const unsigned char *key, size_t keylen,
				const unsigned char *input, size_t ilen,
				unsigned char *output);

/* Internal use */
int ttls_md_process(ttls_md_context_t *ctx, const unsigned char *data);

#endif /* TTLS_MD_H */
