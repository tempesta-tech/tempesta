/**
 *		Tempesta TLS
 *
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
#ifndef TTLS_TICKET_H
#define TTLS_TICKET_H

/*
 * This implementation of the session ticket callbacks includes key
 * management, rotating the keys periodically in order to preserve forward
 * secrecy.
 */

#include "crypto.h"
#include "ttls.h"

/**
 * \brief   Information for session ticket protection
 */
typedef struct
{
	unsigned char name[4];		/*!< random key identifier */
	uint32_t generation_time;	/*!< key generation timestamp (seconds) */
	TlsCipherCtx ctx;		/*!< context for auth enc/decryption	*/
}
ttls_ticket_key;

/**
 * \brief   Context for session ticket handling functions
 */
typedef struct
{
	ttls_ticket_key keys[2]; /*!< ticket protection keys			 */
	unsigned char active;		   /*!< index of the currently active key  */

	uint32_t ticket_lifetime;	   /*!< lifetime of tickets in seconds	 */

	spinlock_t mutex;
}
ttls_ticket_context;

/**
 * \brief		   Initialize a ticket context.
 *				  (Just make it ready for ttls_ticket_setup()
 *				  or ttls_ticket_free().)
 *
 * \param ctx	   Context to be initialized
 */
void ttls_ticket_init(ttls_ticket_context *ctx);

/**
 * \brief		   Prepare context to be actually used
 *
 * \param ctx	   Context to be set up
 * \param cipher	AEAD cipher to use for ticket protection.
 *				  Recommended value: TTLS_CIPHER_AES_256_GCM.
 * \param lifetime  Tickets lifetime in seconds
 *				  Recommended value: 86400 (one day).
 *
 * \note			It is highly recommended to select a cipher that is at
 *				  least as strong as the the strongest ciphersuite
 *				  supported. Usually that means a 256-bit key.
 *
 * \note			The lifetime of the keys is twice the lifetime of tickets.
 *				  It is recommended to pick a reasonnable lifetime so as not
 *				  to negate the benefits of forward secrecy.
 *
 * \return		  0 if successful,
 *				  or a specific TTLS_ERR_XXX error code
 */
int ttls_ticket_setup(ttls_ticket_context *ctx,
	ttls_cipher_type_t cipher,
	uint32_t lifetime);

/**
 * \brief		   Implementation of the ticket write callback
 *
 * \note			See \c mbedlts_ticket_write_t for description
 */
ttls_ticket_write_t ttls_ticket_write;

/**
 * \brief		   Implementation of the ticket parse callback
 *
 * \note			See \c mbedlts_ticket_parse_t for description
 */
ttls_ticket_parse_t ttls_ticket_parse;

/**
 * \brief		   Free a context's content and zeroize it.
 *
 * \param ctx	   Context to be cleaned up
 */
void ttls_ticket_free(ttls_ticket_context *ctx);

#endif /* ssl_ticket.h */
