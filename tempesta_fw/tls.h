/**
 *		Tempesta FW
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_TLS_H__
#define __TFW_TLS_H__

#include "gfsm.h"
#include "ttls.h"

#define TFW_FSM_TLS		TFW_FSM_HTTPS

/**
 * TLS states.
 */
#define TFW_GFSM_TLS_STATE(s)	((TFW_FSM_TLS << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* TLS FSM initial state, not hookable. */
	TFW_TLS_FSM_INIT	= TFW_GFSM_TLS_STATE(0),

	TFW_TLS_FSM_DATA_READY	= TFW_GFSM_TLS_STATE(1),

	TFW_TLS_FSM_DONE	= TFW_GFSM_TLS_STATE(TFW_GFSM_STATE_LAST)
};

/**
 * TLS context.
 *
 * @ssl		- mbedTLS context;
 * @rx_queue	- temporary queue for incoming SKBs;
 * @tx_queue	- temporary queue for outgoing SKBs;
 * @lock	- lock for serializing @ssl context access;
 *
 * TODO: Get rid of @rx_queue and @tx_queue. The queues seem like dirty
 *       workaround to be able to work with mbedTLS w/o reworking its IO and FSM
 *       internals mostly placed in ttls/ssl_tls.c. We leave with them for the
 *       very first release, but they must be removed.
 *
 * TODO: Get rid of @lock. That's bad to access TLS context from many CPUs, so
 *       the @lock must be removed.
 *
 * Also, see PR #595 and #603 discussions about this TODOs.
 */
typedef struct {
	ttls_ssl_context	ssl;
	struct sk_buff		*rx_queue;
	struct sk_buff		*tx_queue;
	spinlock_t		lock;
} TfwTlsContext;

void tfw_tls_cfg_require(void);

#endif /* __TFW_TLS_H__ */

