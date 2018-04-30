/**
 *		Tempesta FW
 *
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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

#define __TFW_TLS_STATE(name)	TFW_TLS_FSM_ ## name

/**
 * TLS states.
 */
#define TFW_GFSM_TLS_STATE(s)	((TFW_FSM_TLS << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* TLS FSM initial state, not hookable. */
	TFW_TLS_FSM_INIT	= TFW_GFSM_TLS_STATE(0),

	TFW_TLS_FSM_DATA_READY	= TFW_GFSM_TLS_STATE(1),

	__TFW_TLS_STATE(HELLO_REQUEST),
	__TFW_TLS_STATE(CLIENT_HELLO),
	__TFW_TLS_STATE(SERVER_HELLO_VERIFY_REQUEST_SENT),
	__TFW_TLS_STATE(SERVER_HELLO),
	__TFW_TLS_STATE(SERVER_CERTIFICATE),
	__TFW_TLS_STATE(SERVER_KEY_EXCHANGE),
	__TFW_TLS_STATE(CERTIFICATE_REQUEST),
	__TFW_TLS_STATE(SERVER_HELLO_DONE),
	__TFW_TLS_STATE(CLIENT_CERTIFICATE),
	__TFW_TLS_STATE(CLIENT_KEY_EXCHANGE),
	__TFW_TLS_STATE(CERTIFICATE_VERIFY),
	__TFW_TLS_STATE(CLIENT_CHANGE_CIPHER_SPEC),
	__TFW_TLS_STATE(CLIENT_FINISHED),
	__TFW_TLS_STATE(SERVER_CHANGE_CIPHER_SPEC),
	__TFW_TLS_STATE(SERVER_FINISHED),
	__TFW_TLS_STATE(FLUSH_BUFFERS),
	__TFW_TLS_STATE(HANDSHAKE_WRAPUP),

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
	mbedtls_ssl_context	ssl;
	struct sk_buff		*rx_queue;
	struct sk_buff		*tx_queue;
	spinlock_t		lock;
} TfwTlsContext;

int tfw_tls_fsm_step(TfwTlsContext *tls, int state);
#define TFW_FSM_STEP(ssl, state)                                        \
	if (tfw_tls_fsm_step(container_of(ssl, TfwTlsContext, ssl),	\
			     __TFW_TLS_STATE(state)) == TFW_BLOCK) {	\
		ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;			\
		break;							\
	}

#endif /* __TFW_TLS_H__ */

