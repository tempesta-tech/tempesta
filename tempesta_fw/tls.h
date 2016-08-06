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
#include "ttls/ttls.h"

/**
 * HTTPS states.
 */
#define TFW_GFSM_HTTPS_STATE(s)	((TFW_FSM_HTTPS << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* HTTPS FSM initial state, not hookable. */
	TFW_HTTPS_FSM_INIT	= TFW_GFSM_HTTPS_STATE(0),
	TFW_HTTPS_FSM_CHUNK	= TFW_GFSM_HTTPS_STATE(1),
	TFW_HTTPS_FSM_DONE	= TFW_GFSM_HTTPS_STATE(TFW_GFSM_STATE_LAST)
};

typedef struct {
	mbedtls_ssl_context	ssl;
	SsSkbList		rx_queue;
	SsSkbList		tx_queue;
} TfwTlsContext;

int
tfw_tls_send_msg(TfwTlsContext *tls, TfwMsg *msg);

#endif /* __TFW_TLS_H__ */

