/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) implementation.
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
#include "connection.h"
#include "tls.h"

/**
 * TODO do all crypto and handle TLS FSM here.
 *
 * Decrypted response messages should be directly placed in TDB area
 * to avoid copying.
 */
static int
tfw_tls_msg_process(void *conn, struct sk_buff *skb, unsigned int off)
{
	int r = TFW_BLOCK;
	TfwConnection *c = (TfwConnection *)conn;
	TfwMsg *msg = (TfwMsg *)c->msg;

	/*
	 * TODO switch to HTTP FSM, @data and @len must be decrypted here.
	 * Typically we don't need original skb any more either for server or
	 * proxy modes, so it has sense to do decryption in-place.
	 */
	r = tfw_gfsm_move(&msg->state, TFW_HTTPS_FSM_TODO_ISSUE_81, skb, off);

	return r;
}

/* TODO alloc TLS- or HTTPS-specific message. */
static TfwMsg *
tfw_tls_conn_msg_alloc(TfwConnection *conn)
{
	return NULL;
}

/* TODO Update @conn for newly established connection */
static int
tfw_tls_conn_init(TfwConnection *conn)
{
	return 0;
}

/* TODO */
static void
tfw_tls_conn_destruct(TfwConnection *conn)
{
}

static TfwConnHooks tls_conn_hooks = {
	.conn_init	= tfw_tls_conn_init,
	.conn_destruct	= tfw_tls_conn_destruct,
	.conn_msg_alloc	= tfw_tls_conn_msg_alloc,
};

int __init
tfw_tls_init(void)
{
	int r = tfw_gfsm_register_fsm(TFW_FSM_HTTPS, tfw_tls_msg_process);
	if (r)
		return r;

	tfw_connection_hooks_register(&tls_conn_hooks, TFW_FSM_HTTPS);

	return 0;
}

void
tfw_tls_exit(void)
{
	tfw_connection_hooks_unregister(TFW_FSM_HTTPS);
	tfw_gfsm_unregister_fsm(TFW_FSM_HTTPS);
}
