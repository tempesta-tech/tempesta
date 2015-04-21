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

/**
 * TODO do all crypto and handle TLS FSM here.
 *
 * Decrypted response messages should be directly placed in TDB area
 * to avoid copying.
 */
static int
tfw_tls_msg_process(void *conn, unsigned char *data, size_t len)
{
	int r = TFW_BLOCK;
	TfwConnection *c = (TfwConnection *)conn;
	TfwMsg *msg = (TfwMsg *)c->msg;

	/* TODO switch to HTTP FSM, @data and @len must be decrypted here. */
	r = tfw_gfsm_move(&msg->state, TFW_HTTPS_FSM_TODO_ISSUE_81, data, len);

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
tfw_tls_conn_estab(TfwConnection *conn)
{
	return 0;
}

/* TODO */
static void
tfw_tls_conn_close(TfwConnection *conn)
{
}

static TfwConnHooks tls_conn_hooks = {
	.conn_estab	= tfw_tls_conn_estab,
	.conn_close	= tfw_tls_conn_close,
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
}
