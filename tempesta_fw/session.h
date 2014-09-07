/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_SESSION_H__
#define __TFW_SESSION_H__

#include "client.h"
#include "server.h"

/**
 * Tempesta reuses server connections to handle many clients.
 * Each client or server connection has ThConneciton descriptor for internal
 * usage. ThSession maps a client connection with a server connection which
 * is currently dedicated to process the client. When we receive first client
 * request we allocate ThSession, choose a server connection and bind
 * the client connection with the server connection through just allocated
 * session.
 */
typedef struct {
	TfwServer	*srv;
	TfwClient	*cli;
} TfwSession;

int tfw_session_sched_msg(TfwSession *s, TfwMsg *msg);
TfwSession *tfw_session_create(TfwClient *cli);
void tfw_session_free(TfwSession *s);

int tfw_session_init(void);
void tfw_session_exit(void);

#endif /* __TFW_SESSION_H__ */
