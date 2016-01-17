/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_CLIENT_H__
#define __TFW_CLIENT_H__

#include <crypto/sha.h>
#include <linux/time.h>

#include "connection.h"

/**
 * Client descriptor.
 *
 * @conn_users		- connections reference counter.
 * 			  The client is released, when the counter reaches zero:
 * 			  no connections to the server - no client for us :)
 * @cookie		- Tempesta sticky cookie;
 * @cookie.ts		- timestamp for the client's session;
 * @cookie.hmac		- crypto hash from values of an HTTP request;
 */
typedef struct {
	TFW_PEER_COMMON;
	atomic_t	conn_users;
	struct {
		struct timespec	ts;
		unsigned char	hmac[SHA1_DIGEST_SIZE];
	} cookie;
} TfwClient;

TfwClient *tfw_client_obtain(struct sock *sk);
void tfw_client_put(TfwClient *cli);
void tfw_cli_conn_release(TfwConnection *conn);
int tfw_cli_conn_send(TfwConnection *conn, TfwMsg *msg, bool unref_data);
int tfw_sock_check_listeners(void);

#endif /* __TFW_CLIENT_H__ */
