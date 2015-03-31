/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_CLIENT_H__
#define __TFW_CLIENT_H__

#include "connection.h"

/**
 * Client descriptor.
 *
 * @conn_users		- connections reference counter.
 * 			  The client is released, when the counter reaches zero:
 * 			  no connections to the srever - no client for us :)
 */
typedef struct {
	TFW_PEER_COMMON;
	atomic_t	conn_users;
} TfwClient;

TfwClient *tfw_create_client(TfwConnection *conn, const TfwAddr *addr);
void tfw_client_put(struct sock *s);

#endif /* __TFW_CLIENT_H__ */
