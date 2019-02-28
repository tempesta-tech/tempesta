/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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

#include "http_limits.h"
#include "connection.h"

/**
 * Client descriptor.
 *
 * @class_prvt		- private client accounting data for classifier module.
 *			  Typically it's large and wastes memory in vain if
 *			  no any classification logic is used;
 */
typedef struct {
	TFW_PEER_COMMON;
	TfwClassifierPrvt	class_prvt;
} TfwClient;

TfwClient *tfw_client_obtain(TfwAddr addr, TfwAddr *cli_addr,
			     TfwStr *user_agent, void (*init)(void *));
void tfw_client_put(TfwClient *cli);
int tfw_client_for_each(int (*fn)(void *));
void tfw_client_set_expires_time(unsigned int expires_time);
void tfw_cli_conn_release(TfwCliConn *cli_conn);
int tfw_cli_conn_send(TfwCliConn *cli_conn, TfwMsg *msg);

#endif /* __TFW_CLIENT_H__ */
