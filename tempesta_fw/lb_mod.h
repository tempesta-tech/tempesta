/**
 *		Tempesta FW
 *
 * Tempesta load balancer module interface.
 *
 * Copyright (C) 2015 Tempesta Technologies.
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
#ifndef __TFW_LB_MOD_H__
#define __TFW_LB_MOD_H__

#include "msg.h"

/**
 * TfwLbMod is the interface for load balancing modules.
 *
 * The module responsibility is:
 *  - Distributing HTTP requests (any messages in general) across backend
 *    servers when Tempesta FW works as a reverse proxy.
 *  - Managing connections to backend servers, restoring closed connections.
 *    Tempesta FW is not aware of how to connect to a back-end server and how
 *    to handle the case when a connection is closed. It is the balcner's job.
 *  - Failover switching across servers: when a server goes offline, it is the
 *    balancer's job to remap its load to other servers.
 *  - Managing backend server configuration: parsing corresponding configuration
 *    options, maintaining the list of backend servers, etc.
 *
 * Tempesta FW should know nothing about internals of how backend server traffic
 * is managed. Different protocols may implement this thing differently.
 * For example, a HTTP module may have a pool of persistent connections and
 * share connections between clients, but a HTTP2 module may want establish a
 * new connection per client.
 *
 * XXX: the interface is the subject to change.
 * send_msg() is sufficient for message-oriented protocols like HTTP, but for
 * connection-oriented protocols like HTTP2 we should do something like:
 * For example,
 *   int  (*open_sess)(TfwSession *sess);
 *   int  (*send_msg)(TfwSession *sess, TfwMsg *msg);
 *   void (*close_sess)(TfwSession *sess);
 *
 * XXX: what if a load balancer wants to establish new connections dynamically
 * as needed (e.g. a separate connection for every HTTP2 stream)?
 * This is a blocking operation, but we are working in the atomic context.
 * The interface should be changed somehow to handle that.
 */
typedef struct  {
	const char *name;
	int (*send_msg)(TfwMsg *msg);
} TfwLbMod;

/* Send the @msg with choosing an appropriate backend server. */
int tfw_lb_send_msg(TfwMsg *msg);

int tfw_lb_mod_register(const TfwLbMod *mod);
void tfw_lb_mod_unregister(void);

#endif /* __TFW_LB_MOD_H__ */
