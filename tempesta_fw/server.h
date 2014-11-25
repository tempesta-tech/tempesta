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
#ifndef __TFW_SERVER_H__
#define __TFW_SERVER_H__

#include <net/sock.h>
#include "addr.h"
#include "ptrset.h"
#include "tempesta.h"

#define TFW_SRV_STR_MAX_SIZE 100
#define TFW_SRV_SOCK_POOL_SIZE 8

typedef TFW_PTRSET_STRUCT(struct sock, TFW_SRV_SOCK_POOL_SIZE) TfwSrvSockPool;


typedef struct {
	/* The server current stress (overloading) value. */
	int		stress;

	TfwAddr addr;
	TfwSrvSockPool socks;
} TfwServer;

TfwServer *tfw_server_alloc(void);
void tfw_server_free(TfwServer *srv);

int tfw_server_snprint(const TfwServer *srv, char *buf, size_t buf_size);

int tfw_server_init(void);
void tfw_server_exit(void);

#endif /* __TFW_CLIENT_H__ */
