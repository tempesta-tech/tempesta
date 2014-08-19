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
#ifndef __TEMPESTA_H__
#define __TEMPESTA_H__

#include <linux/in6.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/tempesta_fw.h>
#include <net/sock.h>

#include "tdb.h"

#define TFW_AUTHOR		"NatSys Lab. (http://natsys-lab.com)"

#define DEF_MAX_PORTS		8
#define DEF_PORT		80
#define DEF_LISTEN_PORT		DEF_PORT
#define DEF_LISTEN_ADDR		INADDR_ANY
#define DEF_BACKEND_PORT	8080
#define DEF_BACKEND_ADDR	0xAC100004 // FIXME (INADDR_LOOPBACK) 172.16.0.4
#define DEF_PROC_STR_LEN	128

typedef struct {
	int	count;
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	}	addr[0];
} TfwAddrCfg;
#define SIZE_OF_ADDR_CFG(n)	(sizeof(TfwAddrCfg) 			\
				 + sizeof(struct sockaddr_in6) * (n))

/* Main configuration structure. */
typedef struct {
	struct rw_semaphore    	mtx; /* configuration lock */

	TfwAddrCfg		*listen;
	TfwAddrCfg		*backends;

	/* Cache configuration. */
	int			cache;
	unsigned int		c_size; /* cache size in pages */
	char			c_path[TDB_PATH_LEN]; /* cache files path */
} TfwCfg;

/* Main configuration structure. */
extern TfwCfg tfw_cfg;


int tfw_if_init(void);
void tfw_if_exit(void);

int tfw_reopen_backend_sockets(void);
int tfw_reopen_listen_sockets(void);

#endif /* __TEMPESTA_H__ */
