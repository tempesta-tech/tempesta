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
#ifndef __TFW_ADDR_H__
#define __TFW_ADDR_H__

#include <net/inet_sock.h>

typedef union {
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
	struct sockaddr addr;
} TfwAddr;

int tfw_inet_pton(char **p, void *addr);
int tfw_inet_ntop(const void *addr, char *buf);
bool tfw_addr_eq(const void *addr1, const void *addr2);

#endif /* __TFW_ADDR_H__ */
