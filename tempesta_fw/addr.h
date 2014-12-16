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
	struct sockaddr sa;
	sa_family_t family;
} TfwAddr;

int tfw_inet_pton(char **p, void *addr);
int tfw_inet_ntop(const void *addr, char *buf);
bool tfw_addr_eq(const TfwAddr *addr1, const TfwAddr *addr2);

/* Maximum size of a buffer needed for tfw_addr_fmt(), including '\0'. */
#define TFW_ADDR_STR_BUF_SIZE \
	sizeof("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:255.255.255.255]:65535")

size_t tfw_addr_fmt(const TfwAddr *addr, char *out_buf, size_t buf_size);

/* A couple of faster alternatives to tfw_addr_fmt().
 * Note that they don't check input arguments and don't terminate output. */
char * tfw_addr_fmt_v4(__be32 in_addr, __be16 in_port, char *out_buf);
char * tfw_addr_fmt_v6(const struct in6_addr *in6_addr, __be16 in_port,
			char *out_buf);

#endif /* __TFW_ADDR_H__ */
