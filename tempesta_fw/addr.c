/**
 *		Tempesta FW
 *
 * IP address related functions.
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
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/in.h>
#include <linux/in6.h>

#include "addr.h"
#include "log.h"
#include "tempesta.h"


/**
 * Print UPv4/IPv6 address in network byte order to @buf.
 * @buf must be MAX_ADDR_LEN bytes in size.
 */
int
tfw_inet_ntop(const void *addr, char *buf)
{
	unsigned short family = *(unsigned short *)addr;

	if (family == AF_INET) {
		const struct sockaddr_in *sa = addr;
		unsigned char *a = (unsigned char *)&sa->sin_addr.s_addr;
		snprintf(buf, MAX_ADDR_LEN, "%u.%u.%u.%u:%u",
			 a[0], a[1], a[2], a[3], ntohs(sa->sin_port));
	}
	else if (family == AF_INET6) {
		const struct sockaddr_in6 *sa = addr;
		snprintf(buf, MAX_ADDR_LEN, "[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
			 ntohs(sa->sin6_addr.s6_addr16[0]),
			 ntohs(sa->sin6_addr.s6_addr16[1]),
			 ntohs(sa->sin6_addr.s6_addr16[2]),
			 ntohs(sa->sin6_addr.s6_addr16[3]),
			 ntohs(sa->sin6_addr.s6_addr16[4]),
			 ntohs(sa->sin6_addr.s6_addr16[5]),
			 ntohs(sa->sin6_addr.s6_addr16[6]),
			 ntohs(sa->sin6_addr.s6_addr16[7]),
			 ntohs(sa->sin6_port));
	}
	else {
		TFW_ERR("Bad address family %u\n", family);
		snprintf(buf, MAX_ADDR_LEN, "<unknown>");
		return -EINVAL;
	}

	return 0;
}

static bool
tfw_addr_eq_inet(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
	/* NOTE: we assume that all compared fields are packed to these 8 bytes:
	 * sin_family and sin_port are 2 bytes each + sin_addr is 4 bytes. */
	return *((u64 *)a)  == *((u64 *)b);
}

static bool
tfw_addr_eq_inet6(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
	/* NOTE: We are comparing only addr and port without other fields, so:
	 *  - sin6_family has to be AF_INET6 for both arguments.
	 *  - The addresses are treated as equal even if they have different
	 *    sin6_flowinfo or sin6_scope_id. */
	return ((a->sin6_port == b->sin6_port) &&
		!memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)));
}

/**
 * Compare two addresses represented by struct sockaddr.
 *
 * The function compares two IPv4 or IPv6 addresses represented by either
 * struct sockaddr_in or struct sockaddr_in6 types. Other address families
 * are not yet supported (the function always returns false for them).
 *
 * Return: true if addresses are equal, false otherwise.
 *         IPv4 addresses are treated as equal if both addr and port are equal.
 *         IPv6 addresses are treated as equal if their address bytes and ports
 *         and scope IDs are equal.
 */
bool
tfw_addr_eq(const void *addr1, const void *addr2)
{
	unsigned short family1, family2;

	BUG_ON(!addr1 || !addr2);

	family1 = *(unsigned short *)addr1;
	family2 = *(unsigned short *)addr2;

	if (family1 != family2)
		return false;

	if (family1 == AF_INET) {
		return tfw_addr_eq_inet(addr1, addr2);
	} else if (family1 == AF_INET6) {
		return tfw_addr_eq_inet6(addr1, addr2);
	} else {
		TFW_WARN("Can't compare address family: %u\n", family1);
		return false;
	}
}
EXPORT_SYMBOL(tfw_addr_eq);


ssize_t
tfw_addr_sa_len(const TfwAddr *addr)
{
	sa_family_t family;

	BUG_ON(!addr);

	family = addr->sa.sa_family;

	if (family == AF_INET) {
		return sizeof(addr->v4);
	}
	else if (family == AF_INET6) {
		return sizeof(addr->v6);
	}
	else {
		TFW_ERR("Bad address family: %d\n", family);
		return -EINVAL;
	}
}
