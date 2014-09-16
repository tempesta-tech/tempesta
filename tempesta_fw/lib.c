/**
 *		Tempesta FW
 *
 * Common helpers.
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
#include "tempesta.h"
#include "lib.h"
#include "log.h"

/**
 * Add compound piece to @str and return pointer to the piece.
 */
TfwStr *
tfw_str_add_compound(TfwPool *pool, TfwStr *str)
{
	if (unlikely(str->flags & TFW_STR_COMPOUND)) {
		unsigned int l = str->len * sizeof(TfwStr);
		unsigned char *p = tfw_pool_realloc(pool, str->ptr, l,
						    l + sizeof(TfwStr));
		if (!p)
			return NULL;
		str->len++;
	}
	else {
		TfwStr *a = tfw_pool_alloc(pool, 2 * sizeof(TfwStr));
		if (!a)
			return NULL;
		a[0].ptr = str->ptr;
		a[0].len = str->len;
		str->ptr = a;
		str->len = 2;
		str->flags |= TFW_STR_COMPOUND;
	}

	TFW_STR_INIT((TfwStr *)str->ptr + str->len - 1);

	return ((TfwStr *)str->ptr + str->len - 1);
}

/**
 * Print UPv4/IPv6 address in network byte order to @buf.
 * @buf must be MAX_ADDR_LEN bytes in size.
 */
int
tfw_inet_ntop(void *addr, char *buf)
{
	unsigned short family = *(unsigned short *)addr;

	if (family == AF_INET) {
		struct sockaddr_in *sa = addr;
		unsigned char *a = (unsigned char *)&sa->sin_addr.s_addr;
		snprintf(buf, MAX_ADDR_LEN, "%u.%u.%u.%u:%u",
			 a[0], a[1], a[2], a[3], ntohs(sa->sin_port));
	}
	else if (family == AF_INET6) {
		struct sockaddr_in6 *sa = addr;
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
	return ((a->sin_addr.s_addr == b->sin_addr.s_addr) &&
		(a->sin_port == b->sin_port) &&
		(a->sin_family == b->sin_family));
}

static bool
tfw_addr_eq_inet6(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
	const __be32 *aw = a->sin6_addr.in6_u.u6_addr32;
	const __be32 *bw = a->sin6_addr.in6_u.u6_addr32;

	/* NOTE: The field 'sin6_flowinfo' is not compared intentionally. */
	/* FIXME: Do we really need to compare the 'sin6_scope_id' field? */
	return ((aw[0] == bw[0]) &&
		(aw[1] == bw[1]) &&
		(aw[2] == bw[2]) &&
		(aw[3] == bw[3]) &&
		(a->sin6_port == b->sin6_port) &&
		(a->sin6_scope_id == b->sin6_scope_id) &&
		(a->sin6_family == b->sin6_family));
}

/**
 * tfw_addr_eq() - Compare two addresses represented by struct sockaddr.
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
