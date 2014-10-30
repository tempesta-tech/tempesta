/**
 *		Tempesta FW
 *
 * Common helpers.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2014 Tempesta Technologies Ltd.
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
	return !memcmp(a, b, sizeof(*a));
}

static bool
tfw_addr_eq_inet6(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
	/* NOTE: The fields 'sin6_flowinfo' and 'sin6_scope_id'  are
	 * not compared intentionally. */
	return (!memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) &&
		(a->sin6_port == b->sin6_port) &&
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
/**
 * Good and fast hash function.
 *
 * BEWARE: your CPU must support SSE 4.2.
 */

#define CRC32_SSE42(a, b)	asm volatile("crc32q %2, %0"		\
					     : "=r"(a) : "0"(a), "r"(b))

unsigned long
tfw_hash_calc(const char *data, size_t len)
{
#define MUL	sizeof(long)
	int i;
	register unsigned long crc0 = 0, crc1 = 0;
	unsigned long h, *d = (unsigned long *)data;
	size_t n = (len / MUL) & ~1UL;

	for (i = 0; i < n; i += 2) {
		CRC32_SSE42(crc0, d[i]);
		CRC32_SSE42(crc1, d[i + 1]);
	}

	n *= MUL;
	if (n + MUL <= len) {
		CRC32_SSE42(crc0, d[n]);
		n += MUL;
	}

	h = (crc1 << 32) | crc0;

	/*
	 * Generate relatively small and dense hash tail values - they are good
	 * for short strings in htrie which uses less significant bits at root,
	 * however collisions are very probable.
	 */
	switch (len - n) {
	case 7:
		h += data[n] * n;
		++n;
	case 6:
		h += data[n] * n;
		++n;
	case 5:
		h += data[n] * n;
		++n;
	case 4:
		h += data[n] * n;
		++n;
	case 3:
		h += data[n] * n;
		++n;
	case 2:
		h += data[n] * n;
		++n;
	case 1:
		h += data[n] * n;
		++n;
	}

	return h;
#undef MUL
}
