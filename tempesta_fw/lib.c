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
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/in.h>
#include <linux/in6.h>

#include "tempesta.h"
#include "lib.h"
#include "log.h"


/**
 * Retrurn number of tokens in @str separated by space ([ \t]+).
 * @str is null-terminated string.
 */
int
tfw_str_tokens_count(const char *str)
{
	int n = 0;

	/* Eat empty string prefix. */
	while (*str == ' ' || *str == '\t')
		++str;

	while (*str) {
		++n;
		/* Eat a word. */
		while (*str && *str != ' ' && *str != '\t')
			++str;
		/* Eat all separators. */
		while (*str && (*str == ' ' || *str == '\t'))
			++str;
	}

	return n;
}

static int
tfw_inet_pton_ipv4(char **p, struct sockaddr_in *addr)
{
	int octet = -1, i = 0, port = 0;
	unsigned char *a = (unsigned char *)&addr->sin_addr.s_addr;

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0;
	for ( ; **p && !isspace(**p); ++*p) {
		if (isdigit(**p)) {
			octet = (octet == -1)
				? **p - '0'
				: octet * 10 + **p - '0';
			if ((!port && octet > 255) || octet > 0xFFFF)
				return -EINVAL;
		}
		else if (octet >= 0 && ((**p == '.' && i < 4)
					|| (**p == ':' && i == 3)))
		{
			a[i++] = octet;
			octet = -1;
			port = **p == ':';
		} else
			return -EINVAL;
	}
	if (octet >= 0) {
		if (i == 3) {
			/* Default port. */
			a[i] = octet;
			addr->sin_port = htons(DEF_PORT);
			return 0;
		}
		else if (i == 4) {
			addr->sin_port = htons(octet);
			return 0;
		}
	}

	return -EINVAL;
}

static int
tfw_inet_pton_ipv6(char **p, struct sockaddr_in6 *addr)
{
#define XD(x) ((x >= 'a') ? 10 + x - 'a' : x - '0')

	int words[9] = { -1, -1, -1, -1, -1, -1, -1, -1, -1 };
	int a, hole = -1, i = 0, port = -1, ipv4_mapped = 0;

	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;

	for ( ; **p && !isspace(**p); ++*p) {
		if (i > 7 && !(i == 8 && port == 1))
			return -EINVAL;
		if (**p == '[') {
			port = 0;
		}
		else if (**p == ':') {
			if (*(*p + 1) == ':') {
				/*
				 * Leave current (if empty) or next (otherwise)
				 * word as a hole.
				 */
				++*p;
				hole = (words[i] != -1) ? ++i : i;
			} else if (words[i] == -1) {
				return -EINVAL;
			}
			/* Store port in the last word. */
			i = (port == 1) ? 8 : i + 1;
		}
		else if (**p == '.') {
			++i;
			if (ipv4_mapped)
				continue;
			if (words[0] != -1 || words[1] != 0xFFFF
			   || words[2] == -1 || i != 3 || hole != 0)
				return -EINVAL;
			/*
			 * IPv4 mapped address.
			 * Recalculate the first 2 hexademical octets from to
			 * 1 decimal octet.
			 */
			addr->sin6_family = AF_INET;
			words[0] = ((words[2] & 0xF000) >> 12) * 1000
				   + ((words[2] & 0x0F00) >> 8) * 100
				   + ((words[2] & 0x00F0) >> 4) * 10
				   + (words[2] & 0x000F);
			if (words[0] > 255)
				return -EINVAL;
			ipv4_mapped = 1;
			i = 1;
			words[1] = words[2] = -1;
		}
		else if (isxdigit(**p)) {
			words[i] = words[i] == -1 ? 0 : words[i];
			if (ipv4_mapped || port == 1) {
				if (!isdigit(**p))
					return -EINVAL;
				words[i] = words[i] * 10 + **p - '0';
				if (port) {
					if (words[i] > 0xFFFF)
						return -EINVAL;
				}
				else if (ipv4_mapped && words[i] > 255) {
					return -EINVAL;
				}
			} else {
				words[i] = (words[i] << 4) | XD(tolower(**p));
				if (words[i] > 0xFFFF)
					return -EINVAL;
			}
		}
		else if (**p == ']') {
			port = 1;
		}
		else
			return -EINVAL;
	}

	/* Some sanity checks. */
	if (!port || (port != -1 && words[8] <= 0)
	    || (ipv4_mapped && hole == -1)
	    || (ipv4_mapped && port == -1 && i != 3)
	    || (port == 1 && i != 8)
	    || (port == -1 && i < 7 && hole == -1))
		return -EINVAL;

	/* Copy parsed address. */
	if (ipv4_mapped) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		for (i = 0; i < 4; ++i)
			addr4->sin_addr.s_addr |= words[i] << (3 - i) * 8;
	} else {
		for (i = a = 7; i >= 0 && a >= 0; ) {
			if (words[i] == -1) {
				if (i > hole)
					--i;
				else
					if (a-- == i && i)
						--i;
			} else
				addr->sin6_addr.s6_addr16[a--]
					= htons(words[i--]);
		}
	}

	/* Set port. */
	if (port == -1) {
		addr->sin6_port = htons(DEF_PORT);
		return 0;
	}
	addr->sin6_port = htons(words[8]);

	return 0;
#undef XD
}

/**
 * Parse IPv4 and IPv6 addresses with optional port.
 * See RFC5952.
 *
 * @p - string pointer, updated by the function.
 * @addr - distination to write as a pointer to a union of sockaddr_in and
 * 	   sockaddr_in6.
 */
int
tfw_inet_pton(char **p, void *addr)
{
	int mode = 0;

	/* Eat empty string prefix. */
	while (**p && isspace(**p))
		++*p;

	/* Determine type of the address (IPv4/IPv6). */
	if (**p == '[' || isalpha(**p)) {
		mode = 6;
	} else {
		char *p1 = *p;
		while (*p1 && isdigit(*p1))
			p1++;
		if (*p1 == ':') {
			mode = 6;
		}
		else if (*p1 == '.') {
			mode = 4;
		}
		else {
			TFW_ERR("bad string: %s\n", *p);
			return -EINVAL;
		}
	}

	if (mode == 4)
		return tfw_inet_pton_ipv4(p, addr);
	if (mode == 6)
		return tfw_inet_pton_ipv6(p, addr);

	TFW_ERR("Can't parse address %s\n", *p);
	return -EINVAL;
}
EXPORT_SYMBOL(tfw_inet_pton);

/**
 * Print UPv4/IPv6 address in network byte order to @buf.
 * @buf must be MAX_ADDR_LEN bytes in size.
 */
int
tfw_inet_ntop(const void *addr, char *buf)
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
EXPORT_SYMBOL(tfw_inet_ntop);

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
EXPORT_SYMBOL(tfw_addr_eq);
