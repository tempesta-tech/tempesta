/**
 *		Tempesta FW
 *
 * IP address related functions.
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
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>

#include "addr.h"
#include "log.h"

static void
validate_addr(const TfwAddr *addr)
{
	/* At this point we are not going to support addresses other than
	 * IPv6 and IPv4-mapped IPv6, so we check it here, so all functions
	 * may safely assume that they get expected family and nothing else.
	 */
	BUG_ON(!addr);
	BUG_ON(addr->sin6_family != AF_INET6);
}

static int
tfw_addr_pton_v4(const TfwStr *s, TfwAddr *addr)
{
	int octet = -1, i = 0, port = 0, k;
	unsigned char *a = (unsigned char *)&addr->sin6_addr.s6_addr32[3];
	const char *p;
	const TfwStr *c, *end;

	addr->sin6_family = AF_INET6;
	ipv6_addr_set_v4mapped(0, &addr->sin6_addr);

	TFW_STR_FOR_EACH_CHUNK(c, s, end) {
		for (k = 0; k != c->len; ++k) {
			p = c->data + k;
			if (isdigit(*p)) {
				octet = (octet == -1)
					? *p - '0'
					: octet * 10 + *p - '0';
				if ((!port && octet > 255) || octet > 0xFFFF)
					return -EINVAL;
			}
			else if (octet >= 0 && ((*p == '.' && i < 4)
						|| (*p == ':' && i == 3)))
			{
				a[i++] = octet;
				octet = -1;
				port = *p == ':';
			} else
				return -EINVAL;
		}
	}
	if (octet >= 0) {
		if (i == 3) {
			/* Default port. */
			a[i] = octet;
			addr->sin6_port = htons(TFW_ADDR_STR_DEF_PORT);
			return 0;
		}
		else if (i == 4) {
			addr->sin6_port = htons(octet);
			return 0;
		}
	}

	return -EINVAL;
}

static int
tfw_addr_pton_v6(const TfwStr *s, TfwAddr *addr)
{
#define XD(x) ((x >= 'a') ? 10 + x - 'a' : x - '0')

	int words[9] = { -1, -1, -1, -1, -1, -1, -1, -1, -1 };
	int a, hole = -1, i = 0, port = -1, ipv4_mapped = 0, k;
	const char *p;
	const TfwStr *c, *end;

	memset(addr, 0, sizeof(*addr));

	TFW_STR_FOR_EACH_CHUNK(c, s, end) {
		for (k = 0; k != c->len; ++k) {
			p = c->data + k;
			if (i > 7 && !(i == 8 && port == 1))
				return -EINVAL;

			if (*p == '[') {
				port = 0;
			}
			else if (*p == ':') {
				const char next = (k < c->len - 1) ?
					*(p + 1) :
					(c != TFW_STR_LAST(s)) ?
						*(c + 1)->data :
						'\0';
				if (next == ':') {
					/*
					 * Leave current (if empty) or next (otherwise)
					 * word as a hole.
					 */
					if (k < c->len - 1) {
						++k;
						++p;
					} else {
						++c;
						k = 0;
						p = c->data;
					}
					hole = (words[i] != -1) ? ++i : i;
				} else if (words[i] == -1)
					return -EINVAL;

				/* Store port in the last word. */
				i = (port == 1) ? 8 : i + 1;
			}
			else if (*p == '.') {
				++i;
				if (ipv4_mapped)
					continue;
				if (words[0] != -1 || words[1] != 0xFFFF
				   || words[2] == -1 || i != 3 || hole != 0)
					return -EINVAL;
				/*
				 * IPv4 mapped address.
				 * Recalculate the first 2 hexadecimal octets from to
				 * 1 decimal octet.
				 */
				addr->sin6_family = AF_INET6;
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
			else if (isxdigit(*p)) {
				words[i] = words[i] == -1 ? 0 : words[i];
				if (ipv4_mapped || port == 1) {
					if (!isdigit(*p))
						return -EINVAL;
					words[i] = words[i] * 10 + *p - '0';
					if (port) {
						if (words[i] > 0xFFFF)
							return -EINVAL;
					}
					else if (ipv4_mapped && words[i] > 255) {
						return -EINVAL;
					}
				} else {
					words[i] = (words[i] << 4) | XD(tolower(*p));
					if (words[i] > 0xFFFF)
						return -EINVAL;
				}
			}
			else if (*p == ']') {
				port = 1;
			}
			else {
				return -EINVAL;
			}
		}
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
		__be32 v4addr = 0;
		for (i = 0; i < 4; ++i)
			v4addr |= words[i] << (3 - i) * 8;
		tfw_addr_set_v4(addr, v4addr);

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
		addr->sin6_port = htons(TFW_ADDR_STR_DEF_PORT);
	} else {
		addr->sin6_port = htons(words[8]);
	}

	addr->sin6_family = AF_INET6;

	return 0;
#undef XD
}

/**
 * Parse IPv4 and IPv6 addresses with optional port.
 * See RFC5952.
 */
int
tfw_addr_pton(const TfwStr *str, TfwAddr *addr)
{
	int ret = -EINVAL;
	int mode = 0;
	const char first = TFW_STR_PLAIN(str) ?
		*str->data :
		*str->chunks->data;

	/* Determine type of the address (IPv4/IPv6). */
	if (first == '[' || isalpha(first)) {
		mode = 6;
	} else {
		const char *pos = NULL;
		const TfwStr *c, *end;
		TFW_STR_FOR_EACH_CHUNK(c, str, end) {
			int i;
			for (i = 0; i != c->len; ++i) {
				pos = c->data + i;
				if (!isdigit(*pos))
					goto delim;
			}
		}
delim:
		if (*pos == ':') {
			mode = 6;
		}
		else if (*pos == '.') {
			mode = 4;
		}
	}

	if (mode == 4)
		ret = tfw_addr_pton_v4(str, addr);
	else if (mode == 6)
		ret = tfw_addr_pton_v6(str, addr);

	return ret;
}
EXPORT_SYMBOL(tfw_addr_pton);

/*
 * Parse an IP address. Try to parse it as an IPv4 address first.
 * If successful, convert the IPv4 address to IPv6 address. Otherwise,
 * try to parse it as an IPv6 address.
 *
 * Return a pointer to the next character after the parsed string
 * if the result is positive. Return NULL in case of an error.
 */
static const char *
tfw_addr_pton_addr(const char *str, TfwAddr *addr)
{
	char delim = '/';
	TfwAddr tmpaddr = { .sin6_family = AF_INET6 };
	const char *pptr;
	__be32 v4_saddr;
	struct in6_addr *v6_inaddr = &tmpaddr.sin6_addr;

	if (in4_pton(str, -1, (u8 *)&v4_saddr, delim, &pptr)) {
		ipv6_addr_set_v4mapped(v4_saddr, v6_inaddr);
		goto done;
	}
	if (*str == '[') {
		str++;
		delim = ']';
	}
	if (!in6_pton(str, -1, (u8 *)&v6_inaddr->s6_addr, delim, &pptr))
		return NULL;
	if (*pptr == ']')
		++pptr;
done:
	*addr = tmpaddr;
	return pptr;
}

/*
 * Parse an IP address in CIDR format. That include an IPv4 or IPv6
 * address, and a potential address prefix specified as the number
 * of significant bits in the address after the '/' char. The prefix
 * is stored in the unused field sin6_scope_id.
 *
 * Return zero if the result is positive.
 * Return a negative error number in case of an error.
 */
int
tfw_addr_pton_cidr(const char *str, TfwAddr *addr)
{
	u8 prefix;
	const char *pptr;

	if ((pptr = tfw_addr_pton_addr(str, addr)) == NULL)
		return -EINVAL;

	/* Parse a possible prefix length. */
	if (*pptr == '/')
		++pptr;
	if (*pptr == '\0') {
		addr->in6_prefix = 128;
		return 0;
	}
	if (kstrtou8(pptr, 10, &prefix) || (prefix == 0))
		return -EINVAL;
	if (ipv6_addr_v4mapped(&addr->sin6_addr)) {
		if (prefix > 32)
			return -EINVAL;
		prefix += 128 - 32;
	} else if (prefix > 128) {
		return -EINVAL;
	}
	addr->in6_prefix = prefix;

	return 0;
}

/**
 * Compare two TfwAddr addresses.
 *
 * Addresses are treated as equal if both address and port bytes are equal.
 * For IPv6, such fields as "Flow Info" and "Scope ID" are ignored, only address
 * and port fields are compared.
 */
bool
tfw_addr_eq(const TfwAddr *a, const TfwAddr *b)
{
	validate_addr(a);
	validate_addr(b);

	/* NOTE: We are comparing only addr and port without other fields, so:
	 *  - sin6_family has to be AF_INET6 for both arguments.
	 *  - The addresses are treated as equal even if they have different
	 *    sin6_flowinfo or sin6_scope_id.
	 */
	return a->sin6_port == b->sin6_port &&
	       memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
}
EXPORT_SYMBOL(tfw_addr_eq);

/*
 * Check, if listener addr matches server addr
 * server - backend address:port
 * listener - listener address:port, address can be 0.0.0.0
 */
int
tfw_addr_ifmatch(const TfwAddr *server, const TfwAddr *listener)
{
	if (unlikely(server->sin6_family != AF_INET6)) {
		TFW_ERR("Unexpected protocol family\n");
		BUG();
		return 0;
	}

	if (tfw_addr_port(listener) != tfw_addr_port(server))
		return 0;

	if (tfw_addr_is_v4mapped(server) && tfw_addr_is_v4mapped(listener)) {
		__be32 laddr = tfw_addr_v4addr(listener);
		__be32 saddr = tfw_addr_v4addr(server);

		if (laddr == 0) {
			if (IN_LOOPBACK(ntohl(saddr)))
				return 1;
				/* TODO: check if client addr is
				 * one of interface addresses
				 */
		}

		return tfw_addr_eq(server, listener);
	}

	if (ipv6_addr_any(&listener->sin6_addr)) {
		/* listener = [::] */
		if (IN6_LOOPBACK(server->sin6_addr)) {
			/* backend = [::1] */
			return 1;
		}

		/* TODO: same as in v4 case */
	}

	return tfw_addr_eq(server, listener);
}
EXPORT_SYMBOL(tfw_addr_ifmatch);

/*
 * ------------------------------------------------------------------------
 *	tfw_addr_ntop() and its helpers
 * ------------------------------------------------------------------------
 *
 * The tfw_addr_ntop() is called at least once for each incoming HTTP request.
 * Although there is not much work to do, we try to minimize the overhead, and
 * define few low-level helpers here instead of using something like snprintf().
 */

/**
 * Convert a number to base-10 textual representation,
 * e.g. 12345 -> "12345".
 *
 * The function can only print up to 5 digits and take input numbers that are
 * less than 65536, which is suitable for printing port and IPv4 octet values.
 *
 * Returns a position behind the last digit in @out_buf.
 */
static char *
tfw_put_dec(u32 q, char *out_buf)
{
	u32 r;
	u8 digits_n = 1 + (q > 9) + (q > 99) + (q > 999) + (q > 9999);

	/* Extract individual digits and convert them to ASCII characters.
	 *
	 * Decimal digits are extracted by fast division by 10.
	 * The code is based on put_dec_full9() from linux/lib/vsprintf.c.
	 *
	 * Some programs treat leading zeros as an octal base mark,
	 * so the switch(digits_n) is used to skip them.
	 */
	switch(digits_n) {
	case 4:
		r  = (q * 0x0ccd) >> 15;
		out_buf[3] = (q - 10 * r) + '0';
		q  = (r * 0x00cd) >> 11;
		out_buf[2] = (r - 10 * q) + '0';
	case 2:
		r  = (q * 0x000d) >> 7;
		out_buf[1] = (q - 10 * r) + '0';
		out_buf[0] = r + '0';

		break;
	case 5:
		r  = (q * 0xcccd) >> 19;
		out_buf[4] = (q - 10 * r) + '0';
		q  = (r * 0x0ccd) >> 15;
		out_buf[3] = (r - 10 * q) + '0';
	case 3:
		r  = (q * 0x00cd) >> 11;
		out_buf[2] = (q - 10 * r) + '0';
		q  = (r * 0x000d) >> 7;
		out_buf[1] = (r - 10 * q) + '0';
	case 1:
		out_buf[0] = q + '0';
	}

	return out_buf + digits_n;
}

/**
 * Convert @group to hexadecimal digits and put them to the buffer,
 * e.g. 0x01F9 -> "1f9".
 *
 * Leading zeros are clipped.
 *
 * Returns a position behind the latest printed digit.
 */
static char *
tfw_put_ipv6_digit_group(u16 group, char *out_buf)
{
	u8 digits_n = 1 + (group > 0xF) + (group > 0xFF) + (group > 0xFFF);

	out_buf += digits_n;

	switch(digits_n) {
	case 4:
		out_buf[-4] = hex_asc[(group >> 12)      ];
	case 3:
		out_buf[-3] = hex_asc[(group >> 8)  & 0xF];
	case 2:
		out_buf[-2] = hex_asc[(group >> 4)  & 0xF];
	case 1:
		out_buf[-1] = hex_asc[ group        & 0xF];
	}

	return out_buf;
}

/**
 * Decide whether the port value should be included to a serialized IP address.
 * We omit port 80 because it is the default value in most HTTP specifications.
 */
#define SHOULD_PRINT_PORT(print_port, port) \
	unlikely(print_port && port != 0 && \
	         port != __constant_cpu_to_be16(TFW_ADDR_STR_DEF_PORT))

/**
 * Convert an address to a string, assuming it's an IPv4 address.
 *
 * @param print_port controls whenever port should be included in the resulting
 * string. Port's omitted if it's 0 or 80, even if @param print_port is true.
 * @param buf is an output buffer. Should be at least 21 bytes long.
 *
 * @returns position behind the latest character in the @param buf.
 * The output is NOT terminated with '\0'.
 */
static char *
tfw_addr_fmt_v4(const TfwAddr *addr, bool print_port, char *buf)
{
	char *pos = buf;
	u8 *octets = (u8 *)&addr->sin6_addr.s6_addr32[3];
	__be16 in_port = addr->sin6_port;

	pos = tfw_put_dec(octets[0], pos);
	*pos++ = '.';
	pos = tfw_put_dec(octets[1], pos);
	*pos++ = '.';
	pos = tfw_put_dec(octets[2], pos);
	*pos++ = '.';
	pos = tfw_put_dec(octets[3], pos);

	if (SHOULD_PRINT_PORT(print_port, in_port)) {
		*pos++ = ':';
		pos = tfw_put_dec(ntohs(in_port), pos);
	}

	return pos;
}

/**
 * Convert an address to a string.
 *
 * Output examples:
 *   "::1"
 *   "[2f1c:22::1a:0:1]:8081"
 *   "[0123:4567:89ab:cdef:0123:4567:89ab:cdef]:65535"
 *   "192.168.0.1"
 *   "192.168.0.2:8082"
 *
 * The address is enclosed by square brackets when it's an IPv6, and a port is
 * present in the result. If the port is 0 or 80, it's omitted even if
 * @param print_port is true.
 *
 * @param print_port controls whenever port gets into the result.
 * @param buf is an output buffer. Should be at least TFW_ADDR_STR_BUF_SIZE
 * bytes long.
 *
 * @returns position behind the last character in @param buf.
 * The output is NOT terminated with '\0'.
 */
char *
tfw_addr_fmt(const TfwAddr *addr, bool print_port, char *buf)
{
	char *pos = buf;
	const u16 *groups = addr->sin6_addr.s6_addr16;
	__be16 in_port = addr->sin6_port;
	u8 zeros_already_omitted = false;
	u8 i;

	if (tfw_addr_is_v4mapped(addr))
		return tfw_addr_fmt_v4(addr, print_port, buf);

	if (SHOULD_PRINT_PORT(print_port, in_port))
		*pos++ = '[';

	/* Print groups of hexadecimal digits separated by ':'.
	 * Consecutive groups of zeros are omitted and leading zeros are clipped
	 * (e.g. 0123:0000:0000:0000:00ab -> 123::ab").
	 *
	 * The output value is inserted to X-Forwarded-For header of every HTTP
	 * request, which is done by patching sk_buff in-place. A shorter string
	 * helps to do less work there and thus likely beneficial.
	 */
	for (i = 0; i < 7; ++i) {
		if (groups[i] || zeros_already_omitted) {
			pos = tfw_put_ipv6_digit_group(ntohs(groups[i]), pos);
			*pos++ = ':';
		}
		else if (!groups[i] && (groups[i + 1] || i == 6)) {
			if (pos == buf || *(pos - 1) != ':')
				*pos++ = ':';
			*pos++ = ':';
			zeros_already_omitted = true;
		}
	}

	/* The last group doesn't have ':' after it. */
	pos = tfw_put_ipv6_digit_group(ntohs(groups[7]), pos);

	if (SHOULD_PRINT_PORT(print_port, in_port)) {
		*pos++ = ']';
		*pos++ = ':';
		pos = tfw_put_dec(ntohs(in_port), pos);
	}

	return pos;
}
EXPORT_SYMBOL(tfw_addr_fmt);

/**
 * Convert IPv4/IPv6 address and a port value to string,
 * e.g. "127.0.0.1:8080" or "[::1]:8080".
 *
 * Note: the port 80 is omitted in the output string since it is a default HTTP
 * port  and we use this function to format an address of a HTTP server.
 * E.g.:
 *   { 127.0.0.1, 81 } => "127.0.0.1:81"
 *   { 127.0.0.1, 80 } => "127.0.0.1"
 *
 * Returns length of a string written to the @out_buf.
 */
size_t
tfw_addr_ntop(const TfwAddr *addr, char *out_buf, size_t buf_size)
{
	char *pos;

	validate_addr(addr);
	BUG_ON(!out_buf);
	BUG_ON(buf_size < TFW_ADDR_STR_BUF_SIZE);

	pos = tfw_addr_fmt(addr, TFW_WITH_PORT, out_buf);

	BUG_ON(pos >= (out_buf + buf_size));
	*pos = '\0';

	return (pos - out_buf);
}
