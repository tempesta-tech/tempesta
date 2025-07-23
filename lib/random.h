/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2025 Tempesta Technologies, INC.
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

#ifndef __LIB_RANDOM_H__
#define __LIB_RANDOM_H__

#include <asm/archrandom.h>

/*
 * This function borrowed from 5.10.35 kernel.
 *
 * This function will use the architecture-specific hardware random
 * number generator if it is available.  The arch-specific hw RNG will
 * almost certainly be faster than what we can do in software, but it
 * is impossible to verify that it is implemented securely (as
 * opposed, to, say, the AES encryption of a sequence number using a
 * key known by the NSA).  So it's useful if we need the speed, but
 * only if we're willing to trust the hardware manufacturer not to
 * have put in a back door.
 *
 * Return number of bytes filled in.
 */
static inline int
get_random_bytes_arch(void *buf, int nbytes)
{
	int left = nbytes;
	char *p = buf;

	while (left) {
		unsigned long v;
		int chunk = min_t(int, left, sizeof(unsigned long));

		if (!arch_get_random_longs(&v, 1))
			break;

		memcpy(p, &v, chunk);
		p += chunk;
		left -= chunk;
	}

	return nbytes - left;
}

/*
 * CPUs since Intel Ice Lake are safe against SRBDS attack, so we're good
 * with the hardware random generator.
 *
 * The random number generator is extremely important for ECDSA, see
 * M.Macchetti, "A Novel Related Nonce Attack for ECDSA", 2023,
 * https://eprint.iacr.org/2023/305.pdf
 */
static inline void
tfw_get_random_bytes(void *buf, int len)
{
	int n = get_random_bytes_arch(buf, len);

	if (unlikely(n < len))
		get_random_bytes((char *)buf + n, len - n);
}

static inline unsigned long
tfw_get_random_long(void)
{
	unsigned long b = 0;

	if (unlikely(!arch_get_random_longs(&b, 1)))
		get_random_bytes((char *)&b, sizeof(b));

	return b;
}

#endif
