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
