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

#include <linux/kernel.h>
#include "hash.h"

#define CRCQ(crc, data64) \
	asm volatile("crc32q %2, %0" : "=r"(crc) : "0"(crc), "r"(data64))

#define CRCB(crc, data8) \
	asm volatile("crc32b %2, %0" : "=r"(crc) : "0"(crc), "r"(data8))


unsigned long
tfw_hash_calc(const char *data, size_t len)
{
#define MUL	sizeof(long)
	int i;
	register unsigned long crc0 = 0, crc1 = 0;
	unsigned long h, *d = (unsigned long *)data;
	size_t n = (len / MUL) & ~1UL;

	for (i = 0; i < n; i += 2) {
		CRCQ(crc0, d[i]);
		CRCQ(crc1, d[i + 1]);
	}

	n *= MUL;
	if (n + MUL <= len) {
		CRCQ(crc0, d[n / MUL]);
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

unsigned long
tfw_hash_str(const TfwStr *str)
{
#define MUL sizeof(long)
	const TfwStr *chunk;
	const char *pos;
	const char *body_end;
	const char *head_end;
	const char *tail_end;
	register unsigned long crc0 = 0xAAAAAAAA;
	register unsigned long crc1 = 0x55555555;
	unsigned int len;

	TFW_STR_FOR_EACH_CHUNK(chunk, str) {
		len = chunk->len;
		pos = chunk->ptr;

		tail_end = pos + len;
		head_end = PTR_ALIGN(pos, MUL);
		body_end = PTR_ALIGN(tail_end, MUL) - MUL;

		if (unlikely(len < MUL)) {
			goto tail;
		}

		while (pos != head_end) {
			CRCB(crc0, *pos);
			CRCB(crc1, *pos);
			++pos;
		}

		while (pos != body_end) {
			CRCQ(crc0, *((unsigned long *)pos));
			CRCQ(crc1, *((unsigned long *)pos));
			pos += MUL;
		}
tail:
		while (pos != tail_end) {
			CRCB(crc0, *pos);
			CRCB(crc1, *pos);
			++pos;
		}
	}

	return (crc1 << 32) | crc0;
#undef MUL
}
EXPORT_SYMBOL(tfw_hash_str);

