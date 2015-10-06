/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
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
#include "lib.h"

#define CRCQ(crc, data64) \
	asm volatile("crc32q %2, %0" : "=r"(crc) : "0"(crc), "r"(data64))

#define CRCB(crc, data8) \
	asm volatile("crc32b %2, %0" : "=r"(crc) : "0"(crc), "r"(data8))

/*
 * At this point the whole hash is just a regular CRC32 of all chunks.
 * The crc value is stored in the 32 least significant bits of the hash,
 * and the high 32 bits are always zero.
 *
 * The CRC32 is used for performance purposes (the algorithm utilizes SSE4.2
 * hardware instructions).
 */
unsigned long
tfw_hash_str(const TfwStr *str)
{
#define MUL sizeof(long)
	const TfwStr *chunk;
	const char *pos;
	const char *body_end;
	const char *head_end;
	const char *tail_end;
	register unsigned long crc = 0xFFFFFFFF;
	unsigned int len;

	TFW_STR_FOR_EACH_CHUNK(chunk, str, {
		len = chunk->len;
		pos = chunk->ptr;

		tail_end = pos + len;
		head_end = PTR_ALIGN(pos, MUL);
		body_end = PTR_ALIGN(tail_end, MUL) - MUL;

		if (likely(len >= MUL)) {
			while (pos != head_end) {
				CRCB(crc, *pos);
				++pos;
			}
			while (pos != body_end) {
				CRCQ(crc, *((unsigned long *)pos));
				pos += MUL;
			}
		}

		while (pos != tail_end) {
			CRCB(crc, *pos);
			++pos;
		}
	});

	return crc;
#undef MUL
}

