/**
 *		Tempesta FW
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#include "str.h"

#include "hash.h"

/**
 * Compute hash function exactly the same way as tdb_hash_calc() does it,
 * but do this over chunked data.
 *
 * The function uses SSE extensions, so make sure that FPU context is
 * properly stored/restored in the caller.
 */
unsigned long
tfw_hash_str(const TfwStr *str)
{
	unsigned long crc0 = 0, crc1 = 0;

	if (likely(TFW_STR_PLAIN(str))) {
		__tdb_hash_calc(&crc0, &crc1, str->data, str->len);
	}
	else {
		const TfwStr *c = (TfwStr *)str->chunks;
		const TfwStr *end = c + TFW_STR_CHUNKN(str);
		unsigned char *p, *e;
		unsigned int tail = 0;

		while (c < end) {
			p = c->data;
			e = p + c->len;

			if (tail) {
				for ( ; tail < 8; ++p, ++tail) {
					if (unlikely(p == e))
						goto next_chunk;
					CRCB(crc0, *p);
				}
				for ( ; tail < 16; ++p, ++tail) {
					if (unlikely(p == e))
						goto next_chunk;
					CRCB(crc1, *p);
				}
			}

			__tdb_hash_calc(&crc0, &crc1, p, e - p);
			tail = c->len & 0xf;
next_chunk:
			++c;
		}
	}

	return (crc1 << 32) | crc0;
}
