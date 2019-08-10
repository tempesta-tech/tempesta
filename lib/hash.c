/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2015-2019 Tempesta Technologies, INC.
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
#include <linux/kernel.h>

#include "hash.h"

/**
 * CRC32 instruction doesn't use FPU registers,
 * so no need for FPU context protection.
 */
void
__hash_calc(unsigned long *crc0, unsigned long *crc1, const char *data,
	    size_t len)
{
	int i;
	size_t n = (len >> 3) & ~1UL;
	unsigned long *d = (unsigned long *)data;

	for (i = 0; i < n; i += 2) {
		CRCQ(*crc0, d[i]);
		CRCQ(*crc1, d[i + 1]);
	}
	if (((n + 1) << 3) <= len) {
		CRCQ(*crc0, d[n]);
		for (n = (n + 1) << 3; n < len; ++n)
			CRCB(*crc1, data[n]);
	} else {
		for (n <<= 3; n < len; ++n)
			CRCB(*crc0, data[n]);
	}
}
EXPORT_SYMBOL(__hash_calc);
