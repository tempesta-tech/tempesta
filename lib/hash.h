/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2015-2018 Tempesta Technologies, INC.
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
#ifndef __LIB_HASH_H__
#define __LIB_HASH_H__

#define CRCQ(crc, data64) \
	asm volatile("crc32q %2, %0" : "=r"(crc) : "0"(crc), "r"(data64))

#define CRCB(crc, data8) \
	asm volatile("crc32b %2, %0" : "=r"(crc) : "0"(crc), "r"(data8))

void __hash_calc(unsigned long *crc0, unsigned long *crc1, const char *data,
		 size_t len);

static inline unsigned long
hash_calc(const char *data, size_t len)
{
	unsigned long crc0 = 0, crc1 = 0;

	__hash_calc(&crc0, &crc1, data, len);

	return (crc1 << 32) | crc0;
}

#endif /* __LIB_HASH_H__ */
