/**
 *		Tempesta DB
 *
 * Copyright (C) 2015-2016 Tempesta Technologies.
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
#include <linux/types.h>
#include <asm/fpu/api.h>

#include "hash.h"

/**
 * CRC32 instruction doesn't use FPU registers,
 * so no need for FPU context protection.
 */
unsigned long
tdb_hash_calc(const char *data, size_t len)
{
	unsigned long crc0 = 0, crc1 = 0;

	__tdb_hash_calc(&crc0, &crc1, data, len);

	return (crc1 << 32) | crc0;
}
