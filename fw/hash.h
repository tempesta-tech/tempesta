/**
 *		Tempesta FW
 *
 * Copyright (C) 2019-2022 Tempesta Technologies, INC.
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

#ifndef __TFW_HASH_H__
#define __TFW_HASH_H__

#include "str.h"

#include "lib/hash.h"

static inline long
basic_hash_str(const BasicStr *str)
{
	unsigned long crc0 = 0, crc1 = 0;

	__hash_calc(&crc0, &crc1, str->data, str->len);

	return (crc1 << 32) | crc0;
}

unsigned long tfw_hash_str_len(const TfwStr *str, unsigned long str_len);

#define tfw_hash_str(str)     tfw_hash_str_len((str), ULONG_MAX)

#endif /* __TFW_HASH_H__ */
