/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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

#include "ja5t_filter.h"
#include "lib/ja5_filter.h"

bool
ja5t_init_filter(size_t max_storage_size)
{
        return init_filter(max_storage_size);
}

u32
ja5t_get_conns_rate(TlsJa5t fingerprint)
{
        BUILD_BUG_ON(sizeof(fingerprint) != sizeof(u64));

        return ja5_get_conns_rate(*(u64 *)&fingerprint);
}

u32
ja5t_get_records_rate(TlsJa5t fingerprint)
{
        BUILD_BUG_ON(sizeof(fingerprint) != sizeof(u64));

        return ja5_get_records_rate(*(u64 *)&fingerprint);
}
