/**
 *		Tempesta FW
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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
#ifndef __JA5_FILTER__
#define __JA5_FILTER__

#include "lib/ja5.h"

bool ja5t_init_filter(size_t max_storage_size);
u32 ja5t_get_conns_rate(TlsJa5t fingerprint);
u32 ja5t_get_records_rate(TlsJa5t fingerprint);

bool ja5h_init_filter(size_t max_storage_size);
u32 ja5h_get_conns_rate(HttpJa5h fingerprint);
u32 ja5h_get_records_rate(HttpJa5h fingerprint);

#endif // __JA5_FILTER__