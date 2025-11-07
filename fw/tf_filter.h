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
#ifndef __TF_FILTER__
#define __TF_FILTER__

#include "lib/tf.h"

bool tft_init_filter(size_t max_storage_size);
void tft_close_filter(void);
u32 tft_get_conns_rate(TlsTft fingerprint);
u32 tft_get_records_rate(TlsTft fingerprint);

bool tfh_init_filter(size_t max_storage_size);
void tfh_close_filter(void);
u32 tfh_get_conns_rate(HttpTfh fingerprint);
u32 tfh_get_records_rate(HttpTfh fingerprint);

#endif /* __TF_FILTER__ */
