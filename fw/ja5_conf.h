/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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

#include "ttls.h"
#include "cfg.h"

typedef struct {
	struct hlist_node	hlist;
	atomic64_t		refcnt;
	/* TODO: make an unified macro for different types of ja5 hashes */
	TlsJa5t			ja5_hash;
	u64			conns_per_sec;
	u64			tls_records_per_sec;
} TlsJa5HashEntry;

TlsJa5HashEntry*
tls_get_ja5_hash_entry(TlsJa5t hash);

void
tls_put_ja5_hash_entry(TlsJa5HashEntry *entry);

u32
tls_get_ja5_max_entries(void);

int
handle_ja5_hash_entry(TfwCfgSpec *cs, TfwCfgEntry *ce);

int
tls_cfgop_ja5_begin(TfwCfgSpec *cs, TfwCfgEntry *ce);

int
tls_cfgop_ja5_finish(TfwCfgSpec *cs);

void
tls_cfgop_ja5_cleanup(TfwCfgSpec *cs);
