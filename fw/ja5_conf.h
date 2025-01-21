/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2025 Tempesta Technologies, Inc.
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
#ifndef __JA5_CONF__
#define __JA5_CONF__

#include "cfg.h"
#include "lib/ja5.h"

/** TLS */
u64 tls_get_ja5_storage_size(void);
u64 tls_get_ja5_conns_limit(TlsJa5t fingerprint);
u64 tls_get_ja5_recs_limit(TlsJa5t fingerprint);

int tls_ja5_cfgop_finish(TfwCfgSpec *cs);
void tls_ja5_cfgop_cleanup(TfwCfgSpec *cs);

/** HTTP */
u64 http_get_ja5_storage_size(void);
u64 http_get_ja5_conns_limit(HttpJa5h fingerprint);
u64 http_get_ja5_recs_limit(HttpJa5h fingerprint);

int http_ja5_cfgop_finish(TfwCfgSpec *cs);
void http_ja5_cfgop_cleanup(TfwCfgSpec *cs);

/** Common */
extern TfwCfgSpec ja5_hash_specs[];

int ja5_cfgop_begin(TfwCfgSpec *cs, TfwCfgEntry *ce);

#endif // __JA5_CONF__
