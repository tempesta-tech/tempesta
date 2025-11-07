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
#ifndef __TF5_CONF__
#define __TF5_CONF__

#include "cfg.h"
#include "lib/tf.h"

/** TLS */
u64 tls_get_tf_storage_size(void);
u64 tls_get_tf_conns_limit(TlsTft fingerprint);
u64 tls_get_tf_recs_limit(TlsTft fingerprint);

int tls_tf_cfgop_finish(TfwCfgSpec *cs);
void tls_tf_cfgop_cleanup(TfwCfgSpec *cs);

/** HTTP */
u64 http_get_tf_storage_size(void);
u64 http_get_tf_conns_limit(HttpTfh fingerprint);
u64 http_get_tf_recs_limit(HttpTfh fingerprint);

int http_tf_cfgop_finish(TfwCfgSpec *cs);
void http_tf_cfgop_cleanup(TfwCfgSpec *cs);

/** Common */
extern TfwCfgSpec tf_hash_specs[];

int tf_cfgop_begin(TfwCfgSpec *cs, TfwCfgEntry *ce);

#endif // __TF_CONF__
