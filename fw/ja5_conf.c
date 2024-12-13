/**
 *		Tempesta FW
 *
 * Transport Layer Security (TLS) interfaces to Tempesta TLS.
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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

#include "ja5_conf.h"
#include "hash.h"

#define TLS_JA5_DEFAULT_MAX_ENTRIES 100
#define TLS_JA5_HASHTABLE_BITS 10

struct {
	u32 max_entries_cnt;
	DECLARE_HASHTABLE(hashes, TLS_JA5_HASHTABLE_BITS);
} TlsJa5FilterCfg;

static TlsJa5FilterCfg __rcu    *tls_filter_cfg;
static TlsJa5FilterCfg          *tls_filter_cfg_reconfig;

TlsJa5HashEntry*
tls_get_ja5_hash_entry(TlsJa5t hash)
{
	u32 key = hash_calc((char *)&hash, sizeof(hash));
	TlsJa5HashEntry *entry = NULL;
	TlsJa5FilterCfg *cfg;

	rcu_read_lock_bh();
	cfg = rcu_dereference_bh(tls_filter_cfg);
	hash_for_each_possible(cfg->hashes, entry, hlist, key) {
		if (!memcmp_fast(&hash, entry, sizeof(hash))) {
			atomic64_inc(&entry->refcnt);
			break;
		}
	}
	rcu_read_unlock_bh();

	return entry;
}

void
tls_put_ja5_hash_entry(TlsJa5HashEntry *entry)
{
	if (!atomic64_dec_return(&entry->refcnt))
		kfree(entry);
}

u32
tls_get_ja5_max_entries(void)
{
	u32 res;

	rcu_read_lock_bh();
	res = rcu_dereference_bh(tls_filter_cfg)->max_entries_cnt;
	rcu_read_unlock_bh();

	return  res;
}

int
handle_ja5_hash_entry(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	TlsJa5t hash;
	u32 conns_per_sec;
	u32 recs_per_sec;
	TlsJa5HashEntry *he;
	u64 key;

	BUILD_BUG_ON(sizeof(hash) > sizeof(u64));
	TFW_CFG_CHECK_VAL_EQ_N(3, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (tfw_cfg_parse_uint(ce->vals[1], &conns_per_sec)) {
		T_ERR_NL("Failed to parse hash entry in ja5 section: "
			"invalid connections per second value %s", ce->vals[1]);
		return -EINVAL;
	}

	if (tfw_cfg_parse_uint(ce->vals[2], &recs_per_sec)) {
		T_ERR_NL("Failed to parse hash entry in ja5 section: "
			"invalid records per second value %s", ce->vals[2]);
		return -EINVAL;
	}

	if (kstrtou64(ce->vals[0], 16, (u64 *)&hash)) {
		T_ERR_NL("Failed to parse hash entry in ja5 section: "
			"invalid hash value %s", ce->vals[0]);
		return -EINVAL;
	}

	if (!(he = kmalloc(sizeof(TlsJa5HashEntry), GFP_KERNEL)))
		return -ENOMEM;

	he->ja5_hash = hash;
	he->conns_per_sec = conns_per_sec;
	he->tls_records_per_sec = recs_per_sec;
	INIT_HLIST_NODE(&he->hlist);
	he->refcnt.counter = 1;

	key = hash_calc((char *)&hash, sizeof(hash));
	hash_add(tls_filter_cfg_reconfig->hashes, &he->hlist, key);

	return 0;
}

int
tls_cfgop_ja5_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tls_filter_cfg_reconfig);
	TFW_CFG_CHECK_VAL_EQ_N(0, cs, ce);
	TFW_CFG_CHECK_ATTR_LE_N(1, cs, ce);

	if (!(tls_filter_cfg_reconfig = kzalloc(sizeof(TlsJa5FilterCfg), GFP_KERNEL)))
		return -ENOMEM;

	if (ce->attr_n == 1) {
		if (strcasecmp(ce->attrs[0].key, "max_entries")) {
			T_ERR_NL("Failed to parse ja5 section: invalid attribute %s",
				ce->attrs[0].key);
			return -EINVAL;
		}

		if (kstrtou32(ce->attrs[0].val, 10, &tls_filter_cfg_reconfig->max_entries_cnt)) {
			T_ERR_NL("Failed to parse ja5 section: invalid max_entries value");
			return -EINVAL;
		}
	} else {
		tls_filter_cfg_reconfig->max_entries_cnt = TLS_JA5_DEFAULT_MAX_ENTRIES;
	}

	return 0;
}

static void
free_cfg(TlsJa5FilterCfg *cfg)
{
	u32 bkt_i;
	TlsJa5HashEntry *entry;

	BUG_ON(!cfg);

	hash_for_each(cfg->hashes, bkt_i, entry, hlist) {
		tls_put_ja5_hash_entry(entry);
	}
	kfree(cfg);
}

int
tls_cfgop_ja5_finish(TfwCfgSpec *cs)
{
	TlsJa5FilterCfg *prev = tls_filter_cfg;

	BUG_ON(!tls_filter_cfg_reconfig);

	rcu_assign_pointer(tls_filter_cfg, tls_filter_cfg_reconfig);
	synchronize_rcu();
	if (prev) {
		free_cfg(prev);
		T_LOG_NL("Successfully reconfigured ja5 filter");
	}
	tls_filter_cfg_reconfig = NULL;

	return 0;
}

void
tls_cfgop_ja5_cleanup(TfwCfgSpec *cs)
{
	/* tls_cfgop_ja5_finish was not called due to parsing error */
	if (tls_filter_cfg_reconfig) {
		free_cfg(tls_filter_cfg_reconfig);
		tls_filter_cfg_reconfig = NULL;
	}
}
