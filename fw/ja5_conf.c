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

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "log.h"
#include "ja5_conf.h"
#include "hash.h"

/* Define default size as multiple of TDB extent size */
#define TLS_JA5_DEFAULT_STORAGE_SIZE ((1 << 21) * 25)
#define TLS_JA5_HASHTABLE_BITS 10

typedef struct {
	struct hlist_node	hlist;
	atomic_t		refcnt;
	/* TODO: make an unified macro for different types of ja5 hashes */
	TlsJa5t			ja5_hash;
	u64			conns_per_sec;
	u64			records_per_sec;
} TlsJa5HashEntry;

typedef struct {
	u64 storage_size;
	DECLARE_HASHTABLE(hashes, TLS_JA5_HASHTABLE_BITS);
} TlsJa5FilterCfg;

static TlsJa5FilterCfg __rcu	*tls_filter_cfg;
static TlsJa5FilterCfg		*tls_filter_cfg_reconfig;

static TlsJa5HashEntry*
tls_get_ja5_hash_entry(TlsJa5t fingerprint)
{
	u64 key;
	TlsJa5HashEntry *entry = NULL;
	TlsJa5FilterCfg *cfg;

	if (!tls_filter_cfg)
		return NULL;

	key = hash_calc((char *)&fingerprint, sizeof(fingerprint));

	rcu_read_lock_bh();
	cfg = rcu_dereference_bh(tls_filter_cfg);
	hash_for_each_possible(cfg->hashes, entry, hlist, key) {
		if (!memcmp(&fingerprint, &entry->ja5_hash, 
			sizeof(fingerprint))) {
			atomic_inc(&entry->refcnt);
			break;
		}
	}
	rcu_read_unlock_bh();

	return entry;
}

static void
tls_put_ja5_hash_entry(TlsJa5HashEntry *entry)
{
	if (entry) {
		s64 cnt = atomic_dec_return(&entry->refcnt);

		BUG_ON(cnt < 0);
		if (!cnt)
			kfree(entry);
	}
}

u64
tls_get_ja5_conns_limit(TlsJa5t fingerprint)
{
	u64 res = U64_MAX;
	TlsJa5HashEntry *e = tls_get_ja5_hash_entry(fingerprint);

	if (e) {
		res = e->conns_per_sec;
		tls_put_ja5_hash_entry(e);
	}

	return res;
}

u64
tls_get_ja5_recs_limit(TlsJa5t fingerprint)
{
	u64 res = U64_MAX;
	TlsJa5HashEntry *e = tls_get_ja5_hash_entry(fingerprint);

	if (e) {
		res = e->records_per_sec;
		tls_put_ja5_hash_entry(e);
	}

	return res;
}

u64
tls_get_ja5_storage_size(void)
{
	u64 res = 0;

	if (tls_filter_cfg) {
		rcu_read_lock_bh();
		res = rcu_dereference_bh(tls_filter_cfg)->storage_size;
		rcu_read_unlock_bh();
	}

	return res;
}

int
ja5_cfgop_handle_hash_entry(TfwCfgSpec *cs, TfwCfgEntry *ce)
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
	he->records_per_sec = recs_per_sec;
	INIT_HLIST_NODE(&he->hlist);
	atomic_set(&he->refcnt, 1);

	key = hash_calc((char *)&hash, sizeof(hash));
	hash_add(tls_filter_cfg_reconfig->hashes, &he->hlist, key);

	return 0;
}

int
ja5_cfgop_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(tls_filter_cfg_reconfig);
	TFW_CFG_CHECK_VAL_EQ_N(0, cs, ce);
	TFW_CFG_CHECK_ATTR_LE_N(1, cs, ce);

	if (!(tls_filter_cfg_reconfig =
		kzalloc(sizeof(TlsJa5FilterCfg), GFP_KERNEL)))
		return -ENOMEM;

	if (ce->attr_n == 1) {
		if (strcasecmp(ce->attrs[0].key, "storage_size")) {
			T_ERR_NL("Failed to parse ja5 section: "
			"invalid attribute %s", ce->attrs[0].key);
			return -EINVAL;
		}

		if (tfw_cfg_parse_ulonglong(ce->attrs[0].val,
			&tls_filter_cfg_reconfig->storage_size)) {
			T_ERR_NL("Failed to parse ja5 section: "
				"invalid storage_size value");
			return -EINVAL;
		}
	} else {
		tls_filter_cfg_reconfig->storage_size =
			TLS_JA5_DEFAULT_STORAGE_SIZE;
	}

	return 0;
}

static void
free_cfg(TlsJa5FilterCfg *cfg)
{
	u32 bkt_i;
	struct hlist_node *tmp;
	TlsJa5HashEntry *entry;

	BUG_ON(!cfg);

	hash_for_each_safe(cfg->hashes, bkt_i, tmp, entry, hlist)
		tls_put_ja5_hash_entry(entry);

	kfree(cfg);
}

int
ja5_cfgop_finish(TfwCfgSpec *cs)
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
ja5_cfgop_cleanup(TfwCfgSpec *cs)
{
	/* tls_cfgop_ja5_finish was not called due to parsing error */
	if (tls_filter_cfg_reconfig) {
		free_cfg(tls_filter_cfg_reconfig);
		tls_filter_cfg_reconfig = NULL;
	}
}
