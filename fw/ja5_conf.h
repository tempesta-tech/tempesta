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

#pragma once

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "lib/ja5.h"
#include "cfg.h"
#include "log.h"
#include "hash.h"
#include "tempesta_fw.h"

#ifndef JA5_STRUCT_T
#error "JA5_STRUCT_T macro is not defined before include of ja5_conf.h"
#endif

/* Define default size as multiple of TDB extent size */
#define JA5_DEFAULT_STORAGE_SIZE ((1 << 21) * 25)
#define JA5_HASHTABLE_BITS 10

typedef struct {
	struct hlist_node	hlist;
	atomic_t		refcnt;
	JA5_STRUCT_T		ja5_hash;
	u64			conns_per_sec;
	u64			records_per_sec;
} Ja5HashEntry;

typedef struct {
	u64 storage_size;
	DECLARE_HASHTABLE(hashes, JA5_HASHTABLE_BITS);
} Ja5FilterCfg;

static Ja5FilterCfg __rcu	*filter_cfg;
static Ja5FilterCfg		*filter_cfg_reconfig;

static Ja5HashEntry*
get_ja5_hash_entry(JA5_STRUCT_T fingerprint)
{
	u64 key;
	Ja5HashEntry *entry = NULL;
	Ja5FilterCfg *cfg;

	if (!filter_cfg)
		return NULL;

	key = hash_calc((char *)&fingerprint, sizeof(fingerprint));

	rcu_read_lock_bh();
	cfg = rcu_dereference_bh(filter_cfg);
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
put_ja5_hash_entry(Ja5HashEntry *entry)
{
	if (entry) {
		s64 cnt = atomic_dec_return(&entry->refcnt);

		BUG_ON(cnt < 0);
		if (!cnt)
			kfree(entry);
	}
}

static u64
get_ja5_conns_limit(JA5_STRUCT_T fingerprint)
{
	u64 res = U64_MAX;
	Ja5HashEntry *e = get_ja5_hash_entry(fingerprint);

	if (e) {
		res = e->conns_per_sec;
		put_ja5_hash_entry(e);
	}

	return res;
}

static u64
get_ja5_recs_limit(JA5_STRUCT_T fingerprint)
{
	u64 res = U64_MAX;
	Ja5HashEntry *e = get_ja5_hash_entry(fingerprint);

	if (e) {
		res = e->records_per_sec;
		put_ja5_hash_entry(e);
	}

	return res;
}

static u64
get_ja5_storage_size(void)
{
	u64 res = 0;

	if (filter_cfg) {
		rcu_read_lock_bh();
		res = rcu_dereference_bh(filter_cfg)->storage_size;
		rcu_read_unlock_bh();
	}

	return res;
}

static int
ja5_cfgop_handle_hash_entry(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	JA5_STRUCT_T hash;
	u32 conns_per_sec;
	u32 recs_per_sec;
	Ja5HashEntry *he;
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

	if (!(he = kmalloc(sizeof(Ja5HashEntry), GFP_KERNEL)))
		return -ENOMEM;

	he->ja5_hash = hash;
	he->conns_per_sec = conns_per_sec;
	he->records_per_sec = recs_per_sec;
	INIT_HLIST_NODE(&he->hlist);
	atomic_set(&he->refcnt, 1);

	key = hash_calc((char *)&hash, sizeof(hash));
	hash_add(filter_cfg_reconfig->hashes, &he->hlist, key);

	return 0;
}

static int
ja5_cfgop_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(filter_cfg_reconfig);
	TFW_CFG_CHECK_VAL_EQ_N(0, cs, ce);
	TFW_CFG_CHECK_ATTR_LE_N(1, cs, ce);

	if (!(filter_cfg_reconfig =
		kzalloc(sizeof(Ja5FilterCfg), GFP_KERNEL)))
		return -ENOMEM;

	if (ce->attr_n == 1) {
		if (strcasecmp(ce->attrs[0].key, "storage_size")) {
			T_ERR_NL("Failed to parse ja5 section: "
			"invalid attribute %s", ce->attrs[0].key);
			return -EINVAL;
		}

		if (tfw_cfg_parse_ulonglong(ce->attrs[0].val,
			&filter_cfg_reconfig->storage_size)) {
			T_ERR_NL("Failed to parse ja5 section: "
				"invalid storage_size value");
			return -EINVAL;
		}
	} else {
		filter_cfg_reconfig->storage_size =
			JA5_DEFAULT_STORAGE_SIZE;
	}

	return 0;
}

static void
free_cfg(Ja5FilterCfg *cfg)
{
	u32 bkt_i;
	struct hlist_node *tmp;
	Ja5HashEntry *entry;

	if (!cfg)
		return;

	hash_for_each_safe(cfg->hashes, bkt_i, tmp, entry, hlist)
		put_ja5_hash_entry(entry);

	kfree(cfg);
}

static int
ja5_cfgop_finish(TfwCfgSpec *cs)
{
	Ja5FilterCfg *prev = filter_cfg;

	BUG_ON(!filter_cfg_reconfig);

	rcu_assign_pointer(filter_cfg, filter_cfg_reconfig);
	synchronize_rcu();
	if (prev) {
		free_cfg(prev);
		T_LOG_NL("Successfully reconfigured ja5 filter");
	}
	filter_cfg_reconfig = NULL;

	return 0;
}

static void
ja5_cfgop_cleanup(TfwCfgSpec *cs)
{
	free_cfg(filter_cfg_reconfig);
	filter_cfg_reconfig = NULL;

	if (!tfw_runstate_is_reconfig()) {
		free_cfg(filter_cfg);
		filter_cfg = NULL;
	}
}
