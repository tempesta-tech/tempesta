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
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

#include "tf_conf.h"
#include "lib/fault_injection_alloc.h"
#include "hash.h"
#include "lib/tf.h"
#include "log.h"
#include "tempesta_fw.h"

static int tf_cfgop_handle_hash_entry(TfwCfgSpec *, TfwCfgEntry *);

/* Define default size as multiple of TDB extent size */
#define TF_DEFAULT_STORAGE_SIZE	((1 << 21) * 25)
#define TF_HASHTABLE_BITS		10

typedef struct {
	struct hlist_node	hlist;
	refcount_t		refcnt;
	union {
		TlsTft		tls_hash;
		HttpTfh		http_hash;
		u64		hash;
	};
	u64			conns_per_sec;
	u64			records_per_sec;
} TfHashEntry;

typedef struct {
	u64 storage_size;
	DECLARE_HASHTABLE(hashes, TF_HASHTABLE_BITS);
} TfFilterCfg;

static TfFilterCfg __rcu	*tls_filter_cfg;
static TfFilterCfg __rcu	*http_filter_cfg;
static TfFilterCfg		*filter_cfg_reconfig;

TfwCfgSpec tf_hash_specs[] = {
	{
		.name = "hash",
		.deflt = NULL,
		.handler = tf_cfgop_handle_hash_entry,
		.allow_none = true,
		.allow_repeat = true,
		.allow_reconfig = true,
	},
	{ 0 }
};

static TfHashEntry*
get_tf_hash_entry(TfFilterCfg *cfg, u64 fingerprint)
{
	u64 key;
	TfHashEntry *entry = NULL;
	TfFilterCfg *local_cfg;

	if (!cfg)
		return NULL;

	/* TODO: maybe directly use fingerprint as a key? */
	key = hash_calc((char *)&fingerprint, sizeof(fingerprint));

	rcu_read_lock_bh();
	local_cfg = rcu_dereference_bh(cfg);
	hash_for_each_possible(local_cfg->hashes, entry, hlist, key) {
		if (!memcmp(&fingerprint, &entry->hash, sizeof(fingerprint))) {
			refcount_inc(&entry->refcnt);
			break;
		}
	}
	rcu_read_unlock_bh();

	return entry;
}

static void
put_tf_hash_entry(TfHashEntry *entry)
{
	if (entry && refcount_dec_and_test(&entry->refcnt))
		kfree(entry);
}

static u64
get_tf_conns_limit(TfFilterCfg *cfg, u64 fingerprint)
{
	u64 res = U64_MAX;
	TfHashEntry *e = get_tf_hash_entry(cfg, fingerprint);

	if (e) {
		res = e->conns_per_sec;
		put_tf_hash_entry(e);
	}

	return res;
}

static u64
get_tf_recs_limit(TfFilterCfg *cfg, u64 fingerprint)
{
	u64 res = U64_MAX;
	TfHashEntry *e = get_tf_hash_entry(cfg, fingerprint);

	if (e) {
		res = e->records_per_sec;
		put_tf_hash_entry(e);
	}

	return res;
}

static u64
get_tf_storage_size(TfFilterCfg *cfg)
{
	u64 res = 0;

	if (cfg) {
		rcu_read_lock_bh();
		res = rcu_dereference_bh(cfg)->storage_size;
		rcu_read_unlock_bh();
	}

	return res;
}

static int
tf_cfgop_handle_hash_entry(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	u64 hash;
	u32 conns_per_sec;
	u32 recs_per_sec;
	TfHashEntry *he, *iter;
	u64 key;
	struct hlist_node *tmp;

	BUILD_BUG_ON(sizeof(TlsTft) != sizeof(u64));
	BUILD_BUG_ON(sizeof(HttpTfh) != sizeof(u64));
	TFW_CFG_CHECK_VAL_EQ_N(3, cs, ce);
	TFW_CFG_CHECK_NO_ATTRS(cs, ce);

	if (tfw_cfg_parse_uint(ce->vals[1], &conns_per_sec)) {
		T_ERR_NL("Failed to parse hash entry in tf(h/t) section: "
			 "invalid connections per second value %s", ce->vals[1]);
		return -EINVAL;
	}

	if (tfw_cfg_parse_uint(ce->vals[2], &recs_per_sec)) {
		T_ERR_NL("Failed to parse hash entry in tf(h/t) section: "
			 "invalid records per second value %s", ce->vals[2]);
		return -EINVAL;
	}

	if (kstrtou64(ce->vals[0], 16, &hash)) {
		T_ERR_NL("Failed to parse hash entry in tf(h/t) section: "
			 "invalid hash value %s", ce->vals[0]);
		return -EINVAL;
	}

	if (!(he = tfw_kmalloc(sizeof(TfHashEntry), GFP_KERNEL)))
		return -ENOMEM;

	he->hash = hash;
	he->conns_per_sec = conns_per_sec;
	he->records_per_sec = recs_per_sec;
	INIT_HLIST_NODE(&he->hlist);
	refcount_set(&he->refcnt, 1);

	key = hash_calc((char *)&hash, sizeof(hash));
	hash_for_each_possible_safe(filter_cfg_reconfig->hashes, iter, tmp,
					hlist, key) {
		if (iter->hash == hash) {
			hash_del(&iter->hlist);
			kfree(iter);
			break;
		}
	}
	hash_add(filter_cfg_reconfig->hashes, &he->hlist, key);

	return 0;
}

int
tf_cfgop_begin(TfwCfgSpec *cs, TfwCfgEntry *ce)
{
	BUG_ON(filter_cfg_reconfig);
	TFW_CFG_CHECK_VAL_EQ_N(0, cs, ce);
	TFW_CFG_CHECK_ATTR_LE_N(1, cs, ce);

	filter_cfg_reconfig = tfw_kzalloc(sizeof(TfFilterCfg), GFP_KERNEL);
	if (unlikely(!filter_cfg_reconfig))
		return -ENOMEM;

	if (ce->attr_n == 1) {
		if (strcasecmp(ce->attrs[0].key, "storage_size")) {
			T_ERR_NL("Failed to parse tf(h/t) section: "
				 "invalid attribute %s", ce->attrs[0].key);
			return -EINVAL;
		}

		if (tfw_cfg_parse_ulonglong(ce->attrs[0].val,
			&filter_cfg_reconfig->storage_size)) {
			T_ERR_NL("Failed to parse tf(h/t) section: "
				 "invalid storage_size value");
			return -EINVAL;
		}
	} else {
		filter_cfg_reconfig->storage_size = TF_DEFAULT_STORAGE_SIZE;
	}

	return 0;
}

static void
free_cfg(TfFilterCfg *cfg)
{
	u32 bkt_i;
	struct hlist_node *tmp;
	TfHashEntry *entry;

	if (!cfg)
		return;

	hash_for_each_safe(cfg->hashes, bkt_i, tmp, entry, hlist)
		put_tf_hash_entry(entry);

	kfree(cfg);
}

static int
tf_cfgop_finish(TfFilterCfg **cfg, TfwCfgSpec *cs)
{
	TfFilterCfg *prev = *cfg;

	BUG_ON(!filter_cfg_reconfig);

	rcu_assign_pointer(*cfg, filter_cfg_reconfig);
	synchronize_rcu();
	free_cfg(prev);
	filter_cfg_reconfig = NULL;

	return 0;
}

static void
tf_cfgop_cleanup(TfFilterCfg **cfg, TfwCfgSpec *cs)
{
	free_cfg(filter_cfg_reconfig);
	filter_cfg_reconfig = NULL;

	if (!tfw_runstate_is_reconfig()) {
		TfFilterCfg *prev = *cfg;

		rcu_assign_pointer(*cfg, NULL);
		synchronize_rcu();
		free_cfg(prev);
	}
}

/* TLS functions */
u64
tls_get_tf_conns_limit(TlsTft fingerprint)
{
	return get_tf_conns_limit(tls_filter_cfg, *(u64 *)&fingerprint);
}

u64
tls_get_tf_recs_limit(TlsTft fingerprint)
{
	return get_tf_recs_limit(tls_filter_cfg, *(u64 *)&fingerprint);
}

u64
tls_get_tf_storage_size(void)
{
	return get_tf_storage_size(tls_filter_cfg);
}

int
tls_tf_cfgop_finish(TfwCfgSpec *cs)
{
	return tf_cfgop_finish(&tls_filter_cfg, cs);
}

void
tls_tf_cfgop_cleanup(TfwCfgSpec *cs)
{
	tf_cfgop_cleanup(&tls_filter_cfg, cs);
}

/* HTTP functions */
u64
http_get_tf_conns_limit(HttpTfh fingerprint)
{
	return get_tf_conns_limit(http_filter_cfg, *(u64 *)&fingerprint);
}

u64
http_get_tf_recs_limit(HttpTfh fingerprint)
{
	return get_tf_recs_limit(http_filter_cfg, *(u64 *)&fingerprint);
}

u64
http_get_tf_storage_size(void)
{
	return get_tf_storage_size(http_filter_cfg);
}

int
http_tf_cfgop_finish(TfwCfgSpec *cs)
{
	return tf_cfgop_finish(&http_filter_cfg, cs);
}

void
http_tf_cfgop_cleanup(TfwCfgSpec *cs)
{
	tf_cfgop_cleanup(&http_filter_cfg, cs);
}
