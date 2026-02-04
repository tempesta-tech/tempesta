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
#include <linux/list.h>

#include "tf_filter.h"
#include "db/core/tdb.h"
#include "lib/str.h"
#include "lib/tf.h"
#include "log.h"


#define TF_FILTER_TIME_SLOTS_POW	3
#define TF_FILTER_TIME_SLOTS_CNT	(1 << TF_FILTER_TIME_SLOTS_POW)
#define TF_FILTER_TIME_SLOTS_MASK	(TF_FILTER_TIME_SLOTS_CNT - 1)
#define DB_RECS_TO_FREE_CNT		32

#define TLS_TDB_FILE_PATH	"/opt/tempesta/db/tft_flt.tdb"
#define HTTP_TDB_FILE_PATH	"/opt/tempesta/db/tfh_flt.tdb"

/**
 * Holds time slot's @counter for timestamp @ts
 */
typedef struct {
	u32 counter;
	u32 ts;
} TimeSlot;

/**
 * Holds connections and data records rates for a particular fingerprint
 *
 * @param list_node - required for LRU list
 * @param conns - array of connections counters for timeslots for the last second
 * @param conns_lock - lock for @conns
 * @param recs - array of records counters for timeslots for the last second
 * @param recs_lock - lock for @recs
 */
typedef struct {
	/** Keep  @list_node first for easy type casts */
	struct list_head	list_node;
	TimeSlot		conns[TF_FILTER_TIME_SLOTS_CNT];
	spinlock_t		conns_lock;
	TimeSlot		recs[TF_FILTER_TIME_SLOTS_CNT];
	spinlock_t		recs_lock;
} Rates;

/**
 * Rates storage for a particular fingerprints types. This file(tf_filter.h)
 * is supposed to be included into a .c file responsible for that fingerprints
 * processing.
 *
 * @param tdb - TDB instance keeping rates by fingerprint value
 * @param lru_list - LRU list used for eviction of outdates fingerprints
 * @param lru_list_lock - lock for @lru_list
 */
typedef struct {
	TDB			*tdb;
	struct list_head	lru_list;
	spinlock_t		lru_list_lock;
} Storage;

static Storage tls_storage, http_storage;

static bool
get_alloc_ctx_eq_rec(TdbRec *, void *)
{
	return true;
}

static void
put_fingerprint_rates(Storage *storage, Rates *rates)
{
	tdb_rec_put(storage->tdb, (char *)rates - sizeof(TdbRec));
}

static int
get_alloc_ctx_init_rec(TdbRec *rec, void *)
{
	Rates *rates = (Rates *)rec->data;

	bzero_fast(rates, sizeof(Rates));
	INIT_LIST_HEAD(&rates->list_node);
	spin_lock_init(&rates->conns_lock);
	spin_lock_init(&rates->recs_lock);
	tdb_rec_keep(rec);

	return 0;
}

/**
 * Finds @Rates object by fingerprint in the @storage if it exists and adds it
 * to the @storage otherwise. Remove outdates rates from the @storage if it's
 * full by RLU algorithm.
 */
static Rates*
get_fingerprint_rates(Storage *storage, u64 fingerprint)
{
	TdbGetAllocCtx get_alloc_ctx = {
		.eq_rec = get_alloc_ctx_eq_rec,
		.ctx = NULL,
		.precreate_rec = NULL,
		.init_rec = get_alloc_ctx_init_rec,
		.len = sizeof(Rates)};
	const u64 key = fingerprint;
	TdbRec *rec;
	Rates *rates;

	/* Try to remove DB_RECS_TO_FREE_CNT records from DB if it's full */
	while (!(rec = tdb_rec_get_alloc(storage->tdb, key, &get_alloc_ctx))) {
		struct list_head *pos, *tmp, head_to_delete;
		u32 cnt = DB_RECS_TO_FREE_CNT;

		INIT_LIST_HEAD(&head_to_delete);

		/* Cut off DB_RECS_TO_FREE_CNT entries from the LRU list */
		spin_lock(&storage->lru_list_lock);
		list_for_each_safe(pos, tmp, &storage->lru_list) {
			list_move(pos, &head_to_delete);
			if (!--cnt)
				break;
		}
		spin_unlock(&storage->lru_list_lock);

		list_for_each_safe(pos, tmp, &head_to_delete) {
			u64 key = ((TdbRec *)pos - 1)->key;
			/* TODO: remove directly by record bypassing search by key */
			tdb_entry_remove(storage->tdb, key, NULL, NULL, true);
		}
		/**
		 * Protect from low probable case where all records
		 * were deleted but are held by references
		 */
		if (cnt == DB_RECS_TO_FREE_CNT)
			return NULL;
	}

	rates = (Rates *)rec->data;

	spin_lock(&storage->lru_list_lock);
	if (list_empty(&rates->list_node)) {
		/* Entry is new or was somehow removed from list, add it to tail (MRU) */
		list_add_tail(&rates->list_node, &storage->lru_list);
	} else {
		/* Entry already exists and is in the list, move it to tail (MRU) */
		list_move_tail(&rates->list_node, &storage->lru_list);
	}
	spin_unlock(&storage->lru_list_lock);

	return rates;
}

/**
 * Inintializes the storage with its max size
 *
 * @param storage - fingerprints storage
 * @param max_storage_size storage size
 * @param file_path path to a file to map TDB to
 * @return true if storage's been successfully initialized or is already
 * initialized
 * @return false otherwise
 */
static bool
init_filter(Storage *storage, size_t max_storage_size, const char *file_path)
{
	/**
	 * Initialize storage only once during whole uptime.
	 * Storage size reconfiguration is not supported.
	 */
	if (storage->tdb)
		return true;

	INIT_LIST_HEAD(&storage->lru_list);
	spin_lock_init(&storage->lru_list_lock);

	return (storage->tdb = tdb_open(
		file_path, max_storage_size, sizeof(Rates), 0));
}

static void
close_filter(Storage *storage)
{
	tdb_close(storage->tdb);
}

static u32
tf_calc_rate(TimeSlot slots[], spinlock_t *lock)
{
	u32 sum = 0;
	u64 ts = jiffies * TF_FILTER_TIME_SLOTS_CNT / HZ;
	u8 slot_num = ts & TF_FILTER_TIME_SLOTS_MASK;
	TimeSlot *current_slot = &slots[slot_num];

	spin_lock(lock);

	if (current_slot->ts != ts) {
		current_slot->ts = ts;
		current_slot->counter = 0;
	}
	current_slot->counter++;

	for (slot_num = 0; slot_num < TF_FILTER_TIME_SLOTS_CNT; slot_num++)
		if (slots[slot_num].ts + TF_FILTER_TIME_SLOTS_CNT >= ts)
			sum += slots[slot_num].counter;

	spin_unlock(lock);

	return sum;
}

/**
 * Returns the last second's connections number for the specified fingerprint
 *
 * @param storage - fingerprints storage
 * @param fingerprint fingerprint connections rates to look for
 */
static u32
tf_get_conns_rate(Storage *storage, u64 fingerprint)
{
	u32 res;
	Rates *rates;

	if (!storage->tdb)
		return 0;

	if (!(rates = get_fingerprint_rates(storage, fingerprint)))
		/* Allow connection if DB is full */
		return 0;

	res = tf_calc_rate(rates->conns, &rates->conns_lock);

	put_fingerprint_rates(storage, rates);

	T_DBG("TF Fingerprint %08llx: connections/sec %d",
	      *(u64 *)&fingerprint, res);

	return res;
}

/**
 * Returns the last second's records number for the specified fingerprint
 *
 * @param storage - fingerprints storage
 * @param fingerprint a fingerprint records rates to look for
 */
static u32
tf_get_records_rate(Storage *storage, u64 fingerprint)
{
	u32 res;
	Rates *rates;

	if (!storage->tdb)
		return 0;

	if (!(rates = get_fingerprint_rates(storage, fingerprint)))
		/* Allow record if DB is full */
		return 0;

	res = tf_calc_rate(rates->recs, &rates->recs_lock);

	put_fingerprint_rates(storage, rates);

	T_DBG("TF Fingerprint %08llx: records/sec %d",
	      *(u64 *)&fingerprint, res);

	return res;
}

bool
tfh_init_filter(size_t max_storage_size)
{
	return init_filter(&http_storage, max_storage_size, HTTP_TDB_FILE_PATH);
}

void
tfh_close_filter(void)
{
	return close_filter(&http_storage);
}

u32
tfh_get_conns_rate(HttpTfh fingerprint)
{
	BUILD_BUG_ON(sizeof(fingerprint) != sizeof(u64));

	return tf_get_conns_rate(&http_storage, *(u64 *)&fingerprint);
}

u32
tfh_get_records_rate(HttpTfh fingerprint)
{
	BUILD_BUG_ON(sizeof(fingerprint) != sizeof(u64));

	return tf_get_records_rate(&http_storage, *(u64 *)&fingerprint);
}

bool
tft_init_filter(size_t max_storage_size)
{
	return init_filter(&tls_storage, max_storage_size, TLS_TDB_FILE_PATH);
}

void
tft_close_filter(void)
{
	return close_filter(&tls_storage);
}

u32
tft_get_conns_rate(TlsTft fingerprint)
{
	BUILD_BUG_ON(sizeof(fingerprint) != sizeof(u64));

	return tf_get_conns_rate(&tls_storage, *(u64 *)&fingerprint);
}

u32
tft_get_records_rate(TlsTft fingerprint)
{
	BUILD_BUG_ON(sizeof(fingerprint) != sizeof(u64));

	return tf_get_records_rate(&tls_storage, *(u64 *)&fingerprint);
}
