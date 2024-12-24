/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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

#include "db/core/tdb.h"
#define BANNER "JA5"
#include "log.h"

#include <linux/list.h>

#define JA5_FILTER_TIME_SLOTS_CNT 8
#define DB_RECS_TO_FREE_CNT 32

typedef struct {
	u32 counter;
	u32 ts;
} TimeSlot;

typedef struct {
	/** Keep  @list_node first for easy type casts */
	struct list_head	list_node;
	TimeSlot		conns[JA5_FILTER_TIME_SLOTS_CNT];
	spinlock_t		conns_lock;
	TimeSlot		recs[JA5_FILTER_TIME_SLOTS_CNT];
	spinlock_t		recs_lock;
} Rates;


static struct {
	TDB			*tdb;
	struct list_head	lru_list;
	spinlock_t		lru_list_lock;
} storage;

static bool
get_alloc_ctx_eq_rec(TdbRec *, void *)
{
	return true;
}

static void
put_fingerprint_rates(Rates *rates)
{
	tdb_rec_put(storage.tdb, (char *)rates - sizeof(TdbRec));
}

static void
get_alloc_ctx_init_rec(TdbRec *rec, void *)
{
	Rates *rates = (Rates *)rec->data;

	INIT_LIST_HEAD(&rates->list_node);
	spin_lock_init(&rates->conns_lock);
	spin_lock_init(&rates->recs_lock);
	tdb_rec_keep(rec);
}

static Rates*
get_fingerprint_rates(u64 fingerprint)
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
	while (!(rec = tdb_rec_get_alloc(storage.tdb, key, &get_alloc_ctx))) {
		struct list_head *pos, *tmp, tail_to_delete;
		u32 cnt = DB_RECS_TO_FREE_CNT;

		INIT_LIST_HEAD(&tail_to_delete);

		/* Cut off DB_RECS_TO_FREE_CNT entries from the LRU list */
		spin_lock(&storage.lru_list_lock);
		list_for_each_prev_safe(pos, tmp, &storage.lru_list) {
			list_move(pos, &tail_to_delete);
			if (!--cnt)
				break;
		}
		spin_unlock(&storage.lru_list_lock);

		list_for_each_safe(pos, tmp, &tail_to_delete)
			put_fingerprint_rates((Rates *)pos);

		/**
		 * Protect from low probable case where all records
		 * were deleted but are held by references
		 */
		if (cnt == DB_RECS_TO_FREE_CNT)
			return NULL;
	}

	rates = (Rates *)rec->data;

	spin_lock(&storage.lru_list_lock);
	/* The record still was not added to the LRU list */
	if (list_empty(&rates->list_node))
		list_add_tail(&rates->list_node, &storage.lru_list);
	spin_unlock(&storage.lru_list_lock);

	return rates;
}

static bool
init_filter(size_t max_storage_size)
{
	if (storage.tdb)
		return false;

	INIT_LIST_HEAD(&storage.lru_list);
	spin_lock_init(&storage.lru_list_lock);

	return (storage.tdb = tdb_open(
		"/tmp/ja5t_flt.tdb", max_storage_size, sizeof(Rates), 0));
}

static u32
ja5_calc_rate(TimeSlot slots[])
{
	u32 sum = 0;
	u64 ts = jiffies * JA5_FILTER_TIME_SLOTS_CNT / HZ;
	u64 end_ts = ts - JA5_FILTER_TIME_SLOTS_CNT;
	u8 slot_num = ts % JA5_FILTER_TIME_SLOTS_CNT;
	TimeSlot *slot = &slots[slot_num];

	if (slot->ts != ts) {
		slot->ts = ts;
		slot->counter = 0;
	}
	slot->counter++;

	for (; slot->ts > end_ts;
		slot_num = (slot->ts - 1) % JA5_FILTER_TIME_SLOTS_CNT,
		slot = &slots[slot_num])
		sum += slot->counter;

	return sum;
}

static u32
ja5_get_conns_rate(u64 fingerprint)
{
	u32 res;
	Rates *rates = get_fingerprint_rates(fingerprint);

	if (!rates)
		/* Allow connection if DB is full */
		return 0;

	spin_lock(&rates->conns_lock);
	res = ja5_calc_rate(rates->conns);
	spin_unlock(&rates->conns_lock);

	put_fingerprint_rates(rates);

	T_LOG_NL("JA5 Fingerprint %08llx: connections/sec %d",
		*(u64 *)&fingerprint, res);

	return res;
}

static u32
ja5_get_records_rate(u64 fingerprint)
{
	u32 res;
	Rates *rates = get_fingerprint_rates(fingerprint);

	if (!rates)
		/* Allow record if DB is full */
		return 0;

	spin_lock(&rates->recs_lock);
	res = ja5_calc_rate(rates->recs);
	spin_unlock(&rates->recs_lock);

	put_fingerprint_rates(rates);

	T_LOG_NL("JA5 Fingerprint %08llx: records/sec %d",
		*(u64 *)&fingerprint, res);

	return res;
}
