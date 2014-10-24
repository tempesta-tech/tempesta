/**
 *		Tempesta DB
 *
 * This is the entry point: initialization functions and public interfaces.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/module.h>
#include <linux/slab.h>

#include "tdb.h"
#include "file.h"
#include "work.h"

MODULE_AUTHOR("NatSys Lab. (http://natsys-lab.com)");
MODULE_DESCRIPTION("Tempesta DB");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");

static struct workqueue_struct *tdb_wq;
static struct kmem_cache *tw_cache;

/**
 * Allocates a new page and links it to @curr record.
 */
static TdbRecord *
tdb_record_new(TDB *db, TdbRecord *curr)
{
	TdbRecord *r;

	/* @db can be uninitialized, see tdb_open(). */
	if (unlikely(!db->map))
		return NULL;

	r = tdb_file_alloc_data_page(db);
	if (!r)
		return NULL;
	memset(r, 0, sizeof(*r));
	if (curr)
		curr->chunk_next = TDB_REC_OFFSET(db, r);

	return r;
}

TdbRecord *
tdb_entry_create(TDB *db, unsigned long *key, size_t elen, unsigned int flags)
{
	TdbRecord *r = tdb_record_new(db, NULL);
	if (!r)
		return NULL;

	WARN_ON(elen + sizeof(*r) > PAGE_SIZE);
	r->flags = flags;
	r->d_len = elen - sizeof(*r);

	/* TODO add the entry to index by @key. */

	return r;
}
EXPORT_SYMBOL(tdb_entry_create);

/**
 * @return pointer to free area of size at least @size bytes or allocate
 * a new record and link it with the current one.
 *
 * TODO update @size to actually allocated space.
 */
void *
tdb_entry_add(TDB *db, TdbRecord **r, size_t size)
{
	char *rd;
	TdbRecord *r_tmp = *r;

	/* Call extension on fixed size record. */
	BUG_ON((*r)->flags & TDB_F_LARGE);

	/* No sense to allocate space room for not the last entry. */
	WARN_ON(!TDB_REC_ISLAST(r_tmp));
	if (unlikely(size > TDB_REC_DMAXSZ(*r))) {
		TDB_ERR("Requested too large record size, %lu\n", size);
		return NULL;
	}

	if (!TDB_REC_ROOM(r_tmp) || TDB_REC_ROOM(r_tmp) < size) {
		r_tmp = tdb_record_new(db, r_tmp);
		if (!r_tmp)
			return NULL;
		*r = r_tmp;
	}

	rd = r_tmp->data + r_tmp->d_len;
	r_tmp->d_len += size;

	return rd;
}
EXPORT_SYMBOL(tdb_entry_add);

void *
tdb_lookup(TDB *db, unsigned long *key)
{
	/* @db can be uninitialized, see tdb_open(). */
	if (!db->map)
		return NULL;

	/* TODO */
	return NULL;
}
EXPORT_SYMBOL(tdb_lookup);

/**
 * Work queue wrapper for tdb_file_open() (real file open).
 */
static void
tdb_open_db(struct work_struct *work)
{
	TdbWork *tw = (TdbWork *)work;

	if (tdb_file_open(tw->db))
		TDB_ERR("can't open");

	kmem_cache_free(tw_cache, tw);
}

/**
 * Open database file and @return its descriptor.
 *
 * The function must not be called from softirq!
 */
TDB *
tdb_open(const char *path, unsigned int size, int index, int key_sz,
	 int eviction)
{
	TDB *db;
	TdbWork *tw;

	db = kzalloc(sizeof(TDB), GFP_KERNEL);
	if (!db)
		return NULL;
	strncpy(db->path, path, TDB_PATH_LEN - 1);
	db->size = size;
	db->index = index;
	db->key_sz = key_sz;
	db->eviction = eviction;

	tw = kmem_cache_alloc(tw_cache, GFP_KERNEL);
	if (!tw)
		goto err_cache;
	INIT_WORK(&tw->work, tdb_open_db);
	tw->db = db;

	queue_work(tdb_wq, (struct work_struct *)tw);

	/*
	 * FIXME at this point the caller can use the DB descriptor,
	 * but work queue probably doesn't initialize it so far.
	 * Put conditional wait here.
	 */
	return db;
err_cache:
	kfree(db);
	return NULL;
}
EXPORT_SYMBOL(tdb_open);

void
tdb_close(TDB *db)
{
	/* Unmapping can be done from process context. */
	tdb_file_close(db);

	kfree(db);
}
EXPORT_SYMBOL(tdb_close);

static int __init
tdb_init(void)
{
	tw_cache = KMEM_CACHE(tdb_work_t, 0);
	if (!tw_cache)
		return -ENOMEM;

	tdb_wq = create_singlethread_workqueue("tdb_wq");
	if (!tdb_wq)
		goto err_wq;

	return 0;
err_wq:
	kmem_cache_destroy(tw_cache);
	return -ENOMEM;
}

static void __exit
tdb_exit(void)
{
	destroy_workqueue(tdb_wq);
	kmem_cache_destroy(tw_cache);
}

module_init(tdb_init);
module_exit(tdb_exit);
