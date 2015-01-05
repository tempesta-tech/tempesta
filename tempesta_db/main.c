/**
 *		Tempesta DB
 *
 * This is the entry point: initialization functions and public interfaces.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies. 
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

#include "file.h"
#include "htrie.h"
#include "work.h"

MODULE_AUTHOR("NatSys Lab. (http://natsys-lab.com)");
MODULE_DESCRIPTION("Tempesta DB");
MODULE_VERSION("0.1.0");
MODULE_LICENSE("GPL");

static struct workqueue_struct *tdb_wq;
static struct kmem_cache *tw_cache;

TdbRec *
tdb_entry_create(TDB *db, unsigned long key, void *data, size_t *len)
{
	TdbRec *r = tdb_htrie_insert(db->hdr, key, data, len);
	if (!r)
		TDB_ERR("Cannot create cache entry for %.*s\n",
			(int)*len, (char *)data);

	return r;
}
EXPORT_SYMBOL(tdb_entry_create);

/**
 * @return pointer to free area of size at least @size bytes or allocate
 * a new record and link it with the current one.
 *
 * TODO update @size to actually allocated space.
 */
TdbVRec *
tdb_entry_add(TDB *db, TdbVRec *r, size_t size)
{
	return tdb_htrie_extend_rec(db->hdr, r, size);
}
EXPORT_SYMBOL(tdb_entry_add);

void *
tdb_lookup(TDB *db, unsigned long key)
{
	TdbFRec *r;
	TdbBucket *b;

	/* @db can be uninitialized, see tdb_open(). */
	if (!db->hdr)
		return NULL;
	BUG_ON(!TDB_HTRIE_VARLENRECS(db->hdr));

	b = tdb_htrie_lookup(db->hdr, key);
	if (!b)
		return NULL;

	TDB_HTRIE_FOREACH_REC(db->hdr, b, r)
		if (tdb_live_fsrec(db->hdr, r))
			return r;

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
	TDB *db = tw->db;

	if (tdb_file_open(db, tw->fsize))
		TDB_ERR("Cannot open db\n");

	db->hdr = tdb_htrie_init(db->hdr, db->filp->f_inode->i_size, tw->rsize);
	if (!db->hdr)
		TDB_ERR("Cannot initialize db header\n");

	kmem_cache_free(tw_cache, tw);
}

/**
 * Open database file and @return its descriptor.
 *
 * The function must not be called from softirq!
 */
TDB *
tdb_open(const char *path, unsigned int fsize, unsigned int rec_size)
{
	TDB *db;
	TdbWork *tw;

	db = kzalloc(sizeof(TDB), GFP_KERNEL);
	if (!db)
		return NULL;
	strncpy(db->path, path, TDB_PATH_LEN - 1);

	tw = kmem_cache_alloc(tw_cache, GFP_KERNEL);
	if (!tw)
		goto err_cache;
	INIT_WORK(&tw->work, tdb_open_db);
	tw->db = db;
	tw->fsize = fsize;
	tw->rsize = rec_size;

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
