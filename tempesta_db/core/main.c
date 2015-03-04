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
#include "table.h"
#include "tdb_if.h"

#define TDB_VERSION	"0.1.11"

MODULE_AUTHOR("Tempesta Technologies");
MODULE_DESCRIPTION("Tempesta DB");
MODULE_VERSION(TDB_VERSION);
MODULE_LICENSE("GPL");

TdbRec *
tdb_entry_create(TDB *db, unsigned long key, void *data, size_t *len)
{
	TdbRec *r = tdb_htrie_insert(db->hdr, key, data, len);
	if (!r)
		TDB_ERR("Cannot create cache entry for %.*s, key=%#lx\n",
			(int)*len, (char *)data, key);

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

/**
 * Lookup and get a record.
 * Since we don't copy returned records, we have to lock the memory location
 * where the record is placed and the user must call tdb_rec_put() when finish
 * with the record.
 *
 * The caller must not call sleeping functions during work with the record.
 * Typically there is only one large record per bucket, so the bucket lock
 * is exactly the same as to lock the record. While there could be many
 * small records in a bucket, so the caller should not perform long jobs
 * with small records.
 *
 * @return pointer to record with acquired bucket lock if the record is
 * found and NULL without acquired locks otherwise.
 */
void *
tdb_rec_get(TDB *db, unsigned long key)
{
	TdbRec *r;
	TdbBucket *b;

	/* @db can be uninitialized, see tdb_open(). */
	if (!db->hdr)
		return NULL;
	BUG_ON(!TDB_HTRIE_VARLENRECS(db->hdr));

	b = tdb_htrie_lookup(db->hdr, key);
	if (!b)
		return NULL;

	/* The bucket must be alive regardless deleted/evicted records in it. */
	TDB_HTRIE_FOREACH_REC(db->hdr, b, r, {
		/* Return the record w/ locked bucket. */
		if (TDB_HTRIE_VARLENRECS(db->hdr)) {
			if (tdb_live_vsrec((TdbVRec *)r))
				return r;
		} else {
			if (tdb_live_fsrec(db->hdr, (TdbFRec *)r))
				return r;
		}
	});

	return NULL;
}
EXPORT_SYMBOL(tdb_rec_get);

void
tdb_rec_put(void *rec)
{
	TdbBucket *b = (TdbBucket *)TDB_HTRIE_DALIGN((unsigned long)rec);
	read_unlock_bh(&b->lock);
}
EXPORT_SYMBOL(tdb_rec_put);

int
tdb_info(char *buf, size_t len)
{
	int n;

	n = snprintf(buf, len,
		     "\nTempesta DB version: %s\n"
		     "Open tables: ",
		     TDB_VERSION);
	if (n <= 0)
		return n;

	n += tdb_tbl_print_all(buf + n, len - n);

	buf[n - 1] = '\n';

	return n;
}

/**
 * Search for already opened handler for the database or allocate a new one.
 *
 * The path to table must end with table name (not more than TDB_TBLNAME_LEN
 * characters in long) followed by TDB_SUFFIX.
 */
static int
tdb_get_db(const char *path, TDB **db)
{
	int len;
	char *slash;

	len = strlen(path);
	if (strncmp(path + len - sizeof(TDB_SUFFIX) + 1,
		    TDB_SUFFIX, sizeof(TDB_SUFFIX) - 1))
	{
		TDB_ERR("Bad table suffix for %s\n", path);
		return -EINVAL;
	}
	slash = strrchr(path, '/');
	if (!slash) {
		TDB_ERR("Please specify absolute path to %s\n", path);
		return -EINVAL;
	}
	len = len - (slash - path) - sizeof(TDB_SUFFIX);
	if (len > TDB_TBLNAME_LEN) {
		TDB_ERR("Too long table name %s\n", path);
		return -ENAMETOOLONG;
	}

	*db = tdb_tbl_lookup(slash + 1, len);
	if (*db)
		return 0;

	*db = kzalloc(sizeof(TDB), GFP_KERNEL);
	if (!*db) {
		TDB_ERR("Cannot allocate new db handler\n");
		return -ENOMEM;
	}
	strncpy((*db)->path, path, TDB_PATH_LEN - 1);
	strncpy((*db)->tbl_name, slash + 1, len);
	tdb_get(*db);

	return 0;
}

/**
 * Open database file and @return its descriptor.
 * If the database is already opened, then returns the handler.
 *
 * The function must not be called from softirq!
 */
TDB *
tdb_open(const char *path, size_t fsize, unsigned int rec_size, int node)
{
	TDB *db;

	if (tdb_get_db(path, &db) < 0)
		return db;

	db->node = node;

	if (tdb_file_open(db, fsize)) {
		TDB_ERR("Cannot open db\n");
		goto err;
	}

	db->hdr = tdb_htrie_init(db->hdr, db->filp->f_inode->i_size, rec_size);
	if (!db->hdr) {
		TDB_ERR("Cannot initialize db header\n");
		goto err_init;
	}

	tdb_tbl_enumerate(db);

	TDB_LOG("Opened table %s: size=%lu rec_size=%u\n",
		path, fsize, rec_size);

	return db;
err_init:
	tdb_file_close(db);
err:
	tdb_put(db);
	return NULL;
}
EXPORT_SYMBOL(tdb_open);

static void
__do_close_table(TDB *db)
{
	/* Unmapping can be done from process context. */
	tdb_file_close(db);

	tdb_htrie_exit(db->hdr);

	TDB_LOG("Closed table %s\n", db->tbl_name);

	kfree(db);
}

void
tdb_close(TDB *db)
{
	if (!atomic_dec_and_test(&db->count))
		return;

	tdb_tbl_forget(db);

	__do_close_table(db);
}
EXPORT_SYMBOL(tdb_close);

static int __init
tdb_init(void)
{
	int r;

	TDB_LOG("Start Tempesta DB\n");

	r = tdb_init_mappings();
	if (r)
		return r;

	r = tdb_if_init();
	if (r)
		return r;

	return 0;
}

static void __exit
tdb_exit(void)
{
	TDB_LOG("Shutdown Tempesta DB\n");

	tdb_if_exit();

	/*
	 * There are no database users, so roughtly close all abandoned
	 * tables w/o refrence checking and so on.
	 */
	tdb_tbl_foreach(__do_close_table);
}

module_init(tdb_init);
module_exit(tdb_exit);
