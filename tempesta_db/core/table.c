/**
 *		Tempesta DB
 *
 * Database table handling.
 *
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
#include "tdb.h"

#define TDB_MAXTBL	512

typedef struct {
	char	name[TDB_TBLNAME_LEN + 1];
	TDB	*db;
} TdbTable;

/* Global list of currently open tables. */
static TdbTable tdb_tbls[TDB_MAXTBL];
static int tbl_last;
static DEFINE_MUTEX(tbl_mtx);

void
tdb_tbl_enumerate(TDB *db)
{
	mutex_lock(&tbl_mtx);

	if (tbl_last < TDB_MAXTBL) {
		strncpy(tdb_tbls[tbl_last].name, db->tbl_name, TDB_TBLNAME_LEN);
		tdb_tbls[tbl_last].db = db;
		++tbl_last;
	} else
		TDB_WARN("Cannot enumerate %s\n", db->tbl_name);

	mutex_unlock(&tbl_mtx);
}

void
tdb_tbl_forget(TDB *db)
{
	int i;

	mutex_lock(&tbl_mtx);

	for (i = 0; i < tbl_last; ++i) {
		if (strncmp(db->tbl_name, tdb_tbls[i].name, TDB_TBLNAME_LEN))
			continue;
		if (i < TDB_MAXTBL - 1)
			memmove(tdb_tbls + i, tdb_tbls + i + 1,
				(tbl_last - i) * sizeof(TdbTable));
		--tbl_last;
		goto forgotten;
	}
	TDB_WARN("Table %s was not enumerated\n", db->tbl_name);

forgotten:
	mutex_unlock(&tbl_mtx);
}

int
tdb_tbl_print_all(char *buf, size_t len)
{
	int i, n = 0;

	mutex_lock(&tbl_mtx);

	for (i = 0; i < tbl_last; ++i) {
		int r = snprintf(buf + n, len - n, "%s ", tdb_tbls[i].name);
		if (r <= 0) {
			TDB_WARN("Not enough space to print all tables\n");
			break;
		}
		n += r;
	}

	mutex_unlock(&tbl_mtx);

	return n;
}

TDB *
tdb_tbl_lookup(char *table, size_t len)
{
	int i;
	TDB *db = NULL;

	mutex_lock(&tbl_mtx);

	for (i = 0; i < tbl_last; ++i) {
		if (!strncmp(tdb_tbls[i].name, table, len)) {
			db = tdb_get(tdb_tbls[i].db);
			break;
		}
	}

	mutex_unlock(&tbl_mtx);

	return db;
}
