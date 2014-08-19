/**
 *		Tempesta DB
 *
 * Generic storage layer.
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
#ifndef __TDB_H__
#define __TDB_H__

#include <linux/fs.h>

#define TDB_FNAME	"data"
#define TDB_PATH_LEN	128

/* Eviction stratagies. */
#define TDB_EVC_LRU	1

/* Index types. */
#define TDB_IDX_SEQLOG	0 /* no index */
#define TDB_IDX_TREE	1

typedef struct {
	struct file	*filp;
	unsigned long	map;
	unsigned int	size;
	int		index;
	int		key_sz;
	int		eviction;
	char		path[TDB_PATH_LEN + sizeof(TDB_FNAME)];
} TDB;

#define TDB_BANNER	"[tdb] "
#define TDB_ERR(...)	pr_err(TDB_BANNER "ERROR: " __VA_ARGS__)

int tdb_write(TDB *db);
void *tdb_lookup(TDB *db, unsigned long *key);

/* Open/close database handler. */
TDB *tdb_open(const char *path, unsigned int size, int index, int key_sz,
	      int eviction);
void tdb_close(TDB *db);

#endif /* __TDB_H__ */
