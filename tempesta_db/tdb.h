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

/*
 * Database record header/descriptor.
 * This is header of PAGE_SIZE memory segment.
 *
 * @coll_next	- next record offset (in pages) in collision chain
 * 		  (can be negative)
 * 		  (TODO: Index???: do we need this?)
 * @chunk_next	- offset of next data chunk (also with TdbRecord as header)
 * @d_len	- data length of current chunk
 */
typedef struct {
	int		coll_next;
	int		chunk_next;
	unsigned int	flags;
	unsigned int	d_len;
	char		data[0];
} __attribute__((packed)) TdbRecord;

/*
 * Data size is always not more than PAGE_SIZE - sizeof(TdbRecord).
 * TdbRecord is always placed at begin of a page.
 */
#define TDB_REC_FROM_PTR(p)	((TdbRecord *)((unsigned long)(p) & PAGE_MASK))
#define TDB_REC_DTAIL(p)	((p)->data + (p)->d_len)
#define TDB_REC_DNEXT(r)	((TdbRecord *)((char *)(r)		\
					       + (r)->chunk_next * PAGE_SIZE))
#define TDB_REC_ISLAST(r)	(!(r)->chunk_next)
#define TDB_REC_DMAXSZ		((size_t)(PAGE_SIZE - sizeof(TdbRecord)))
#define TDB_REC_ROOM(r)		(TDB_REC_DMAXSZ - (r)->d_len)

/* Database handle descriptor. */
typedef struct {
	struct file	*filp;	/* mmap'ed file */
	unsigned long	map;	/* mmap address, setted only when the hadler
				   is fully initialized */
	unsigned int	size;	/* whole data size */
	int		index;	/* index type */
	int		key_sz;	/* key size */
	int		eviction; /* eviction stratagy */
	char		path[TDB_PATH_LEN /* path to mmaped file */
			     + sizeof(TDB_FNAME)];
} TDB;

#define TDB_REC_OFFSET(db, r)	(((unsigned long)(r) - (db)->map) / PAGE_SIZE)

#define TDB_BANNER	"[tdb] "
#define TDB_ERR(...)	pr_err(TDB_BANNER "ERROR: " __VA_ARGS__)

TdbRecord *tdb_entry_create(TDB *db, unsigned long *key, size_t elen);
void *tdb_entry_add(TDB *db, TdbRecord **r, size_t size);
void *tdb_lookup(TDB *db, unsigned long *key);

static inline void *
tdb_get_next_data_ptr(TDB *db, TdbRecord **trec)
{
	return TDB_REC_ROOM(*trec)
	       ? TDB_REC_DTAIL(*trec)
	       : tdb_entry_add(db, trec, 0);
}

/* Open/close database handler. */
TDB *tdb_open(const char *path, unsigned int size, int index, int key_sz,
	      int eviction);
void tdb_close(TDB *db);

#endif /* __TDB_H__ */
