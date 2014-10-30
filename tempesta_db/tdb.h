/**
 *		Tempesta DB
 *
 * Generic storage layer.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2014 Tempesta Technologies Ltd.
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

/**
 * Tempesta DB file descriptor.
 *
 * We store independent records in at least cache line size data blocks
 * to avoid false sharing.
 *
 * @dbsz	- the database size in bytes;
 * @rec_len	- fixed-size records length or zero for variable-length records;
 * @i_wcl	- index block next to write (byte offset);
 * @d_wcl	- data block next to write (byte offset);
 * @ext_bmp	- bitmap of used/free extents.
 * 		  Must be small and cache line aligned;
 * @i_wm, @d_wm	- watermarks (in extents) for index and data correspondingly.
 * 		  The watermarks grow towards each other and their meeting
 * 		  signals that the data file is full;
 */
typedef struct {
	unsigned long	magic;
	unsigned long	dbsz;
	unsigned long	i_wcl;
	unsigned long	d_wcl;
	unsigned int	rec_len;
	unsigned short	i_wm;
	unsigned short	d_wm;
	unsigned char	_padding[8 * 3];
	unsigned long	ext_bmp[0];
} __attribute__((packed)) TdbHdr;

/* Database handle descriptor. */
typedef struct {
	TdbHdr		*hdr;
	struct file	*filp;	/* mmap'ed file */
	char		path[TDB_PATH_LEN /* path to mmaped file */
			     + sizeof(TDB_FNAME)];
} TDB;

/**
 * Fixed-size (and typically small) records.
 */
typedef struct {
	unsigned long	key; /* must be the first */
	char		data[0];
} __attribute__((packed)) TdbFRec;

/**
 * Variable-size (typically large) record.
 *
 * @chunk_next	- offset of next data chunk (also with TdbRec as header)
 * @len		- data length of current chunk
 */
typedef struct {
	unsigned long	key; /* must be the first */
	unsigned int	chunk_next;
	unsigned int	len;
	char		data[0];
} __attribute__((packed)) TdbVRec;

/* Common interface for database records of all kinds. */
typedef TdbFRec TdbRec;

/**
 * We use very small index nodes size of only one cache line.
 * So overall memory footprint of the index is mininal by a cost of more LLC
 * or main memory transfers. However, smaller memory usage means better TLB
 * utilization on huge worksets.
 */
#define TDB_HTRIE_NODE_SZ	L1_CACHE_BYTES
/*
 * There is no sense to allocate a new resolving node for each new small
 * (less than cache line size) data record. So we place small records in
 * 2 cache lines in sequential order and burst the node only when there
 * is no room.
 */
#define TDB_HTRIE_MINDREC	(L1_CACHE_BYTES * 2)

/* Convert internal offsets to system pointer. */
#define TDB_PTR(h, o)		(void *)((char *)(h) + (o))
/* Get index and data block indexes by byte offset and vise versa. */
#define TDB_O2DI(o)		((o) / TDB_HTRIE_MINDREC)
#define TDB_O2II(o)		((o) / TDB_HTRIE_NODE_SZ)
#define TDB_DI2O(i)		((i) * TDB_HTRIE_MINDREC)
#define TDB_II2O(i)		((i) * TDB_HTRIE_NODE_SZ)

#define TDB_BANNER		"[tdb] "

#ifdef DEBUG
#define TDB_DBG(...)		pr_debug(TDB_BANNER "  " __VA_ARGS__)
#else
#define TDB_DBG(...)
#endif
#define TDB_ERR(...)		pr_err(TDB_BANNER "ERROR: " __VA_ARGS__)

TdbRec *tdb_entry_create(TDB *db, unsigned long key, void *data, size_t *len);
TdbVRec *tdb_entry_add(TDB *db, TdbVRec *r, size_t size);
void *tdb_lookup(TDB *db, unsigned long key);

/* Open/close database handler. */
TDB *tdb_open(const char *path, unsigned int fsize, unsigned int rec_size);
void tdb_close(TDB *db);

#endif /* __TDB_H__ */
