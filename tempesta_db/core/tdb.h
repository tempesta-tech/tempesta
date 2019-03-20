/**
 *		Tempesta DB
 *
 * Generic storage layer.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, INC.
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
#ifndef __TDB_H__
#define __TDB_H__

#include <linux/fs.h>
#include <linux/slab.h>

#include "tdb_if.h"

/**
 * Per-CPU dynamically allocated data for TDB handler.
 * Access to the data must be with preemption disabled for reentrance between
 * softirq and process contexts.
 *
 * @i_wcl, @d_wcl - per-CPU current partially written index and data blocks.
 *		    TdbHdr->i_wcl and TdbHdr->d_wcl are the global values for
 *		    the variable. The variables are initialized in runtime,
 *		    so we lose some free space on system restart.
 */
typedef struct {
	unsigned long	i_wcl;
	unsigned long	d_wcl;
} TdbPerCpu;

/**
 * Tempesta DB file descriptor.
 *
 * We store independent records in at least cache line size data blocks
 * to avoid false sharing.
 *
 * @dbsz	- the database size in bytes;
 * @nwb		- next to write block (byte offset);
 * @pcpu	- pointer to per-cpu dynamic data for the TDB handler;
 * @rec_len	- fixed-size records length or zero for variable-length records;
 ** @ext_bmp	- bitmap of used/free extents.
 * 		  Must be small and cache line aligned;
 */
typedef struct {
	unsigned long		magic;
	unsigned long		dbsz;
	atomic64_t		nwb;
	TdbPerCpu __percpu	*pcpu;
	unsigned int		rec_len;
	unsigned char		_padding[8 * 3 + 4];
	unsigned long		ext_bmp[0];
} __attribute__((packed)) TdbHdr;

/**
 * Database handle descriptor.
 *
 * @filp	- mmap()'ed file;
 * @node	- NUMA node ID;
 * @count	- reference counter;
 * @tbl_name	- table name;
 * @path	- path to the table;
 */
typedef struct {
	TdbHdr		*hdr;
	struct file	*filp;
	int		node;
	atomic_t	count;
	char		tbl_name[TDB_TBLNAME_LEN + 1];
	char		path[TDB_PATH_LEN];
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
 * @chunk_next	- index of next data chunk
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
 * Iterator for TDB full key collision chains.
 */
typedef struct {
	TdbRec	*rec;
	void	*bckt;
} TdbIter;

#define TDB_ITER_BAD(i)		(!(i).rec)

/**
 * We use very small index nodes size of only one cache line.
 * So overall memory footprint of the index is minimal by a cost of more LLC
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

/* Convert internal offset to system pointer. */
#define TDB_PTR(h, o)		(void *)((char *)(h) + (o))
/* Convert system pointer to internal offset. */
#define TDB_OFF(h, p)		(long)((char *)(p) - (char *)(h))
/* Get index and data block indexes by byte offset and vise versa. */
#define TDB_O2DI(o)		((o) / TDB_HTRIE_MINDREC)
#define TDB_O2II(o)		((o) / TDB_HTRIE_NODE_SZ)
#define TDB_DI2O(i)		((i) * TDB_HTRIE_MINDREC)
#define TDB_II2O(i)		((i) * TDB_HTRIE_NODE_SZ)

#define TDB_BANNER		"[tdb] "

/*
 * Tempesta DB is too internal piece of code, so print its messages on
 * higher debugging levels.
 */
#if defined(DEBUG) && (DEBUG >= 2)
#define TDB_DBG(...)		pr_debug(TDB_BANNER "  " __VA_ARGS__)
#else
#define TDB_DBG(...)		do { } while (0)
#endif
#define TDB_LOG(...)		pr_info(TDB_BANNER __VA_ARGS__)
#define TDB_WARN(...)		pr_warn(TDB_BANNER "Warning: " __VA_ARGS__)
#define TDB_ERR(...)		pr_err(TDB_BANNER "ERROR: " __VA_ARGS__)

/*
 * Storage routines.
 *
 * BEWARE(!) the routines use SIMD instructions, so protect them with
 * kernel_fpu_begin()/kernel_fpu_end() or call from softirq context only.
 */
TdbRec *tdb_entry_alloc(TDB *db, unsigned long key, size_t *len);
TdbRec *tdb_entry_create(TDB *db, unsigned long key, void *data, size_t *len);
TdbVRec *tdb_entry_add(TDB *db, TdbVRec *r, size_t size);
void *tdb_entry_get_room(TDB *db, TdbVRec **r, char *curr_ptr, size_t tail_len,
			 size_t tot_size);
TdbIter tdb_rec_get(TDB *db, unsigned long key);
void tdb_rec_next(TDB *db, TdbIter *iter);
void tdb_rec_put(void *rec);
int tdb_info(char *buf, size_t len);
TdbRec * tdb_rec_get_alloc(TDB *db, unsigned long key, size_t *len,
			   bool (*predicate)(TdbRec *, void (*)(void *), void *),
			   void (*init)(TdbRec *, void (*)(void *), void *),
			   void (*cb)(void *), void *data, bool *is_new);
int tdb_entry_walk(TDB *db, int (*fn)(void *));
void tdb_rec_get_lock(void *rec);

/* Open/close database handler. */
TDB *tdb_open(const char *path, size_t fsize, unsigned int rec_size, int node);
void tdb_close(TDB *db);

static inline TDB *
tdb_get(TDB *db)
{
	atomic_inc(&db->count);
	return db;
}

static inline void
tdb_put(TDB *db)
{
	if (atomic_dec_and_test(&db->count))
		kfree(db);
}

static inline TdbVRec *
tdb_next_rec_chunk(TDB *db, TdbVRec *r)
{
	if (!r->chunk_next)
		return NULL;
	return TDB_PTR(db->hdr, TDB_DI2O(r->chunk_next));
}

#endif /* __TDB_H__ */
