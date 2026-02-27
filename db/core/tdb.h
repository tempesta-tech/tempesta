/**
 *		Tempesta DB
 *
 * Generic storage layer.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2025 Tempesta Technologies, INC.
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
 * @i_wcl, @d_wcl,
 * @b_wcl -	    per-CPU current partially written index, bucket and data
 *		    blocks. TdbHdr->i_wcl, TdbHdr->b_wcl and TdbHdr->d_wcl are
 *		    the global values for the variable. The variables are
 *		    initialized in runtime, so we lose some free space on system
 *		    restart.
 * @freelist	  - pre-CPU freelist of blocks.
 * @fl_size	  - number of elements in @freelist.
 */
typedef struct {
	unsigned long	b_wcl;
	unsigned long	i_wcl;
	unsigned long	d_wcl;
	unsigned long	freelist;
	unsigned long	fl_size;
} TdbPerCpu;

#define TDB_REC_COMMON			\
	unsigned long	key;		\
	unsigned int	flags;		\
	atomic_t	refcnt

/**
 * Fixed-size (and typically small) records.
 */
typedef struct {
	TDB_REC_COMMON;
	char		data[0];
} __attribute__((packed)) TdbFRec;

/**
 * Variable-size (typically large) record.
 *
 * @chunk_next	- index of next data chunk
 * @len		- data length of current chunk
 */
typedef struct {
	TDB_REC_COMMON;
	unsigned int	chunk_next;
	unsigned int	len;
	char		data[0];
} __attribute__((packed)) TdbVRec;

/* Common interface for database records of all kinds. */
typedef TdbFRec TdbRec;
typedef void tdb_before_free_cb_t(TdbRec *rec);

/**
 * Tempesta DB file descriptor.
 *
 * We store independent records in at least cache line size data blocks
 * to avoid false sharing.
 *
 * @dbsz	- the database size in bytes;
 * @nwb		- next to write block (byte offset);
 * @pcpu	- pointer to per-cpu dynamic data for the TDB handler;
 * @before_free - called before freeing the record;
 * @ga_freelist - global freelist of blocks;
 * @gfl_lock	- protects ga_freelist;
 * @rec_len	- fixed-size records length or zero for variable-length records;
 * @oom		- indicates out of main memory. In this case only freelists
 *		  will be used, avoid allocations from main memory.
 ** @ext_bmp	- bitmap of used/free extents.
 * 		  Must be small and cache line aligned;
 */
typedef struct {
	unsigned long		magic;
	unsigned long		dbsz;
	atomic64_t		nwb;
	TdbPerCpu __percpu	*pcpu;
	tdb_before_free_cb_t	*before_free;
	unsigned long		ga_freelist;
	spinlock_t		gfl_lock;
	unsigned int		rec_len;
	bool			oom;
	unsigned long		ext_bmp[0];
} ____cacheline_aligned TdbHdr;

/**
 * Database handle descriptor.
 *
 * @filp	- mmap()'ed file;
 * @node	- NUMA node ID;
 * @count	- reference counter;
 * @ga_lock	- Lock for atomic execution of lookup and create a record TDB;
 * @tbl_name	- table name;
 * @path	- path to the table;
 */
typedef struct {
	TdbHdr		*hdr;
	struct file	*filp;
	int		node;
	atomic_t	count;
	spinlock_t	ga_lock; /* TODO: remove and make lockless. */
	char		tbl_name[TDB_TBLNAME_LEN + 1];
	char		path[TDB_PATH_LEN];
} TDB;

/**
 * Iterator for TDB full key collision chains.
 */
typedef struct {
	TdbRec	*rec;
	void	*bckt;
} TdbIter;

#define TDB_ITER_BAD(i)		(!(i).rec)

/**
 * Hooks for tdb_rec_get_alloc() function.
 * @eq_rec		- record match function, used in collision chain;
 * @precreate_rec	- called before a new record will be created int tdb,
 *			record creation will be aborted in non zero return code;
 * @init_rec		- init record before use;
 * @ctx			- arbitrary pointer to pass arguments into callbacks;
 * @len			- requested and resulting record size;
 * @is_new		- true if entry wasn't found in tdb and a new one was
 *			  created;
 *
 * All function pointers get @ctx as argument. If @init_rec fail the
 * record is already created and placed into tdb. Tdb user is responsible to
 * deal with invalid records.
 */
typedef struct {
	bool		(*eq_rec)(TdbRec *rec, void *ctx);
	int		(*precreate_rec)(void *ctx);
	int		(*init_rec)(TdbRec *rec, void *ctx);
	void		*ctx;
	size_t		len;
	bool		is_new;
} TdbGetAllocCtx;

typedef bool tdb_eq_cb_t(TdbHdr *db_hdr, TdbRec *rec, void *data);

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

/*
 * Version for buckets.
 */
#define TDB_O2BI(o)		((o) / TDB_HTRIE_IALIGN(sizeof(TdbBucket)))
#define TDB_BI2O(i)		((i) * TDB_HTRIE_IALIGN(sizeof(TdbBucket)))

#define TDB_BANNER		"[tdb] "

/*
 * Tempesta DB is too internal piece of code, so print its messages on
 * higher debugging levels.
 */
#if defined(DEBUG) && (DEBUG >= 2)
#define TDB_DBG(...)		pr_debug(TDB_BANNER "  " __VA_ARGS__)
#else
#define TDB_DBG(...)
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
TdbRec *tdb_entry_alloc_unique(TDB *db, unsigned long key, size_t *len,
			       tdb_eq_cb_t *eq_cb, void *eq_data);

bool tdb_entry_is_complete(void *rec);
void tdb_entry_mark_complete(void *rec);
TdbRec *tdb_entry_create(TDB *db, unsigned long key, void *data, size_t *len);
TdbVRec *tdb_entry_add(TDB *db, TdbVRec *r, size_t size);
void tdb_entry_remove(TDB *db, unsigned long key, tdb_eq_cb_t *eq_cb, void *data,
		      bool force);
void *tdb_entry_get_room(TDB *db, TdbVRec **r, char *curr_ptr, size_t tail_len,
			 size_t tot_size);
TdbIter tdb_rec_get(TDB *db, unsigned long key);
void tdb_rec_next(TDB *db, TdbIter *iter);

/*
 * Release a read-lock on the record's bucket.
 */
void tdb_rec_put(TDB *db, void *rec);

/*
 * Acquire a read-lock on the record's bucket.
 *
 * Record iteration functions take a read-lock that is released when iteration
 * finishes, or when moving between buckets. Use this function, if you need to
 * keep the record locked.
 *
 */
void tdb_rec_keep(void *rec);

/*
 * Check that it is a last reference to the rec.
 */
bool tdb_rec_has_last_ref(void *rec);

int tdb_info(char *buf, size_t len);
TdbRec * tdb_rec_get_alloc(TDB *db, unsigned long key, TdbGetAllocCtx *ctx);
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
