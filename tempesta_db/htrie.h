/**
 *		Tempesta DB
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
#ifndef __HTRIE_H__
#define __HTRIE_H__

#include "tdb.h"

#define TDB_EXT_BITS		21
#define TDB_EXT_SZ		(1UL << TDB_EXT_BITS)
#define TDB_EXT_MASK		(~(TDB_EXT_SZ - 1))
#define TDB_BLK_BMP_2L		(TDB_EXT_SZ / PAGE_SIZE / BITS_PER_LONG)
/* Get current extent by an offset in it. */
#define TDB_EXT_O(o)		((unsigned long)(o) & TDB_EXT_MASK)
/* Get extent id by a record offset. */
#define TDB_EXT_ID(o)		((unsigned long)(o) >> TDB_EXT_BITS)
/* Block absolute offset. */
#define TDB_BLK_O(x)		((x) & TDB_BLK_MASK)
/* Get block index in an extent. */
#define TDB_BLK_ID(x)		(((x) & PAGE_MASK) & ~TDB_EXT_MASK)
#define TDB_BLK_ALIGN(x)	TDB_BLK_O((x) + TDB_BLK_SZ - 1)

/* True if the tree keeps variable length records. */
#define TDB_HTRIE_VARLENRECS(h)	(!(h)->rec_len)
/* Each record in the tree must be at least 8-byte aligned. */
#define TDB_HTRIE_RALIGN(n)	(((unsigned long)(n) + 7) & ~7UL)
#define TDB_HTRIE_IALIGN(n)	(((n) + L1_CACHE_BYTES - 1) &		\
				 ~(L1_CACHE_BYTES - 1))
#define TDB_HTRIE_DALIGN(n)	(((n) + TDB_HTRIE_MINDREC - 1)		\
				 & ~(TDB_HTRIE_MINDREC - 1))
#define TDB_HTRIE_BITS		4
#define TDB_HTRIE_FANOUT	(1 << TDB_HTRIE_BITS)
#define TDB_HTRIE_KMASK		(TDB_HTRIE_FANOUT - 1) /* key mask */
#define TDB_HTRIE_RESOLVED(b)	((b) + TDB_HTRIE_BITS >= BITS_PER_LONG)
/*
 * We use 31 bits to address index and data blocks.
 * The most significant bit is used to flag data pointer/offset.
 * Index blocks are addressed by index of a L1_CACHE_BYTES-byte blocks in the file,
 * while data blocks are addressed by indexes of TDB_HTRIE_MINDREC blocks.
 *
 * So the maximum size of one database table is 128GB per processor package,
 * which is 1/3 of supported per-socket RAM by modern x86-64.
 */
#define TDB_HTRIE_DBIT		(1U << (sizeof(int) * 8 - 1))
#define TDB_HTRIE_OMASK		(TDB_HTRIE_DBIT - 1) /* offset mask */
#define TDB_HTRIE_IDX(k, b)	(((k) >> (b)) & TDB_HTRIE_KMASK)
#define TDB_EXT_BMP_2L(h)	(((h)->dbsz / TDB_EXT_SZ + BITS_PER_LONG - 1)\
				 / BITS_PER_LONG)
#define TDB_MAX_DB_SZ		((1UL << 31) * L1_CACHE_BYTES)
/* Get internal offset from a pointer. */
#define TDB_HTRIE_OFF(h, p)	((unsigned long)(p) - (unsigned long)(h))
/* Base offset of extent containing pointer @p. */
#define TDB_EXT_BASE(h, p)	TDB_EXT_O(TDB_HTRIE_OFF(h, p))

/**
 * Header for bucket of small records.
 *
 * @coll_next	- next record offset (in data blocks) in collision chain;
 */
typedef struct {
	unsigned int 	coll_next;
	unsigned int	flags;
	rwlock_t	lock;
} __attribute__((packed)) TdbBucket;

#define TDB_HTRIE_VRFREED	TDB_HTRIE_DBIT
#define TDB_HTRIE_VRLEN(r)	((r)->len & ~TDB_HTRIE_VRFREED)
#define __RECLEN(h, r)							\
	__builtin_choose_expr(__builtin_types_compatible_p(typeof(*(r)),\
							   TdbVRec),	\
			      /* The type cast is only to avoid compiler \
			       * error, @r is always TdbVRec. */	\
			      TDB_HTRIE_VRLEN((TdbVRec *)r),		\
			      (h)->rec_len)
#define TDB_HTRIE_RECLEN(h, r)	TDB_HTRIE_RALIGN(sizeof(*(r)) + __RECLEN(h, r))
#define TDB_HTRIE_BUCKET_1ST(b)	((void *)((b) + 1))
#define TDB_HTRIE_BUCKET_KEY(b)	(*(unsigned long *)TDB_HTRIE_BUCKET_1ST(b))
/* Iterate over buckets in collision chain. */
#define TDB_HTRIE_BUCKET_NEXT(h, b) ((b)->coll_next			\
				     ? TDB_PTR(h, TDB_DI2O((b)->coll_next))\
				     : NULL)				\

#define TDB_HDR_SZ(h)							\
	(sizeof(TdbHdr) + TDB_EXT_BMP_2L(h) * sizeof(long))
#define TDB_HTRIE_ROOT(h)						\
	(TdbHtrieNode *)((char *)(h) + TDB_HDR_SZ(h) + sizeof(TdbExt))

/**
 * Iterate over all records in collision chain.
 * Buckets are inspected according to following rules:
 * - if first record is > TDB_HTRIE_MINDREC, then only it is observer;
 * - all records which fit TDB_HTRIE_MINDREC.
 *
 * @d	- database handler;
 * @b	- bucket to iterate over;
 * @r	- record pointer;
 */
#define TDB_HTRIE_FOREACH_REC(d, b, r)					\
	for ( ; b; b = TDB_HTRIE_BUCKET_NEXT(d, b))			\
		for (r = TDB_HTRIE_BUCKET_1ST(b);			\
		     ({ long _n = (char *)r - (char *)b + sizeof(*r);	\
		        /* Crash if small records exceed small block	\
			 * boundary. */					\
			BUG_ON(_n < TDB_HTRIE_MINDREC			\
			       && r != TDB_HTRIE_BUCKET_1ST(b)		\
			       && _n + __RECLEN(d, r) > TDB_HTRIE_MINDREC);\
			_n <= TDB_HTRIE_MINDREC; });			\
		     r = (typeof(r))((char *)r + TDB_HTRIE_RECLEN(d, r)))

static inline int
tdb_live_fsrec(TdbHdr *dbh, TdbFRec *rec)
{
	int i, res = 0;
	size_t len = TDB_HTRIE_RALIGN(sizeof(*rec) + dbh->rec_len)
		     / sizeof(long);

	for (i = 0; i < len; ++i)
		res = !!((unsigned long *)rec)[i];
	return res;
}

static inline int
tdb_live_vsrec(TdbVRec *rec)
{
	return rec->len && !(rec->len & TDB_HTRIE_VRFREED);
}

TdbVRec *tdb_htrie_extend_rec(TdbHdr *dbh, TdbVRec *rec, size_t size);
TdbRec *tdb_htrie_insert(TdbHdr *dbh, unsigned long key, void *data,
			 size_t *len);
TdbBucket *tdb_htrie_lookup(TdbHdr *dbh, unsigned long key);
TdbHdr *tdb_htrie_init(void *p, size_t db_size, unsigned int rec_len);
void tdb_htrie_exit(TdbHdr *dbh);

#endif /* __HTRIE_H__ */
