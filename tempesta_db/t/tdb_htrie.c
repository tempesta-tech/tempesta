/**
 * Unit test for Tempesta DB HTrie storage.
 *
 * If index is not SEQLOG (i.e. no index at all), then to improve space locality
 * for large data sets index records grow from lower addresses to higher while
 * data records grow towards them, from maximum to minimum addresses.
 *
 * TODO
 * - freeing interface for eviction thread
 * - eviction
 * - garbage collection
 * - consistensy checking and recovery
 * - reduce number of memset(.., 0, ..) calls
 * - large contigous allocations
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#define _GNU_SOURCE
#include <assert.h>
#include <cpuid.h>
#include <fcntl.h>
#include <immintrin.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * ------------------------------------------------------------------------
 *	Kernel stubs
 * ------------------------------------------------------------------------
 */
#ifndef TDB_CL_SZ
#error "Unknown size of cache line"
#endif

#define PAGE_SIZE	4096UL
#define BITS_PER_LONG	64
#ifndef ENOMEM
#define ENOMEM		1
#endif

#define likely(e)	__builtin_expect((e), 1)
#define unlikely(e)	__builtin_expect((e), 0)

#define BUG_ON(c)	assert(!(c))
#define BUG()		abort()

#define TDB_ERR(...)							\
do {									\
	fprintf(stderr, "Error: " __VA_ARGS__);				\
	fprintf(stderr, "\n");						\
	exit(1);							\
} while (0)

#ifndef NDEBUG
#define TDB_DBG(...)	printf("\t" __VA_ARGS__)
#else
#define TDB_DBG(...)
#endif

#define LOCK_PREFIX "\n\tlock; "
#define IS_IMMEDIATE(nr)		(__builtin_constant_p(nr))
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#define CONST_MASK_ADDR(nr, addr)	BITOP_ADDR((void *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)			(1 << ((nr) & 7))

static inline void
set_bit(unsigned int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr)) {
		asm volatile(LOCK_PREFIX "orb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((unsigned char)CONST_MASK(nr))
			: "memory");
	} else {
		asm volatile(LOCK_PREFIX "bts %1,%0"
			: BITOP_ADDR(addr) : "Ir" (nr) : "memory");
	}
}

static inline unsigned long
ffz(unsigned long word)
{
	asm("rep; bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	long counter;
} atomic64_t;

static inline int
atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return __atomic_compare_exchange_n(&v->counter, &old, new, false,
					   __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static inline long
xadd(unsigned long *v, unsigned long i)
{
	return __atomic_fetch_add(v, i, __ATOMIC_SEQ_CST);
}

/*
 * Pthread doesn't have RW spin-locks,
 * so just use semaphores to test concurrency.
 */
typedef pthread_rwlock_t rwlock_t;

#define rwlock_init(lock)	pthread_rwlock_init(lock, NULL)
#define write_lock_bh(lock)	pthread_rwlock_wrlock(lock)
#define write_unlock_bh(lock)	pthread_rwlock_unlock(lock)

/*
 * ------------------------------------------------------------------------
 *	Tempesta DB index and data manipulations
 * ------------------------------------------------------------------------
 */
#define TDB_MAGIC		0x434947414D424454UL /* "TDBMAGIC" */
#define TDB_MAP_ADDR		0x600000000000UL
#define TDB_BLK_SZ		PAGE_SIZE
#define TDB_BLK_MASK		(~(TDB_BLK_SZ - 1))
#define TDB_EXT_BITS		21
#define TDB_EXT_SZ		(1UL << TDB_EXT_BITS)
#define TDB_EXT_MASK		(~(TDB_EXT_SZ - 1))
#define TDB_BLK_BMP_2L		(TDB_EXT_SZ / TDB_BLK_SZ / BITS_PER_LONG)
/* Get current extent by an offset in it. */
#define TDB_EXT_O(o)		((unsigned long)(o) & TDB_EXT_MASK)
/* Get extent id by a record offset. */
#define TDB_EXT_ID(o)		(TDB_EXT_O(o) >> TDB_EXT_BITS)
/* Block absolute offset. */
#define TDB_BLK_O(x)		((x) & TDB_BLK_MASK)
/* Get block index in an extent. */
#define TDB_BLK_ID(x)		(((x) & TDB_BLK_MASK) & ~TDB_EXT_MASK)

/* True if the tree keeps variable length records. */
#define TDB_HTRIE_VARLENRECS(h)	(!(h)->rec_len)
/**
 * We use very small index nodes size of only one cache line.
 * So overall memory footprint of the index is mininal by a cost of more LLC
 * or main memory transfers. However, smaller memory usage means better TLB
 * utilization on huge worksets.
 */
#define TDB_HTRIE_NODE_SZ	TDB_CL_SZ
/*
 * There is no sense to allocate a new resolving node for each new small
 * (less than cache line size) data record. So we place small records in
 * 2 cache lines in sequential order and burst the node only when there
 * is no room.
 */
#define TDB_HTRIE_MINDREC	(TDB_CL_SZ * 2)
/* Each record in the tree must be at least 8-byte aligned. */
#define TDB_HTRIE_RALIGN(n)	(((unsigned long)(n) + 7) & ~7UL)
#define TDB_HTRIE_IALIGN(n)	(((n) + TDB_CL_SZ - 1) & ~(TDB_CL_SZ - 1))
#define TDB_HTRIE_DALIGN(n)	(((n) + TDB_HTRIE_MINDREC - 1)		\
				 & ~(TDB_HTRIE_MINDREC - 1))
#define TDB_HTRIE_BITS		4
#define TDB_HTRIE_FANOUT	(1 << TDB_HTRIE_BITS)
#define TDB_HTRIE_KMASK		(TDB_HTRIE_FANOUT - 1) /* key mask */
#define TDB_HTRIE_RESOLVED(b)	((b) + TDB_HTRIE_BITS >= BITS_PER_LONG)
/*
 * We use 31 bits to address index and data blocks.
 * The most significant bit is used to flag data pointer/offset.
 * Index blocks are addressed by index of a TDB_CL_SZ-byte blocks in the file,
 * while data blocks are addressed by indexes of TDB_HTRIE_MINDREC blocks.
 * So theoretical size of the database shard which can be addressed is 256GB.
 */
#define TDB_HTRIE_DBIT		(1U << (sizeof(int) * 8 - 1))
#define TDB_HTRIE_OMASK		(TDB_HTRIE_DBIT - 1) /* offset mask */
#define TDB_HTRIE_IDX(k, b)	(((k) >> (b)) & TDB_HTRIE_KMASK)
#define TDB_EXT_BMP_2L(h)	(((h)->dbsz / TDB_EXT_SZ + BITS_PER_LONG - 1)\
				 / BITS_PER_LONG)
/* Convert internal offsets to system pointer. */
#define TDB_PTR(h, o)		(void *)((char *)(h) + (o))
/* Get internal offset from a pointer. */
#define TDB_HTRIE_OFF(h, p)	((unsigned long)(p) - (unsigned long)(h))
/* Get index and data block indexes by byte offset and vise versa. */
#define TDB_O2DI(o)		((o) / TDB_HTRIE_MINDREC)
#define TDB_O2II(o)		((o) / TDB_HTRIE_NODE_SZ)
#define TDB_DI2O(i)		((i) * TDB_HTRIE_MINDREC)
#define TDB_II2O(i)		((i) * TDB_HTRIE_NODE_SZ)
/* Base offset of extent containing pointer @p. */
#define TDB_EXT_BASE(h, p)	TDB_EXT_O(TDB_HTRIE_OFF(h, p))

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

/**
 * Tempesta DB extent descriptor.
 *
 * @b_bmp	- bitmap of used/free blocks;
 */
typedef struct {
	unsigned long	b_bmp[TDB_BLK_BMP_2L];
} __attribute__((packed)) TdbExt;

/**
 * Tempesta DB HTrie node.
 * This is exactly one cache line.
 * Each shift in @shifts determine index of a node in file including extent
 * and/or file headers, i.e. they start from 2 or 3.
 */
typedef struct {
	unsigned int	shifts[TDB_HTRIE_FANOUT];
} __attribute__((packed)) TdbHtrieNode;

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
 * @chunk_next	- offset of next data chunk
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
				     : NULL)

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

static inline TdbExt *
tdb_ext(TdbHdr *dbh, void *ptr)
{
	unsigned long e = TDB_EXT_O(ptr);

	if (e == (unsigned long)dbh)
		e += TDB_HDR_SZ(dbh); /* first extent */
	return (TdbExt *)e;
}

static inline void
tdb_set_bit(unsigned long *bmp, unsigned int nr)
{
	set_bit(nr % BITS_PER_LONG, bmp + nr / BITS_PER_LONG);
}

unsigned long
tdb_hash_calc(const char *data, size_t len)
{
#define MUL	sizeof(long)
	int i;
	unsigned long crc0 = 0, crc1 = 0, h;
	unsigned long *d = (unsigned long *)data;
	size_t n = (len / MUL) & ~1UL;

	for (i = 0; i < n; i += 2) {
		/* See linux/arch/x86/crypto/crc32c-intel.c for CRC32C. */
		crc0 = _mm_crc32_u64(crc0, d[i]);
		crc1 = _mm_crc32_u64(crc1, d[i + 1]);
	}

	if (n * MUL + MUL <= len) {
		crc0 = _mm_crc32_u64(crc0, d[n]);
		n++;
	}

	h = (crc1 << 32) | crc0;

	/*
	 * Generate relatively small and dense hash tail values - they are good
	 * for short strings in htrie which uses less significant bits at root,
	 * however collisions are very probable.
	 */
	n *= MUL;
	switch (len - n) {
	case 7:
		h += data[n] * n;
		++n;
	case 6:
		h += data[n] * n;
		++n;
	case 5:
		h += data[n] * n;
		++n;
	case 4:
		h += data[n] * n;
		++n;
	case 3:
		h += data[n] * n;
		++n;
	case 2:
		h += data[n] * n;
		++n;
	case 1:
		h += data[n] * n;
	}

	return h;
#undef MUL
}

static TdbHdr *
tdb_init_mapping(void *p, size_t db_size, unsigned int rec_len)
{
	TdbHdr *hdr = (TdbHdr *)p;

	/* Use variable-size records for large stored data. */
	if (rec_len > TDB_BLK_SZ / 2)
		return NULL;

	/* Zero whole area. */
	memset(hdr, 0, db_size);

	hdr->magic = TDB_MAGIC;
	hdr->dbsz = db_size;
	hdr->rec_len = rec_len;
	/* Set index write cache line just after rool index node. */
	hdr->i_wcl = TDB_HTRIE_IALIGN(TDB_HDR_SZ(hdr) + sizeof(TdbExt)
				      + sizeof(TdbHtrieNode));
	/* Data grows from the last extent to begin. */
	hdr->d_wm = db_size / TDB_EXT_SZ - 1;
	hdr->d_wcl = TDB_HTRIE_DALIGN(hdr->d_wm * TDB_EXT_SZ + sizeof(TdbExt));

	/* Set first (current) extents and blocks as used. */
	set_bit(0, hdr->ext_bmp);
	set_bit(BITS_PER_LONG - 1, &hdr->ext_bmp[TDB_EXT_BMP_2L(hdr) - 1]);
	set_bit(0, tdb_ext(hdr, hdr)->b_bmp);
	set_bit(0, tdb_ext(hdr, TDB_PTR(hdr, hdr->d_wcl))->b_bmp);

	return hdr;
}

static inline void
tdb_free_index_blk(TdbHtrieNode *node)
{
	/* Just zero the block and leave it for garbage collector. */
	memset(node, 0, sizeof(*node));
}

static inline void
tdb_free_data_blk(TdbBucket *bckt)
{
	bckt->flags |= TDB_HTRIE_VRFREED;
}

static inline void
tdb_free_fsrec(TdbHdr *dbh, TdbFRec *rec)
{
	memset(rec, 0, TDB_HTRIE_RALIGN(sizeof(*rec) + dbh->rec_len));
}

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

static inline void
tdb_free_vsrec(TdbVRec *rec)
{
	rec->len |= TDB_HTRIE_VRFREED;
}

static inline int
tdb_live_vsrec(TdbVRec *rec)
{
	return rec->len && !(rec->len & TDB_HTRIE_VRFREED);
}

/**
 * Allocates a free block (system page) in extent @e.
 * @return start of available room (offset in bytes) at the block.
 */
static inline unsigned long
tdb_alloc_blk(TdbHdr *dbh, TdbExt *e)
{
	int i;
	unsigned long r;

	for (i = 0; i < TDB_BLK_BMP_2L; ++i) {
		if (!(e->b_bmp[i] ^ ~0UL))
			continue;

		// TODO synchronize this and below callers!
		r = ffz(e->b_bmp[i]);
		set_bit(r, &e->b_bmp[i]);
		if (unlikely(!i && !r)) {
			r = sizeof(*e);
			if (unlikely(TDB_EXT_O(e) == TDB_EXT_O(dbh)))
				return r + TDB_HDR_SZ(dbh);
			return r + TDB_EXT_BASE(dbh, e);
		}
		return TDB_EXT_BASE(dbh, e)
		       + (i * BITS_PER_LONG + r) * TDB_BLK_SZ;
	}

	return 0;
}

static unsigned long
tdb_alloc_index_blk(TdbHdr *dbh)
{
	unsigned long ei, rptr;
	TdbExt *e = tdb_ext(dbh, TDB_PTR(dbh, dbh->i_wcl));

	/* Check extent pointed by next to write index block. */
	if (!(dbh->i_wcl & ~TDB_EXT_MASK))
		goto point_to_new_ext;

	rptr = tdb_alloc_blk(dbh, e);
	if (likely(rptr))
		return TDB_HTRIE_IALIGN(rptr);

	/* No room in current extent, try the next one. */
	e = (TdbExt *)((unsigned long)e + TDB_EXT_SZ);

point_to_new_ext:
	ei = TDB_EXT_ID(TDB_HTRIE_OFF(dbh, e));
	if (ei >= dbh->d_wm)
		return 0;
	if (ei > dbh->i_wm)
		dbh->i_wm = ei;
	tdb_set_bit(dbh->ext_bmp, TDB_EXT_ID(TDB_EXT_BASE(dbh, e)));

	TDB_DBG("Alloc new index extent %p\n", e);

	rptr = tdb_alloc_blk(dbh, e);
	BUG_ON(!rptr);

	return TDB_HTRIE_IALIGN(rptr);
}

static unsigned long
tdb_alloc_data_blk(TdbHdr *dbh)
{
	unsigned long ei, rptr;
	TdbExt *e = tdb_ext(dbh, TDB_PTR(dbh, dbh->d_wcl));

	/* Check extent pointed by next to write data block. */
	if (!(dbh->d_wcl & ~TDB_EXT_MASK)) {
		e = (TdbExt *)((unsigned long)e - TDB_EXT_SZ * 2);
		goto point_to_new_ext;
	}

	rptr = tdb_alloc_blk(dbh, e);
	if (likely(rptr))
		return TDB_HTRIE_DALIGN(rptr);

	/* No room in current extent, try the next one. */
	e = (TdbExt *)((unsigned long)e - TDB_EXT_SZ);

point_to_new_ext:
	ei = TDB_EXT_ID(TDB_HTRIE_OFF(dbh, e));
	if (ei <=  dbh->i_wm)
		return 0;
	if (ei < dbh->d_wm)
		dbh->d_wm = ei;
	tdb_set_bit(dbh->ext_bmp, TDB_EXT_ID(TDB_EXT_BASE(dbh, e)));

	TDB_DBG("Alloc new data extent %p\n", e);

	rptr = tdb_alloc_blk(dbh, e);
	BUG_ON(!rptr);

	return TDB_HTRIE_DALIGN(rptr);
}

static void
tdb_htrie_init_bucket(TdbBucket *b)
{
	b->coll_next = 0;
	b->flags = 0;
	rwlock_init(&b->lock);
}

/**
 * @return byte offset of the allocated data block and sets @len to actually
 * available room for writting if @len doesn't fit to block.
 *
 * Return 0 on error.
 *
 * TODO Allocate set of pages if there are any for large @len.
 *      Defragment memory blocks in background.
 */
static unsigned long
tdb_alloc_data(TdbHdr *dbh, size_t *len, int bucket_hdr)
{
	unsigned long rptr = dbh->d_wcl;
	size_t hdr_len, res_len = *len;

	hdr_len = (bucket_hdr ? sizeof(TdbBucket) : 0)
		  + (TDB_HTRIE_VARLENRECS(dbh)
		     ? sizeof(TdbVRec)
		     : sizeof(TdbFRec));
	res_len += hdr_len;

	/*
	 * Allocate at least 2 cache lines for small data records
	 * and keep records after tails of large records also aligned.
	 */
	res_len = TDB_HTRIE_DALIGN(res_len);

	if (unlikely((dbh->i_wm + 1) * TDB_EXT_SZ + res_len + dbh->d_wcl
		      > dbh->dbsz + dbh->d_wm * TDB_EXT_SZ))
		return 0; /* not enough space */

	if (!(rptr & ~TDB_BLK_MASK)
	    || TDB_BLK_O(rptr + res_len) > TDB_BLK_O(rptr))
	{
		size_t max_data_len;

		/* Use a new page and/or extent for the data. */
		rptr = tdb_alloc_data_blk(dbh);
		if (!rptr)
			return 0;

		max_data_len = TDB_BLK_SZ - (rptr & ~TDB_BLK_MASK);
		if (res_len > max_data_len) {
			res_len = max_data_len;
			*len = res_len - hdr_len;
		}
	}

	TDB_DBG("alloc dblk %#lx for len=%lu\n", rptr, *len);
	BUG_ON(TDB_HTRIE_DALIGN(rptr) != rptr);

	dbh->d_wcl = rptr + res_len;
	BUG_ON(TDB_HTRIE_DALIGN(dbh->d_wcl) != dbh->d_wcl);

	if (bucket_hdr) {
		tdb_htrie_init_bucket(TDB_PTR(dbh, rptr));
		rptr += sizeof(TdbBucket);
	}

	return rptr;
}

/**
 * Allocates a new index block.
 * @return byte offset of the block.
 *
 * TODO synchronize this!
 */
static unsigned long
tdb_alloc_index(TdbHdr *dbh)
{
	unsigned long rptr = dbh->i_wcl;

	if (unlikely(TDB_BLK_O(rptr + sizeof(TdbHtrieNode) - 1) > TDB_BLK_O(rptr)))
	{
		/* Use a new page and/or extent for the data. */
		rptr = tdb_alloc_index_blk(dbh);
		if (!rptr)
			return 0;
	}

	TDB_DBG("alloc iblk %#lx\n", rptr);
	BUG_ON(TDB_HTRIE_IALIGN(rptr) != rptr);

	dbh->i_wcl = rptr + sizeof(TdbHtrieNode);

	return rptr;
}

/**
 * Lookup for some room just after @b bucket if it's small enough.
 * Traverses the collision chain in hope to find some room somewhere.
 *
 * The function links the last small record with the new (returned) one.
 *
 * Called under bucket lock.
 */
static unsigned long
tdb_htrie_smallrec_link(TdbHdr *dbh, size_t len, TdbBucket *bckt)
{
	unsigned long n, o = 0;

	if (TDB_HTRIE_VARLENRECS(dbh)) {
		TdbVRec *r;
		TDB_HTRIE_FOREACH_REC(dbh, bckt, r) {
			n = (char *)r - (char *)bckt
			    + TDB_HTRIE_RALIGN(sizeof(*r) + len);
			if (!tdb_live_vsrec(r) && n <= TDB_HTRIE_MINDREC) {
				/* Freed record - reuse. */
				memset(r, 0, sizeof(*r) + TDB_HTRIE_VRLEN(r));
				o = TDB_HTRIE_OFF(dbh, r);
				goto done;
			}
		}
	} else {
		TdbFRec *r;
		TDB_HTRIE_FOREACH_REC(dbh, bckt, r) {
			n = (char *)r - (char *)bckt
			    + TDB_HTRIE_RALIGN(sizeof(*r) + len);
			if (!tdb_live_fsrec(dbh, r) && n <= TDB_HTRIE_MINDREC) {
				/* Already freed record - just reuse. */
				o = TDB_HTRIE_OFF(dbh, r);
				goto done;
			}
		}
	}

done:
	TDB_DBG("Small record aggregation dblk=%#lx bckt=%#lx len=%lu\n",
		o, TDB_HTRIE_OFF(dbh, bckt), len);

	return o;
}

/**
 * Grow the tree.
 *
 * @node	- current index node at which least significant bits collision
 * 		  happened. Set to the new node to continue the search from.
 *
 * Called under bucket lock, so we can safely copy and remove records
 * from the bucket.
 */
static int
tdb_htrie_burst(TdbHdr *dbh, TdbHtrieNode **node, TdbBucket *bckt,
		unsigned long key, int bits)
{
	int i, free_nb;
	unsigned int new_in_idx, shift_save;
	unsigned long k, n;
	TdbBucket *b = TDB_HTRIE_BUCKET_1ST(bckt);
	TdbHtrieNode *new_in;
	struct {
		unsigned long	b;
		unsigned char	off;
	} nb[TDB_HTRIE_FANOUT] = {{0, 0}};

	/* Just a consistency check. Should be removed in future. */
	shift_save = (*node)->shifts[TDB_HTRIE_IDX(key, bits - TDB_HTRIE_BITS)];

	n = tdb_alloc_index(dbh);
	if (!n)
		return -ENOMEM;
	new_in = TDB_PTR(dbh, n);
	new_in_idx = TDB_O2II(n);

#define MOVE_RECORDS(Type, live)					\
do {									\
	Type *r = (Type *)b;						\
	k = TDB_HTRIE_IDX(r->key, bits);				\
	/* Always leave first record in the same data block. */		\
	new_in->shifts[k] = TDB_O2DI(TDB_HTRIE_OFF(dbh, bckt))		\
			    | TDB_HTRIE_DBIT;				\
	TDB_DBG("link bckt=%p w/ iblk=%#x by %#lx (key=%#lx)\n",	\
		bckt, new_in_idx, k, r->key);				\
	n = TDB_HTRIE_RALIGN(sizeof(*r) + __RECLEN(dbh, r));		\
	nb[k].b = TDB_HTRIE_OFF(dbh, bckt);				\
	nb[k].off = sizeof(*b) + n;					\
	free_nb = -(long)k; /* remember which block we save & copy */	\
	r = (Type *)((char *)r + n);					\
	for ( ; ; r = (Type *)((char *)r + n)) {			\
		unsigned long copied = (char *)r - (char *)bckt;	\
		if (sizeof(*r) + copied >= TDB_HTRIE_MINDREC)		\
			break; /* end of records */			\
		n = TDB_HTRIE_RECLEN(dbh, r);				\
		if (!live)						\
			continue;					\
		/* Small record cannot exceed TDB_HTRIE_MINDREC. */	\
		BUG_ON(copied + n > TDB_HTRIE_MINDREC);			\
		k = TDB_HTRIE_IDX(r->key, bits);			\
		if (!nb[k].b) {						\
			size_t _n = 0;					\
			nb[k].b = tdb_alloc_data(dbh, &_n, 0);		\
			if (!nb[k].b)					\
				goto err_cleanup;			\
			b = TDB_PTR(dbh, nb[k].b);			\
			tdb_htrie_init_bucket(b);			\
			memcpy(TDB_HTRIE_BUCKET_1ST(b), r, n);		\
			nb[k].off = sizeof(*b) + n;			\
			new_in->shifts[k] = TDB_O2DI(nb[k].b) | TDB_HTRIE_DBIT;\
			/* We copied a record, clear its orignal place. */\
			free_nb = free_nb > 0 ? free_nb : -free_nb;	\
			TDB_DBG("copied rec=%p (len=%lu key=%#lx) to"	\
				" new dblk=%#lx w/ idx=%#lx\n",		\
				r, n, r->key, nb[k].b, k);		\
		} else {						\
			b = TDB_PTR(dbh, nb[k].b + nb[k].off);		\
			memmove(b, r, n);				\
			nb[k].off += n;					\
			TDB_DBG("moved rec=%p (len=%lu key=%#lx) to"	\
				" dblk=%#lx w/ idx=%#lx\n",		\
				r, n, r->key, nb[k].b, k);		\
		}							\
	}								\
} while (0)

	if (TDB_HTRIE_VARLENRECS(dbh))
		MOVE_RECORDS(TdbVRec, tdb_live_vsrec(r));
	else
		MOVE_RECORDS(TdbFRec, tdb_live_fsrec(dbh, r));

#undef MOVE_RECORDS

	/* Link the new index node with @node. */
	TDB_DBG("link iblk=%p w/ iblk=%p (%#x) by idx=%#lx\n",
		*node, new_in, new_in_idx, k);
	if (unlikely(atomic_cmpxchg((atomic_t *)&(*node)->shifts[k],
				    shift_save, new_in_idx)
		     != shift_save))
		/*
		 * Nobody should change the index block,
		 * while the bucket lock is held.
		 */
		BUG();
	*node = new_in;

	/* Now we can safely remove all copied records. */
	if (free_nb > 0) {
		TDB_DBG("clear dblk=%#lx from %#x\n",
			nb[free_nb].b, nb[free_nb].off);
		memset(TDB_PTR(dbh, nb[free_nb].b + nb[free_nb].off),
		       0, TDB_HTRIE_MINDREC - nb[free_nb].off);
	}

	return 0;
err_cleanup:
	if (free_nb > 0)
		for (i = 0; i < TDB_HTRIE_FANOUT; ++i)
			if (i != free_nb && nb[i].b)
				tdb_free_data_blk(TDB_PTR(dbh, nb[i].b));
	tdb_free_index_blk(new_in);
	return -ENOMEM;
}

/**
 * Descend the the tree starting at @node.
 *
 * @retrurn byte offset of data (w/o TDB_HTRIE_DBIT bit) on success
 * or 0 if key @key was not found.
 * When function exits @node stores the last index node.
 * @bits - number of bits (from less significant to most significant) from
 * which we should start descending and the stored number of resolved bits.
 *
 * Least significant bits in our hash function have most entropy,
 * so we resolve the key from least significant bits to most significant.
 */
static unsigned long
tdb_htrie_descend(TdbHdr *dbh, TdbHtrieNode **node, unsigned long key,
		  int *bits)
{
	while (1) {
		unsigned long o;

		BUG_ON(TDB_HTRIE_RESOLVED(*bits));

		o = (*node)->shifts[TDB_HTRIE_IDX(key, *bits)];

		TDB_DBG("Descend iblk=%p key=%#lx bits=%d -> %#lx\n",
			*node, key, *bits, o);
		BUG_ON(o
		       && (TDB_DI2O(o & ~TDB_HTRIE_DBIT)
				< TDB_HDR_SZ(dbh) + sizeof(TdbExt)
			   || TDB_DI2O(o & ~TDB_HTRIE_DBIT)
				> dbh->dbsz));

		if (o & TDB_HTRIE_DBIT) {
			/* We're at a data pointer - resolve it. */
			*bits += TDB_HTRIE_BITS;
			o ^= TDB_HTRIE_DBIT;
			BUG_ON(!o);
			return TDB_DI2O(o);
		} else {
			if (!o)
				return 0; /* cannot descend deeper */
			*node = TDB_PTR(dbh, TDB_II2O(o));
			*bits += TDB_HTRIE_BITS;
		}
	}
}

static TdbRec *
tdb_htrie_create_rec(TdbHdr *dbh, unsigned long off, unsigned long key,
		     void *data, size_t len)
{
	char *ptr = TDB_PTR(dbh, off);
	TdbRec *r = (TdbRec *)ptr;

	BUG_ON(r->key);
	r->key = key;
	if (TDB_HTRIE_VARLENRECS(dbh)) {
		TdbVRec *vr = (TdbVRec *)r;
		BUG_ON(vr->len || vr->chunk_next);
		vr->chunk_next = 0;
		vr->len = len;
		ptr += sizeof(TdbVRec);
	} else {
		ptr += sizeof(TdbFRec);
	}
	memcpy(ptr, data, len);

	return r;
}

/**
 * Add more data to @rec.
 */
TdbVRec *
tdb_htrie_extend_rec(TdbHdr *dbh, TdbVRec *rec, size_t size)
{
	unsigned long o;
	TdbVRec *chunk;

	/* Cannot extend fixed-size records. */
	BUG_ON(!TDB_HTRIE_VARLENRECS(dbh));

	TDB_DBG("Extend record: rec_ptr=%p to_copy=%lu\n", rec, size);

	o = tdb_alloc_data(dbh, &size, 0);
	if (!o)
		return NULL;

	chunk = TDB_PTR(dbh, o);
	chunk->key = rec->key;
	chunk->chunk_next = 0;
	chunk->len = size;

	/* A caller is appreciated to pass the last record chunk by @rec. */
retry:
	while (unlikely(rec->chunk_next))
		rec = TDB_PTR(dbh, TDB_DI2O(rec->chunk_next));
	BUG_ON(!tdb_live_vsrec(rec));

	if (atomic_cmpxchg((atomic_t *)&rec->chunk_next, 0, o))
		goto retry;

	return chunk;
}

/**
 * @len returns number of copied data on success.
 */
TdbRec *
tdb_htrie_insert(TdbHdr *dbh, unsigned long key, void *data, size_t *len)
{
	int i, bits = 0;
	unsigned long o;
	TdbBucket *bckt;
	TdbRec *rec = NULL;
	TdbHtrieNode *node = TDB_HTRIE_ROOT(dbh);

	/* Don't store empty data. */
	if (unlikely(!*len))
		return NULL;

retry:
	o = tdb_htrie_descend(dbh, &node, key, &bits);
	if (!o) {
		TDB_DBG("Create a new htrie node for key %#lx\n", key);

		o = tdb_alloc_data(dbh, len, 1);
		if (!o)
			return NULL;

		rec = tdb_htrie_create_rec(dbh, o, key, data, *len);

		i = TDB_HTRIE_IDX(key, bits);
		if (atomic_cmpxchg((atomic_t *)&node->shifts[i], 0,
				   TDB_O2DI(o) | TDB_HTRIE_DBIT) == 0)
			return rec;
	}

	/*
	 * HTrie collision.
	 */
	bckt = TDB_PTR(dbh, o);
	BUG_ON(!bckt);

	write_lock_bh(&bckt->lock);

	/*
	 * Try to place the small record in preallocated room for
	 * small records. There could be full or partial key match.
	 * Small and large variable-length records can be intermixed
	 * in collision chain, so we do this before processing
	 * full key collision.
	 *
	 * Don't try to place the small record if we passed there due to
	 * concurrent data allocation above.
	 */
	if (*len < TDB_HTRIE_MINDREC && likely(!o)) {
		/* Align small record length to 8 bytes. */
		size_t n = TDB_HTRIE_RALIGN(*len);

		TDB_DBG("Small record (len=%lu) collision on %d bits for"
			" key %#lx\n", n, bits, key);

		o = tdb_htrie_smallrec_link(dbh, n, bckt);
		if (o) {
			rec = tdb_htrie_create_rec(dbh, o, key, data, *len);
			write_unlock_bh(&bckt->lock);
			return rec;
		}
	}

	if (TDB_HTRIE_RESOLVED(bits)) {
		TDB_DBG("Hash full key %#lx collision on %d bits,"
			" add new record (len=%lu) to collision chain\n",
			key, bits, *len);

		BUG_ON(TDB_HTRIE_BUCKET_KEY(bckt) != key);

		while (bckt->coll_next && !(bckt->flags & TDB_HTRIE_VRFREED)) {
			TdbBucket *next = TDB_HTRIE_BUCKET_NEXT(dbh, bckt);
			write_lock_bh(&next->lock);
			write_unlock_bh(&bckt->lock);
			bckt = next;
		}

		o = tdb_alloc_data(dbh, len, 1);
		if (!o) {
			write_unlock_bh(&bckt->lock);
			return NULL;
		}
		bckt->coll_next = TDB_O2DI(o);

		write_unlock_bh(&bckt->lock);

		return tdb_htrie_create_rec(dbh, o, key, data, *len);
	}

	/*
	 * But there is no room. Burst the node.
	 * We should never see collision chains at this point.
	 */
	BUG_ON(bckt->coll_next);
	BUG_ON(bits < TDB_HTRIE_BITS);

	TDB_DBG("Least significant bits %d collision for key %#lx"
		" and new record (len=%lu) - burst the node\n",
		bits, key, *len);

	if (tdb_htrie_burst(dbh, &node, bckt, key, bits)) {
		write_unlock_bh(&bckt->lock);
		TDB_ERR("Cannot burst node=%p and bckt=%p for key %#lx\n",
			node, bckt, key);
		return NULL;
	}

	write_unlock_bh(&bckt->lock);

	goto retry;
}

TdbBucket *
tdb_htrie_lookup(TdbHdr *dbh, unsigned long key)
{
	int bits = 0;
	unsigned long o;
	TdbHtrieNode *root = TDB_HTRIE_ROOT(dbh);

	o = tdb_htrie_descend(dbh, &root, key, &bits);
	if (!o)
		return NULL;

	return TDB_PTR(dbh, o);
}

TdbHdr *
tdb_htrie_init(void *p, size_t db_size, unsigned int rec_len)
{
	TdbHdr *hdr = (TdbHdr *)p;

	if (hdr->magic != TDB_MAGIC)
		hdr = tdb_init_mapping(p, db_size, rec_len);

	TDB_DBG("init db header: i_wcl=%lu d_wcl=%lu db_size=%lu rec_len=%u"
		" i_wm=%u d_wm=%u\n",
		hdr->i_wcl, hdr->d_wcl, hdr->dbsz, hdr->rec_len, hdr->i_wm,
		hdr->d_wm);

	return hdr;
}

/*
 * ------------------------------------------------------------------------
 *	Testing routines
 * ------------------------------------------------------------------------
 */
#define TDB_VSF_SZ		(2UL * 1024 * 1024 * 1024)
#define TDB_FSF_SZ		(16UL * 1024 * 1024)
#define THR_N			2
#define DATA_N			100
#define LOOP_N			2

typedef struct {
	char	*body;
	size_t	len;
} TestUrl;

static TestUrl urls[DATA_N] = {
	{"", 0},
	{"http://www.w3.org/1999/02/22-rdf-syntax-ns#", 0},
	{"http://ns.adobe.com/iX/1.0/", 0},
	{"http://www.w3.org/1999/02/22-rdf-syntax-ns#", 0},
	{"http://purl.org/dc/elements/1.1/", 0},
	{"http://www.cse.unsw.edu.au/~disy/papers/", 0},
	{"http://developer.intel.com/design/itanium/family", 0},
	{"http://www.caldera.com/developers/community/contrib/aim.html", 0},
	{"http://www.sparc.org/standards.html", 0},
	{"http://www.xplain.com", 0},
	{"http://www.mactech.com/misc/about_mt.html", 0},
	{"http://www.mactech.com/", 0},
	{"http://www.google-analytics.com/urchin.js", 0},
	{"http://www.betterram.com/", 0},
	{"http://www.mactechdomains.com/", 0},
	{"http://www.mactechsupplies.com/store.php?nfid=34", 0},
	{"http://www.mactech.com/cables/", 0},
	{"http://www.xplain.com", 0},
	{"http://www.amazon.com/exec/obidos/redirect?link_code=ur2&amp;camp=178"
	 "9&amp;tag=mactechmagazi-20&amp;creative=9325&amp;path=external-search"
	 "\%3Fsearch-type=ss\%26keyword=ipod\%26index=pc-hardware", 0},
	{"http://store.mactech.com/mactech/riskfree/offer.html?FROM=MTRF", 0},
	{"http://www.google.com/", 0},
	{"http://www.google.com/logos/Logo_25wht.gif", 0},
	{"http://www.xplain.com", 0},
};

static unsigned int ints[DATA_N];

static inline unsigned long
tv_to_ms(const struct timeval *tv)
{
	return ((unsigned long)tv->tv_sec * 1000000 + tv->tv_usec) / 1000;
}

unsigned long
test_hash_calc_dummy(const char *data, size_t len)
{
	int i;
	unsigned long h = 0;

	for (i = 0; i < len; ++i)
		h += data[i] * (i + 1);

	return h;
}

/**
 * Benchmark for SSE 4.2 and trivial C hash function.
 */
void
hash_calc_benchmark(void)
{
#define N 1024
	int r __attribute__((unused)), i, acc = 0;
	TestUrl *u;
	struct timeval tv0, tv1;

	r = gettimeofday(&tv0, NULL);
	assert(!r);
	for (i = 0; i < N; ++i)
		for (u = urls; u->body; ++u)
			acc += tdb_hash_calc(u->body, u->len);
	r = gettimeofday(&tv1, NULL);
	assert(!r);
	printf("tdb hash: time=%lums ignore_val=%d\n",
	       tv_to_ms(&tv1) - tv_to_ms(&tv0), acc);

	r = gettimeofday(&tv0, NULL);
	assert(!r);
	for (i = 0; i < N; ++i)
		for (u = urls; u->body; ++u)
			acc += test_hash_calc_dummy(u->body, u->len);
	r = gettimeofday(&tv1, NULL);
	assert(!r);
	printf("dummy hash: time=%lums ignore_val=%d\n",
	       tv_to_ms(&tv1) - tv_to_ms(&tv0), acc);
#undef N
}

void *
tdb_htrie_open(const char *fname, size_t size)
{
	int fd;
	void *p;
	struct stat sb;

	if (stat(fname, &sb) < 0) {
		printf("filesize: %ld\n", sb.st_size);
		TDB_ERR("no file");
	}

	if ((fd = open(fname, O_RDWR|O_CREAT)) < 0)
        	TDB_ERR("open failure");

	if (sb.st_size != size)
		if (fallocate(fd, 0, 0, size))
			TDB_ERR("fallocate failure");

	/* Use MAP_SHARED to carry changes to underlying file. */
	p = mmap((void *)TDB_MAP_ADDR, size, PROT_READ | PROT_WRITE,
		 MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		TDB_ERR("cannot mmap the file");
	printf("maped to %p\n", p);

	if (mlock(p, size))
		TDB_ERR("mlock failure");

	return p;
}

/**
 * Just free the memory region, the file will be closed on program exit.
 */
void
tdb_htrie_pure_close(void *addr, size_t size)
{
	munlock(addr, size);
	munmap(addr, size);
}

static void
print_bin_url(TestUrl *u)
{
	int i, len = u->len < 40 ? u->len : 40;

	printf("insert [0x");
	for (i = 0; i < len; ++i)
		printf("%x", (unsigned char)u->body[i]);
	printf(len < u->len ? "...] (len=%lu)\n" : "] (len=%lu)\n", u->len);
	fflush(NULL);
}

static void
do_varsz(TdbHdr *dbh)
{
	int i;
	TestUrl *u;

	/* Store records. */
	for (i = 0, u = urls; i < DATA_N; ++u, ++i) {
		unsigned long k = tdb_hash_calc(u->body, u->len);
		size_t copied, to_copy = u->len;
		TdbVRec *rec;

		print_bin_url(u);

		rec = (TdbVRec *)tdb_htrie_insert(dbh, k, u->body, &to_copy);
		assert((u->len && rec) || (!u->len && !rec));

		copied = to_copy;

		while (copied != u->len) {
			char *p;

			rec = tdb_htrie_extend_rec(dbh, rec, u->len - copied);
			assert(rec);

			p = (char *)(rec + 1);
			memcpy(p, u->body + copied, rec->len);

			copied += rec->len;
		}
	}

	/* Read records. */
	for (i = 0, u = urls; i < DATA_N; ++u, ++i) {
		unsigned long k = tdb_hash_calc(u->body, u->len);
		TdbBucket *b;

		print_bin_url(u);

		b = tdb_htrie_lookup(dbh, k);
		if (!b) {
			fprintf(stderr, "ERROR: can't find URL [%.20s...]\n",
				u->body);
			fflush(NULL);
			continue;
		}

		if (TDB_HTRIE_VARLENRECS(dbh)) {
			TdbVRec *r;
			TDB_HTRIE_FOREACH_REC(dbh, b, r) {
				if (tdb_live_vsrec(r))
					TDB_DBG("\t[%.64s...] key=%#lx"
						" bckt=%p\n", r->data,
						tdb_hash_calc(r->data, r->len),
						b);
			}
		} else {
			BUG();
		}
	}
}

static void *
varsz_thr_f(void *data)
{
	int i;
	TdbHdr *dbh = (TdbHdr *)data;

	for (i = 0; i < LOOP_N; ++i)
		do_varsz(dbh);

	return NULL;
}

static void
do_fixsz(TdbHdr *dbh)
{
	int i;

	/* Store records. */
	for (i = 0; i < DATA_N; ++i) {
		size_t copied = sizeof(ints[i]);
		TdbRec *rec __attribute__((unused));

		printf("insert int %u\n", ints[i]);
		fflush(NULL);

		rec = tdb_htrie_insert(dbh, ints[i], &ints[i], &copied);
		assert(rec && copied == sizeof(ints[i]));
	}

	/* Read records. */
	for (i = 0; i < DATA_N; ++i) {
		TdbBucket *b;

		printf("results for int %u lookup:\n", ints[i]);
		fflush(NULL);

		b = tdb_htrie_lookup(dbh, ints[i]);
		if (!b) {
			fprintf(stderr, "ERROR: can't find int %u\n", ints[i]);
			fflush(NULL);
			continue;
		}

		if (TDB_HTRIE_VARLENRECS(dbh)) {
			BUG();
		} else {
			TdbFRec *r;
			TDB_HTRIE_FOREACH_REC(dbh, b, r) {
				if (tdb_live_fsrec(dbh, r))
					TDB_DBG("\t(%#x) %u bckt=%p\n",
						*(unsigned int *)r->data,
						*(unsigned int *)r->data, b);
			}
		}
	}
}

static void *
fixsz_thr_f(void *data)
{
	int i;
	TdbHdr *dbh = (TdbHdr *)data;

	for (i = 0; i < LOOP_N; ++i)
		do_fixsz(dbh);

	return NULL;
}

void
tdb_htrie_test_varsz(const char *fname)
{
	int r __attribute__((unused));
	int t;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;
	pthread_t thr[THR_N];

	printf("\n----------- Variable size records test -------------\n");

	addr = tdb_htrie_open(fname, TDB_VSF_SZ);
	dbh = tdb_htrie_init(addr, TDB_VSF_SZ, 0);
	if (!dbh)
		TDB_ERR("cannot initialize htrie for urls");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	for (t = 0; t < THR_N; ++t)
		if (pthread_create(thr + t, NULL, varsz_thr_f, dbh))
			perror("cannot spawn varsz thread");
	for (t = 0; t < THR_N; ++t)
		pthread_join(thr[t], NULL);

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie urls test: time=%lums\n",
		tv_to_ms(&tv1) - tv_to_ms(&tv0));

	tdb_htrie_pure_close(addr, TDB_VSF_SZ);
}

void
tdb_htrie_test_fixsz(const char *fname)
{
	int r __attribute__((unused));
	int t;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;
	pthread_t thr[THR_N];

	printf("\n----------- Fixed size records test -------------\n");

	addr = tdb_htrie_open(fname, TDB_FSF_SZ);

	dbh = tdb_htrie_init(addr, TDB_FSF_SZ, sizeof(ints[0]));
	if (!dbh)
		TDB_ERR("cannot initialize htrie for ints");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	for (t = 0; t < THR_N; ++t)
		if (pthread_create(thr + t, NULL, fixsz_thr_f, dbh))
			perror("cannot spawn fixsz thread");
	for (t = 0; t < THR_N; ++t)
		pthread_join(thr[t], NULL);

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie ints test: time=%lums\n",
		tv_to_ms(&tv1) - tv_to_ms(&tv0));

	tdb_htrie_pure_close(addr, TDB_FSF_SZ);
}

static void
tdb_htrie_test(const char *vsf, const char *fsf)
{
	tdb_htrie_test_varsz(vsf);
	tdb_htrie_test_fixsz(fsf);
}

static void
init_test_data_for_hash(void)
{
	TestUrl *u;

	/* Load urls pages and precompute string lengths (with terminator). */
	for (u = urls; u->body; ++u)
		u->len = strlen(u->body) + 1;
}

static void
init_test_data_for_htrie(void)
{
	int i, rfd;

	printf("prepare htrie testing data..."); fflush(NULL);

	if ((rfd = open("/dev/urandom", O_RDONLY)) < 0)
		TDB_ERR("cannot open /dev/urandom\n");

	/* Leave first element empty. */
	for (i = 1; i < DATA_N; ++i) {
		int r = rand();

		ints[i] = r;

		r %= 65536;
		urls[i].body = malloc(r + 1);
		urls[i].len = r + 1;
		if (!urls[i].body) {
			TDB_ERR("not enough memory\n");
			BUG();
		}
		read(rfd, urls[i].body, r);
		urls[i].body[r] = 0;
	}

	close(rfd);

	printf("done\n");
}

int
main(int argc, char *argv[])
{
	unsigned int eax, ebx, ecx = 0, edx;
	struct rlimit rlim = { TDB_VSF_SZ, TDB_VSF_SZ * 2};
	
	if (argc < 3) {
		printf("\nUsage: %s <vsf> <fsf>\n"
		       "  vsf    - file name for variable-size records test\n"
		       "  fsf    - file name for fixed-size records test\n\n",
		       argv[0]);
		return 1;
	}

	/* Don't forget to set appropriate system hard limit. */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim))
		TDB_ERR("cannot set RLIMIT_MEMLOCK");

	__get_cpuid(1, &eax, &ebx, &ecx, &edx);
	   
	if (!(ecx & bit_SSE4_2))
		TDB_ERR("SSE4.2 is not supported");

	printf("Run test with parameters:\n"
	       "\tfix rec db size: %lu\n"
	       "\tvar rec db size: %lu\n"
	       "\textent size:     %lu\n"
	       "\tthreads number:  %d\n"
	       "\tdata size:       %d\n"
	       "\tloops:           %d\n",
	       TDB_FSF_SZ, TDB_VSF_SZ, TDB_EXT_SZ,
	       THR_N, DATA_N, LOOP_N);

	init_test_data_for_hash();
	hash_calc_benchmark();

	init_test_data_for_htrie();
	tdb_htrie_test(argv[1], argv[2]);

	return 0;
}
