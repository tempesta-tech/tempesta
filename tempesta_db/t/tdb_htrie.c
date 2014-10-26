/**
 * Unit test for Tempesta DB HTrie storage.
 *
 * If index is not SEQLOG (i.e. no index at all), then to improve space locality
 * for large data sets index records grow from lower addresses to higher while
 * data records grow towards them, from maximum to minimum addresses.
 *
 * TODO
 * - consistensy checking and recovery
 * - garbage collection
 * - reduce number of memset(.., 0, ..) calls
 * - freeing interface for eviction thread
 * - unit test for concurrency
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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
#define _GNU_SOURCE
#include <assert.h>
#include <cpuid.h>
#include <fcntl.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>

/*
 * ------------------------------------------------------------------------
 *	Kernel stubs
 * ------------------------------------------------------------------------
 */
#ifndef TDB_CL_SZ
#error "Unknown size of cache line"
#endif

#define PAGE_SIZE	4096
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

/*
 * ------------------------------------------------------------------------
 *	Tempesta DB index and data manipulations
 * ------------------------------------------------------------------------
 */
#define TDB_MAGIC		0x434947414D424454UL /* "TDBMAGIC" */
#define TDB_MAP_ADDR		0x600000000000
#define TDB_BLK_SZ		PAGE_SIZE
#define TDB_BLK_MASK		(~(TDB_BLK_SZ - 1))
#define TDB_EXT_BITS		21
#define TDB_EXT_SZ		(1 << TDB_EXT_BITS)
#define TDB_EXT_MASK		(~(TDB_EXT_SZ - 1))
#define TDB_BLK_BMP_2L		(TDB_EXT_SZ / TDB_BLK_SZ / BITS_PER_LONG)
/* Get current extent by an offset in it. */
#define TDB_EXT_O(o)		((unsigned long)(o) & TDB_EXT_MASK)
/* Get extent id by a record offset. */
#define TDB_EXT_ID(o)		(TDB_EXT_O(o) >> TDB_EXT_BITS)
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
#define TDB_HTRIE_PTR(h, o)	(void *)((char *)(h) + (o))
/* Get internal offset from a pointer. */
#define TDB_HTRIE_OFF(h, p)	((char *)(p) - (char *)(h))
/* Get index and data block indexes by byte offset and vise versa. */
#define TDB_HTRIE_O2DI(o)	((o) / TDB_HTRIE_MINDREC)
#define TDB_HTRIE_O2II(o)	((o) / TDB_HTRIE_NODE_SZ)
#define TDB_HTRIE_DI2O(i)	((i) * TDB_HTRIE_MINDREC)
#define TDB_HTRIE_II2O(i)	((i) * TDB_HTRIE_NODE_SZ)
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
 * @chunk_next	- offset of next data chunk (also with TdbRecord as header)
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
#define TDB_HTRIE_BUCKET_NEXT(h, b)					\
({									\
	(b)->coll_next							\
	? TDB_HTRIE_PTR(h, TDB_HTRIE_DI2O((b)->coll_next))		\
	: NULL;								\
 })

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

	n *= MUL;
	if (n + MUL <= len) {
		crc0 = _mm_crc32_u64(crc0, d[n]);
		n += MUL;
	}

	h = (crc1 << 32) | crc0;

	/*
	 * Generate relatively small and dense hash tail values - they are good
	 * for short strings in htrie which uses less significant bits at root,
	 * however collisions are very probable.
	 */
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
		++n;
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
	set_bit(0, tdb_ext(hdr, TDB_HTRIE_PTR(hdr, hdr->d_wcl))->b_bmp);

	return hdr;
}

/*
 * @return aligned and shrinked (if necessary) length to allocate data block.
 * Can be significanly less than @len for chunked data.
 */
static size_t
tdb_full_rec_len(TdbHdr *dbh, size_t *len)
{
	size_t align_len, rhl;

	rhl = TDB_HTRIE_VARLENRECS(dbh) ? sizeof(TdbVRec) : sizeof(TdbFRec);

	/* Allocate at least 2 cache lines for small data records. */
	align_len = TDB_HTRIE_DALIGN(*len + rhl);

	if (align_len > TDB_BLK_SZ) {
		*len -= align_len - TDB_BLK_SZ;
		align_len = TDB_BLK_SZ;
	}

	return align_len;
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

		r = ffz(e->b_bmp[i]);
		set_bit(r, &e->b_bmp[i]);
		r = TDB_EXT_BASE(dbh, e) + r * TDB_BLK_SZ;
		if (!r) {
			r += sizeof(*e);
			if (TDB_EXT_O(e) == TDB_EXT_O(dbh))
				r += TDB_HDR_SZ(dbh);
		}
		return r;
	}

	return 0;
}

static unsigned long
tdb_alloc_index_blk(TdbHdr *dbh)
{
	unsigned long rptr;
	TdbExt *e = tdb_ext(dbh, TDB_HTRIE_PTR(dbh, dbh->i_wcl));

	while (1) {
		rptr = tdb_alloc_blk(dbh, e);
		if (!rptr) {
			unsigned long eo;
			if (TDB_HTRIE_OFF(dbh, e) + TDB_EXT_SZ * 2 > dbh->d_wm)
				return 0;
			e = (TdbExt *)(TDB_EXT_O(e) + TDB_EXT_SZ);
			eo = TDB_EXT_ID(TDB_HTRIE_OFF(dbh, e));
			if (dbh->i_wm < eo)
				dbh->i_wm = eo;
			tdb_set_bit(dbh->ext_bmp,
				    TDB_EXT_ID(TDB_EXT_BASE(dbh, e)));
			continue;
		}
		return TDB_HTRIE_IALIGN(rptr);
	}
}

static unsigned long
tdb_alloc_data_blk(TdbHdr *dbh)
{
	unsigned long rptr;
	TdbExt *e = tdb_ext(dbh, TDB_HTRIE_PTR(dbh, dbh->d_wcl));

	while (1) {
		rptr = tdb_alloc_blk(dbh, e);
		if (!rptr) {
			/* No room in current extent, try the next one. */
			unsigned long eo;
			if (TDB_HTRIE_OFF(dbh, e) <  dbh->i_wm + TDB_EXT_SZ * 2)
				return 0;
			e = (TdbExt *)((char *)e - TDB_EXT_SZ);
			eo = TDB_EXT_ID(TDB_HTRIE_OFF(dbh, e));
			if (dbh->d_wm > eo)
				dbh->d_wm = eo;
			tdb_set_bit(dbh->ext_bmp,
				    TDB_EXT_ID(TDB_EXT_BASE(dbh, e)));
			continue;
		}
		return TDB_HTRIE_DALIGN(rptr);
	}
}

/**
 * @return byte offset of the allocated data block and sets @len to actually
 * available room for writting if @len doesn't fit to block.
 *
 * Return 0 on error.
 */
static unsigned long
tdb_alloc_data(TdbHdr *dbh, size_t len)
{
	unsigned long rptr = dbh->d_wcl;

	BUG_ON(len > TDB_BLK_SZ);

	/* Never allocate too small chunks. */
	if (len < TDB_HTRIE_MINDREC)
		len = TDB_HTRIE_MINDREC;

	if (unlikely((dbh->i_wm + 1) * TDB_EXT_SZ + len + dbh->d_wcl
		      > dbh->dbsz + dbh->d_wm * TDB_EXT_SZ))
		return 0; /* not enough space */

	if (TDB_BLK_ID(rptr + len) > TDB_BLK_ID(rptr)) {
		/* Use a new page and/or extent for the data. */
		rptr = tdb_alloc_data_blk(dbh);
		if (!rptr)
			return 0;
	}

	TDB_DBG("alloc dblk %#lx for len=%lu\n", rptr, len);
	BUG_ON(TDB_HTRIE_DALIGN(rptr) != rptr);

	dbh->d_wcl = rptr + len;

	return rptr;
}

/**
 * Allocates a new index block.
 * @return byte offset of the block.
 */
static unsigned long
tdb_alloc_index(TdbHdr *dbh)
{
	unsigned long rptr = dbh->i_wcl;

	if (unlikely(TDB_BLK_ID(rptr + sizeof(TdbHtrieNode))
		     > TDB_BLK_ID(rptr)))
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

static void
tdb_htrie_init_bucket(TdbBucket *b)
{
	b->coll_next = 0;
	b->flags = 0;
}

/**
 * Lookup for some room just after @b bucket if it's small enough.
 * Traverses the collision chain in hope to find some room somewhere.
 *
 * The function links the last small record with the new (returned) one.
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
 * 		  happened.
 */
static int
tdb_htrie_burst(TdbHdr *dbh, TdbHtrieNode **node, TdbBucket *bckt,
		unsigned long key, int bits)
{
	int i, free_nb;
	unsigned int new_in_idx;
	unsigned long k, n;
	TdbBucket *b = TDB_HTRIE_BUCKET_1ST(bckt);
	TdbHtrieNode *new_in;
	struct {
		unsigned long	b;
		unsigned char	off;
	} nb[TDB_HTRIE_FANOUT] = {{0, 0}};

	n = tdb_alloc_index(dbh);
	if (!n)
		return -ENOMEM;
	new_in = TDB_HTRIE_PTR(dbh, n);
	new_in_idx = TDB_HTRIE_O2II(n);

#define MOVE_RECORDS(Type, live)					\
do {									\
	Type *r = (Type *)b;						\
	k = TDB_HTRIE_IDX(r->key, bits);				\
	/* Always leave first record in the same data block. */		\
	new_in->shifts[k] = TDB_HTRIE_O2DI(TDB_HTRIE_OFF(dbh, bckt))	\
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
			nb[k].b = tdb_alloc_data(dbh, 0);		\
			if (!nb[k].b)					\
				goto err_cleanup;			\
			b = TDB_HTRIE_PTR(dbh, nb[k].b);		\
			tdb_htrie_init_bucket(b);			\
			memcpy(TDB_HTRIE_BUCKET_1ST(b), r, n);		\
			nb[k].off = sizeof(*b) + n;			\
			new_in->shifts[k] = TDB_HTRIE_O2DI(nb[k].b)	\
					    | TDB_HTRIE_DBIT;		\
			/* We copied a record, clear its orignal place. */\
			free_nb = free_nb > 0 ? free_nb : -free_nb;	\
			TDB_DBG("copied rec=%p (len=%lu key=%#lx) to"	\
				" new dblk=%#lx w/ idx=%#lx\n",		\
				r, n, r->key, nb[k].b, k);		\
		} else {						\
			b = TDB_HTRIE_PTR(dbh, nb[k].b + nb[k].off);	\
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
	k = TDB_HTRIE_IDX(key, bits - TDB_HTRIE_BITS);
	(*node)->shifts[k] = new_in_idx;
	*node = new_in;

	/* Now we can safely remove all copied records. */
	if (free_nb > 0) {
		TDB_DBG("clear dblk=%#lx from %#x\n",
			nb[free_nb].b, nb[free_nb].off);
		memset(TDB_HTRIE_PTR(dbh, nb[free_nb].b + nb[free_nb].off),
		       0, TDB_HTRIE_MINDREC - nb[free_nb].off);
	}

	return 0;
err_cleanup:
	if (free_nb > 0)
		for (i = 0; i < TDB_HTRIE_FANOUT; ++i)
			if (i != free_nb && nb[i].b)
				tdb_free_data_blk(TDB_HTRIE_PTR(dbh, nb[i].b));
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
		       && (TDB_HTRIE_DI2O(o & ~TDB_HTRIE_DBIT)
				< TDB_HDR_SZ(dbh) + sizeof(TdbExt)
			   || TDB_HTRIE_DI2O(o & ~TDB_HTRIE_DBIT)
				> dbh->dbsz));

		if (o & TDB_HTRIE_DBIT) {
			/* We're at a data pointer - resolve it. */
			*bits += TDB_HTRIE_BITS;
			o ^= TDB_HTRIE_DBIT;
			BUG_ON(!o);
			return TDB_HTRIE_DI2O(o);
		} else {
			if (!o)
				return 0; /* cannot descend deeper */
			*node = TDB_HTRIE_PTR(dbh, TDB_HTRIE_II2O(o));
			*bits += TDB_HTRIE_BITS;
		}
	}
}

static TdbRec *
tdb_htrie_create_rec(TdbHdr *dbh, unsigned long off, unsigned long key,
		     void *data, size_t len, int init_bucket)
{
	char *ptr = TDB_HTRIE_PTR(dbh, off);
	TdbRec *r;

	if (init_bucket) {
		tdb_htrie_init_bucket((TdbBucket *)ptr);
		ptr += sizeof(TdbBucket);
	}

	r = (TdbRec *)ptr;
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
void *
tdb_htrie_extend_rec(TdbHdr *dbh, TdbRec *rec, size_t *size)
{
	unsigned long o;
	TdbVRec *chunk, *r = (TdbVRec *)rec;

	/* Cannot extend fixed-size records. */
	BUG_ON(!TDB_HTRIE_VARLENRECS(dbh));

	o = tdb_alloc_data(dbh, tdb_full_rec_len(dbh, size));
	if (!o)
		return NULL;

	chunk = TDB_HTRIE_PTR(dbh, o);
	chunk->key = r->key;
	chunk->chunk_next = 0;
	chunk->len = *size;

	while (r->chunk_next)
		r = TDB_HTRIE_PTR(dbh, TDB_HTRIE_DI2O(r->chunk_next));
	BUG_ON(!tdb_live_vsrec(r));

	r->chunk_next = o;

	return chunk + 1;
}

/**
 * @len returns number of copied data on success.
 */
TdbRec *
tdb_htrie_insert(TdbHdr *dbh, unsigned long key, void *data, size_t *len)
{
	int bits = 0;
	unsigned long o;
	TdbBucket *bckt;
	TdbRec *rec;
	TdbHtrieNode *node = TDB_HTRIE_ROOT(dbh);

	/* Don't store empty data. */
	if (unlikely(!*len))
		return NULL;

retry:
	o = tdb_htrie_descend(dbh, &node, key, &bits);
	if (!o) {
		TDB_DBG("Create a new htrie node for key %#lx\n", key);

		o = tdb_alloc_data(dbh, tdb_full_rec_len(dbh, len));
		if (!o)
			return NULL;

		rec = tdb_htrie_create_rec(dbh, o, key, data, *len, 1);

		node->shifts[TDB_HTRIE_IDX(key, bits)] = TDB_HTRIE_O2DI(o)
							 | TDB_HTRIE_DBIT;

		return rec;
	}

	/*
	 * HTrie collision.
	 */
	bckt = TDB_HTRIE_PTR(dbh, o);
	BUG_ON(!bckt);

	/*
	 * Try to place the small record in preallocated room for
	 * small records. There could be full or partial key match.
	 * Small and large variable-length records can be intermixed
	 * in collision chain, so we do this before processing
	 * full key collision.
	 */
	if (*len < TDB_HTRIE_MINDREC) {
		/* Align small record length to 8 bytes. */
		size_t n = TDB_HTRIE_RALIGN(*len);

		TDB_DBG("Small record (len=%lu) collision on %d bits for"
			" key %#lx\n", n, bits, key);

		o = tdb_htrie_smallrec_link(dbh, n, bckt);
		if (o)
			return tdb_htrie_create_rec(dbh, o, key, data, *len, 0);
	}

	if (TDB_HTRIE_RESOLVED(bits)) {
		TDB_DBG("Hash full key %#lx collision on %d bits,"
			" add new record (len=%lu) to collision chain\n",
			key, bits, *len);

		BUG_ON(TDB_HTRIE_BUCKET_KEY(bckt) != key);
		o = tdb_alloc_data(dbh, tdb_full_rec_len(dbh, len));
		if (!o)
			return NULL;
		while (bckt->coll_next && !(bckt->flags & TDB_HTRIE_VRFREED))
			bckt = TDB_HTRIE_BUCKET_NEXT(dbh, bckt);
		bckt->coll_next = TDB_HTRIE_O2DI(o);
		return tdb_htrie_create_rec(dbh, o, key, data, *len, 1);
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
		TDB_ERR("Cannot burst node=%p and bckt=%p for key %#lx\n",
			node, bckt, key);
		return NULL;
	}
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

	return TDB_HTRIE_PTR(dbh, o);
}

/*
 * ------------------------------------------------------------------------
 *	Testing routines
 * ------------------------------------------------------------------------
 */
#define TDB_VSF_SZ		(2UL * 1024 * 1024 * 1024)
#define TDB_FSF_SZ		(16UL * 1024 * 1024)

#if 0
#include "urls.h"
#else
typedef struct {
	char	*body;
	size_t	len;
} TestUrl;

static TestUrl urls[] = {
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
	{NULL, 0}
};
#endif

static unsigned int ints[] = {
	0, 324, 2324345, 10, 4000111222, 2111222999, 2, 3, 4, 5, 6, 7, 100,
	3999888999, 4222999888, 2500600800, 65535, 200, 2000, 20000, 200000,
	2000000, 20000000, 200000000, 2000000000, 2000000001, 10, 11, 12, 13,
	4000111222, 3111222999, 4294967290, 32424, 9986, 7344, 23354, 6876437
};

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

void
tdb_htrie_test_varsz(const char *fname)
{
	char *addr;
	int r __attribute__((unused));
	TestUrl *u;
	TdbHdr *dbh;
	struct timeval tv0, tv1;

	printf("\n----------- Variable size records test -------------\n");

	addr = tdb_htrie_open(fname, TDB_VSF_SZ);

	dbh = tdb_htrie_init(addr, TDB_VSF_SZ, 0);
	if (!dbh)
		TDB_ERR("cannot initialize htrie for urls");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	/* Store records. */
	for (u = urls; u->body; ++u) {
		unsigned long k = tdb_hash_calc(u->body, u->len);
		size_t copied = 0, to_copy = u->len;
		char *p;
		TdbRec *rec;

		printf("insert [%.40s...] (len=%lu)\n", u->body, u->len);
		fflush(NULL);

		rec = tdb_htrie_insert(dbh, k, u->body, &to_copy);
		assert((u->len && rec) || (!u->len && !rec));

		copied += to_copy;
		to_copy = u->len - to_copy;

		while (copied != u->len) {
			p = tdb_htrie_extend_rec(dbh, rec, &to_copy);
			assert(p);

			memcpy(p, u->body + copied, to_copy);

			copied += to_copy;
			to_copy = u->len - to_copy;
		}
	}

	/* Read records. */
	for (u = urls; u->body; ++u) {
		unsigned long k = tdb_hash_calc(u->body, u->len);
		TdbBucket *b;

		printf("results for [%.40s...] lookup:\n", u->body);
		fflush(NULL);

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
				if (tdb_live_vsrec(r)) {
					printf("\t[%.64s...] key=%#lx"
					       " bckt=%p\n", r->data,
					       tdb_hash_calc(r->data, r->len),
					       b);
					fflush(NULL);
				}
			}
		} else {
			BUG();
		}
	}

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
	char *addr;
	unsigned int *i;
	TdbHdr *dbh;
	struct timeval tv0, tv1;

	printf("\n----------- Fixed size records test -------------\n");

	addr = tdb_htrie_open(fname, TDB_FSF_SZ);

	dbh = tdb_htrie_init(addr, TDB_FSF_SZ, sizeof(ints[0]));
	if (!dbh)
		TDB_ERR("cannot initialize htrie for ints");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	/* Store records. */
	for (i = ints; i < ints + sizeof(ints) / sizeof(ints[0]); ++i) {
		size_t copied = sizeof(*i);
		TdbRec *rec __attribute__((unused));

		printf("insert int %u\n", *i);
		fflush(NULL);

		rec = tdb_htrie_insert(dbh, *i, i, &copied);
		assert(rec && copied == sizeof(*i));
	}

	/* Read records. */
	for (i = ints; i < ints + sizeof(ints) / sizeof(ints[0]); ++i) {
		TdbBucket *b;

		printf("results for int %u lookup:\n", *i);
		fflush(NULL);

		b = tdb_htrie_lookup(dbh, *i);
		if (!b) {
			fprintf(stderr, "ERROR: can't find int %u\n", *i);
			fflush(NULL);
			continue;
		}

		if (TDB_HTRIE_VARLENRECS(dbh)) {
			BUG();
		} else {
			TdbFRec *r;
			TDB_HTRIE_FOREACH_REC(dbh, b, r) {
				if (tdb_live_fsrec(dbh, r)) {
					printf("\t(%#x) %u bckt=%p\n",
					       *(unsigned int *)r->data,
					       *(unsigned int *)r->data, b);
					fflush(NULL);
				}
			}
		}
	}

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie ints test: time=%lums\n",
		tv_to_ms(&tv1) - tv_to_ms(&tv0));

	tdb_htrie_pure_close(addr, TDB_FSF_SZ);
}

void
tdb_htrie_test(const char *vsf, const char *fsf)
{
	tdb_htrie_test_varsz(vsf);
	tdb_htrie_test_fixsz(fsf);
}

int
main(int argc, char *argv[])
{
	unsigned int eax, ebx, ecx = 0, edx;
	TestUrl *u;
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

	/* Load urls pages and precompute string lengths (with terminator). */
	for (u = urls; u->body; ++u)
		u->len = strlen(u->body) + 1;

	hash_calc_benchmark();

	tdb_htrie_test(argv[1], argv[2]);

	return 0;
}
