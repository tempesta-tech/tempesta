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
 * - freeing interface for eviction thread
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
//#define ____cacheline_aligned   __attribute__((aligned(TDB_CL_SZ)))

#define likely(e)	__builtin_expect((e), 1)
#define unlikely(e)	__builtin_expect((e), 0)

#define BUG_ON(c)	assert(!(c))
#define BUG()		abort()

#define ERR(m)								\
do {									\
	perror("Error: " m);						\
	exit(1);							\
} while (0)

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
#define TDB_MFSZ		(2UL * 1024 * 1024 * 1024)
#define TDB_MAP_ADDR		0x600000000000
#define TDB_BLK_SZ		PAGE_SIZE
#define TDB_BLK_MASK		(~(TDB_BLK_SZ - 1))
#define TDB_EXT_BITS		21
#define TDB_EXT_SZ		(1 << TDB_EXT_BITS)
#define TDB_EXT_MASK		(~(TDB_EXT_SZ - 1))
#define TDB_EXT_BMP_2L		(TDB_MFSZ / TDB_EXT_SZ / BITS_PER_LONG)
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
#define TDB_HTRIE_ROOT(h)	(TdbHtrieNode *)((char *)((h) + 1)	\
						 + sizeof(TdbExt))
/* Convert internal offsets to system pointer. */
#define TDB_HTRIE_PTR(h, o)	(void *)((char *)(h) + (o))
/* Get internal offset from a pointer. */
#define TDB_HTRIE_OFF(h, p)	((char *)(p) - (char *)(h))
/* Get index and data block indexes by byte offset and vise versa. */
#define TDB_HTRIE_O2DI(o)	((o) / TDB_HTRIE_MINDREC)
#define TDB_HTRIE_O2II(o)	((o) / TDB_HTRIE_NODE_SZ)
#define TDB_HTRIE_DI2O(i)	((i) * TDB_HTRIE_MINDREC)
/* Base offset of extent containing pointer @p. */
#define TDB_EXT_BASE(h, p)	TDB_EXT_O(TDB_HTRIE_OFF(h, p))

/**
 * Tempesta DB file descriptor.
 *
 * We store independent records in at least cache line size data blocks
 * to avoid false sharing.
 *
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
	unsigned long	i_wcl;
	unsigned long	d_wcl;
	unsigned int	rec_len;
	unsigned short	i_wm;
	unsigned short	d_wm;
	unsigned char	_padding[8 * 4];
	unsigned long	ext_bmp[TDB_EXT_BMP_2L];
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
#define TDB_HTRIE_RECLEN(h, r)	(TDB_HTRIE_VARLENRECS(h)		\
				 ? TDB_HTRIE_VRLEN(r) + sizeof(TdbVRec)	\
				 : (h)->rec_len + sizeof(TdbFRec))
#define TDB_HTRIE_BUCKET_1ST(b)	((void *)((b) + 1))
#define TDB_HTRIE_BUCKET_KEY(b)	(*(unsigned long *)TDB_HTRIE_BUCKET_1ST(b))
#define TDB_HTRIE_BUCKET_NEXT(h, b)					\
({									\
	TDB_HTRIE_PTR(h, TDB_HTRIE_DI2O((b)->coll_next));		\
 })

static inline TdbExt *
tdb_ext(TdbHdr *dbh, void *ptr)
{
	unsigned long e = TDB_EXT_O(ptr);

	if (e == (unsigned long)dbh)
		e += sizeof(dbh); /* first extent */
	return (TdbExt *)e;
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
tdb_init_mapping(void *p, unsigned int rec_len)
{
	TdbHdr *hdr = (TdbHdr *)p;

	/* Use variable-size records for large stored data. */
	if (rec_len > TDB_BLK_SZ / 2)
		return NULL;

	memset(hdr, 0, TDB_MFSZ);

	hdr->magic = TDB_MAGIC;
	hdr->rec_len = TDB_HTRIE_RALIGN(rec_len);
	hdr->i_wcl = sizeof(TdbHdr) + sizeof(TdbExt);
	/* Data grows from the last extent to begin. */
	hdr->d_wm = TDB_MFSZ / TDB_EXT_SZ - 1;
	hdr->d_wcl = TDB_HTRIE_DALIGN(hdr->d_wm * TDB_EXT_SZ + sizeof(TdbExt));

	/* Zero first index node, just after the headers. */
	memset((char *)hdr + hdr->i_wcl, 0, TDB_HTRIE_NODE_SZ);

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
	memset(rec, 0, dbh->rec_len);
}

static inline int
tdb_live_fsrec(TdbHdr *dbh, TdbFRec *rec)
{
	int i;

	for (i = 0; i < dbh->rec_len / sizeof(long); ++i)
		if (((unsigned long *)rec)[i])
			return 1;
	return 0;
}

static inline void
tdb_free_vsrec(TdbVRec *rec)
{
	rec->len |= TDB_HTRIE_VRFREED;
}

static inline int
tdb_live_vsrec(TdbVRec *rec)
{
	return !(rec->len & TDB_HTRIE_VRFREED);
}

/**
 * @return start of available room (offset in bytes) at allocated block.
 */
static inline long
tdb_alloc_blk(TdbHdr *dbh, TdbExt *e)
{
	int i, r;

	for (i = 0; i < TDB_BLK_BMP_2L; ++i) {
		if (!(e->b_bmp[i] ^ ~0UL))
			continue;

		r = ffz(e->b_bmp[i]);
		set_bit(r, &e->b_bmp[i]);
		r = TDB_EXT_BASE(dbh, e) + r * TDB_BLK_SZ;
		if (!r) {
			r += sizeof(*e);
			if (TDB_EXT_O(e) == TDB_EXT_O(dbh))
				r += sizeof(*dbh);
		}
		return r;
	}

	return -1;
}

static unsigned long
tdb_alloc_index_blk(TdbHdr *dbh)
{
	unsigned long rptr;
	TdbExt *e = tdb_ext(dbh, TDB_HTRIE_PTR(dbh, dbh->i_wcl));

	while (1) {
		rptr = tdb_alloc_blk(dbh, e);
		if (rptr < 0) {
			if ((unsigned long)e + TDB_EXT_SZ * 2 > dbh->d_wm)
				return 0;
			e = (TdbExt *)((char *)e + TDB_EXT_SZ);
			set_bit(TDB_EXT_ID(TDB_EXT_BASE(dbh, e)), dbh->ext_bmp);
			continue;
		}
		else if (rptr > dbh->i_wcl) {
			dbh->i_wcl = rptr;
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
		if (rptr < 0) {
			if ((unsigned long)e <  dbh->i_wm + TDB_EXT_SZ * 2)
				return 0;
			e = (TdbExt *)((char *)e - TDB_EXT_SZ);
			set_bit(TDB_EXT_ID(TDB_EXT_BASE(dbh, e)), dbh->ext_bmp);
			continue;
		}
		else if (rptr > dbh->d_wcl) {
			dbh->d_wcl = rptr;
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
		      > TDB_MFSZ + dbh->d_wm * TDB_EXT_SZ))
		return 0; /* not enough space */

	if (len <= TDB_BLK_SZ
	    && TDB_BLK_ID(rptr + len) == TDB_BLK_ID(rptr))
	{
		/* Allocate data in the same page. */
		TdbExt *e = tdb_ext(dbh, TDB_HTRIE_PTR(dbh, rptr));
		if (unlikely(rptr == (unsigned long)e + sizeof(TdbExt)))
			/* First allocation, set the page bit. */
			set_bit(TDB_BLK_ID(rptr), e->b_bmp);
		dbh->d_wcl += len;
		return rptr;
	}

	/* Use a new page and/or extent for the data. */
	return tdb_alloc_data_blk(dbh);
}

/**
 * Allocates a new index block.
 * @return byte offset of the block.
 */
static unsigned long
tdb_alloc_index(TdbHdr *dbh)
{
	unsigned long rptr = dbh->i_wcl;

	/* Try current page. */
	if (likely(TDB_BLK_ID(rptr + sizeof(TdbHtrieNode))
		   <= TDB_BLK_ID(rptr)))
	{
		TdbExt *e = tdb_ext(dbh, TDB_HTRIE_PTR(dbh, rptr));
		if (unlikely(rptr == (unsigned long)e + sizeof(TdbExt)))
			/* First allocation, set the page bit. */
			set_bit(TDB_BLK_ID(rptr), e->b_bmp);
		dbh->i_wcl += sizeof(TdbHtrieNode);
		return rptr;
	}

	/* Use a new page and/or extent for the data. */
	return tdb_alloc_index_blk(dbh);
}

TdbHdr *
tdb_htrie_init(void *p, unsigned int rec_len)
{
	TdbHdr *hdr = (TdbHdr *)p;

	if (hdr->magic != TDB_MAGIC)
		hdr = tdb_init_mapping(p, rec_len);

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
	unsigned long n, used;
	void *b = TDB_HTRIE_BUCKET_1ST(bckt);

	for ( ; bckt; bckt = TDB_HTRIE_BUCKET_NEXT(dbh, bckt)) {
		if (TDB_HTRIE_VARLENRECS(dbh)) {
			TdbVRec *r = (TdbVRec *)b;
			while (1) {
				used = (unsigned long)r - (unsigned long)bckt;
				if (len + sizeof(*r) + used > TDB_HTRIE_MINDREC)
					break; /* end of records */
				n = TDB_HTRIE_VRLEN(r);
				if (!n)
					/* No record, empty space. */
					return TDB_HTRIE_OFF(dbh, r);
				if (!tdb_live_vsrec(r) && len <= n)
					/* Freed record - reuse. */
					return TDB_HTRIE_OFF(dbh, r);
				n += (unsigned long)(r + 1);
				r = (TdbVRec *)TDB_HTRIE_RALIGN(n);
			}
		} else {
			TdbFRec *r = (TdbFRec *)b;
			BUG_ON(len != dbh->rec_len);
			while (1) {
				used = (unsigned long)r - (unsigned long)bckt;
				if (len + sizeof(*r) + used > TDB_HTRIE_MINDREC)
					break; /* end of records */
				if (!tdb_live_fsrec(dbh, r))
					/* Freed record - reuse. */
					return TDB_HTRIE_OFF(dbh, r);
				n = len + (unsigned long)(r + 1);
				r = (TdbFRec *)TDB_HTRIE_RALIGN(n);
			}
		}
	}

	return 0;
}

/**
 * Grow the tree.
 *
 * @node	- current index node at which least significant bits collision
 * 		  happened.
 */
static int
tdb_htrie_burst(TdbHdr *dbh, TdbHtrieNode *node, TdbBucket *bckt,
		unsigned long key, int bits)
{
	int i;
	unsigned int new_in_idx;
	unsigned long n;
	char *freeing_ptr = NULL;
	TdbBucket *b = TDB_HTRIE_BUCKET_1ST(bckt);
	TdbHtrieNode *new_in;
	struct {
		unsigned long	b;
		unsigned char	off;
	} new_dblks[TDB_HTRIE_FANOUT] = {{0, 0}};

	BUG_ON(bits >= TDB_HTRIE_BITS);

	n = tdb_alloc_index(dbh);
	if (!n)
		return -ENOMEM;
	new_in = TDB_HTRIE_PTR(dbh, n);
	new_in_idx = TDB_HTRIE_O2II(n);

#define MOVE_RECORDS(Type, length, live)				\
do {									\
	Type *r = (Type *)b;						\
	unsigned long copied, k;					\
	/* Always leave first record in the same data block. */		\
	n = (unsigned long)(r + 1) + length;				\
	r = (Type *)TDB_HTRIE_RALIGN(n);				\
	k = TDB_HTRIE_IDX(r->key, bits);				\
	new_in->shifts[k] = TDB_HTRIE_O2DI(TDB_HTRIE_OFF(dbh, bckt));	\
	while (1) {							\
		copied = (unsigned long)r - (unsigned long)bckt;	\
		if (sizeof(*r) + copied >= TDB_HTRIE_MINDREC)		\
			break; /* end of records */			\
		n = length;						\
		/* Small record cannot exceed TDB_HTRIE_MINDREC. */	\
		BUG_ON(copied + sizeof(*r) + n >= TDB_HTRIE_MINDREC);	\
		if (n && live) {					\
			k = TDB_HTRIE_IDX(r->key, bits);		\
			if (!new_dblks[k].b) {				\
				new_dblks[k].b = tdb_alloc_data(dbh, 0); \
				if (!new_dblks[k].b)			\
					goto err_cleanup;		\
				b = TDB_HTRIE_PTR(dbh, new_dblks[k].b);	\
				tdb_htrie_init_bucket(b);		\
				memmove(b + 1, r, n + sizeof(*r));	\
				new_dblks[k].off = sizeof(*b)		\
						   + TDB_HTRIE_RALIGN(n); \
				new_in->shifts[k] = new_dblks[k].b;	\
			} else {					\
				memmove(TDB_HTRIE_PTR(dbh, new_dblks[k].b \
							   + new_dblks[k].off),\
				       r, n + sizeof(*r));		\
				new_dblks[k].off += TDB_HTRIE_RALIGN(n); \
			}						\
		}							\
		if (!freeing_ptr)					\
			freeing_ptr = (char *)r;			\
		n += (unsigned long)(r + 1);				\
		r = (Type *)TDB_HTRIE_RALIGN(n);			\
	}								\
} while (0)

	if (TDB_HTRIE_VARLENRECS(dbh))
		MOVE_RECORDS(TdbVRec, TDB_HTRIE_VRLEN(r), tdb_live_vsrec(r));
	else
		MOVE_RECORDS(TdbFRec, dbh->rec_len, tdb_live_fsrec(dbh, r));

#undef MOVE_RECORDS

	/* Link the new index node with @node. */
	node->shifts[TDB_HTRIE_IDX(key, bits + TDB_HTRIE_BITS)] = new_in_idx;

	/* Now we can safely remove all copied records. */
	if (freeing_ptr)
		memset(freeing_ptr, 0,
		       (char *)bckt + TDB_HTRIE_MINDREC - freeing_ptr);

	return 0;
err_cleanup:
	for (i = 0; i < TDB_HTRIE_FANOUT; ++i) {
		bckt = TDB_HTRIE_PTR(dbh, new_dblks[i].b);
		if (bckt)
			tdb_free_data_blk(bckt);
	}
	tdb_free_index_blk(new_in);
	return -ENOMEM;
}

/**
 * Descend the the tree starting at @node.
 *
 * @retrurn byte offset of data (w/o TDB_HTRIE_DBIT bit) on success
 * or 0 if key @k was not found.
 * When function exits @node stores the last index node.
 * @bits - number of bits (from less significant to most significant) from
 * which we should start descending and the stored number of resolved bits.
 *
 * Least significant bits in our hash function have most entropy,
 * so we resolve the key from least significant bits to most significant.
 */
static unsigned long
tdb_htrie_descend(TdbHdr *dbh, TdbHtrieNode **node, unsigned long k, int *bits)
{
	while (1) {
		unsigned long o;

		BUG_ON(TDB_HTRIE_RESOLVED(*bits));

		o = (*node)->shifts[TDB_HTRIE_IDX(k, *bits)];

		if (o & TDB_HTRIE_DBIT) {
			/* We're at a data pointer - resolve it. */
			*bits += TDB_HTRIE_BITS;
			o ^= TDB_HTRIE_DBIT;
			BUG_ON(!o);
			return TDB_HTRIE_O2DI(o);
		} else {
			if (!o)
				return 0; /* cannot descend deeper */
			*node = TDB_HTRIE_PTR(dbh, o);
			*bits += TDB_HTRIE_BITS;
		}
	}
}

static TdbRec *
tdb_htrie_create_rec(TdbHdr *dbh, unsigned long off, unsigned long key,
		     char *data, size_t len, int init_bucket)
{
	char *ptr = TDB_HTRIE_PTR(dbh, off);
	TdbRec *r;

	if (init_bucket) {
		tdb_htrie_init_bucket((TdbBucket *)ptr);
		ptr += sizeof(TdbBucket);
	}

	r = (TdbRec *)ptr;
	r->key = key;
	if (TDB_HTRIE_VARLENRECS(dbh)) {
		TdbVRec *vr = (TdbVRec *)r;
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
tdb_htrie_insert(TdbHdr *dbh, unsigned long key, char *data, size_t *len)
{
	int bits = 0;
	unsigned long o;
	TdbBucket *bckt;
	TdbRec *rec;
	TdbHtrieNode *node = TDB_HTRIE_ROOT(dbh);
	
retry:
	o = tdb_htrie_descend(dbh, &node, key, &bits);
	if (!o) {
		/* Create a new node. */
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
		size_t n = TDB_HTRIE_RALIGN(len);
		o = tdb_htrie_smallrec_link(dbh, n, bckt);
		if (o)
			return tdb_htrie_create_rec(dbh, o, key, data, *len, 0);
	}

	if (TDB_HTRIE_RESOLVED(bits)) {
		/*
		 * Hash full key collision -
		 * add new record to collision chain.
		 */
		size_t rec_len = tdb_full_rec_len(dbh, len);
		BUG_ON(TDB_HTRIE_BUCKET_KEY(bckt) != key);
		o = tdb_alloc_data(dbh, rec_len);
		if (!o)
			return NULL;
		while (!(bckt->flags & TDB_HTRIE_VRFREED))
			bckt = TDB_HTRIE_BUCKET_NEXT(dbh, bckt);
		bckt->coll_next = TDB_HTRIE_O2DI(o);
		return tdb_htrie_create_rec(dbh, o, key, data, *len, 1);
	}

	/*
	 * Just least significant bits collision.
	 * But there is no room. Burst the node.
	 *
	 * We should never see collision chains at this point.
	 */
	BUG_ON(bckt->coll_next);
	if (tdb_htrie_burst(dbh, node, bckt, key, bits))
		return NULL;
	/*
	 * Try to resolve the key for the new path starting
	 * from current index node.
	 */
	bits += TDB_HTRIE_BITS;
	goto retry;
}

TdbRec *
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
	{"http://www.amazon.com/exec/obidos/redirect?link_code=ur2&amp;camp=1789&amp;tag=mactechmagazi-20&amp;creative=9325&amp;path=external-search\%3Fsearch-type=ss\%26keyword=ipod\%26index=pc-hardware", 0},
	{"http://store.mactech.com/mactech/riskfree/offer.html?FROM=MTRF", 0},
	{"http://www.google.com/", 0},
	{"http://www.google.com/logos/Logo_25wht.gif", 0},
	{"http://www.xplain.com", 0},
	{NULL, 0}
};
#endif

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
	int r, i, acc = 0;
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

/**
 * All resources are closed on the program exit.
 */
void *
tdb_htrie_open(const char *fname)
{
	int fd;
	void *p;
	struct stat sb;

	if (stat(fname, &sb) < 0) {
		printf("filesize: %ld\n", sb.st_size);
		ERR("no file");
	}

	if ((fd = open(fname, O_RDWR)) < 0)
        	ERR("open failure");

	if (sb.st_size != TDB_MFSZ)
		if (fallocate(fd, 0, 0, TDB_MFSZ))
			ERR("fallocate failure");

	/* Use MAP_SHARED to carry changes to underlying file. */
	p = mmap((void *)TDB_MAP_ADDR, TDB_MFSZ, PROT_READ | PROT_WRITE,
		 MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
		ERR("cannot mmap the file");
	printf("maped to %p\n", p);

	if (mlock(p, TDB_MFSZ))
		ERR("mlock failure");

	return p;
}

void
tdb_htrie_test(const char *fname)
{
	char *p;
	int r;
	TestUrl *u;
	TdbHdr *dbh;
	struct timeval tv0, tv1;

	p = tdb_htrie_open(fname);

	dbh = tdb_htrie_init(p, 0);
	if (!dbh)
		ERR("cannot initialize htrie");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	/* Store records. */
	for (u = urls; u->body; ++u) {
		unsigned long k = tdb_hash_calc(u->body, u->len);
		size_t copied = 0, to_copy = u->len;
		TdbRec *rec;

		rec = tdb_htrie_insert(dbh, k, u->body, &to_copy);
		assert(rec);

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
		TdbVRec *r;

		r = (TdbVRec *)tdb_htrie_lookup(dbh, k);
		if (!r)
			fprintf(stderr, "can't find URL [%.20s...]\n", u->body);
		else
			printf("found [%.20s...] for [%.20s...]\n",
			       r->data, u->body);
	}

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie test: time=%lums\n", tv_to_ms(&tv1) - tv_to_ms(&tv0));
}

int
main(int argc, char *argv[])
{
	unsigned int eax, ebx, ecx = 0, edx;
	TestUrl *u;
	struct rlimit rlim = { TDB_MFSZ, TDB_MFSZ * 2};
	
	if (argc < 2) {
		printf("using: %s <file name>\n", argv[0]);
		return 1;
	}

	/* Don't forget to set appropriate system hard limit. */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim))
		ERR("cannot set RLIMIT_MEMLOCK");

	__get_cpuid(1, &eax, &ebx, &ecx, &edx);
	   
	if (!(ecx & bit_SSE4_2))
		ERR("SSE4.2 is not supported");

	/* Load urls pages and precompute string lengths. */
	for (u = urls; u->body; ++u)
		u->len = strlen(u->body);

	hash_calc_benchmark();

	tdb_htrie_test(argv[1]);

	return 0;
}
