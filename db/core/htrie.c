/**
 *		Tempesta DB
 *
 * Index and memory management for cache conscious Burst Hash Trie.
 * Operations over the index tree are lock-free while buckets with collision
 * chains of small records are protected by RW-spinlock.
 *
 * Data modification is designed to run in softirq context, so the trie uses
 * SIMD instructions to speedup memory operations. Do not use the DML operations
 * in sleepable contexts, such as configuration. Only the trie initialization
 * and shutdown are performed in process context.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#include <linux/bitops.h>
#include <linux/slab.h>
#include <asm/sync_bitops.h>
#include <linux/error-injection.h>

#include "lib/str.h"
#include "lib/fault_injection_alloc.h"
#include "htrie.h"

#define TDB_MAX_PCP_SZ  (TDB_EXT_SZ / PAGE_SIZE) /* Store one extent per cpu. */
#define TDB_MAGIC	0x434947414D424454UL /* "TDBMAGIC" */
#define TDB_BLK_SZ	PAGE_SIZE
#define TDB_BLK_SHIFT	PAGE_SHIFT
#define TDB_BLK_MASK	(~(TDB_BLK_SZ - 1))

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

#define TDB_HTRIE_FOREACH_REC_SMALL(d, b, fr, r, t)			\
	for (r = TDB_HTRIE_BCKT_1ST_REC(dbh, b), fr = r;		\
	     r && (char *)r - (char *)fr + sizeof(t) <= TDB_HTRIE_MINDREC \
	     && (char *)r - (char *)fr + TDB_HTRIE_RECLEN(d, r)		\
	     <= TDB_HTRIE_MINDREC;					\
	     r = (typeof(r))((char *)r + TDB_HTRIE_RECLEN(d, r)))

/**
 * Unlocked and simplified version of tdb_htrie_bscan_for_rec() for
 * small records only.
 */
#define TDB_HTRIE_FOREACH_REC_UNLOCKED(d, b, fr, r, t)			\
	for ( ; b; b = TDB_HTRIE_BUCKET_NEXT(d, b))			\
		TDB_HTRIE_FOREACH_REC_SMALL(d, b, fr, r, t)


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

/**
 * Reserve the last block of extent for reference table.
 */
static void
tdb_reserve_reftbl(TdbExt *e)
{
	set_bit(BITS_PER_LONG - 1, &(e->b_bmp[TDB_BLK_BMP_2L - 1]));
}

static atomic_t*
tdb_get_reftbl(TdbHdr *dbh, TdbExt *e)
{
	return TDB_PTR(dbh, (TDB_EXT_BASE(dbh, e) + TDB_EXT_SZ) - TDB_BLK_SZ);
}

/**
 * Add block to global freelist.
 */
static void
tdb_ga_freelist_push(TdbHdr *dbh, unsigned long ptr, unsigned long *page_addr)
{
	spin_lock_bh(&dbh->gfl_lock);
	if (!dbh->ga_freelist) {
		dbh->ga_freelist = ptr;
		*page_addr = 0;
	} else {
		*page_addr = dbh->ga_freelist;
		dbh->ga_freelist = ptr;
	}
	spin_unlock_bh(&dbh->gfl_lock);
}

/**
 * Add block to per-CPU or global freelist.
 */
static void
tdb_freelist_push(TdbHdr *dbh, unsigned long ptr)
{
	unsigned long *page_addr = TDB_PTR(dbh, ptr);
	TdbPerCpu *pcpu = this_cpu_ptr(dbh->pcpu);

	if (!pcpu->freelist) {
		pcpu->freelist = ptr;
		pcpu->fl_size = 1;
		*page_addr = 0;
		return;
	}

	/* If per-cpu list is full, push block to global list. */
	if (pcpu->fl_size >= TDB_MAX_PCP_SZ) {
		tdb_ga_freelist_push(dbh, ptr, page_addr);
	} else {
		*page_addr = pcpu->freelist;
		pcpu->freelist = ptr;
		pcpu->fl_size++;
	}
}

static void
tdb_get_blk(TdbHdr *dbh, unsigned long ptr)
{
	TdbExt *e = tdb_ext(dbh, TDB_PTR(dbh, ptr));
	atomic_t *reftbl = tdb_get_reftbl(dbh, e);
	unsigned int blkoff = TDB_BLK_ID(ptr & TDB_BLK_MASK) >> TDB_BLK_SHIFT;
	atomic_t *refcnt = reftbl + blkoff;

	BUG_ON((void *) refcnt > TDB_PTR(dbh, (TDB_EXT_BASE(dbh, e) + TDB_EXT_SZ)));
	atomic_inc(refcnt);
}

static void
tdb_put_blk(TdbHdr *dbh, unsigned long ptr)
{
	TdbExt *e = tdb_ext(dbh, TDB_PTR(dbh, ptr));
	atomic_t *reftbl = tdb_get_reftbl(dbh, e);
	unsigned int blkoff = TDB_BLK_ID(ptr & TDB_BLK_MASK) >> TDB_BLK_SHIFT;
	atomic_t *refcnt = reftbl + blkoff;
	int pgref;

	pgref = atomic_dec_return(refcnt);
	if (!pgref)
		tdb_freelist_push(dbh, ptr & TDB_BLK_MASK);

	BUG_ON(pgref < 0);
}

/* Zero key for fixed size record indicates that record is freed. */
static inline void
tdb_free_fsrec(TdbHdr *dbh, TdbFRec *rec)
{
	rec->key = 0;
	tdb_put_blk(dbh, TDB_OFF(dbh, rec));
}

static inline void
tdb_free_vsrec(TdbHdr *dbh, TdbVRec *rec)
{
	tdb_put_blk(dbh, TDB_OFF(dbh, rec));
}

static void
tdb_htrie_free_rec(TdbHdr *dbh, TdbRec *rec)
{
	if (dbh->before_free)
		dbh->before_free(rec);

	if (TDB_HTRIE_VARLENRECS(dbh)) {
		TdbVRec *next, *curr = (TdbVRec *)rec;

		while (curr) {
			next = curr->chunk_next
				? TDB_PTR(dbh, TDB_DI2O(curr->chunk_next))
				: 0;

			tdb_free_vsrec(dbh, curr);
			curr = next;
		}
	} else {
		tdb_free_fsrec(dbh, (TdbFRec *)rec);
	}
}

void
tdb_htrie_get_rec(TdbRec *rec)
{
	atomic_inc(&rec->refcnt);
}

void
tdb_htrie_put_rec(TdbHdr *dbh, TdbRec *rec)
{
	int refcnt = atomic_dec_return(&rec->refcnt);

	BUG_ON(refcnt < 0);
	if (!refcnt)
		tdb_htrie_free_rec(dbh, rec);
}

/* Call only under lock. */
static void
tdb_rec_set_remove(TdbRec *rec)
{
	rec->flags |= TDB_HTRIE_REC_REMOVED_BIT;
}

/* Call only under lock. */
static bool
tdb_rec_is_removed(TdbRec *rec)
{
	return rec->flags & TDB_HTRIE_REC_REMOVED_BIT;
}

static TdbHdr *
tdb_init_mapping(void *p, size_t db_size, unsigned int rec_len)
{
	int b, hdr_sz;
	TdbHdr *hdr = (TdbHdr *)p;

	if (db_size > TDB_MAX_DB_SZ) {
		TDB_ERR("too large database size (%lu)", db_size);
		return NULL;
	}
	/* Use variable-size records for large data to store. */
	if (rec_len > TDB_BLK_SZ / 2) {
		TDB_ERR("too large record length (%u)\n", rec_len);
		return NULL;
	}

	/* Zero whole area. */
	memset(hdr, 0, db_size);

	hdr->magic = TDB_MAGIC;
	hdr->dbsz = db_size;
	hdr->rec_len = rec_len;

	/* Set next block to just after block with root index node. */
	hdr_sz = TDB_BLK_ALIGN(TDB_HDR_SZ(hdr) + sizeof(TdbExt)
			       + sizeof(TdbHtrieNode));
	atomic64_set(&hdr->nwb, hdr_sz);

	/* Set first (current) extents and header blocks as used. */
	set_bit(0, hdr->ext_bmp);
	for (b = 0; b < hdr_sz / TDB_BLK_SZ; b++)
		set_bit(b, tdb_ext(hdr, hdr)->b_bmp);

	/* Get page that holds tdb header. This page must not be freed. */
	tdb_get_blk(hdr, TDB_EXT_BASE(hdr, tdb_ext(hdr, hdr)));
	tdb_reserve_reftbl(tdb_ext(hdr, hdr));

	return hdr;
}

bool
tdb_rec_is_complete(void *rec)
{
	return ((TdbRec *)rec)->flags & TDB_HTRIE_COMPLETE_BIT;
}

/**
 * Intended to be called as complete of insertion, only in the same thread.
 *
 * TODO: Incomplete records can be used as base for implementation #500 issue.
 */
void
tdb_rec_mark_complete(void *rec)
{
	BUG_ON(!rec);

	((TdbRec *)rec)->flags |= TDB_HTRIE_COMPLETE_BIT;
}

static inline void
tdb_free_index_blk(TdbHtrieNode *node)
{
	/* Just zero the block and leave it for garbage collector. */
	bzero_fast(node, sizeof(*node));
}

/**
 * Allocates a free block (system page) in extent @e.
 * @return start of available room (offset in bytes) at the block.
 */
static inline unsigned long
__tdb_alloc_blk_ext(TdbHdr *dbh, TdbExt *e)
{
	int i = 0;
	unsigned long r;

repeat:
	r = e->b_bmp[i];

	if (!(r ^ ~0UL)) {
		if (++i == TDB_BLK_BMP_2L)
			return 0;
		goto repeat;
	}

	r = ffz(r);

	if (sync_test_and_set_bit(r, &e->b_bmp[i]))
		goto repeat; /* race conflict, retry */

	if (unlikely(!i && !r)) {
		/* First block in the extent. */
		tdb_reserve_reftbl(e);
		/* Get block that holds extent header. */
		tdb_get_blk(dbh, TDB_EXT_BASE(dbh, e));
		r = sizeof(*e);
		if (unlikely(TDB_EXT_O(e) == TDB_EXT_O(dbh)))
			/* First extent in the database. */
			return r + TDB_HDR_SZ(dbh);
		return r + TDB_EXT_BASE(dbh, e);
	}

	return TDB_EXT_BASE(dbh, e)
	       + (i * BITS_PER_LONG + r) * TDB_BLK_SZ;
}

static unsigned long
tdb_alloc_blk_pcp_freelist(TdbHdr *dbh)
{
	unsigned long rptr, *next;
	TdbPerCpu *pcpu = this_cpu_ptr(dbh->pcpu);

	rptr = pcpu->freelist;
	if (!rptr)
		return 0;

	next = TDB_PTR(dbh, rptr);
	pcpu->freelist = *next;
	pcpu->fl_size--;
	tdb_get_blk(dbh, rptr);

	return rptr;
}

static unsigned long
tdb_alloc_blk_global_freelist(TdbHdr *dbh)
{
	unsigned long rptr = 0, *next;

	spin_lock_bh(&dbh->gfl_lock);
	rptr = dbh->ga_freelist;
	if (!rptr) {
		spin_unlock_bh(&dbh->gfl_lock);
		return 0;
	}

	next = TDB_PTR(dbh, rptr);
	dbh->ga_freelist = *next;
	spin_unlock_bh(&dbh->gfl_lock);
	tdb_get_blk(dbh, rptr);

	return rptr;
}

static unsigned long
tdb_alloc_blk(TdbHdr *dbh)
{
	TdbExt *e;
	long g_nwb, rptr, next_blk;

	rptr = tdb_alloc_blk_pcp_freelist(dbh);
	if (rptr)
		return rptr;

retry:
	/*
	 * Use global freelist only when block allocator is exhausted.
	 * Do so to quickly fill per-cpu lists and global freelist.
	 */
	if (dbh->oom) {
		rptr = tdb_alloc_blk_global_freelist(dbh);
		if (rptr)
			return rptr;

		TDB_ERR("out of free space\n");
		return 0;
	}

	g_nwb = atomic64_read(&dbh->nwb);
	e = tdb_ext(dbh, TDB_PTR(dbh, g_nwb));

	if (likely(g_nwb & ~TDB_EXT_MASK)) {
		/*
		 * Current extent was already got.
		 * Probably we can allocate some memory in this extent.
		 */
		rptr = __tdb_alloc_blk_ext(dbh, e);
		if (likely(rptr))
			goto allocated;
		/*
		 * No way, there is no room in current extent -
		 * update current pointer or try the next extent.
		 *
		 * TODO we recheck dbh->nwb just in assumption
		 * that eviction/freeing thread moved it back.
		 */
		if (unlikely(g_nwb != atomic64_read(&dbh->nwb)))
			goto retry;
		e = TDB_PTR(dbh, TDB_EXT_BASE(dbh, e) + TDB_EXT_SZ);
	}

	/*
	 * The new extent should be used.
	 * Whole extent shouldn't be fully utilized by concurrent contexts
	 * while we're in the function, so we expect that it will satisfy
	 * our allocation request.
	 */
	if (unlikely(TDB_HTRIE_OFF(dbh, e) == dbh->dbsz)) {
		/* We do this set because we skip the last page in extent. */
		atomic64_set(&dbh->nwb, dbh->dbsz);
		dbh->oom = true;
		goto retry;
	}
	BUG_ON(TDB_HTRIE_OFF(dbh, e) > dbh->dbsz);
	set_bit(TDB_EXT_ID(TDB_EXT_BASE(dbh, e)), dbh->ext_bmp);

	TDB_DBG("Allocated new extent %p\n", e);

	rptr = __tdb_alloc_blk_ext(dbh, e);
	BUG_ON(!rptr);

allocated:
	next_blk = rptr + TDB_BLK_SZ;
	for ( ; g_nwb <= rptr; g_nwb = atomic64_read(&dbh->nwb))
		atomic64_cmpxchg(&dbh->nwb, g_nwb, next_blk);

	/*
	 * Align offsets of new blocks for data records.
	 * This is only for first blocks in extents, so we lose only
	 * TDB_HTRIE_MINDREC - L1_CACHE_BYTES per extent.
	 */
	rptr = TDB_HTRIE_DALIGN(rptr);
	tdb_get_blk(dbh, rptr);
	return rptr;
}
ALLOW_ERROR_INJECTION(tdb_alloc_blk, NULL);

static void
tdb_htrie_init_bucket(TdbBucket *b)
{
	b->coll_next = 0;
	b->rec = 0;
	rwlock_init(&b->lock);
#ifdef CONFIG_LOCKDEP
	/*
	 * To lock buckets in a chain for the trie traversal.
	 * Use subclass > SINGLE_DEPTH_NESTING to avoid collisions with
	 * kernel and Tempesta FW locking subclasses.
	 */
	lockdep_init_map(&b->lock.dep_map, "TdbBucket->lock",
			 &__lockdep_no_validate__, 3);
#endif
}

/**
 * @return byte offset of the allocated data block and sets @len to actually
 * available room for writing if @len doesn't fit to block.
 *
 * Return 0 on error.
 *
 * TODO We initialize bucket in the function and this is ugly, but
 *      we need this to properly calculate length.
 *      This mess must be fixed.
 *
 * TODO Allocate sequence of pages if there are any for large @len.
 *      Probably we should use external location for large data.
 *      Defragment memory blocks in background by page table remappings.
 */
static unsigned long
tdb_alloc_data(TdbHdr *dbh, size_t *len)
{
	unsigned long rptr, old_rptr, new_wcl;
	size_t hdr_len = tdb_rec_hdr_size(dbh), res_len = *len;

	/*
	 * Allocate at least 2 cache lines for small data records
	 * and keep records after tails of large records also aligned.
	 */
	res_len = TDB_HTRIE_DALIGN(hdr_len + res_len);

	local_bh_disable();

	rptr = this_cpu_ptr(dbh->pcpu)->d_wcl;

	if (!(rptr & ~TDB_BLK_MASK)
	    || TDB_BLK_O(rptr + res_len - 1) > TDB_BLK_O(rptr)) {
		size_t max_data_len;

		old_rptr = ((rptr - 1) & TDB_BLK_MASK);
		rptr = tdb_alloc_blk(dbh);

		if (!rptr)
			goto out;

		BUG_ON(old_rptr == 0);
		tdb_put_blk(dbh, old_rptr);

		max_data_len = TDB_BLK_SZ - (rptr & ~TDB_BLK_MASK);
		if (res_len > max_data_len) {
			TDB_DBG("cannot allocate %lu bytes,"
				" %lu will be allocated instead\n",
				res_len, max_data_len);
			res_len = max_data_len;
			*len = res_len - hdr_len;
		}
	}

	BUG_ON(TDB_HTRIE_DALIGN(rptr) != rptr);
	TDB_DBG("alloc dblk %#lx for len=%lu(%lu)\n", rptr, *len, res_len);

	new_wcl = rptr + res_len;
	BUG_ON(TDB_HTRIE_DALIGN(new_wcl) != new_wcl);
	this_cpu_ptr(dbh->pcpu)->d_wcl = new_wcl;

out:
	local_bh_enable();
	return rptr;
}

/**
 * Allocates a new bucket.
 *
 * Never do tdb_htrie_put_rec with bucket block, buckets live forever.
 *
 * @return byte offset of the block.
 */
static unsigned long
tdb_alloc_bucket(TdbHdr *dbh)
{
	unsigned long rptr = 0;
	size_t len;

	local_bh_disable();

	rptr = this_cpu_ptr(dbh->pcpu)->b_wcl;

	len = TDB_HTRIE_IALIGN(sizeof(TdbBucket));

	if (unlikely(!(rptr & ~TDB_BLK_MASK)
		     || TDB_BLK_O(rptr + len - 1) > TDB_BLK_O(rptr))) {
			/* Use a new page and/or extent for local CPU. */
			rptr = tdb_alloc_blk(dbh);
		if (!rptr)
			goto out;
	}

	TDB_DBG("alloc bucket %#lx\n", rptr);
	BUG_ON(TDB_HTRIE_IALIGN(rptr) != rptr);

	this_cpu_ptr(dbh->pcpu)->b_wcl = rptr + len;

	tdb_htrie_init_bucket(TDB_PTR(dbh, rptr));

out:
	local_bh_enable();
	return rptr;
}

/**
 * Allocates a new index block.
 *
 * Never do tdb_htrie_put_rec with index block, indexes live forever.
 * @return byte offset of the block.
 */
static unsigned long
tdb_alloc_index(TdbHdr *dbh)
{
	unsigned long rptr = 0;

	local_bh_disable();

	rptr = this_cpu_ptr(dbh->pcpu)->i_wcl;

	if (unlikely(!(rptr & ~TDB_BLK_MASK)
		     || TDB_BLK_O(rptr + sizeof(TdbHtrieNode) - 1)
			> TDB_BLK_O(rptr)))
	{
		/* Use a new page and/or extent for local CPU. */
		rptr = tdb_alloc_blk(dbh);
		if (!rptr)
			goto out;
	}

	TDB_DBG("alloc iblk %#lx\n", rptr);
	BUG_ON(TDB_HTRIE_IALIGN(rptr) != rptr);

	this_cpu_ptr(dbh->pcpu)->i_wcl = rptr + sizeof(TdbHtrieNode);
	bzero_fast(TDB_PTR(dbh, rptr), sizeof(TdbHtrieNode));

out:
	local_bh_enable();
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
	unsigned long o = 0;
	TdbFRec *r, *first;

	TDB_HTRIE_FOREACH_REC_UNLOCKED(dbh, bckt, first, r, TdbFRec) {
		if (!tdb_live_fsrec(dbh, r)) {
			/* Already freed record - just reuse. */
			o = TDB_HTRIE_OFF(dbh, r);
			goto done;
		}
	}

done:
	TDB_DBG("Small record aggregation dblk=%#lx bckt=%#lx len=%lu\n",
		o, TDB_HTRIE_OFF(dbh, bckt), len);

	return o;
}

static TdbRec *
tdb_htrie_create_rec(TdbHdr *dbh, unsigned long off, unsigned long key,
		     void *data, size_t len, bool complete)
{
	char *ptr = TDB_PTR(dbh, off);
	TdbRec *r = (TdbRec *)ptr;

	BUG_ON(complete && !data);
	if (TDB_HTRIE_VARLENRECS(dbh)) {
		TdbVRec *vr = (TdbVRec *)r;

		memset(ptr, 0, sizeof(TdbVRec));
		vr->len = len;
		ptr += sizeof(TdbVRec);
	} else {
		memset(ptr, 0, sizeof(TdbFRec));
		ptr += sizeof(TdbFRec);
	}
	r->key = key;
	if (data)
		memcpy_fast(ptr, data, len);

	r->flags |= (TDB_HTRIE_COMPLETE_BIT * complete);

	atomic_set(&r->refcnt, 1);

	tdb_get_blk(dbh, off);

	return r;
}

/**
 * Grow the tree by bursting current data bucket @bckt.
 *
 * @node	- current index node at which least significant bits collision
 * 		  happened. Set to the new node to continue the search from.
 * @bits	- number of successfully resolved bits, the next TDB_HTRIE_BITS
 * 		  determine next tree branch offset at new node created by
 * 		  the function.
 *
 * Called under bucket lock, so we can safely copy and remove records
 * from the bucket.
 */
static int
tdb_htrie_burst(TdbHdr *dbh, TdbHtrieNode **node, TdbBucket *bckt,
		unsigned long key, int bits)
{
	int i, free_nb;
	unsigned int new_in_idx;
	unsigned long k, n;
	TdbRec *frec = TDB_HTRIE_BCKT_1ST_REC(dbh, bckt);
	TdbHtrieNode *new_in;
	struct {
		unsigned long	r;
		unsigned char	off;
	} nb[TDB_HTRIE_FANOUT] = {{0, 0}};

	n = tdb_alloc_index(dbh);
	if (!n)
		return -ENOMEM;
	new_in = TDB_PTR(dbh, n);
	new_in_idx = TDB_O2II(n);

	/* We must not burst empty bucket, just reuse it. */
	BUG_ON(!frec);

#define MOVE_RECORDS(Type, live)					\
do {									\
	Type *r = (Type *)frec;						\
	k = TDB_HTRIE_IDX(r->key, bits);				\
	/* Always leave first record in the same data block. */		\
	new_in->shifts[k] = TDB_O2BI(TDB_HTRIE_OFF(dbh, bckt))		\
			    | TDB_HTRIE_DBIT;				\
	TDB_DBG("burst: link bckt=%p w/ iblk=%#x by %#lx (key=%#lx)\n",	\
		bckt, new_in_idx, k, r->key);				\
	/*								\
	 * Don't move removed records to prevent case when freed records\
	 * stay in the bucket, this case is forbidden. When all records \
	 * are dead we detach them from bucket.				\
	 */								\
	if (tdb_rec_is_removed(frec))					\
		bckt->rec = 0;						\
	n = TDB_HTRIE_RECLEN(dbh, r);					\
	nb[k].r = TDB_HTRIE_OFF(dbh, frec);				\
	nb[k].off = n;							\
	free_nb = -(long)k; /* remember which block we save & copy */	\
	r = (Type *)((char *)r + n);					\
	for ( ; ; r = (Type *)((char *)r + n)) {			\
		unsigned long copied = (char *)r - (char *)frec;	\
		if (tdb_rec_is_removed((TdbRec *)r))			\
			continue;					\
		if (sizeof(*r) + copied >= TDB_HTRIE_MINDREC)		\
			break; /* end of records */			\
		n = TDB_HTRIE_RECLEN(dbh, r);				\
		if (n + copied >= TDB_HTRIE_MINDREC)			\
			break; /* end of records */			\
		if (!live)						\
			continue;					\
		/* Small record cannot exceed TDB_HTRIE_MINDREC. */	\
		BUG_ON(copied + n > TDB_HTRIE_MINDREC);			\
		k = TDB_HTRIE_IDX(r->key, bits);			\
		if (!nb[k].r) {						\
			/* Just allocate TDB_HTRIE_MINDREC bytes. */	\
			size_t _n = 0;					\
			unsigned long o_b, o_r;				\
			TdbBucket *nbckt;				\
			o_r = tdb_alloc_data(dbh, &_n);			\
			if (!o_r)					\
				goto err_cleanup;			\
			o_b = tdb_alloc_bucket(dbh);			\
			if (!o_b)					\
				goto err_cleanup;			\
			nb[k].r = o_r;					\
			nbckt = TDB_PTR(dbh, o_b);			\
			tdb_htrie_init_bucket(nbckt);			\
			nbckt->rec = TDB_O2DI(nb[k].r);			\
			tdb_htrie_create_rec(dbh, nb[k].r, r->key, r->data,\
					     TDB_HTRIE_RBODYLEN(dbh, r),\
					     true);			\
			TDB_DBG("burst: copied rec=%p (len=%lu key=%#lx)"\
				" to new dblk=%#lx w/ idx=%#lx\n",	\
				r, n, r->key, nb[k].r, k);		\
			nb[k].off = n;					\
			new_in->shifts[k] = TDB_O2BI(o_b) | TDB_HTRIE_DBIT;\
			/* We copied a record, clear its original place. */\
			free_nb = free_nb > 0 ? free_nb : -free_nb;	\
			/* Remove source record */			\
			tdb_rec_set_remove((TdbRec *)r);		\
			tdb_htrie_put_rec(dbh, (TdbRec *)r);		\
		} else {						\
			unsigned long off = nb[k].r + nb[k].off;	\
			/*						\
			 * Don't copy to the same record. It happens	\
			 * when records have equal key parts.		\
			 */						\
			if (TDB_HTRIE_OFF(dbh, frec) == nb[k].r)	\
				continue;				\
			tdb_htrie_create_rec(dbh, off, r->key, r->data,	\
					     TDB_HTRIE_RBODYLEN(dbh, r),\
					     true);			\
			TDB_DBG("burst: moved rec=%p (len=%lu key=%#lx)"\
				" to dblk=%#lx w/ idx=%#lx\n",		\
				r, n, r->key, nb[k].r, k);		\
			nb[k].off += n;					\
			/* Remove source record */			\
			tdb_rec_set_remove((TdbRec *)r);		\
			tdb_htrie_put_rec(dbh, (TdbRec *)r);		\
		}							\
	}								\
} while (0)

	if (TDB_HTRIE_VARLENRECS(dbh))
		/*
		 * Variable-length records always alive when it stored in
		 * bucket.
		 */
		MOVE_RECORDS(TdbVRec, true);
	else
		MOVE_RECORDS(TdbFRec, tdb_live_fsrec(dbh, r));

#undef MOVE_RECORDS

	/*
	 * Link the new index node with @node.
	 * Nobody should change the index block, while the bucket lock is held.
	 */
	k = TDB_HTRIE_IDX(key, bits - TDB_HTRIE_BITS);
	TDB_DBG("link iblk=%p w/ iblk=%p (%#x) by idx=%#lx\n",
		*node, new_in, new_in_idx, k);
	(*node)->shifts[k] = new_in_idx;
	*node = new_in;

	return 0;

err_cleanup:
	if (free_nb > 0)
		for (i = 0; i < TDB_HTRIE_FANOUT; ++i)
			if (i != free_nb && nb[i].r)
				tdb_htrie_put_rec(dbh, (TdbRec *)nb[i].r);
	tdb_free_index_blk(new_in);
	return -ENOMEM;
}

/**
 * Descend the tree starting at @node.
 *
 * @return byte offset of data (w/o TDB_HTRIE_DBIT bit) on success
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

		if (o & TDB_HTRIE_DBIT) {
			BUG_ON(TDB_BI2O(o & ~TDB_HTRIE_DBIT)
				< TDB_HDR_SZ(dbh) + sizeof(TdbExt)
			       || TDB_BI2O(o & ~TDB_HTRIE_DBIT)
				> dbh->dbsz);
			/* We're at a data pointer - resolve it. */
			*bits += TDB_HTRIE_BITS;
			o ^= TDB_HTRIE_DBIT;
			BUG_ON(!o);

			return TDB_BI2O(o);
		} else {
			if (!o)
				return 0; /* cannot descend deeper */
			BUG_ON(TDB_II2O(o) > dbh->dbsz);
			*node = TDB_PTR(dbh, TDB_II2O(o));
			*bits += TDB_HTRIE_BITS;
		}
	}
}

/**
 * Add more data to @rec.
 *
 * The function is called to extend just added new record, so it's not expected
 * that it can be called concurrently for the same record.
 */
TdbVRec *
tdb_htrie_extend_rec(TdbHdr *dbh, TdbVRec *rec, size_t size)
{
	unsigned long o;
	TdbVRec *chunk;

	/* Cannot extend fixed-size records. */
	BUG_ON(!TDB_HTRIE_VARLENRECS(dbh));

	o = tdb_alloc_data(dbh, &size);
	if (!o)
		return NULL;

	chunk = TDB_PTR(dbh, o);
	chunk->key = rec->key;
	chunk->flags = 0;
	chunk->chunk_next = 0;
	chunk->len = size;

	tdb_get_blk(dbh, o);

retry:
	/* A caller is appreciated to pass the last record chunk by @rec. */
	while (unlikely(rec->chunk_next))
		rec = TDB_PTR(dbh, TDB_DI2O(rec->chunk_next));
	BUG_ON(tdb_rec_is_removed((TdbRec *)rec));

	o = TDB_O2DI(o);
	if (atomic_cmpxchg((atomic_t *)&rec->chunk_next, 0, o))
		goto retry;

	TDB_DBG("Extend record %p by new chunk %x, size=%lu\n",
		rec, rec->chunk_next, size);

	return chunk;
}

static void
tdb_bucket_remove_record(TdbHdr *dbh, TdbBucket *bckt, tdb_eq_cb_t *eq_cb,
			 void *data, bool force)
{
	/*
	 * For variable-length records and for large fixed size records
	 * remove the bucket relying on the first record in the bucket.
	 * By design only one variable length record can be stored in the bucket
	 * for variable records. We do like this because in this case we don't
	 * need to try to scan the bucket for another records when the last
	 * record is removed. Variable-length records intended to store
	 * large data, small records not expected in such case.
	 */
	if (TDB_HTRIE_VARLENRECS(dbh) ||
	    TDB_HTRIE_RALIGN(dbh->rec_len) >= TDB_HTRIE_MINDREC) {
		TdbRec *rec = TDB_HTRIE_BCKT_1ST_REC(dbh, bckt);

		if (!rec)
			return;

		BUG_ON(tdb_rec_is_removed(rec));

		if (tdb_rec_is_complete(rec)) {
			if (!eq_cb || eq_cb(dbh, rec, data)) {
				tdb_rec_set_remove(rec);
				tdb_htrie_put_rec(dbh, rec);
				bckt->rec = 0;
			}
		} else {
			/* Remove incomplete record only if @force is set. */
			if (force && (!eq_cb || eq_cb(dbh, rec, data))) {
				tdb_rec_set_remove(rec);
				tdb_htrie_put_rec(dbh, rec);
				bckt->rec = 0;
			}
		}
	} else {
		/* Remove only small records. */
		TdbFRec *first, *rec;
		bool has_alive = false;

		TDB_HTRIE_FOREACH_REC_SMALL(dbh, bckt, first, rec, TdbFRec) {
			if (!tdb_live_fsrec(dbh, (TdbFRec *)rec))
				continue;

			/* Record is removed, but still has users. */
			if (tdb_rec_is_removed(rec))
				continue;

			if (!eq_cb || eq_cb(dbh, rec, data)) {
				tdb_rec_set_remove(rec);
				tdb_htrie_put_rec(dbh, rec);
			} else {
				has_alive = true;
			}
		}

		if (!has_alive)
			bckt->rec = 0;
	}
}

/* Must be called with locked bucket. */
static TdbBucket *
__tdb_htrie_remove(TdbHdr *dbh, TdbBucket *bckt, tdb_eq_cb_t *eq_cb, void *data,
		   bool force)
{
	TdbBucket *prev = bckt;

	/* Iterate all buckets except the head bucket. */
	while (bckt) {
		tdb_bucket_remove_record(dbh, bckt, eq_cb, data, force);

		prev = bckt;
		bckt = TDB_HTRIE_BUCKET_NEXT(dbh, bckt);
		if (bckt) {
			write_lock_bh(&bckt->lock);
			write_unlock_bh(&prev->lock);
		}
	}

	return prev;
}

void
tdb_htrie_remove(TdbHdr *dbh, unsigned long key, tdb_eq_cb_t *eq_cb, void *data,
		 bool force)
{
	int bits = 0;
	unsigned long o;
	TdbBucket *bckt;
	TdbHtrieNode *node = TDB_HTRIE_ROOT(dbh);

	o = tdb_htrie_descend(dbh, &node, key, &bits);
	if (!o)
		return;

	bckt = TDB_PTR(dbh, o);

	TDB_DBG("Remove htrie record for key=%#lx force=%d bucket=[%p]", key,
		force, bckt);

	write_lock_bh(&bckt->lock);
	bckt = __tdb_htrie_remove(dbh, bckt, eq_cb, data, force);
	write_unlock_bh(&bckt->lock);
}

static TdbRec *
tdb_htrie_assign_record(TdbHdr *dbh, TdbBucket *bckt, unsigned long key,
			void *data, size_t *len, bool complete)
{
	TdbRec *rec;
	unsigned long o;

	o = tdb_alloc_data(dbh, len);
	if (!o) {
		write_unlock_bh(&bckt->lock);
		return NULL;
	}
	bckt->rec = TDB_O2DI(o);
	rec = tdb_htrie_create_rec(dbh, o, key, data, *len, complete);
	tdb_htrie_get_rec(rec);
	write_unlock_bh(&bckt->lock);

	return rec;
}

/**
 * @len returns number of copied data on success.
 *
 * TODO it seems the function can be rewritten w/o RW-lock using transactional
 * notation: assemble set of operations to do in double word in shared location
 * and do CAS on it with comparing the location with zero.
 * If competing context helps the current trx owner, then we get true lock-free.
 */
TdbRec *
tdb_htrie_insert(TdbHdr *dbh, unsigned long key, void *data, tdb_eq_cb_t *eq_cb,
		 void *eq_data, size_t *len, bool complete)
{
	int bits = 0;
	unsigned long o, o_bckt = 0;
	TdbBucket *bckt, *new_bckt;
	TdbHtrieNode *node = TDB_HTRIE_ROOT(dbh);

	/* Don't store empty data. */
	if (unlikely(!*len) || unlikely(!key))
		return NULL;

retry:
	o = tdb_htrie_descend(dbh, &node, key, &bits);
	if (!o) {
		TdbRec *rec;
		int i;

		TDB_DBG("Create a new htrie node for key=%#lx len=%lu"
			" bits_used=%d, shift=%lx\n", key, *len, bits,
			TDB_HTRIE_IDX(key, bits));

		o = tdb_alloc_data(dbh, len);
		if (!o)
			return NULL;

		o_bckt = o_bckt ?: tdb_alloc_bucket(dbh);
		if (!o_bckt)
			return NULL;

		rec = tdb_htrie_create_rec(dbh, o, key, data, *len, complete);

		new_bckt = TDB_PTR(dbh, o_bckt);
		new_bckt->rec = TDB_O2DI(o);
		tdb_htrie_get_rec(rec);

		i = TDB_HTRIE_IDX(key, bits);
		if (atomic_cmpxchg((atomic_t *)&node->shifts[i], 0,
				   TDB_O2BI(o_bckt) | TDB_HTRIE_DBIT) == 0)
		{
			return rec;
		}

		/*
		 * Somebody already created the new branch, free just allocated
		 * data block. Bucket will be reused or leaked if on the new
		 * place record can be placed without bucket creation.
		 *
		 * TODO: Free bucket.
		 */
		tdb_htrie_free_rec(dbh, rec);
		new_bckt->rec = 0;

		goto retry;
	}

	/*
	 * HTrie collision.
	 * At this point arbitrary new intermediate index nodes could appear.
	 */
	bckt = TDB_PTR(dbh, o);
	BUG_ON(!bckt);

	write_lock_bh(&bckt->lock);

	/*
	 * Recheck last index node in case of just inserted new nodes -
	 * probably we should process collision at different (new) bucket.
	 */
	if (!TDB_HTRIE_RESOLVED(bits)) {
		int bits_cur;
		unsigned long o_new;

		BUG_ON(bits < TDB_HTRIE_BITS);

		bits_cur = bits - TDB_HTRIE_BITS;
		o_new = node->shifts[TDB_HTRIE_IDX(key, bits_cur)];

		if (!o_new || TDB_BI2O(o_new & ~TDB_HTRIE_DBIT) != o) {
			/* Try to descend again from the last index node. */
			bits -= TDB_HTRIE_BITS;
			write_unlock_bh(&bckt->lock);
			goto retry;
		}
	}

	if (eq_cb)
		tdb_bucket_remove_record(dbh, bckt, eq_cb, eq_data, false);
	/*
	 * If record in the bucket is freed place new record to its place.
	 */
	if (!bckt->rec)
		return tdb_htrie_assign_record(dbh, bckt, key, data, len,
					       complete);

	/*
	 * Try to place the small record in preallocated room for
	 * small records. There could be full or partial key match.
	 * Small fixed-size records can be intermixed in collision chain,
	 * so we do this before processing full key collision. Applicable
	 * only for fixed size records, variable size records always have
	 * only one record per bucket, therefore handled by
	 * @tdb_htrie_assign_record().
	 */
	if (*len < TDB_HTRIE_MINDREC && !TDB_HTRIE_VARLENRECS(dbh)) {
		/* Align small record length to 8 bytes. */
		size_t n = TDB_HTRIE_RALIGN(*len);

		TDB_DBG("Small record (len=%lu) collision on %d bits for"
			" key %#lx\n", n, bits, key);

		o = tdb_htrie_smallrec_link(dbh, n, bckt);
		if (o) {
			TdbRec *rec = tdb_htrie_create_rec(dbh, o, key, data,
							   *len, true);
			tdb_htrie_get_rec(rec);
			write_unlock_bh(&bckt->lock);
			return rec;
		}
	}

	if (unlikely(TDB_HTRIE_RESOLVED(bits))) {
		TdbRec *rec;

		TDB_DBG("Hash full key %#lx collision on %d bits,"
			" add new record (len=%lu) to collision chain\n",
			key, bits, *len);

		BUG_ON(TDB_HTRIE_BUCKET_KEY(dbh, bckt) != key);

		while (bckt->coll_next) {
			TdbBucket *next = TDB_HTRIE_BUCKET_NEXT(dbh, bckt);

			write_lock_bh(&next->lock);
			write_unlock_bh(&bckt->lock);
			bckt = next;

			if (eq_cb)
				tdb_bucket_remove_record(dbh, bckt, eq_cb,
							 eq_data, false);

			if (bckt->rec)
				continue;

			return tdb_htrie_assign_record(dbh, bckt, key, data,
						       len, complete);
		}

		o_bckt = o_bckt ?: tdb_alloc_bucket(dbh);
		if (!o_bckt) {
			write_unlock_bh(&bckt->lock);
			return NULL;
		}

		bckt->coll_next = TDB_O2BI(o_bckt);

		o = tdb_alloc_data(dbh, len);
		if (!o) {
			write_unlock_bh(&bckt->lock);
			return NULL;
		}

		rec = tdb_htrie_create_rec(dbh, o, key, data, *len, complete);

		new_bckt = TDB_PTR(dbh, o_bckt);
		new_bckt->rec = TDB_O2DI(o);

		tdb_htrie_get_rec(rec);
		write_unlock_bh(&bckt->lock);

		return rec;
	}

	/*
	 * But there is no room. Burst the node.
	 * We should never see collision chains at this point.
	 */
	BUG_ON(bckt->coll_next);
	BUG_ON(bits < TDB_HTRIE_BITS);

	TDB_DBG("Least significant bits %d collision for key %#lx"
		" and new record (len=%lu) - burst the node %p\n",
		bits, key, *len, bckt);

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
	TdbBucket *b;
	TdbHtrieNode *root = TDB_HTRIE_ROOT(dbh);

	o = tdb_htrie_descend(dbh, &root, key, &bits);
	if (!o)
		return NULL;
	b = TDB_PTR(dbh, o);

	return b;
}

#define TDB_HTRIE_FOREACH_REC(dbh, b_tmp, b, fr, r, body)		\
do {									\
	size_t hdr_len = tdb_rec_hdr_size(dbh);				\
	read_lock_bh(&((*(b))->lock));					\
	do {								\
		r = fr = TDB_HTRIE_BCKT_1ST_REC(dbh, *b);		\
		if (!r)							\
			goto next_bucket;				\
		do {							\
			size_t rlen = hdr_len +				\
				      TDB_HTRIE_RBODYLEN(dbh, r);	\
			rlen = TDB_HTRIE_RALIGN(rlen);			\
			if ((char *)r + rlen - (char *)fr		\
				> TDB_HTRIE_MINDREC			\
			    && r != fr)					\
				break;					\
			if (!tdb_rec_is_removed(r) && tdb_rec_is_complete(r)) {\
				tdb_htrie_get_rec(r);			\
				body;					\
				tdb_htrie_put_rec(dbh, r);		\
			}						\
			r = (TdbRec *)((char *)r + rlen);		\
		} while ((char *)r + hdr_len - (char *)fr		\
			 <= TDB_HTRIE_MINDREC);				\
next_bucket:								\
		b_tmp = TDB_HTRIE_BUCKET_NEXT(dbh, *b);			\
		if (b_tmp)						\
			read_lock_bh(&b_tmp->lock);			\
		else							\
			b_tmp = NULL;					\
		read_unlock_bh(&(*b)->lock);				\
		*b = b_tmp;						\
	} while (*b);							\
} while (0)
/**
 * Iterate over all records in collision chain with locked buckets.
 * Buckets are inspected according to following rules:
 * - if first record is > TDB_HTRIE_MINDREC, then only it is observer;
 * - all records which fit TDB_HTRIE_MINDREC.
 *
 * The bucket @b at the head of the list must be alive regardless
 * deleted/evicted records in it.
 */
TdbRec *
tdb_htrie_bscan_for_rec(TdbHdr *dbh, TdbBucket **b, unsigned long key)
{
	TdbBucket *b_tmp;
	TdbRec *r, *fr;

	TDB_HTRIE_FOREACH_REC(dbh, b_tmp, b, fr, r, {
		if (!tdb_rec_is_removed(r) && r->key == key) {
			read_unlock_bh(&((*(b))->lock));
			/* Release the bucket by tdb_rec_put(). */
			return r;
		}
	});

	return NULL;
}

/**
 * Releases(tdb_rec_put) the last bucket when all records are read from it.
 */
TdbRec *
tdb_htrie_next_rec(TdbHdr *dbh, TdbRec *r, TdbBucket **b, unsigned long key)
{
	TdbBucket *_b = *b;
	TdbRec *fr;
	size_t hdr_len = tdb_rec_hdr_size(dbh);

	BUG_ON(!r);
	read_lock_bh(&_b->lock);
	fr = TDB_HTRIE_BCKT_1ST_REC(dbh, _b);
	tdb_htrie_put_rec(dbh, r);

	do {
		size_t rlen;

		/* Variable length records doens't have small records. */
		if (!r || TDB_HTRIE_VARLENRECS(dbh) ||
		    dbh->rec_len >= TDB_HTRIE_MINDREC)
			goto next_bckt;

		rlen = TDB_HTRIE_RALIGN(hdr_len + dbh->rec_len);
		if ((char *)r + rlen - (char *)fr > TDB_HTRIE_MINDREC)
			goto next_bckt;
		r = (TdbRec *)((char *)r + rlen);

		do {
			rlen = TDB_HTRIE_RALIGN(hdr_len + dbh->rec_len);
			if ((char *)r + rlen - (char *)fr > TDB_HTRIE_MINDREC)
				break;
			if (!tdb_rec_is_removed(r) && r->key == key) {
				tdb_htrie_get_rec(r);
				read_unlock_bh(&(*b)->lock);
				/* Release the bucket by tdb_rec_put(). */
				return r;
			}
			r = (TdbRec *)((char *)r + rlen);
		} while ((char *)r + hdr_len - (char *)fr
			 <= TDB_HTRIE_MINDREC);
next_bckt:
		*b = TDB_HTRIE_BUCKET_NEXT(dbh, _b);
		if (*b) {
			read_lock_bh(&(*b)->lock);
			read_unlock_bh(&_b->lock);
			r = TDB_HTRIE_BCKT_1ST_REC(dbh, *b);
			if (r && !tdb_rec_is_removed(r) &&
			    tdb_rec_is_complete(r) && r->key == key) {
				tdb_htrie_get_rec(r);
				read_unlock_bh(&(*b)->lock);
				/* Release the bucket by tdb_rec_put(). */
				return r;
			}

		} else {
			read_unlock_bh(&_b->lock);
		}
		_b = *b;
	} while (_b);

	return NULL;
}

TdbHdr *
tdb_htrie_init(void *p, size_t db_size, unsigned int rec_len)
{
	int cpu;
	TdbHdr *hdr = (TdbHdr *)p;

	if (hdr->magic != TDB_MAGIC) {
		hdr = tdb_init_mapping(p, db_size, rec_len);
		if (!hdr) {
			TDB_ERR("cannot init db mapping\n");
			return NULL;
		}
	}

	spin_lock_init(&hdr->gfl_lock);

	/* Set per-CPU pointers. */
	hdr->pcpu = tfw_alloc_percpu(TdbPerCpu);
	if (!hdr->pcpu) {
		TDB_ERR("cannot allocate per-cpu data\n");
		return NULL;
	}
	for_each_online_cpu(cpu) {
		TdbPerCpu *p = per_cpu_ptr(hdr->pcpu, cpu);

		p->b_wcl = tdb_alloc_blk(hdr);
		p->i_wcl = tdb_alloc_blk(hdr);
		p->d_wcl = tdb_alloc_blk(hdr);
	}

	TDB_DBG("init db header: nwb=%llu db_size=%lu rec_len=%u\n",
		atomic64_read(&hdr->nwb), hdr->dbsz, hdr->rec_len);

	return hdr;
}

void
tdb_htrie_exit(TdbHdr *dbh)
{
	free_percpu(dbh->pcpu);
}

static int
tdb_htrie_bucket_walk(TdbHdr *dbh, TdbBucket *b, int (*fn)(void *))
{
	TdbBucket *b_tmp;
	TdbRec *r, *fr;

	TDB_HTRIE_FOREACH_REC(dbh, b_tmp, &b, fr, r, {
		if (!tdb_rec_is_removed(r)) {
			int res = fn(r->data);
			if (unlikely(res)) {
				read_unlock_bh(&b->lock);
				return res;
			}
		}
	});

	return 0;
}

static int
tdb_htrie_node_visit(TdbHdr *dbh, TdbHtrieNode *node, int (*fn)(void *))
{
	int bits;
	int res;

	for (bits = 0; bits < TDB_HTRIE_FANOUT; ++bits) {
		unsigned long o;

		BUG_ON(TDB_HTRIE_RESOLVED(bits));

		o = node->shifts[bits];

		if (likely(!o))
			continue;

		BUG_ON(TDB_BI2O(o & ~TDB_HTRIE_DBIT) < TDB_HDR_SZ(dbh)
							+ sizeof(TdbExt));

		if (o & TDB_HTRIE_DBIT) {
			TdbBucket *b;

			/* We're at a data pointer - resolve it. */
			o ^= TDB_HTRIE_DBIT;
			BUG_ON(!o);
			BUG_ON(TDB_BI2O(o) > dbh->dbsz);

			b = (TdbBucket *)TDB_PTR(dbh, TDB_BI2O(o));
			res = tdb_htrie_bucket_walk(dbh, b, fn);
			if (unlikely(res))
				return res;
		} else {
			BUG_ON(TDB_II2O(o) > dbh->dbsz);

			/*
			 * The recursion depth being hard-limited.
			 * The function has the deepest nesting 16.
			 */
			res = tdb_htrie_node_visit(dbh, TDB_PTR(dbh,
						   TDB_II2O(o)), fn);
			if (unlikely(res))
				return res;
		}
	}

	return 0;
}

int
tdb_htrie_walk(TdbHdr *dbh, int (*fn)(void *))
{
	TdbHtrieNode *node = TDB_HTRIE_ROOT(dbh);

	return tdb_htrie_node_visit(dbh, node, fn);
}
