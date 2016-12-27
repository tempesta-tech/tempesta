/**
 *		Tempesta DB
 *
 * Index and memory management for cache conscious Burst Hash Trie.
 * Operations over the index tree are lock-free while buckets with collision
 * chains of small records are protected by RW-spinlock.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2016 Tempesta Technologies, Inc.
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
#include <asm/sync_bitops.h>
#include <linux/bitops.h>
#include <linux/slab.h>

#include "htrie.h"

#define TDB_MAGIC	0x434947414D424454UL /* "TDBMAGIC" */
#define TDB_BLK_SZ	PAGE_SIZE
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

/**
 * Unlocked and simplified version of tdb_htrie_bscan_for_rec() for
 * small records only.
 */
#define TDB_HTRIE_FOREACH_REC_UNLOCKED(d, b, r)				\
	for ( ; b; b = TDB_HTRIE_BUCKET_NEXT(d, b))			\
		for (r = TDB_HTRIE_BCKT_1ST_REC(b);			\
		     (char *)r - (char *)b + sizeof(*r)	<= TDB_HTRIE_MINDREC \
		     && (char *)r - (char *)b + TDB_HTRIE_RECLEN(d, r)	\
			<= TDB_HTRIE_MINDREC;				\
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

	return hdr;
}

static inline void
tdb_free_index_blk(TdbHtrieNode *node)
{
	/* Just zero the block and leave it for garbage collector. */
	memset(node, 0, sizeof(*node));
}

/* TODO synchronize the bucket access. */
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

static inline void
tdb_free_vsrec(TdbVRec *rec)
{
	rec->len |= TDB_HTRIE_VRFREED;
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
tdb_alloc_blk(TdbHdr *dbh)
{
	TdbExt *e;
	long g_nwb, rptr, next_blk;

retry:
	g_nwb = atomic64_read(&dbh->nwb);
	e = tdb_ext(dbh, TDB_PTR(dbh, g_nwb));

	if (likely(g_nwb & ~TDB_EXT_MASK)) {
		/*
		 * Current extent was already getted.
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
		e = (TdbExt *)((unsigned long)e + TDB_EXT_SZ);
	}

	/*
	 * The new extent should be used.
	 * Whole extent shouldn't be fully utilized by concurrent contexts
	 * while we're in the function, so we expect that it will satisfy
	 * our allocation request.
	 */
	if (unlikely(TDB_HTRIE_OFF(dbh, e) == dbh->dbsz)) {
		TDB_ERR("out of free space\n");
		return 0;
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
	return TDB_HTRIE_DALIGN(rptr);
}

static void
tdb_htrie_init_bucket(TdbBucket *b)
{
	b->coll_next = 0;
	b->flags = 0;
	rwlock_init(&b->lock);
#ifdef CONFIG_LOCKDEP
	lockdep_init_map(&b->lock.dep_map, "TdbBucket->lock",
			 &__lockdep_no_validate__, SINGLE_DEPTH_NESTING);
#endif
}

/**
 * @return byte offset of the allocated data block and sets @len to actually
 * available room for writting if @len doesn't fit to block.
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
tdb_alloc_data(TdbHdr *dbh, size_t *len, int bucket_hdr)
{
	unsigned long rptr, new_wcl;
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

	local_bh_disable();

	rptr = this_cpu_ptr(dbh->pcpu)->d_wcl;

	if (!(rptr & ~TDB_BLK_MASK)
	    || TDB_BLK_O(rptr + res_len) > TDB_BLK_O(rptr))
	{
		size_t max_data_len;

		/*
		 * Use a new page and/or extent for the data.
		 * Less than a page can be allocated.
		 */
		rptr = tdb_alloc_blk(dbh);
		if (!rptr)
			goto out;

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

	if (bucket_hdr) {
		tdb_htrie_init_bucket(TDB_PTR(dbh, rptr));
		rptr += sizeof(TdbBucket);
	}

out:
	local_bh_enable();
	return rptr;
}

/**
 * Allocates a new index block.
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
	unsigned long n, o = 0;

	if (TDB_HTRIE_VARLENRECS(dbh)) {
		TdbVRec *r;
		TDB_HTRIE_FOREACH_REC_UNLOCKED(dbh, bckt, r) {
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
		TDB_HTRIE_FOREACH_REC_UNLOCKED(dbh, bckt, r) {
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
	TdbBucket *b = TDB_HTRIE_BCKT_1ST_REC(bckt);
	TdbHtrieNode *new_in;
	struct {
		unsigned long	b;
		unsigned char	off;
	} nb[TDB_HTRIE_FANOUT] = {{0, 0}};

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
	TDB_DBG("burst: link bckt=%p w/ iblk=%#x by %#lx (key=%#lx)\n",	\
		bckt, new_in_idx, k, r->key);				\
	n = TDB_HTRIE_RECLEN(dbh, r);					\
	nb[k].b = TDB_HTRIE_OFF(dbh, bckt);				\
	nb[k].off = sizeof(*b) + n;					\
	free_nb = -(long)k; /* remember which block we save & copy */	\
	r = (Type *)((char *)r + n);					\
	for ( ; ; r = (Type *)((char *)r + n)) {			\
		unsigned long copied = (char *)r - (char *)bckt;	\
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
		if (!nb[k].b) {						\
			/* Just allocate TDB_HTRIE_MINDREC bytes. */	\
			size_t _n = 0;					\
			nb[k].b = tdb_alloc_data(dbh, &_n, 0);		\
			if (!nb[k].b)					\
				goto err_cleanup;			\
			b = TDB_PTR(dbh, nb[k].b);			\
			tdb_htrie_init_bucket(b);			\
			memcpy(TDB_HTRIE_BCKT_1ST_REC(b), r, n);	\
			nb[k].off = sizeof(*b) + n;			\
			new_in->shifts[k] = TDB_O2DI(nb[k].b) | TDB_HTRIE_DBIT;\
			/* We copied a record, clear its orignal place. */\
			free_nb = free_nb > 0 ? free_nb : -free_nb;	\
			TDB_DBG("burst: copied rec=%p (len=%lu key=%#lx)"\
				" to new dblk=%#lx w/ idx=%#lx\n",	\
				r, n, r->key, nb[k].b, k);		\
		} else {						\
			b = TDB_PTR(dbh, nb[k].b + nb[k].off);		\
			memmove(b, r, n);				\
			nb[k].off += n;					\
			TDB_DBG("burst: moved rec=%p (len=%lu key=%#lx)"\
				" to dblk=%#lx w/ idx=%#lx\n",		\
				r, n, r->key, nb[k].b, k);		\
		}							\
	}								\
} while (0)

	if (TDB_HTRIE_VARLENRECS(dbh))
		MOVE_RECORDS(TdbVRec, tdb_live_vsrec(r));
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

	o = tdb_alloc_data(dbh, &size, 0);
	if (!o)
		return NULL;

	chunk = TDB_PTR(dbh, o);
	chunk->key = rec->key;
	chunk->chunk_next = 0;
	chunk->len = size;

retry:
	/* A caller is appreciated to pass the last record chunk by @rec. */
	while (unlikely(rec->chunk_next))
		rec = TDB_PTR(dbh, TDB_DI2O(rec->chunk_next));
	BUG_ON(!tdb_live_vsrec(rec));

	o = TDB_O2DI(o);
	if (atomic_cmpxchg((atomic_t *)&rec->chunk_next, 0, o))
		goto retry;

	TDB_DBG("Extend record %p by new chunk %x, size=%lu\n",
		rec, rec->chunk_next, size);

	return chunk;
}

/**
 * @len returns number of copied data on success.
 *
 * TODO it seems the function can be rewrited w/o RW-lock using transactional
 * notation: assemble set of operations to do in double word in shared location
 * and do CAS on it with comparing the location with zero.
 * If competing context helps the current trx owner, then we get true lock-free.
 */
TdbRec *
tdb_htrie_insert(TdbHdr *dbh, unsigned long key, void *data, size_t *len)
{
	int bits = 0;
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
		int i;

		TDB_DBG("Create a new htrie node for key=%#lx len=%lu"
			" bits_used=%d\n", key, *len, bits);

		o = tdb_alloc_data(dbh, len, 1);
		if (!o)
			return NULL;

		rec = tdb_htrie_create_rec(dbh, o, key, data, *len);

		i = TDB_HTRIE_IDX(key, bits);
		if (atomic_cmpxchg((atomic_t *)&node->shifts[i], 0,
				   TDB_O2DI(o) | TDB_HTRIE_DBIT) == 0)
			return rec;
		/* Somebody already created the new brach. */
		// TODO free just allocated data block
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

		if (!o_new || TDB_DI2O(o_new & ~TDB_HTRIE_DBIT) != o) {
			/* Try to descend again from the last index node. */
			bits -= TDB_HTRIE_BITS;
			write_unlock_bh(&bckt->lock);
			goto retry;
		}
	}

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
		if (o) {
			rec = tdb_htrie_create_rec(dbh, o, key, data, *len);
			write_unlock_bh(&bckt->lock);
			return rec;
		}
	}

	if (unlikely(TDB_HTRIE_RESOLVED(bits))) {
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

		rec = tdb_htrie_create_rec(dbh, o, key, data, *len);
		bckt->coll_next = TDB_O2DI(o);

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
	TdbHtrieNode *root = TDB_HTRIE_ROOT(dbh);

	o = tdb_htrie_descend(dbh, &root, key, &bits);
	if (!o) {
		TDB_DBG("...not found\n");
		return NULL;
	}

	return TDB_PTR(dbh, o);
}

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
	TdbRec *r;

	read_lock_bh(&(*b)->lock);

	do {
		r = TDB_HTRIE_BCKT_1ST_REC(*b);
		do {
			size_t rlen = sizeof(*r) + TDB_HTRIE_RBODYLEN(dbh, r);
			rlen = TDB_HTRIE_RALIGN(rlen);
			if ((char *)r + rlen - (char *)*b > TDB_HTRIE_MINDREC
			    && r != TDB_HTRIE_BCKT_1ST_REC(*b))
				break;
			if (tdb_live_rec(dbh, r) && r->key == key)
				/* Unlock the bucket by tdb_rec_put(). */
				return r;
			r = (TdbRec *)((char *)r + rlen);
		} while ((char *)r + sizeof(*r) - (char *)*b
			 <= TDB_HTRIE_MINDREC);

		b_tmp = TDB_HTRIE_BUCKET_NEXT(dbh, *b);
		if (b_tmp)
			read_lock_bh(&b_tmp->lock);
		read_unlock_bh(&(*b)->lock);
		*b = b_tmp;
	} while (*b);

	return NULL;
}

/**
 * Called with already locked bucket by tdb_htrie_lookup().
 * Unlocks the last bucked when all records are read from it.
 */
TdbRec *
tdb_htrie_next_rec(TdbHdr *dbh, TdbRec *r, TdbBucket **b, unsigned long key)
{
	TdbBucket *_b = *b;

	do {
		size_t rlen = TDB_HTRIE_RALIGN(sizeof(*r)
					       + TDB_HTRIE_RBODYLEN(dbh, r));
		if ((char *)r + rlen - (char *)_b > TDB_HTRIE_MINDREC)
			goto next_bckt;
		r = (TdbRec *)((char *)r + rlen);

		do {
			rlen = TDB_HTRIE_RALIGN(sizeof(*r)
						+ TDB_HTRIE_RBODYLEN(dbh, r));
			if ((char *)r + rlen - (char *)_b > TDB_HTRIE_MINDREC)
				break;
			if (tdb_live_rec(dbh, r) && r->key == key)
				/* Unlock the bucket by tdb_rec_put(). */
				return r;
			r = (TdbRec *)((char *)r + rlen);
		} while ((char *)r + sizeof(*r) - (char *)_b
			 <= TDB_HTRIE_MINDREC);
next_bckt:
		*b = TDB_HTRIE_BUCKET_NEXT(dbh, _b);
		if (*b) {
			read_lock_bh(&(*b)->lock);
			r = TDB_HTRIE_BCKT_1ST_REC(*b);
		}
		read_unlock_bh(&_b->lock);
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

	/* Set per-CPU pointers. */
	hdr->pcpu = alloc_percpu(TdbPerCpu);
	if (!hdr->pcpu) {
		TDB_ERR("cannot allocate per-cpu data\n");
		return NULL;
	}
	for_each_possible_cpu(cpu) {
		TdbPerCpu *p = per_cpu_ptr(hdr->pcpu, cpu);
		p->i_wcl = tdb_alloc_blk(hdr);
		p->d_wcl = tdb_alloc_blk(hdr);
	}

	TDB_DBG("init db header: nwb=%lu db_size=%lu rec_len=%u\n",
		atomic64_read(&hdr->nwb), hdr->dbsz, hdr->rec_len);

	return hdr;
}

void
tdb_htrie_exit(TdbHdr *dbh)
{
	free_percpu(dbh->pcpu);
}
