/**
 *		Tempesta DB
 *
 * Index and memory management for cache conscious Burst Hash Trie.
 *
 * If index is not SEQLOG (i.e. no index at all), then to improve space locality
 * for large data sets index records grow from lower addresses to higher while
 * data records grow towards them, from maximum to minimum addresses.
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
#include <linux/bitops.h>

#include "htrie.h"

#define TDB_MAGIC	0x434947414D424454UL /* "TDBMAGIC" */

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
	TdbHdr *hdr = (TdbHdr *)p;

	/* Use variable-size records for large stored data. */
	if (rec_len > PAGE_SIZE / 2)
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

	if (align_len > PAGE_SIZE) {
		*len -= align_len - PAGE_SIZE;
		align_len = PAGE_SIZE;
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
tdb_alloc_blk(TdbHdr *dbh, TdbExt *e)
{
	int i;
	unsigned long r;

	for (i = 0; i < TDB_BLK_BMP_2L; ++i) {
		if (!(e->b_bmp[i] ^ ~0UL))
			continue;

		r = ffz(e->b_bmp[i]);
		set_bit(r, &e->b_bmp[i]);
		r = TDB_EXT_BASE(dbh, e) + r * PAGE_SIZE;
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
	TdbExt *e = tdb_ext(dbh, TDB_PTR(dbh, dbh->i_wcl));

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
	TdbExt *e = tdb_ext(dbh, TDB_PTR(dbh, dbh->d_wcl));

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

	BUG_ON(len > PAGE_SIZE);

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
			nb[k].b = tdb_alloc_data(dbh, 0);		\
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
	k = TDB_HTRIE_IDX(key, bits - TDB_HTRIE_BITS);
	(*node)->shifts[k] = new_in_idx;
	*node = new_in;

	/* Now we can safely remove all copied records. */
	if (free_nb > 0) {
		TDB_DBG("clear dblk=%#lx from %#x\n",
			nb[free_nb].b, nb[free_nb].off);
		memset(TDB_PTR(dbh, nb[free_nb].b + nb[free_nb].off), 0,
		       TDB_HTRIE_MINDREC - nb[free_nb].off);
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
		     void *data, size_t len, int init_bucket)
{
	char *ptr = TDB_PTR(dbh, off);
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
TdbVRec *
tdb_htrie_extend_rec(TdbHdr *dbh, TdbVRec *rec, size_t size)
{
	unsigned long o;
	TdbVRec *chunk;

	/* Cannot extend fixed-size records. */
	BUG_ON(!TDB_HTRIE_VARLENRECS(dbh));

	o = tdb_alloc_data(dbh, tdb_full_rec_len(dbh, &size));
	if (!o)
		return NULL;

	chunk = TDB_PTR(dbh, o);
	chunk->key = rec->key;
	chunk->chunk_next = 0;
	chunk->len = size;

	/* A caller is appreciated to pass the last record chunk by @rec. */
	while (unlikely(rec->chunk_next))
		rec = TDB_PTR(dbh, TDB_DI2O(rec->chunk_next));
	BUG_ON(!tdb_live_vsrec(rec));

	rec->chunk_next = o;

	return chunk;
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

		node->shifts[TDB_HTRIE_IDX(key, bits)] = TDB_O2DI(o)
							 | TDB_HTRIE_DBIT;

		return rec;
	}

	/*
	 * HTrie collision.
	 */
	bckt = TDB_PTR(dbh, o);
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
		bckt->coll_next = TDB_O2DI(o);
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
