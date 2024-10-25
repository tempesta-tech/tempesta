/** Unit test for Tempesta DB HTrie storage.
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
#include "../../ktest/ktest.h"

/* Include HTrie for test. */
#include "../core/htrie.c"

/*
 * HTrie requires extent-aligned address.
 * These are just some good addresses to be mapped to.
 * Use different map addresses to ensure that data structures and algorithms
 * are address independent.
 */
#define TDB_MAP_ADDR1		((void *)(0x600000000000UL + TDB_EXT_SZ))
#define TDB_MAP_ADDR2		((void *)(0x600000000000UL + TDB_EXT_SZ * 3))

#define TDB_SZ_SMALL		(TDB_EXT_SZ * 16)
#define TDB_SZ_MEDIUM		(TDB_EXT_SZ * 512)
#define TDB_VSF_SZ		(TDB_EXT_SZ * 1024)
#define TDB_FSF_SZ		(TDB_EXT_SZ * 8)
#define THR_N			4
#define DATA_N			100
#define LOOP_N			10

typedef struct {
	unsigned long	key;
	char		data[0];
} TestRecord;

typedef struct {
	unsigned long	key;
	char		data[512];
} TestRecordFix;

typedef struct {
	TdbHdr		*dbh;
	TestRecordFix	*records;
	size_t		rnum;
} ParallelData;

typedef struct {
	unsigned int	key;
	unsigned int	val1;
	unsigned int	val2;
	unsigned int	val3;
	unsigned int	val4;
} TestRecordSmall;

typedef struct {
	char	*data;
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
		for (u = urls; u->data; ++u)
			acc += tdb_hash_calc(u->data, u->len);
	r = gettimeofday(&tv1, NULL);
	assert(!r);
	printf("tdb hash: time=%lums ignore_val=%d\n",
	       tv_to_ms(&tv1) - tv_to_ms(&tv0), acc);

	r = gettimeofday(&tv0, NULL);
	assert(!r);
	for (i = 0; i < N; ++i)
		for (u = urls; u->data; ++u)
			acc += test_hash_calc_dummy(u->data, u->len);
	r = gettimeofday(&tv1, NULL);
	assert(!r);
	printf("dummy hash: time=%lums ignore_val=%d\n",
	       tv_to_ms(&tv1) - tv_to_ms(&tv0), acc);
#undef N
}

void *
tdb_htrie_open(void *addr, const char *fname, size_t size, int *fd)
{
	void *p;
	struct stat sb = { 0 };

	if (!stat(fname, &sb)) {
		printf("filesize: %ld\n", sb.st_size);
	} else {
		TDB_WARN("no files, create them\n");
	}

	if ((*fd = open(fname, O_RDWR|O_CREAT, O_RDWR)) < 0) {
		perror("ERROR: open failure");
		exit(1);
	}

	if (sb.st_size != size)
		if (fallocate(*fd, 0, 0, size)) {
			perror("ERROR: fallocate failure");
			exit(1);
		}

	/* Use MAP_SHARED to carry changes to underlying file. */
	p = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
	if (p != addr) {
		perror("ERROR: cannot mmap the file");
		exit(1);
	}
	printf("maped to %p\n", p);

	if (mlock(p, size)) {
		perror("ERROR: mlock failure, please check rlimit");
		exit(1);
	}

	return p;
}

/**
 * Just free the memory region, the file will be closed on program exit.
 */
void
tdb_htrie_pure_close(void *addr, size_t size, int fd)
{
	munlock(addr, size);
	munmap(addr, size);
	close(fd);
}

#define __print_bin(s, prefix, suffix)					\
do {									\
	int _i, _n = (s)->len < 40 ? (s)->len : 40;			\
	printf(prefix "[0x");						\
	for (_i = 0; _i < _n; ++_i)					\
		printf("%x", (unsigned char)(s)->data[_i]);		\
	printf(_n < (s)->len						\
	       ? "...] (len=%lu)" suffix				\
	       : "] (len=%lu)",						\
	       (unsigned long)(s)->len);				\
} while (0)

static void
print_bin_url(TestUrl *u)
{
	__print_bin(u, "insert ", "\n");
	fflush(NULL);
}

/**
 * Read stored variable sized records.
 */
static void
lookup_varsz_records(TdbHdr *dbh)
{
	int i;
	TestUrl *u;

	/* Skip zero key. */
	for (i = 1, u = urls + 1; i < DATA_N; ++u, ++i) {
		unsigned long k = tdb_hash_calc(u->data, u->len);
		TdbBucket *b;
		TdbRec *r;

		print_bin_url(u);

		b = tdb_htrie_lookup(dbh, k);
		if (!b) {
			fprintf(stderr, "ERROR: can't find bucket for URL"
				" [%.20s...] (key=%#lx)\n", u->data, k);
			fflush(NULL);
			continue;
		}

		BUG_ON(!TDB_HTRIE_VARLENRECS(dbh));

		r = tdb_htrie_bscan_for_rec(dbh, &b, k);
		if (!r) {
			fprintf(stderr, "ERROR: can't find URL %#lx\n", k);
		} else {
			while ((r = tdb_htrie_next_rec(dbh, r, &b, k)))
				;
		}
	}
}

/* Release record using tdb_htrie_put_rec. */
static TdbIter
__tdb_rec_get(TdbHdr *hdr, unsigned long key)
{
	TdbIter iter = { NULL };

	iter.bckt = tdb_htrie_lookup(hdr, key);
	if (!iter.bckt)
		goto out;

	iter.rec = tdb_htrie_bscan_for_rec(hdr, (TdbBucket **)&iter.bckt, key);

out:
	return iter;
}

static TdbVRec *
insert_vrec(TdbHdr *dbh, unsigned long key, void *data, tdb_eq_cb_t *eq_cb,
	    size_t *len, bool complete)
{
	TdbVRec *rec, *root;
	size_t to_copy = *len;
	size_t copied;

	root = (TdbVRec *)tdb_htrie_insert(dbh, key, NULL, eq_cb, data,
					   &to_copy, complete);
	rec = root;
	assert(rec);

	memcpy(rec->data, data, to_copy);
	copied = to_copy;

	while (copied != *len) {
		char *p;

		rec = tdb_htrie_extend_rec(dbh, rec, *len - copied);
		assert(rec);

		p = (char *)(rec->data);
		memcpy(p, data + copied, rec->len);

		copied += rec->len;
	}

	return root;
}

/*
 * Test simple remove.
 */
void
varsz_remove_test(TdbHdr *dbh)
{
	TdbVRec *rec;
	TdbIter iter;
	TestRecord *data;
	size_t len = 13000;

	printf("Start %s\n", __func__);

	data = malloc(len);
	assert(data);
	data->key = rand();

	rec = insert_vrec(dbh, data->key, data, NULL, &len, false);

	/* Try find incomplete record. */
	iter = __tdb_rec_get(dbh, data->key);
	assert(!iter.rec);
	tdb_rec_mark_complete(rec);
	tdb_htrie_put_rec(dbh, (TdbRec *)rec);

	iter = __tdb_rec_get(dbh, data->key);
	assert(iter.rec);

	/* Remove record, but not free, record has user. */
	tdb_htrie_remove(dbh, data->key, NULL, NULL, false);

	iter = __tdb_rec_get(dbh, data->key);
	assert(!iter.rec);

	/* Free record. */
	tdb_htrie_put_rec(dbh, (TdbRec *)rec);
}

static bool
rec_eq(TdbRec *rec, void *data)
{
	TestRecord *r1 = (TestRecord *)(((TdbVRec *)rec) + 1);
	TestRecord *r2 = (TestRecord *)data;

	return r1->key == r2->key;
}

/*
 * Test incomplete record, it must not be found during lookup.
 */
void
varsz_incomplete_test(TdbHdr *dbh)
{
	TdbVRec *rec;
	TdbIter iter;
	TestRecord *data;
	unsigned long key;
	size_t len = 13000;

	printf("Start %s\n", __func__);
	data = malloc(len);
	assert(data);
	key = rand();
	data->key = key;

	rec = insert_vrec(dbh, key, data, rec_eq, &len, false);

	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);

	tdb_rec_mark_complete(rec);
	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);
}

/*
 * Test incomplete record with collision chain, it must not be found during
 * lookup.
 */
void
varsz_col_incomplete_test(TdbHdr *dbh)
{
	TdbVRec *rec;
	TdbIter iter;
	TestRecord *data[4], *ent;
	TdbRec *incomplete[3];
	unsigned long key = 0x1111111111111111;
	size_t len = 13000;
	int col_n = 0;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 4; i++) {
		data[i] = malloc(len);
		assert(data[i]);
		data[i]->key = 1000 + i;
	}

	rec = insert_vrec(dbh, key, data[0], rec_eq, &len, false);
	tdb_rec_mark_complete(rec);
	tdb_htrie_put_rec(dbh, (TdbRec *)rec);

	for (int i = 1; i < 4; i++)
		incomplete[i - 1] = (TdbRec *)insert_vrec(dbh, key, data[i],
							  rec_eq, &len,
							  false);

	iter = __tdb_rec_get(dbh, key);

	assert((char *)iter.rec == (char *)rec);

	while (iter.rec) {
		ent = (TestRecord *)((TdbVRec *)iter.rec)->data;
		assert(ent->key == data[col_n]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	/* Only one record must be found, 3 records are incomplete. */
	assert(col_n == 1);

	/* Mark 3 records as complete. */
	for (int i = 0; i < 3; i++)
		tdb_rec_mark_complete(incomplete[i]);

	iter = __tdb_rec_get(dbh, key);

	col_n = 0;
	while (iter.rec) {
		ent = (TestRecord *)((TdbVRec *)iter.rec)->data;
		assert(ent->key == data[col_n]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	/* All records is complete. */
	assert(col_n == 4);
}

/*
 * Test removing incomplete records with collision chain, only complete records
 * must be removed.
 */
void
varsz_col_remove_incomplete_test(TdbHdr *dbh)
{
	TdbVRec *rec;
	TdbIter iter;
	TestRecord *data[4], *ent;
	TdbRec *incomplete[3];
	unsigned long key = 0x1111111111111111;
	size_t len = 13000;
	int col_n = 0;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 4; i++) {
		data[i] = malloc(len);
		assert(data[i]);
		data[i]->key = 1000 + i;
	}

	rec = insert_vrec(dbh, key, data[0], rec_eq, &len, false);
	tdb_rec_mark_complete(rec);
	tdb_htrie_put_rec(dbh, (TdbRec *)rec);

	for (int i = 1; i < 4; i++)
		incomplete[i - 1] = (TdbRec *)insert_vrec(dbh, key, data[i],
							  rec_eq, &len,
							  false);
	/*
	 * Try to remove all records, however only complete record must be
	 * removed.
	 */
	tdb_htrie_remove(dbh, key, NULL, NULL, false);

	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);

	/* Mark 3 records as complete. */
	for (int i = 0; i < 3; i++) {
		tdb_rec_mark_complete(incomplete[i]);
		tdb_htrie_put_rec(dbh, incomplete[i]);
	}

	iter = __tdb_rec_get(dbh, key);

	col_n = 0;
	while (iter.rec) {
		ent = (TestRecord *)((TdbVRec *)iter.rec)->data;
		/* All records must be found, except first. */
		assert(ent->key == data[col_n + 1]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 3);
}

/*
 * Test removing duplicated records during insertion. Add one record, then
 * add one more the same record, during addition first record must be removed.
 */
void
varsz_remove_dupl_test(TdbHdr *dbh)
{
	TdbVRec *rec, *rec2;
	int num = 0;
	TdbIter iter;
	TestRecord *data;
	unsigned long key;
	size_t len = 13000;

	printf("Start %s\n", __func__);
	data = malloc(len);
	assert(data);
	key = rand();
	data->key = key;

	rec = insert_vrec(dbh, key, data, rec_eq, &len, false);
	tdb_rec_mark_complete(rec);
	tdb_htrie_put_rec(dbh, (TdbRec *)rec);

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);
	rec = (TdbVRec *)iter.rec;

	/* First inserted record must be removed during this insertion. */
	rec2 = insert_vrec(dbh, key, data, rec_eq, &len, false);
	tdb_rec_mark_complete(rec2);
	tdb_htrie_put_rec(dbh, (TdbRec *)rec2);

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);
	while (iter.rec) {
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		num++;
	}

	assert(num == 1);

	/* Free first record. */
	tdb_htrie_put_rec(dbh, (TdbRec *)rec);
}

/*
 * Test bucket reuse. Add 4 records, save them buckets and remove all records,
 * again add 4 records, check that records placed to the same buckets.
 */
void
varsz_bucket_reuse_test(TdbHdr *dbh)
{
	TdbVRec *rec;
	TdbIter iter;
	TestRecord *data[4], *ent;
	TdbBucket *bckts[4];
	unsigned long key = 0x1111111111111111;
	size_t len = 13000;
	int col_n = 0;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 4; i++) {
		data[i] = malloc(len);
		assert(data[i]);
		data[i]->key = 1000 + i;
	}

	for (int i = 0; i < 4; i++) {
		rec = insert_vrec(dbh, key, data[i], rec_eq, &len, false);
		tdb_rec_mark_complete(rec);
		tdb_htrie_put_rec(dbh, (TdbRec *)rec);
	}

	iter = __tdb_rec_get(dbh, key);

	while (iter.rec) {
		bckts[col_n] = iter.bckt;
		ent = (TestRecord *)((TdbVRec *)iter.rec)->data;
		assert(ent->key == data[col_n]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 4);

	tdb_htrie_remove(dbh, key, NULL, NULL, false);

	for (int i = 0; i < 4; i++) {
		rec = insert_vrec(dbh, key, data[i], rec_eq, &len, false);
		tdb_rec_mark_complete(rec);
		tdb_htrie_put_rec(dbh, (TdbRec *)rec);
	}

	iter = __tdb_rec_get(dbh, key);

	col_n = 0;
	while (iter.rec) {
		assert(bckts[col_n] == iter.bckt);
		ent = (TestRecord *)((TdbVRec *)iter.rec)->data;
		assert(ent->key == data[col_n]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 4);
}

static void
do_varsz(TdbHdr *dbh)
{
	int i;
	TdbVRec *rec;
	TestUrl *u = urls;
	unsigned long k = tdb_hash_calc(u->data, u->len);
	size_t to_copy = u->len;

	rec = (TdbVRec *)tdb_htrie_insert(dbh, k, u->data, NULL, NULL, &to_copy,
					  false);
	/* Record with zero key can't be inserted. */
	assert(!rec);

	/* Store records. */
	for (i = 1, u = urls + 1; i < DATA_N; ++u, ++i) {
		k = tdb_hash_calc(u->data, u->len);
		size_t copied;
		TdbVRec *e_rec;

		to_copy = u->len;
		print_bin_url(u);

		rec = (TdbVRec *)tdb_htrie_insert(dbh, k, u->data, NULL, NULL,
						  &to_copy, false);
		assert((u->len && rec) || (!u->len && !rec));

		copied = to_copy;

		e_rec = rec;
		while (copied != u->len) {
			char *p;

			e_rec = tdb_htrie_extend_rec(dbh, e_rec,
						     u->len - copied);
			assert(e_rec);

			p = (char *)(e_rec + 1);
			memcpy(p, u->data + copied, e_rec->len);

			copied += e_rec->len;
		}
		tdb_rec_mark_complete(rec);
		tdb_htrie_put_rec(dbh, (TdbRec *)rec);
	}

	lookup_varsz_records(dbh);
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

/**
 * Read stored fixed size records.
 */
void
lookup_fixsz_records(TdbHdr *dbh)
{
	int i;

	/* Skip zero key. */
	for (i = 1; i < DATA_N; ++i) {
		TdbBucket *b;
		TdbRec *r;

		printf("results for int %u lookup:\n", ints[i]);
		fflush(NULL);

		b = tdb_htrie_lookup(dbh, ints[i]);
		if (!b) {
			fprintf(stderr, "ERROR: can't find bucket for int %u\n",
				ints[i]);
			fflush(NULL);
			continue;
		}

		BUG_ON(TDB_HTRIE_VARLENRECS(dbh));

		r = tdb_htrie_bscan_for_rec(dbh, &b, ints[i]);
		if (!r) {
			fprintf(stderr, "ERROR: can't find int %u\n", ints[i]);
		} else {
			while ((r = tdb_htrie_next_rec(dbh, r, &b, ints[i])))
				;
		}
	}
}

bool
fix_req_eq(TdbRec *rec, void *data)
{
	TestRecordFix *trec = (TestRecordFix *)rec->data;
	TestRecordFix *trec2 = data;

	return trec->key == trec2->key;
}

void
fixsz_remove_simple_test(TdbHdr *dbh)
{
	TdbRec *rec;
	TdbIter iter;
	size_t copied = sizeof(TestRecordFix);
	unsigned long key = 0x1111111111111111;
	TestRecordFix data = {0xAA};

	printf("Start %s\n", __func__);

	data.key = 123;
	rec = tdb_htrie_insert(dbh, key, &data, NULL, NULL, &copied,
			       true);
	assert(rec && copied == sizeof(TestRecordFix));
	tdb_htrie_put_rec(dbh, rec);

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);

	tdb_htrie_remove(dbh, key, fix_req_eq, &data, false);

	tdb_htrie_put_rec(dbh, iter.rec);

	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);
}

void
fixsz_remove_all_test(TdbHdr *dbh)
{
	TdbRec *rec;
	TdbIter iter;
	size_t copied = sizeof(TestRecordFix);
	unsigned long key = 0x1111111111111111;
	TestRecordFix *data[4], *ent;
	int col_n = 0;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 4; i++) {
		data[i] = malloc(sizeof(TestRecordFix));
		assert(data[i]);
		data[i]->key = 1000 + i;
	}

	for (int i = 0; i < 4; i++) {
		rec = tdb_htrie_insert(dbh, key, data[i], NULL, NULL, &copied,
				       true);
		assert(rec && copied == sizeof(TestRecordFix));
		tdb_htrie_put_rec(dbh, rec);
	}

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);

	while (iter.rec) {
		ent = (TestRecordFix *)iter.rec->data;
		assert(ent->key == data[col_n]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 4);

	tdb_htrie_remove(dbh, key, NULL, NULL, false);

	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);
}

void
fixsz_remove_col_test(TdbHdr *dbh)
{
	TdbRec *rec;
	size_t copied = sizeof(TestRecordFix);
	TdbIter iter;
	unsigned long key = 0x1111111111111111;
	TestRecordFix *data[4], *ent;
	int col_n = 0;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 4; i++) {
		data[i] = malloc(sizeof(TestRecordFix));
		assert(data[i]);
		data[i]->key = 1000 + i;
	}

	for (int i = 0; i < 4; i++) {
		rec = tdb_htrie_insert(dbh, key, data[i], NULL, NULL, &copied,
				       true);
		assert(rec && copied == sizeof(TestRecordFix));
		tdb_htrie_put_rec(dbh, rec);
	}

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);

	while (iter.rec) {
		ent = (TestRecordFix *)iter.rec->data;
		assert(ent->key == data[col_n]->key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 4);

	tdb_htrie_remove(dbh, key, &fix_req_eq, data[3], false);
	tdb_htrie_remove(dbh, key, &fix_req_eq, data[0], false);
	tdb_htrie_remove(dbh, key, &fix_req_eq, data[2], false);

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);
	col_n = 0;

	while (iter.rec) {
		ent = (TestRecordFix *)iter.rec->data;
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 1);
	assert(ent->key == data[1]->key);

	tdb_htrie_remove(dbh, key, &fix_req_eq, data[1], false);
	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);
}

void
fixsz_remove_small_test(TdbHdr *dbh)
{
	TdbRec *rec;
	size_t copied = sizeof(TestRecordSmall);
	unsigned long key = 0x1111111111111111;
	TestRecordSmall data = {0xAA};
	TdbIter iter;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 3; i++) {
		data.key = 10000 + i;
		rec = tdb_htrie_insert(dbh, key, &data, NULL, NULL, &copied,
				       true);
		assert(rec && copied == sizeof(TestRecordSmall));
		tdb_htrie_put_rec(dbh, rec);
	}

	tdb_htrie_remove(dbh, key, NULL, NULL, false);

	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);
}

bool
fix_req_eq_small(TdbRec *rec, void *data)
{
	TestRecordSmall *trec = (TestRecordSmall *)rec->data;
	TestRecordSmall *trec2 = data;

	return trec->key == trec2->key;
}

void
fixsz_remove_col_small_test(TdbHdr *dbh)
{
	TdbRec *rec;
	size_t copied = sizeof(TestRecordSmall);
	TdbIter iter;
	unsigned long key = 0x1111111111111111;
	TestRecordSmall data[4] = {{0xAA}}, *ent;
	int col_n = 0;

	printf("Start %s\n", __func__);

	for (int i = 0; i < 4; i++)
		data[i].key = 1000 + i;

	for (int i = 0; i < 4; i++) {
		rec = tdb_htrie_insert(dbh, key, &data[i], NULL, NULL, &copied,
				       true);
		assert(rec && copied == sizeof(TestRecordSmall));
		tdb_htrie_put_rec(dbh, rec);
	}

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);

	while (iter.rec) {
		ent = (TestRecordSmall *)iter.rec->data;
		assert(ent->key == data[col_n].key);
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 4);

	tdb_htrie_remove(dbh, key, &fix_req_eq_small, &data[3], false);
	tdb_htrie_remove(dbh, key, &fix_req_eq_small, &data[0], false);
	tdb_htrie_remove(dbh, key, &fix_req_eq_small, &data[2], false);

	iter = __tdb_rec_get(dbh, key);
	assert(iter.rec);
	col_n = 0;

	while (iter.rec) {
		ent = (TestRecordSmall *)iter.rec->data;
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 1);
	assert(ent->key == data[1].key);

	tdb_htrie_remove(dbh, key, &fix_req_eq, &data[1], false);
	iter = __tdb_rec_get(dbh, key);
	assert(!iter.rec);
}

void
fixsz_remove_small_burst_test(TdbHdr *dbh)
{
	TdbRec *rec;
	TdbIter iter;
	int col_n = 0;
	size_t copied = sizeof(TestRecordSmall);
	unsigned long key[4];
	TestRecordSmall data[4] = {{0xAA}}, *ent;

	printf("Start %s\n", __func__);

	key[0] = 0x1111111111111111;
	key[1] = 0x1111111111111121;
	key[2] = 0x1111111111111221;
	key[3] = 0x1111111111112221;

	for (int i = 0; i < 4; i++)
		data[i].key = 10000 + i;

	/* One record in first bucket and 3 records in new bucket. */
	for (int i = 0; i < 4; i++) {
		rec = tdb_htrie_insert(dbh, key[i], &data[i], NULL, NULL,
				       &copied, true);
		assert(rec && copied == sizeof(TestRecordSmall));
		tdb_htrie_put_rec(dbh, rec);
	}

	iter = __tdb_rec_get(dbh, key[0]);
	assert(iter.rec);

	ent = (TestRecordSmall *)iter.rec->data;
	assert(ent->key == data[0].key);

	while (iter.rec) {
		iter.rec = tdb_htrie_next_rec(dbh, iter.rec,
					      (TdbBucket **)&iter.bckt,
					      iter.rec->key);
		col_n++;
	}

	assert(col_n == 1);

	/* Try to find last inserted record. */
	iter = __tdb_rec_get(dbh, key[3]);
	assert(iter.rec);
	tdb_htrie_put_rec(dbh, iter.rec);

	/* Remove record from first bucket and from second bucket. */
	tdb_htrie_remove(dbh, key[0], &fix_req_eq_small, &data[0], false);
	tdb_htrie_remove(dbh, key[3], &fix_req_eq_small, &data[3], false);

	iter = __tdb_rec_get(dbh, key[0]);
	assert(!iter.rec);

	iter = __tdb_rec_get(dbh, key[3]);
	assert(!iter.rec);

	tdb_htrie_remove(dbh, key[2], &fix_req_eq_small, &data[2], false);
	tdb_htrie_remove(dbh, key[1], &fix_req_eq_small, &data[1], false);

	iter = __tdb_rec_get(dbh, key[2]);
	assert(!iter.rec);

	iter = __tdb_rec_get(dbh, key[1]);
	assert(!iter.rec);
}

static void *
init_test_data_for_stress(size_t num)
{
	int i, rfd;
	size_t size = sizeof(TestRecordFix);
	TestRecordFix *recs;

	printf("prepare fixed size testing data...\n");
	recs = malloc(size * num);
	assert(recs);

	if ((rfd = open("/dev/urandom", O_RDONLY)) < 0)
		TDB_ERR("cannot open /dev/urandom\n");

	for (i = 0; i < num; ++i) {
		int r;

		r = read(rfd, recs[i].data, sizeof(recs[i].data));
		if (!r)
			printf("Errno: %i", r);
		BUG_ON(!r);
		recs[i].key = tdb_hash_calc(recs[i].data,
					    sizeof(recs[i].data)) & 0xFFFFFFFF;
		if (r <= 0) {
			TDB_ERR("can't read urandom data\n");
			BUG();
		}
	}

	close(rfd);

	return recs;
}

void
insert_fixsz_trecs(TdbHdr *dbh, TestRecordFix *records, size_t num)
{
	int i;

	/* Store records. */
	for (i = 0; i < num; ++i) {
		size_t copied = sizeof(TestRecordFix);
		TdbRec *rec;

		rec = tdb_htrie_insert(dbh, records[i].key, &records[i], NULL,
				       NULL, &copied, true);
		assert(rec);
		tdb_htrie_put_rec(dbh, rec);
		assert(rec && copied == sizeof(records[i]));
	}
}

void
lookup_fixsz_trecs(TdbHdr *dbh, TestRecordFix *records, size_t num, bool strict)
{
	int i;
	TdbRec *r;

	for (i = 0; i < num; ++i) {
		TdbBucket *b;

		b = tdb_htrie_lookup(dbh, records[i].key);
		if (!b) {
			fprintf(stderr, "ERROR: can't find bucket for int %lu\n",
				records[i].key);
			continue;
		}

		BUG_ON(TDB_HTRIE_VARLENRECS(dbh));

		r = tdb_htrie_bscan_for_rec(dbh, &b, records[i].key);
		if (strict) {
			assert(r);
			while ((r = tdb_htrie_next_rec(dbh, r, &b, records[i].key)))
				;
		}
	}
}

void
remove_fixsz_trecs(TdbHdr *dbh, TestRecordFix *records, size_t num)
{
	int i;

	for (i = 0; i < num; ++i) {
		tdb_htrie_remove(dbh, records[i].key, fix_req_eq, &records[i],
				 false);
	}
}

void
fixsz_remove_stress(TdbHdr *dbh)
{
#define S_LOOP_N 100
#define S_DATA_N 1000
	int i;
	TestRecordFix *records;

	printf("Start %s\n", __func__);

	for (i = 0; i < S_LOOP_N; i++) {
		records = init_test_data_for_stress(S_DATA_N);
		insert_fixsz_trecs(dbh, records, S_DATA_N);
		lookup_fixsz_trecs(dbh, records, S_DATA_N, true);
		remove_fixsz_trecs(dbh, records, S_DATA_N);
		free(records);
	}

#undef S_LOOP_N
#undef S_DARA_N
}

void *
fixsz_rm_insert_f(void *arg)
{
#define S_LOOP_N 100
	int i = 0;
	ParallelData *data = (ParallelData *)arg;

	for (i = 0; i < S_LOOP_N; i++) {
		insert_fixsz_trecs(data->dbh, data->records, data->rnum);
		lookup_fixsz_trecs(data->dbh, data->records, data->rnum, false);
		remove_fixsz_trecs(data->dbh, data->records, data->rnum);
	}

	return NULL;

#undef S_LOOP_N
}

void
fixsz_rm_insert_parallel(TdbHdr *dbh)
{
#define S_DATA_N 1000
#define S_THR_N 22
	int i, t;
	TestRecordFix *records;
	pthread_t thr[S_THR_N];
	ParallelData arg;

	printf("Start %s\n", __func__);

	records = init_test_data_for_stress(S_DATA_N);
	arg.dbh = dbh;
	arg.records = records;
	arg.rnum = S_DATA_N;

	for (t = 0; t < S_THR_N; ++t)
		if (spawn_thread(thr + t, fixsz_rm_insert_f, &arg))
			perror("cannot spawn varsz thread");
	for (t = 0; t < S_THR_N; ++t)
		pthread_join(thr[t], NULL);

	/* Check all records removed. */
	for (i = 0; i < S_DATA_N; ++i) {
		TdbIter iter;

		iter = __tdb_rec_get(dbh, records[i].key);
		if (iter.rec) {
			printf("ERROR: Record must not be found\n");
			BUG();
		}
	}

	free(records);

#undef S_DARA_N
#undef S_THR_N
}

static void
do_fixsz(TdbHdr *dbh)
{
	int i;
	TdbRec *rec;
	size_t copied = sizeof(ints[i]);

	rec = tdb_htrie_insert(dbh, ints[0], &ints[0], NULL, NULL, &copied,
			       true);
	/* Record with zero key can't be inserted. */
	assert(!rec);

	/* Store records. */
	for (i = 1; i < DATA_N; ++i) {
		copied = sizeof(ints[i]);

		printf("insert int %u\n", ints[i]);
		fflush(NULL);

		rec = tdb_htrie_insert(dbh, ints[i], &ints[i], NULL, NULL,
				       &copied, true);
		assert(rec && copied == sizeof(ints[i]));
		tdb_htrie_put_rec(dbh, rec);
	}

	lookup_fixsz_records(dbh);
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
tdb_htrie_run_test(const char *fname, size_t db_size,
		   void (*fn)(TdbHdr *dbh), unsigned int rec_len)
{
	int r __attribute__((unused));
	int fd;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;

	if (rec_len == 0)
		printf("\n----------- Variable size records test -------------\n");
	else
		printf("\n----------- Fixed size records test -------------\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR1, fname, db_size, &fd);
	dbh = tdb_htrie_init(addr, db_size, rec_len);
	if (!dbh)
		TDB_ERR("cannot initialize htrie for test");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	fn(dbh);

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie test: time=%lums\n",
		tv_to_ms(&tv1) - tv_to_ms(&tv0));

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, db_size, fd);
	remove(fname);
}

void
tdb_htrie_test_varsz(const char *fname)
{
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, varsz_remove_test, 0);
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, varsz_remove_dupl_test, 0);
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, varsz_incomplete_test, 0);
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, varsz_col_incomplete_test, 0);
	tdb_htrie_run_test(fname, TDB_SZ_SMALL,
			   varsz_col_remove_incomplete_test, 0);
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, varsz_bucket_reuse_test, 0);
}

void
tdb_htrie_test_fixsz(const char *fname)
{
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, fixsz_remove_simple_test,
			   sizeof(TestRecordFix));
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, fixsz_remove_all_test,
			   sizeof(TestRecordFix));
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, fixsz_remove_col_test,
			   sizeof(TestRecordFix));
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, fixsz_remove_small_test,
			   sizeof(TestRecordSmall));
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, fixsz_remove_small_burst_test,
			   sizeof(TestRecordSmall));
	tdb_htrie_run_test(fname, TDB_SZ_SMALL, fixsz_remove_col_small_test,
			   sizeof(TestRecordSmall));
	tdb_htrie_run_test(fname, TDB_FSF_SZ, fixsz_remove_stress,
			   sizeof(TestRecordFix));
	tdb_htrie_run_test(fname, TDB_SZ_MEDIUM, fixsz_rm_insert_parallel,
			   sizeof(TestRecordFix));
}

void
tdb_htrie_test_varsz_mthread(const char *fname)
{
	int r __attribute__((unused));
	int t, fd;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;
	pthread_t thr[THR_N];

	printf("Run test with parameters:\n"
	       "\tfix rec db size: %lu\n"
	       "\tvar rec db size: %lu\n"
	       "\textent size:     %lu\n"
	       "\tthreads number:  %d\n"
	       "\tdata size:       %d\n"
	       "\tloops:           %d\n",
	       TDB_FSF_SZ, TDB_VSF_SZ, TDB_EXT_SZ,
	       THR_N, DATA_N, LOOP_N);

	printf("\n----------- Variable size records test mthread -------------\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR1, fname, TDB_VSF_SZ, &fd);
	dbh = tdb_htrie_init(addr, TDB_VSF_SZ, 0);
	if (!dbh)
		TDB_ERR("cannot initialize htrie for urls");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	for (t = 0; t < THR_N; ++t)
		if (spawn_thread(thr + t, varsz_thr_f, dbh))
			perror("cannot spawn varsz thread");
	for (t = 0; t < THR_N; ++t)
		pthread_join(thr[t], NULL);

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie urls test: time=%lums\n",
		tv_to_ms(&tv1) - tv_to_ms(&tv0));

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, TDB_VSF_SZ, fd);

	printf("\n	**** Variable size records test reopen mthread ****\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR2, fname, TDB_VSF_SZ, &fd);
	dbh = tdb_htrie_init(addr, TDB_VSF_SZ, 0);
	if (!dbh)
		TDB_ERR("cannot initialize htrie for urls");

	lookup_varsz_records(dbh);

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, TDB_VSF_SZ, fd);
	remove(fname);
}

void
tdb_htrie_test_fixsz_mthread(const char *fname)
{
	int r __attribute__((unused));
	int t, fd;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;
	pthread_t thr[THR_N];

	printf("Run test with parameters:\n"
	       "\tfix rec db size: %lu\n"
	       "\tvar rec db size: %lu\n"
	       "\textent size:     %lu\n"
	       "\tthreads number:  %d\n"
	       "\tdata size:       %d\n"
	       "\tloops:           %d\n",
	       TDB_FSF_SZ, TDB_VSF_SZ, TDB_EXT_SZ,
	       THR_N, DATA_N, LOOP_N);

	printf("\n----------- Fixed size records test mthread -------------\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR1, fname, TDB_FSF_SZ, &fd);
	dbh = tdb_htrie_init(addr, TDB_FSF_SZ, sizeof(ints[0]));
	if (!dbh)
		TDB_ERR("cannot initialize htrie for ints");

	r = gettimeofday(&tv0, NULL);
	assert(!r);

	for (t = 0; t < THR_N; ++t)
		if (spawn_thread(thr + t, fixsz_thr_f, dbh))
			perror("cannot spawn fixsz thread");
	for (t = 0; t < THR_N; ++t)
		pthread_join(thr[t], NULL);

	r = gettimeofday(&tv1, NULL);
	assert(!r);

	printf("tdb htrie ints test: time=%lums\n",
		tv_to_ms(&tv1) - tv_to_ms(&tv0));

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, TDB_FSF_SZ, fd);

	printf("\n	**** Fixed size records test reopen mthread ****\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR2, fname, TDB_FSF_SZ, &fd);
	dbh = tdb_htrie_init(addr, TDB_FSF_SZ, sizeof(ints[0]));
	if (!dbh)
		TDB_ERR("cannot initialize htrie for ints");

	lookup_fixsz_records(dbh);

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, TDB_FSF_SZ, fd);
	remove(fname);
}

static void
tdb_remove_files(const char *vsf, const char *fsf)
{
	if (!access(vsf, F_OK))
		remove(vsf);
	if (!access(fsf, F_OK))
		remove(fsf);
}

static void
tdb_htrie_test(const char *vsf, const char *fsf)
{
	tdb_htrie_test_varsz(vsf);
	tdb_htrie_test_fixsz(fsf);
	tdb_htrie_test_varsz_mthread(vsf);
	tdb_htrie_test_fixsz_mthread(fsf);
}

static void
init_test_data_for_hash(void)
{
	TestUrl *u;

	/* Load urls pages and precompute string lengths (with terminator). */
	for (u = urls; u->data; ++u)
		u->len = strlen(u->data) + 1;
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
		urls[i].data = malloc(r + 1);
		if (!urls[i].data) {
			TDB_ERR("not enough memory\n");
			BUG();
		}
		r = read(rfd, urls[i].data, r);
		if (r <= 0) {
			TDB_ERR("can't read urandom data\n");
			BUG();
		}
		urls[i].data[r] = 0;
		urls[i].len = r + 1;
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

	init_test_data_for_hash();
	hash_calc_benchmark();

	init_test_data_for_htrie();
	tdb_remove_files(argv[1], argv[2]);
	tdb_htrie_test(argv[1], argv[2]);

	return 0;
}
