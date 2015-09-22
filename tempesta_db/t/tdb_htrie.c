/**
 * Unit test for Tempesta DB HTrie storage.
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

#define TDB_VSF_SZ		(TDB_EXT_SZ * 1024)
#define TDB_FSF_SZ		(TDB_EXT_SZ * 8)
#define THR_N			4
#define DATA_N			100
#define LOOP_N			10

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
		perror("ERROR: mlock failure");
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

	for (i = 0, u = urls; i < DATA_N; ++u, ++i) {
		unsigned long k = tdb_hash_calc(u->data, u->len);
		TdbBucket *b;

		print_bin_url(u);

		b = tdb_htrie_lookup(dbh, k);
		if (!b) {
			fprintf(stderr, "ERROR: can't find bucket for URL"
				" [%.20s...] (key=%#lx)\n", u->data, k);
			fflush(NULL);
			continue;
		}

		BUG_ON(!TDB_HTRIE_VARLENRECS(dbh));

		if (!tdb_htrie_bscan_for_rec(dbh, b, k))
			fprintf(stderr, "ERROR: can't find URL %#lx\n", k);
	}
}

static void
do_varsz(TdbHdr *dbh)
{
	int i;
	TestUrl *u;

	/* Store records. */
	for (i = 0, u = urls; i < DATA_N; ++u, ++i) {
		unsigned long k = tdb_hash_calc(u->data, u->len);
		size_t copied, to_copy = u->len;
		TdbVRec *rec;

		print_bin_url(u);

		rec = (TdbVRec *)tdb_htrie_insert(dbh, k, u->data, &to_copy);
		assert((u->len && rec) || (!u->len && !rec));

		copied = to_copy;

		while (copied != u->len) {
			char *p;

			rec = tdb_htrie_extend_rec(dbh, rec, u->len - copied);
			assert(rec);

			p = (char *)(rec + 1);
			memcpy(p, u->data + copied, rec->len);

			copied += rec->len;
		}
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
static void
lookup_fixsz_records(TdbHdr *dbh)
{
	int i;

	for (i = 0; i < DATA_N; ++i) {
		TdbBucket *b;

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

		if (!tdb_htrie_bscan_for_rec(dbh, b, ints[i]))
			fprintf(stderr, "ERROR: can't find int %u\n", ints[i]);
	}
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
tdb_htrie_test_varsz(const char *fname)
{
	int r __attribute__((unused));
	int t, fd;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;
	pthread_t thr[THR_N];

	printf("\n----------- Variable size records test -------------\n");

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

	printf("\n	**** Variable size records test reopen ****\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR2, fname, TDB_VSF_SZ, &fd);
	dbh = tdb_htrie_init(addr, TDB_VSF_SZ, 0);
	if (!dbh)
		TDB_ERR("cannot initialize htrie for urls");

	lookup_varsz_records(dbh);

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, TDB_VSF_SZ, fd);
}

void
tdb_htrie_test_fixsz(const char *fname)
{
	int r __attribute__((unused));
	int t, fd;
	char *addr;
	TdbHdr *dbh;
	struct timeval tv0, tv1;
	pthread_t thr[THR_N];

	printf("\n----------- Fixed size records test -------------\n");

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

	printf("\n	**** Fixed size records test reopen ****\n");

	addr = tdb_htrie_open(TDB_MAP_ADDR2, fname, TDB_FSF_SZ, &fd);
	dbh = tdb_htrie_init(addr, TDB_FSF_SZ, sizeof(ints[0]));
	if (!dbh)
		TDB_ERR("cannot initialize htrie for ints");

	lookup_fixsz_records(dbh);

	tdb_htrie_exit(dbh);
	tdb_htrie_pure_close(addr, TDB_FSF_SZ, fd);
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
