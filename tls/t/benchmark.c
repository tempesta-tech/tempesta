/**
 *		Tempesta TLS benchmark for crypto routines
 *
 * Copyright (C) 2020 Tempesta Technologies, INC.
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
#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "ttls_mocks.h"
/* mpool.c requires ECP and DHM routines. */
#include "../asn1.c"
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../ec_p256.c"
#include "../ecp.c"
#include "../ecdh.c"
#include "../pk.c"
#include "../mpool.c"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP384_G = {};
const TlsEcpGrp CURVE25519_G = {};

#define BM_TIME		10
static bool		run_bm;
static unsigned long	iter;

static void
fill_random(unsigned char *buf, size_t bytes)
{
	int rd = open("/dev/urandom", O_RDONLY);
	read(rd, buf, bytes);
	close(rd);
}

static void
bm_timeout(int sig)
{
	run_bm = false;
}

unsigned long
tv_to_ms(const struct timeval *tv)
{
	return ((unsigned long)tv->tv_sec * 1000000 + tv->tv_usec) / 1000;
}

#define BENCHMARK(desc, bm_func)					\
do {									\
	unsigned long t;						\
	struct timeval tv0, tv1;					\
									\
	printf(" %s:\t", desc);						\
									\
	/* We need only the single rare signal, so signal(2) is fine here. */\
	signal(SIGALRM, bm_timeout);					\
	alarm(BM_TIME);							\
									\
	gettimeofday(&tv0, NULL);					\
	for (iter = 0, run_bm = true; run_bm; ++iter) {			\
		bm_func;						\
	}								\
	gettimeofday(&tv1, NULL);					\
									\
	t = tv_to_ms(&tv1) - tv_to_ms(&tv0);				\
	printf("ops=%lu time=%lums ops/s=%lu\n", iter, t, iter * 1000 / t); \
} while (0)

void
bm_ecdsa_sign_p256(void)
{
	/*
	 * Just some constants used as the key - hopefully they don't
	 * affect speed of the test.
	 */
#define EC_Qx								   \
	"\xB8\x81\xE6\x91\x1E\xAD\xA2\x23\x61\xC5\x48\x7D\x77\xC6\xD2\x49" \
	"\xDD\x38\xFF\xF8\xF7\x5E\xC2\x8D\x08\xFA\x02\x5B\x8C\xD4\xCE\x5B"
#define EC_Qy								   \
	"\x80\xDF\x24\x74\xAB\x78\x97\x59\xF4\x09\x6A\x6C\xFD\xD4\x26\xD5" \
	"\x32\x6D\x6B\xC3\xEA\x6F\xB5\x02\x2B\x1E\x7A\xB6\x79\x43\x62\x6A"
#define EC_d								   \
	"\xC7\x1C\xBC\x8A\xCA\x38\xF7\xC9\x97\xF9\x3A\x6C\xBD\xFD\xCF\x7F" \
	"\x4C\x9D\x32\xAA\x35\x1F\x49\xDB\xF4\x7D\x72\xD6\x64\x2F\x06\xDC"

	int r;
	TlsMpiPool *mp;
	TlsEcpKeypair *ctx;
	size_t slen;
	char hash[32], sig[80];

	mp = ttls_mpi_pool_create(TTLS_MPOOL_ORDER, GFP_KERNEL);
	BUG_ON(!mp);
	ctx = ttls_mpool_alloc_data(mp, sizeof(*ctx));
	BUG_ON(!ctx);
	ctx->grp = ttls_ecp_group_lookup(TTLS_ECP_DP_SECP256R1);
	BUG_ON(!ctx->grp);

	ttls_mpi_read_binary(&ctx->Q.X, EC_Qx, 32);
	ttls_mpi_read_binary(&ctx->Q.Y, EC_Qy, 32);
	ttls_mpi_lset(&ctx->Q.Z, 1);
	ttls_mpi_read_binary(&ctx->d, EC_d, 32);

	fill_random(hash, 32);

	/*
	 * TODO #1064: move the pregenerated G multiplies out of the loop
	 * - OpenSSL speed does the same.
	 */
	BENCHMARK("ECDSA sign (nistp256)",
		r = ctx->grp->ecdsa_sign(&ctx->d, hash, 32, sig, &slen);
		BUG_ON(r);
		ttls_mpi_pool_cleanup_ctx(0, false);
	);
#undef EC_d
#undef EC_Qy
#undef EC_Qx
}

void
bm_ecdhe_srv_p256(void)
{
	int r;
	size_t n;
	TlsECDHCtx *ctx;
	TlsMpiPool *mp;
	unsigned char buf[128] = {0}, pms[TTLS_PREMASTER_SIZE] = {0};
	const char clnt_buf[66] = "\x41\x04\xCE\xD4\x8B\x4C\x8A\x45"
				  "\xA2\x08\xF8\x1F\xFD\xAF\xA6\x8C"
				  "\x75\x21\x19\x95\xC5\x10\xB1\xDB"
				  "\x19\xA7\x0D\xA2\x9F\x33\x82\x70"
				  "\x90\xE0\x94\xA3\x0B\xE5\xA4\xB1"
				  "\xBD\x8A\x9B\x3E\xF3\x2C\x43\x02"
				  "\x58\x88\x64\x88\x64\x22\xB8\xE6"
				  "\xE9\x84\x9D\x52\x79\x7C\x9C\x74"
				  "\x8F\x67";

	mp = ttls_mpi_pool_create(TTLS_MPOOL_ORDER, GFP_KERNEL);
	BUG_ON(!mp);

	/*
	 * Copy (clone) ECDH context from the MPI profile for Secp256r1 PK
	 * operations, see __mpi_profile_clone().
	 * Correctness of the group load is tested in test_ecp.c.
	 */
	ctx = ttls_mpool_alloc_data(mp, cs_mp_ecdhe_secp256.mp.curr
					- sizeof(*mp));
	BUG_ON(!ctx);
	mp->curr = cs_mp_ecdhe_secp256.mp.curr;
	memcpy_fast(ctx, MPI_POOL_DATA(&cs_mp_ecdhe_secp256.mp),
		    mp->curr - sizeof(*mp));

	BENCHMARK("ECDHE srv (nistp256)",
		r = ttls_ecdh_make_params(ctx, &n, buf, 128);
		BUG_ON(r);
		ttls_ecdh_read_public(ctx, clnt_buf, 66);
		BUG_ON(r);
		ttls_ecdh_calc_secret(ctx, &n, pms, TTLS_MPI_MAX_SIZE);
		BUG_ON(r);
		ttls_mpi_pool_cleanup_ctx(0, false);
	);
}

int
main(int argc, char *argv[])
{
	if (ttls_mpool_init()) {
		fprintf(stderr, "Cannot initialize crypto memoty pool\n");
		return 1;
	}

	bm_ecdsa_sign_p256();
	bm_ecdhe_srv_p256();

	ttls_mpool_exit();

	return 0;
}
