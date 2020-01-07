/**
 *		Tempesta TLS ECP unit test
 *
 * Copyright (C) 2018-2020 Tempesta Technologies, Inc.
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
#include "ttls_mocks.h"
/* mpool.c requires DHM routines. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../ecp_curves.c"
#include "../ecp.c"
#include "../ecdh.c"
#include "../mpool.c"

static void
ecdhe_srv(void)
{
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

	/* ttls_mpool() treats the pool as "handshake" pool. */
	EXPECT_FALSE(!(mp = ttls_mpi_pool_alloc(TTLS_MPOOL_ORDER, GFP_KERNEL)));

	/*
	 * Copy (clone) ECDH context from the MPI profile for Secp256r1 PK
	 * operations, see __mpi_profile_clone().
	 * Correctness of the group load is tested in test_ecp.c.
	 */
	ctx = ttls_mpool_alloc_data(mp, cs_mp_ecdhe_secp256.mp.curr
					- sizeof(*mp));
	EXPECT_FALSE(!ctx);
	mp->curr = cs_mp_ecdhe_secp256.mp.curr;
	memcpy_fast(ctx, MPI_POOL_DATA(&cs_mp_ecdhe_secp256.mp),
		    mp->curr - sizeof(*mp));

	EXPECT_ZERO(ttls_ecdh_make_params(ctx, &n, buf, 128));
	EXPECT_TRUE(n == 69);
	EXPECT_ZERO(memcmp(buf, "\x03\x00\x17\x41\x04\x38\x01\x4C", 8));
	EXPECT_ZERO(memcmp(buf + 8, "\x60\x3C\x89\xDA\x97\x12\x42\x63", 8));
	EXPECT_ZERO(memcmp(buf + 16, "\x20\xEE\x53\xA9\x4C\x79\x5D\xDA", 8));
	EXPECT_ZERO(memcmp(buf + 24, "\x3B\x90\xBB\x5B\x07\x91\xAE\x8F", 8));
	EXPECT_ZERO(memcmp(buf + 32, "\x5D\xB4\x86\xB7\xDB\x25\xE3\xAA", 8));
	EXPECT_ZERO(memcmp(buf + 40, "\x36\x8E\xDE\x37\xB9\x65\x66\xF6", 8));
	EXPECT_ZERO(memcmp(buf + 48, "\x65\x90\xF8\x9E\xA2\xAC\x83\x4B", 8));
	EXPECT_ZERO(memcmp(buf + 56, "\xCD\x61\x54\x1B\x90\x73\x8C\xBC", 8));
	EXPECT_ZERO(memcmp(buf + 64, "\x82\x94\x70\x6C\x96\x00\x00\x00", 8));

	EXPECT_ZERO(ttls_ecdh_read_public(ctx, clnt_buf, 66));
	EXPECT_ZERO(ttls_ecdh_calc_secret(ctx, &n, pms, TTLS_MPI_MAX_SIZE));
	EXPECT_TRUE(n == 32);
	EXPECT_ZERO(memcmp(pms, "\x27\x53\xE1\x88\x57\x89\xB4\xB0", 8));
	EXPECT_ZERO(memcmp(pms + 8, "\x24\xCB\x3D\x31\x06\x10\x4B\x40", 8));
	EXPECT_ZERO(memcmp(pms + 16, "\xF1\x9A\xAB\x92\x57\xD2\x00\x44", 8));
	EXPECT_ZERO(memcmp(pms + 24, "\x49\x53\xEF\xC8\x58\xE5\xA2\xF4", 8));

	ttls_mpi_pool_free(ctx);
}

int
main(int argc, char *argv[])
{
	BUG_ON(ttls_mpool_init());

	ecdhe_srv();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
