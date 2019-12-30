/**
 *		Tempesta FW
 *
 * Copyright (C) 2018-2019 Tempesta Technologies, Inc.
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
#include <linux/types.h>
#include <asm/fpu/api.h>
#include <linux/bug.h>
#include <linux/kernel.h>

#include "test.h"
#include "ttls.h"

/*
 * ------------------------------------------------------------------------
 *	Testing mocks
 * ------------------------------------------------------------------------
 */
void
ttls_md_init(TlsMdCtx *ctx)
{
}

void
ttls_md_free(TlsMdCtx *ctx)
{
}

int
ttls_md_finish(TlsMdCtx *ctx, unsigned char *output)
{
	return 0;
}

int
ttls_md(const TlsMdInfo *md_info, const unsigned char *input,
		   size_t ilen, unsigned char *output)
{
	return 0;
}

int
ttls_md_setup(TlsMdCtx *ctx, const TlsMdInfo *md_info, int hmac)
{
	return 0;
}

const TlsMdInfo *
ttls_md_info_from_type(ttls_md_type_t md_type)
{
	return NULL;
}

int
ttls_md_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen)
{
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	Tests for Tempesta TLS low-level basic math/crypto operations.
 *
 * Note that some of the routines are designed to be called in process
 * context during Tempesta FW initialization and some of them are for
 * run-time softirq context, so the testing routines must enable/disable
 * FPU for them on its own.
 * ------------------------------------------------------------------------
 */
#ifdef __init
#undef __init
#define __init
#endif

#include "../../../tls/bignum.c"
#include "../../../tls/ciphersuites.c"
#include "../../../tls/dhm.c"
#include "../../../tls/ecp_curves.c"
#include "../../../tls/ecp.c"
#include "../../../tls/mpool.c"
#include "../../../tls/rsa.c"

TEST(mpi, alloc_init)
{
	TlsMpi *A;
	unsigned long p[7] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0, 0 };
	unsigned short save_off;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(0)));

	/* Grow empty MPI by zero - must remain the same. */
	EXPECT_ZERO(__mpi_alloc(A, 0));
	EXPECT_ZERO(A->used);
	EXPECT_ZERO(A->limbs);
	EXPECT_ZERO(A->_off);
	EXPECT_TRUE(A->s == 1);

	/* Nothing bad happens on freeing empty MPI. */
	ttls_mpi_free(A);
	ttls_mpi_init_next(A, 1);
	ttls_mpi_free(A);
	ttls_mpi_free(A);

	/* Grow empty MPI. */
	EXPECT_ZERO(__mpi_alloc(A, 7));
	EXPECT_ZERO(A->used);
	EXPECT_TRUE(A->limbs == 7);
	EXPECT_TRUE(A->_off != 0);
	EXPECT_TRUE(A->s == 1);
	save_off = A->_off;

	/* Calculate correct @A->used from invalid size assumption. */
	memcpy(MPI_P(A), p, CIL * 7);
	mpi_fixup_used(A, 8);
	EXPECT_TRUE(A->used == 5);
	EXPECT_TRUE(A->limbs == 7);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(MPI_P(A)[4] == 5 && MPI_P(A)[5] == 0 && MPI_P(A)[6] == 0);

	/* Backward fixing up @used - exact point must remain the same. */
	MPI_P(A)[0] = MPI_P(A)[1] = 1;
	mpi_fixup_used(A, 2);
	EXPECT_TRUE(A->used == 2);

	/* Finally free the MPI. */
	EXPECT_TRUE(ttls_mpi_initialized(A));
	ttls_mpi_free(A);
	EXPECT_ZERO(A->used);
	EXPECT_ZERO(A->s);
	EXPECT_TRUE(A->limbs == 7);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_FALSE(ttls_mpi_initialized(A));

	ttls_mpi_pool_cleanup_ctx(0, false);
}

TEST(mpi, read_write)
{
	int i;
	unsigned short save_off;
	TlsMpi *A;
	char buf[118] = { 0 };
	const char *mpi_data = "\x60\x2A\xB7\xEC\xA5\x97\xA3\xD6"
			       "\xB5\x6F\xF9\x82\x9A\x5E\x8B\x85"
			       "\x9E\x85\x7E\xA9\x5A\x03\x51\x2E"
			       "\x2B\xAE\x73\x91\x68\x8D\x26\x4A"
			       "\xA5\x66\x3B\x03\x41\xDB\x9C\xCF"
			       "\xD2\xC4\xC5\xF4\x21\xFE\xC8\x14"
			       "\x80\x01\xB7\x2E\x84\x8A\x38\xCA"
			       "\xE1\xC6\x5F\x78\xE5\x6A\xBD\xEF"
			       "\xE1\x2D\x3C\x03\x9B\x8A\x02\xD6"
			       "\xBE\x59\x3F\x0B\xBB\xDA\x56\xF1"
			       "\xEC\xF6\x77\x15\x2E\xF8\x04\x37"
			       "\x0C\x1A\x30\x5C\xAF\x3B\x5B\xF1"
			       "\x30\x87\x9B\x56\xC6\x1D\xE5\x84"
			       "\xA0\xF5\x3A\x24\x47\xA5\x1E";

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(0)));
	EXPECT_ZERO(ttls_mpi_read_binary(A, mpi_data, 111));
	/* 112 / 8 = 14 - necessary limbs to store 111 bytes. */
	EXPECT_TRUE(A->used == 14);
	EXPECT_TRUE(A->limbs == 14);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0x84a0f53a2447a51eUL);
	EXPECT_TRUE(MPI_P(A)[1] == 0xf130879b56c61de5UL);
	EXPECT_TRUE(MPI_P(A)[2] == 0x370c1a305caf3b5bUL);
	EXPECT_TRUE(MPI_P(A)[11] == 0x859e857ea95a0351UL);
	EXPECT_TRUE(MPI_P(A)[12] == 0xd6b56ff9829a5e8bUL);
	EXPECT_TRUE(MPI_P(A)[13] == 0x602ab7eca597a3UL);

	/* Some bit operation tests for this data. */
	EXPECT_EQ(ttls_mpi_bitlen(A), 887);
	EXPECT_EQ(ttls_mpi_lsb(A), 1);

	EXPECT_ZERO(ttls_mpi_write_binary(A, buf, 118));
	EXPECT_ZERO(memcmp(buf, "\x00\x00\x00\x00\x00\x00\x00", 7));
	EXPECT_ZERO(memcmp(buf + 7, mpi_data, 111));

	/* Too short buffer writting. */
	memset(buf, 0, 118);
	EXPECT_EQ(ttls_mpi_write_binary(A, buf, 1), -ENOSPC);
	for (i = 0; i < 118; ++i)
		EXPECT_ZERO(buf[i]);

	ttls_mpi_free(A);

	/* Read 1 byte. */
	save_off = A->_off;
	EXPECT_ZERO(ttls_mpi_read_binary(A, mpi_data, 1));
	EXPECT_ZERO(memcmp(MPI_P(A), mpi_data, 1));
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(A->limbs == 14);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_TRUE(A->s == 1);

	/* No reading at all. */
	ttls_mpi_free(A);
	EXPECT_ZERO(ttls_mpi_read_binary(A, mpi_data, 0));
	EXPECT_ZERO(A->used);
	EXPECT_ZERO(A->s);
	EXPECT_TRUE(A->limbs == 14);
	EXPECT_TRUE(A->_off == save_off);

	/* No writting on empty MPI. */
	memset(buf, 0, 118);
	EXPECT_ZERO(ttls_mpi_write_binary(A, buf, 0));
	for (i = 0; i < 118; ++i)
		EXPECT_ZERO(buf[i]);

	ttls_mpi_pool_cleanup_ctx(0, true);
}

TEST(mpi, copy)
{
	size_t bits;
	unsigned short save_off;
	TlsMpi *A, *B;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(TTLS_MPI_MAX_SIZE / CIL)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stck_init(TTLS_MPI_MAX_SIZE / CIL)));

	EXPECT_ZERO(ttls_mpi_lset(A, -5));
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(A->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_FALSE(A->_off == 0);
	EXPECT_TRUE(MPI_P(A)[0] == 5L);
	EXPECT_TRUE(A->s == -1);
	save_off = A->_off;

	EXPECT_ZERO(ttls_mpi_copy(A, B));
	EXPECT_TRUE(A->used == 0);
	EXPECT_TRUE(A->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_TRUE(A->s == 1);

	EXPECT_ZERO(ttls_mpi_lset(A, -1L));
	EXPECT_ZERO(ttls_mpi_copy(B, A));
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(B->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(B->_off != 0);
	EXPECT_TRUE(MPI_P(B)[0] == 1L);
	EXPECT_TRUE(B->s == -1);
	save_off = B->_off;

	EXPECT_ZERO(ttls_mpi_fill_random(A, TTLS_MPI_MAX_SIZE));
	EXPECT_TRUE(A->used == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(A->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_TRUE(A->s == 1);
	bits = ttls_mpi_bitlen(A);

	EXPECT_ZERO(ttls_mpi_copy(B, A));
	EXPECT_TRUE(B->used == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(B->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(B->_off == save_off);
	EXPECT_TRUE(B->s == 1);
	EXPECT_EQ(ttls_mpi_bitlen(B), bits);

	ttls_mpi_pool_cleanup_ctx(0, false);
}

TEST(mpi, safe_cond)
{
	TlsMpi *A, *B;
	unsigned short save_offA, save_offB;
	unsigned long valB0;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(25)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stck_init(0)));

	EXPECT_ZERO(ttls_mpi_lset(A, -0x1122334455667788L));
	EXPECT_ZERO(ttls_mpi_fill_random(B, 200)); /* 25 limbs */
	save_offA = A->_off;
	save_offB = B->_off;
	valB0 = MPI_P(B)[0];

	/* No actual data swapping. */
	ttls_mpi_safe_cond_swap(A, B, 0);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(B->used == 25);
	EXPECT_TRUE(A->limbs == 25);
	EXPECT_TRUE(B->limbs == 25);
	EXPECT_TRUE(A->s == -1);
	EXPECT_TRUE(B->s == 1);
	EXPECT_TRUE(A->_off == save_offA);
	EXPECT_TRUE(B->_off == save_offB);
	EXPECT_TRUE(MPI_P(A)[0] == 0x1122334455667788L);
	EXPECT_TRUE(MPI_P(B)[0] == valB0);

	/* Data swap: sizes the same. */
	ttls_mpi_safe_cond_swap(A, B, 5);
	EXPECT_TRUE(A->used == 25);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(A->limbs == 25);
	EXPECT_TRUE(B->limbs == 25);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(B->s == -1);
	EXPECT_TRUE(A->_off == save_offA);
	EXPECT_TRUE(B->_off == save_offB);
	EXPECT_TRUE(MPI_P(A)[0] == valB0);
	EXPECT_TRUE(MPI_P(B)[0] == 0x1122334455667788L);

	ttls_mpi_safe_cond_assign(A, B, 0);
	EXPECT_TRUE(A->used == 25);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(A->limbs == 25);
	EXPECT_TRUE(B->limbs == 25);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(B->s == -1);
	EXPECT_TRUE(A->_off == save_offA);
	EXPECT_TRUE(B->_off == save_offB);
	EXPECT_TRUE(MPI_P(A)[0] == valB0);
	EXPECT_TRUE(MPI_P(B)[0] == 0x1122334455667788L);

	/* Data swap: sizes the same. */
	ttls_mpi_safe_cond_assign(A, B, 1);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(A->limbs == 25);
	EXPECT_TRUE(B->limbs == 25);
	EXPECT_TRUE(A->s == -1);
	EXPECT_TRUE(B->s == -1);
	EXPECT_TRUE(A->_off == save_offA);
	EXPECT_TRUE(B->_off == save_offB);
	EXPECT_TRUE(MPI_P(A)[0] == 0x1122334455667788L);
	EXPECT_TRUE(MPI_P(B)[0] == 0x1122334455667788L);

	ttls_mpi_pool_cleanup_ctx(0, true);
}

TEST(mpi, bitop)
{
	TlsMpi *A;
	unsigned long *save_ptr;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(11)));

	EXPECT_ZERO(ttls_mpi_read_binary(A, "\xEF\xE0\x21\xC2\x64\x5F\xD1\xDC"
					    "\x58\x6E\x69\x18\x4A\xF4\xA3\x1E"
					    "\xD5\xF5\x3E\x93\xB5\xF1\x23\xFA"
					    "\x41\x68\x08\x67\xBA\x11\x01\x31"
					    "\x94\x4F\xE7\x95\x2E\x25\x17\x33"
					    "\x77\x80\xCB\x0D\xB8\x0E\x61\xAA"
					    "\xE7\xC8\xDD\xC6\xC5\xC6\xAA\xDE"
					    "\xB3\x4E\xB3\x8A\x2F\x40\xD5\xE6",
					    64)); /* 512 bits */
	EXPECT_ZERO(ttls_mpi_get_bit(A, 512));
	EXPECT_TRUE(ttls_mpi_get_bit(A, 300) == 0);
	EXPECT_TRUE(ttls_mpi_get_bit(A, 299) == 1);
	EXPECT_EQ(ttls_mpi_bitlen(A), 512);
	EXPECT_EQ(ttls_mpi_lsb(A), 1);

	EXPECT_ZERO(ttls_mpi_set_bit(A, 300, 1));
	EXPECT_ZERO(ttls_mpi_set_bit(A, 299, 0));
	EXPECT_TRUE(ttls_mpi_get_bit(A, 300) == 1);
	EXPECT_TRUE(ttls_mpi_get_bit(A, 299) == 0);
	EXPECT_EQ(ttls_mpi_bitlen(A), 512);
	EXPECT_EQ(ttls_mpi_lsb(A), 1);

	/* Access to the limbs by pointer as well as by offset. */
	save_ptr = MPI_P(A);

	EXPECT_ZERO(ttls_mpi_set_bit(A, 600, 1));
	EXPECT_TRUE(ttls_mpi_get_bit(A, 600) == 1);
	EXPECT_TRUE(A->used == 10);
	EXPECT_TRUE(A->limbs == 11);
	EXPECT_TRUE(MPI_P(A) == save_ptr);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0xb34eb38a2f40d5e6UL);
	EXPECT_TRUE(MPI_P(A)[7] == 0xefe021c2645fd1dcUL);
	EXPECT_TRUE(MPI_P(A)[8] == 0);
	EXPECT_TRUE(MPI_P(A)[9] == 1 << 24);
	EXPECT_EQ(ttls_mpi_bitlen(A), 601);
	EXPECT_EQ(ttls_mpi_lsb(A), 1);

	EXPECT_ZERO(ttls_mpi_shift_r(A, 71));
	EXPECT_TRUE(A->used == 9);
	EXPECT_TRUE(A->limbs == 11);
	EXPECT_TRUE(MPI_P(A) == save_ptr);
	EXPECT_TRUE(A->s == 1);
	/* (0x7780cb0db80e61aa << (128-71)) | (0xe7c8ddc6c5c6aade >> (71-64)) */
	EXPECT_TRUE(MPI_P(A)[0] == 0x55cf91bb8d8b8d55UL);
	EXPECT_TRUE(MPI_P(A)[7] == 0);
	EXPECT_TRUE(MPI_P(A)[8] == 1 << (24 - (71 - 64)));
	EXPECT_EQ(ttls_mpi_bitlen(A), 601 - 71);
	EXPECT_EQ(ttls_mpi_lsb(A), 0);

	/* No allocation - shift in-place. */
	EXPECT_ZERO(ttls_mpi_shift_l(A, 59));
	EXPECT_TRUE(A->used == 10);
	EXPECT_TRUE(A->limbs == 11);
	EXPECT_TRUE(MPI_P(A) == save_ptr);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0xa800000000000000UL);
	EXPECT_TRUE(MPI_P(A)[7] == 0xefe021c2645fdUL);
	EXPECT_TRUE(MPI_P(A)[8] == 0);
	EXPECT_TRUE(MPI_P(A)[9] == 1 << (24 - (71 - 59)));
	EXPECT_EQ(ttls_mpi_bitlen(A), 601 - 71 + 59);
	EXPECT_EQ(ttls_mpi_lsb(A), 59);

	/* Allocated a new limb - data copying. */
	EXPECT_ZERO(ttls_mpi_shift_l(A, 65));
	EXPECT_TRUE(A->used == 11);
	EXPECT_TRUE(A->limbs == 11);
	EXPECT_TRUE(MPI_P(A) != save_ptr);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0);
	/* 0xefe021c2645fdUL << 1 */
	EXPECT_TRUE(MPI_P(A)[8] == 0x1dfc04384c8bfaUL);
	EXPECT_TRUE(MPI_P(A)[9] == 0);
	EXPECT_TRUE(MPI_P(A)[10] == 1 << (24 - (71 - 59) + 1));
	EXPECT_EQ(ttls_mpi_bitlen(A), 601 - 71 + 59 + 65);
	EXPECT_EQ(ttls_mpi_lsb(A), 59 + 65);

	ttls_mpi_pool_cleanup_ctx(0, false);
}

TEST(mpi, elementary)
{
	TlsMpi *A, *B;
	unsigned long *save_ptr;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(2)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stck_init(2)));

	EXPECT_ZERO(ttls_mpi_lset(A, -1));
	EXPECT_ZERO(ttls_mpi_lset(B, 1));
	EXPECT_TRUE(ttls_mpi_cmp_int(A, -1) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_int(A, -10) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_int(A, 0) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	EXPECT_ZERO(ttls_mpi_add_int(B, B, 1));
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	/* Check absense of side effects. */
	EXPECT_TRUE(MPI_P(A)[0] == 1);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(A->limbs == 2);
	EXPECT_TRUE(A->s == -1);
	EXPECT_TRUE(MPI_P(B)[0] == 2);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);

	/* ttls_mpi_lset() can set only LONG_MAX. */
	MPI_P(B)[0] = ULONG_MAX;
	save_ptr = MPI_P(B);

	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);

	/* Add 1 and carry it to a new limb. */
	EXPECT_ZERO(ttls_mpi_add_abs(B, B, A));
	EXPECT_TRUE(ttls_mpi_cmp_int(B, LONG_MAX) > 0);
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B) == save_ptr);
	EXPECT_TRUE(MPI_P(B)[0] == 0);
	EXPECT_TRUE(MPI_P(B)[1] == 1);

	EXPECT_ZERO(ttls_mpi_copy(A, B));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(A, B));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(A, A));

	EXPECT_ZERO(ttls_mpi_add_mpi(B, B, A));
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B)[0] == 0);
	EXPECT_TRUE(MPI_P(B)[1] == 2);

	save_ptr = MPI_P(A);
	EXPECT_ZERO(ttls_mpi_sub_int(A, A, 2));
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(A->limbs == 2);
	EXPECT_TRUE(MPI_P(A) == save_ptr);
	EXPECT_TRUE(MPI_P(A)[0] == ULONG_MAX - 1);

	EXPECT_ZERO(ttls_mpi_sub_mpi(B, B, A));
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B)[0] == 2);
	EXPECT_TRUE(MPI_P(B)[1] == 1);

	A->s = -1; /* have no signed integer multiplication */
	EXPECT_ZERO(ttls_mpi_sub_mpi(B, B, A));
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);
	EXPECT_TRUE(MPI_P(B)[0] == 0);
	EXPECT_TRUE(MPI_P(B)[1] == 2);

	EXPECT_ZERO(ttls_mpi_sub_abs(B, B, A));
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);
	EXPECT_TRUE(MPI_P(B)[0] == 2);
	EXPECT_TRUE(MPI_P(B)[1] == 1);

	EXPECT_ZERO(ttls_mpi_sub_abs(B, B, A));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(B->s == 1);

	EXPECT_ZERO(ttls_mpi_lset(A, 0));
	EXPECT_ZERO(ttls_mpi_sub_mpi(A, A, B));
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	ttls_mpi_pool_cleanup_ctx((unsigned long)A, true);
}

/*
 * Test specific constants and operations uncovered by other tests and where
 * bugs were discovered. The numbers are taken from debug messags produced by
 * ttls_mpi_dump() - note that the function prints limbs and bytes in then in
 * reverse order
 */
TEST(mpi, consts)
{
	TlsMpi *A, *B;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(4)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stck_init(5)));

	EXPECT_ZERO(ttls_mpi_read_binary(A, "\x01\x77\x63\x34\xb6\xde\x8c\x09"
					    "\x0b\x92\x92\xe4\xbd\xd3\x70\xcc"
					    "\x08\xe8\xd0\x6a\xc9\xc6\x36\x29"
					    "\x80",
					    25));
	EXPECT_ZERO(ttls_mpi_read_binary(B, "\xff\xff\xff\xff\xff\xff\xff\xff"
					    "\xff\xff\xff\xff\xff\xff\xff\xfe"
					    "\xff\xff\xff\xff\xff\xff\xff\xff",
					    24));
	EXPECT_ZERO(ttls_mpi_sub_abs(A, A, B));
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(A->used == 3);
	EXPECT_ZERO(ttls_mpi_read_binary(B, "\x77\x63\x34\xb6\xde\x8c\x09\x0b"
					    "\x92\x92\xe4\xbd\xd3\x70\xcc\x09"
					    "\xe8\xd0\x6a\xc9\xc6\x36\x29\x81",
					    24));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);

	EXPECT_ZERO(ttls_mpi_read_binary(A, "\x98\xf6\xb8\x4e\x29\xbe\xf2\xb1"
					    "\x81\x81\x9a\x5e\x0e\x36\x90\xd8"
					    "\x33\xb6\x99\x48\x5d\x69\x4d\xd1"
					    "\x00\x2a\xe5\x6c\x42\x6b\x3f\x8d",
					    32));
	EXPECT_ZERO(ttls_mpi_read_binary(B, "\x00\x00\x00\x00\x00\x00\x00\x01"
					    "\x00\x00\x00\x00\x00\x00\x00\x00"
					    "\x00\x00\x00\x00\x00\x00\x00\x00"
					    "\x00\x00\x00\x00\x00\x00\x00\x00"
					    "\x00\x00\x00\x00\x00\x00\x00\x00",
					    40));
	EXPECT_ZERO(ttls_mpi_sub_abs(A, B, A));
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(A->used == 4);
	EXPECT_ZERO(ttls_mpi_read_binary(B, "\x67\x09\x47\xb1\xd6\x41\x0d\x4e"
					    "\x7e\x7e\x65\xa1\xf1\xc9\x6f\x27"
					    "\xcc\x49\x66\xb7\xa2\x96\xb2\x2e"
					    "\xff\xd5\x1a\x93\xbd\x94\xc0\x73",
					    32));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);

	ttls_mpi_pool_cleanup_ctx((unsigned long)A, false);
}

TEST(mpi, mul_div_simple)
{
	TlsMpi *A, *B, *D, *R;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(7)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stck_init(7)));
	EXPECT_FALSE(!(R = ttls_mpi_alloc_stck_init(1))); /* enough for % 8 */
	EXPECT_FALSE(!(D = ttls_mpi_alloc_stck_init(0)));

	EXPECT_ZERO(ttls_mpi_read_binary(A, "\x66\x13\xF2\x61\x62\x22\x3D\xF4"
					    "\x88\xE9\xCD\x48\xCC\x13\x2C\x7A"
					    "\x0A\xC9\x3C\x70\x1B\x00\x1B\x09"
					    "\x2E\x4E\x5B\x9F\x73\xBC\xD2\x7B"
					    "\x9E\xE5\x0D\x06\x57\xC7\x7F\x37"
					    "\x4E\x90\x3C\xDF\xA4\xC6\x42",
					    47));
	EXPECT_ZERO(ttls_mpi_copy(B, A));

	EXPECT_ZERO(ttls_mpi_shift_l(A, 11));
	EXPECT_ZERO(ttls_mpi_mul_uint(B, B, 2048));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(A->used == 7);

	EXPECT_ZERO(ttls_mpi_lset(D, 8));
	EXPECT_ZERO(ttls_mpi_shift_r(B, 3));
	EXPECT_ZERO(ttls_mpi_div_mpi(A, R, A, D));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_int(R, 0) == 0);

	ttls_mpi_pool_cleanup_ctx((unsigned long)A, true);
}

TEST(mpi, big)
{
#define GCD_PAIR_COUNT	3
	int i;
	static const int gcd_pairs[GCD_PAIR_COUNT][3] = {
		{693, 609, 21},
		{1764, 868, 28},
		{768454923, 542167814, 1}
	};
	TlsMpi *A, *E, *N, *X, *Y, *U, *V;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stck_init(8)));
	EXPECT_FALSE(!(N = ttls_mpi_alloc_stck_init(6)));
	EXPECT_FALSE(!(E = ttls_mpi_alloc_stck_init(8)));
	EXPECT_FALSE(!(X = ttls_mpi_alloc_stck_init(8 + 6)));
	EXPECT_FALSE(!(Y = ttls_mpi_alloc_stck_init(8 - 6)));
	EXPECT_FALSE(!(U = ttls_mpi_alloc_stck_init(14)));
	EXPECT_FALSE(!(V = ttls_mpi_alloc_stck_init(6)));

	EXPECT_ZERO(ttls_mpi_read_binary(A, "\xEF\xE0\x21\xC2\x64\x5F\xD1\xDC"
					    "\x58\x6E\x69\x18\x4A\xF4\xA3\x1E"
					    "\xD5\xF5\x3E\x93\xB5\xF1\x23\xFA"
					    "\x41\x68\x08\x67\xBA\x11\x01\x31"
					    "\x94\x4F\xE7\x95\x2E\x25\x17\x33"
					    "\x77\x80\xCB\x0D\xB8\x0E\x61\xAA"
					    "\xE7\xC8\xDD\xC6\xC5\xC6\xAA\xDE"
					    "\xB3\x4E\xB3\x8A\x2F\x40\xD5\xE6",
					    64));
	EXPECT_ZERO(ttls_mpi_read_binary(N, "\x00\x66\xA1\x98\x18\x6C\x18\xC1"
					    "\x0B\x2F\x5E\xD9\xB5\x22\x75\x2A"
					    "\x98\x30\xB6\x99\x16\xE5\x35\xC8"
					    "\xF0\x47\x51\x8A\x88\x9A\x43\xA5"
					    "\x94\xB6\xBE\xD2\x7A\x16\x8D\x31"
					    "\xD4\xA5\x2F\x88\x92\x5A\xA8\xF5",
					    48));
	EXPECT_ZERO(ttls_mpi_read_binary(U, "\x60\x2A\xB7\xEC\xA5\x97\xA3\xD6"
					    "\xB5\x6F\xF9\x82\x9A\x5E\x8B\x85"
					    "\x9E\x85\x7E\xA9\x5A\x03\x51\x2E"
					    "\x2B\xAE\x73\x91\x68\x8D\x26\x4A"
					    "\xA5\x66\x3B\x03\x41\xDB\x9C\xCF"
					    "\xD2\xC4\xC5\xF4\x21\xFE\xC8\x14"
					    "\x80\x01\xB7\x2E\x84\x8A\x38\xCA"
					    "\xE1\xC6\x5F\x78\xE5\x6A\xBD\xEF"
					    "\xE1\x2D\x3C\x03\x9B\x8A\x02\xD6"
					    "\xBE\x59\x3F\x0B\xBB\xDA\x56\xF1"
					    "\xEC\xF6\x77\x15\x2E\xF8\x04\x37"
					    "\x0C\x1A\x30\x5C\xAF\x3B\x5B\xF1"
					    "\x30\x87\x9B\x56\xC6\x1D\xE5\x84"
					    "\xA0\xF5\x3A\x24\x47\xA5\x1E",
					    111));
	EXPECT_ZERO(ttls_mpi_mul_mpi(X, A, N));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);

	EXPECT_ZERO(ttls_mpi_read_binary(U, "\x02\x56\x56\x73\x36\x05\x9E\x52"
					    "\xCA\xE2\x29\x25\x47\x47\x05\xF3"
					    "\x9A\x94",
					    18));
	EXPECT_ZERO(ttls_mpi_read_binary(V, "\x66\x13\xF2\x61\x62\x22\x3D\xF4"
					    "\x88\xE9\xCD\x48\xCC\x13\x2C\x7A"
					    "\x0A\xC9\x3C\x70\x1B\x00\x1B\x09"
					    "\x2E\x4E\x5B\x9F\x73\xBC\xD2\x7B"
					    "\x9E\xE5\x0D\x06\x57\xC7\x7F\x37"
					    "\x4E\x90\x3C\xDF\xA4\xC6\x42",
					    47));
	EXPECT_ZERO(ttls_mpi_div_mpi(X, Y, A, N));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(Y, V) == 0);

	EXPECT_ZERO(ttls_mpi_read_binary(E, "\xB2\xE7\xEF\xD3\x70\x75\xB9\xF0"
					    "\x3F\xF9\x89\xC7\xC5\x05\x1C\x20"
					    "\x34\xD2\xA3\x23\x81\x02\x51\x12"
					    "\x7E\x7B\xF8\x62\x5A\x4F\x49\xA5"
					    "\xF3\xE2\x7F\x4D\xA8\xBD\x59\xC4"
					    "\x7D\x6D\xAA\xBA\x4C\x81\x27\xBD"
					    "\x5B\x5C\x25\x76\x32\x22\xFE\xFC"
					    "\xCF\xC3\x8B\x83\x23\x66\xC2\x9E",
					    64));
	EXPECT_ZERO(ttls_mpi_read_binary(U, "\x36\xE1\x39\xAE\xA5\x52\x15\x60"
					    "\x9D\x28\x16\x99\x8E\xD0\x20\xBB"
					    "\xBD\x96\xC3\x78\x90\xF6\x51\x71"
					    "\xD9\x48\xE9\xBC\x7C\xBA\xA4\xD9"
					    "\x32\x5D\x24\xD6\xA3\xC1\x27\x10"
					    "\xF1\x0A\x09\xFA\x08\xAB\x87",
					    47));
	/* Pre-compute RR as R^2 mod N, use V as it's not needed any more. */
	EXPECT_ZERO(ttls_mpi_lset(V, 1));
	EXPECT_ZERO(ttls_mpi_shift_l(V, N->used * 2 * 64));
	EXPECT_ZERO(ttls_mpi_mod_mpi(V, V, N));
	EXPECT_ZERO(ttls_mpi_exp_mod(X, A, E, N, V));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);

	EXPECT_ZERO(ttls_mpi_read_binary(U, "\x00\x3A\x0A\xAE\xDD\x7E\x78\x4F"
					    "\xC0\x7D\x8F\x9E\xC6\xE3\xBF\xD5"
					    "\xC3\xDB\xA7\x64\x56\x36\x3A\x10"
					    "\x86\x96\x22\xEA\xC2\xDD\x84\xEC"
					    "\xC5\xB8\xA7\x4D\xAC\x4D\x09\xE0"
					    "\x3B\x5E\x0B\xE7\x79\xF2\xDF\x61",
					    48));
	EXPECT_ZERO(ttls_mpi_inv_mod(X, A, N));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);

	for (i = 0; i < GCD_PAIR_COUNT; i++) {
		EXPECT_ZERO(ttls_mpi_lset(X, gcd_pairs[i][0]));
		EXPECT_ZERO(ttls_mpi_lset(Y, gcd_pairs[i][1]));

		EXPECT_ZERO(ttls_mpi_gcd(A, X, Y));

		EXPECT_TRUE(ttls_mpi_cmp_int(A, gcd_pairs[i][2]) == 0);
	}

	ttls_mpi_pool_cleanup_ctx((unsigned long)X, false);
	ttls_mpi_pool_cleanup_ctx((unsigned long)A, true);
#undef GCD_PAIR_COUNT
}

TEST(tls, ecp)
{
	int i;
	TlsEcpGrp *grp;
	TlsEcpPoint *R, *P;
	TlsMpi *m;
	/* Exponents especially adapted for secp256r1, 32 bytes in size. */
	const char *exponents[] = {
		/* one */
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x01",

		/* N - 1 */
		"\xFF\xFF\xFF\xFF\x00\x00\x00\x00"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84"
		"\xF3\xB9\xCA\xC2\xFC\x63\x25\x50"

		/* random */
		"\x5E\xA6\xF3\x89\xA3\x8B\x8B\xC8"
		"\x1E\x76\x77\x53\xB1\x5A\xA5\x56"
		"\x9E\x17\x82\xE3\x0A\xBE\x7D\x25"
		"\x31\x28\xD2\xB4\xB1\xC9\x6B\x14",

		/* one and zeros */
		"\x40\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00",

		/* all ones */
		"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",

		/* 101010... */
		"\x55\x55\x55\x55\x55\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x55\x55\x55",
	};

	EXPECT_FALSE(!(R = ttls_mpool_alloc_stck(sizeof(TlsEcpPoint))));
	ttls_ecp_point_init(R);
	EXPECT_FALSE(!(P = ttls_mpool_alloc_stck(sizeof(TlsEcpPoint))));
	ttls_ecp_point_init(P);
	EXPECT_FALSE(!(m = ttls_mpi_alloc_stck_init(4)));
	EXPECT_FALSE(!(grp = ttls_mpool_alloc_stck(sizeof(TlsEcpGrp))));

	EXPECT_ZERO(ttls_ecp_group_load(grp, TTLS_ECP_DP_SECP256R1));
	EXPECT_EQ(grp->id, TTLS_ECP_DP_SECP256R1);
	EXPECT_EQ(grp->nbits, 256);
	EXPECT_EQ(grp->pbits, 256);
	EXPECT_EQ(grp->h, 1);
	EXPECT_EQ(grp->P.used, 4);
	EXPECT_EQ(grp->P.limbs, 4);
	EXPECT_EQ(grp->P.s, 1);
	EXPECT_EQ(MPI_P(&grp->P)[0], 0xffffffffffffffff);
	EXPECT_EQ(MPI_P(&grp->P)[1], 0xffffffff);
	EXPECT_EQ(MPI_P(&grp->P)[2], 0);
	EXPECT_EQ(MPI_P(&grp->P)[3], 0xffffffff00000001);
	EXPECT_EQ(grp->A.used, 0);
	EXPECT_EQ(grp->A.limbs, 0);
	EXPECT_EQ(grp->A.s, 0);
	EXPECT_EQ(grp->B.used, 4);
	EXPECT_EQ(grp->B.limbs, 4);
	EXPECT_EQ(grp->B.s, 1);
	EXPECT_EQ(MPI_P(&grp->B)[0], 0x3bce3c3e27d2604b);
	EXPECT_EQ(MPI_P(&grp->B)[1], 0x651d06b0cc53b0f6);
	EXPECT_EQ(MPI_P(&grp->B)[2], 0xb3ebbd55769886bc);
	EXPECT_EQ(MPI_P(&grp->B)[3], 0x5ac635d8aa3a93e7);
	EXPECT_EQ(grp->N.used, 4);
	EXPECT_EQ(grp->N.limbs, 4);
	EXPECT_EQ(grp->N.s, 1);
	EXPECT_EQ(MPI_P(&grp->N)[0], 0xf3b9cac2fc632551);
	EXPECT_EQ(MPI_P(&grp->N)[1], 0xbce6faada7179e84);
	EXPECT_EQ(MPI_P(&grp->N)[2], 0xffffffffffffffff);
	EXPECT_EQ(MPI_P(&grp->N)[3], 0xffffffff00000000);
	EXPECT_EQ(grp->G.X.used, 4);
	EXPECT_EQ(grp->G.X.limbs, 4);
	EXPECT_EQ(grp->G.X.s, 1);
	EXPECT_EQ(MPI_P(&grp->G.X)[0], 0xf4a13945d898c296);
	EXPECT_EQ(MPI_P(&grp->G.X)[1], 0x77037d812deb33a0);
	EXPECT_EQ(MPI_P(&grp->G.X)[2], 0xf8bce6e563a440f2);
	EXPECT_EQ(MPI_P(&grp->G.X)[3], 0x6b17d1f2e12c4247);
	EXPECT_EQ(grp->G.Y.used, 4);
	EXPECT_EQ(grp->G.Y.limbs, 4);
	EXPECT_EQ(grp->G.Y.s, 1);
	EXPECT_EQ(MPI_P(&grp->G.Y)[0], 0xcbb6406837bf51f5);
	EXPECT_EQ(MPI_P(&grp->G.Y)[1], 0x2bce33576b315ece);
	EXPECT_EQ(MPI_P(&grp->G.Y)[2], 0x8ee7eb4a7c0f9e16);
	EXPECT_EQ(MPI_P(&grp->G.Y)[3], 0x4fe342e2fe1a7f9b);
	EXPECT_EQ(grp->G.Z.used, 1);
	EXPECT_EQ(grp->G.Z.limbs, 1);
	EXPECT_EQ(grp->G.Z.s, 1);
	EXPECT_EQ(MPI_P(&grp->G.Z)[0], 1);

	/*
	 * ECP test #1 (constant op_count, base point G).
	 */
	/* Do a dummy multiplication first to trigger precomputation */
	EXPECT_ZERO(ttls_mpi_lset(m, 2));
	EXPECT_ZERO(ttls_ecp_mul(grp, P, m, &grp->G, false));

	EXPECT_ZERO(ttls_mpi_read_binary(m, exponents[0], 32));
	EXPECT_ZERO(ttls_ecp_mul(grp, R, m, &grp->G, false));

	for (i = 1; i < sizeof(exponents) / sizeof(exponents[0]); i++) {
		EXPECT_ZERO(ttls_mpi_read_binary(m, exponents[i], 32));
		EXPECT_ZERO(ttls_ecp_mul(grp, R, m, &grp->G, false));
	}

	/*
	 * ECP test #2 (constant op_count, other point).
	 * We computed P = 2G last time, use it.
	 */
	EXPECT_ZERO(ttls_mpi_read_binary(m, exponents[0], 32));
	EXPECT_ZERO(ttls_ecp_mul(grp, R, m, P, false));

	for (i = 1; i < sizeof(exponents) / sizeof(exponents[0]); i++) {
		EXPECT_ZERO(ttls_mpi_read_binary(m, exponents[i], 32));
		EXPECT_ZERO(ttls_ecp_mul(grp, R, m, P, false));
	}

	ttls_mpi_pool_cleanup_ctx((unsigned long)R, true);
}

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN	128
#define PT_LEN  (256 / 8) /* SHA256 size, 32 bytes */

#define RSA_N								   \
	"\x92\x92\x75\x84\x53\x06\x3D\x80\x3D\xD6\x03\xD5\xE7\x77\xD7\x88" \
	"\x8E\xD1\xD5\xBF\x35\x78\x61\x90\xFA\x2F\x23\xEB\xC0\x84\x8A\xEA" \
	"\xDD\xA9\x2C\xA6\xC3\xD8\x0B\x32\xC4\xD1\x09\xBE\x0F\x36\xD6\xAE" \
	"\x71\x30\xB9\xCE\xD7\xAC\xDF\x54\xCF\xC7\x55\x5A\xC1\x4E\xEB\xAB" \
	"\x93\xA8\x98\x13\xFB\xF3\xC4\xF8\x06\x6D\x2D\x80\x0F\x7C\x38\xA8" \
	"\x1A\xE3\x19\x42\x91\x74\x03\xFF\x49\x46\xB0\xA8\x3D\x3D\x3E\x05" \
	"\xEE\x57\xC6\xF5\xF5\x60\x6F\xB5\xD4\xBC\x6C\xD3\x4E\xE0\x80\x1A" \
	"\x5E\x94\xBB\x77\xB0\x75\x07\x23\x3A\x0B\xC7\xBA\xC8\xF9\x0F\x79"

#define RSA_E	"\x01\x00\x01"

#define RSA_D								   \
	"\x24\xBF\x61\x85\x46\x87\x86\xFD\xD3\x03\x08\x3D\x25\xE6\x4E\xFC" \
	"\x66\xCA\x47\x2B\xC4\x4D\x25\x31\x02\xF8\xB4\xA9\xD3\xBF\xA7\x50" \
	"\x91\x38\x6C\x00\x77\x93\x7F\xE3\x3F\xA3\x25\x2D\x28\x85\x58\x37" \
	"\xAE\x1B\x48\x4A\x8A\x9A\x45\xF7\xEE\x8C\x0C\x63\x4F\x99\xE8\xCD" \
	"\xDF\x79\xC5\xCE\x07\xEE\x72\xC7\xF1\x23\x14\x21\x98\x16\x42\x34" \
	"\xCA\xBB\x72\x4C\xF7\x8B\x81\x73\xB9\xF8\x80\xFC\x86\x32\x24\x07" \
	"\xAF\x1F\xED\xFD\xDE\x2B\xEB\x67\x4C\xA1\x5F\x3E\x81\xA1\x52\x1E" \
	"\x07\x15\x13\xA1\xE8\x5B\x5D\xFA\x03\x1F\x21\xEC\xAE\x91\xA3\x4D"

#define RSA_P								   \
	"\xC3\x6D\x0E\xB7\xFC\xD2\x85\x22\x3C\xFB\x5A\xAB\xA5\xBD\xA3\xD8" \
	"\x2C\x01\xCA\xD1\x9E\xA4\x84\xA8\x7E\xA4\x37\x76\x37\xE7\x55\x00" \
	"\xFC\xB2\x00\x5C\x5C\x7D\xD6\xEC\x4A\xC0\x23\xCD\xA2\x85\xD7\x96" \
	"\xC3\xD9\xE7\x5E\x1E\xFC\x42\x48\x8B\xB4\xF1\xD1\x3A\xC3\x0A\x57"

#define RSA_Q								   \
	"\xC0\x00\xDF\x51\xA7\xC7\x7A\xE8\xD7\xC7\x37\x0C\x1F\xF5\x5B\x69" \
	"\xE2\x11\xC2\xB9\xE5\xDB\x1E\xD0\xBF\x61\xD0\xD9\x89\x96\x20\xF4" \
	"\x91\x0E\x41\x68\x38\x7E\x3C\x30\xAA\x1E\x00\xC3\x39\xA7\x95\x08" \
	"\x84\x52\xDD\x96\xA9\xA5\xEA\x5D\x9D\xCA\x68\xDA\x63\x60\x32\xAF"

#define RSA_PT								   \
	"\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF\x11\x22\x33\x0A" \
	"\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD\x84\xF7\x55\xF0\x40\x88\x3C\x96"

TEST(tls, rsa)
{
	TlsRSACtx *rsa;
	unsigned char hash[PT_LEN], sig[KEY_LEN];

	EXPECT_FALSE(!(rsa = ttls_mpool_alloc_stck(sizeof(TlsRSACtx))));
	memset(rsa, 0, sizeof(TlsRSACtx));
	ttls_rsa_init(rsa, TTLS_RSA_PKCS_V15, 0);

	EXPECT_ZERO(ttls_mpi_read_binary(&rsa->N, RSA_N, 128));
	rsa->len = ttls_mpi_size(&rsa->N);
	EXPECT_ZERO(ttls_mpi_read_binary(&rsa->P, RSA_P, 64));
	EXPECT_ZERO(ttls_mpi_read_binary(&rsa->Q, RSA_Q, 64));
	EXPECT_ZERO(ttls_mpi_read_binary(&rsa->D, RSA_D, 128));
	EXPECT_ZERO(ttls_mpi_read_binary(&rsa->E, RSA_E, 3));

	EXPECT_ZERO(ttls_rsa_complete(rsa));

	EXPECT_ZERO(ttls_rsa_check_pubkey(rsa));

	/* Run-time (softirq) logic. */
	kernel_fpu_begin();

	memcpy(hash, RSA_PT, PT_LEN);
	EXPECT_ZERO(ttls_rsa_pkcs1_sign(rsa, TTLS_MD_SHA256, hash, sig));
	EXPECT_ZERO(ttls_rsa_pkcs1_verify(rsa, TTLS_MD_SHA256, PT_LEN, hash,
					  sig));

	kernel_fpu_end();

	ttls_mpi_pool_cleanup_ctx((unsigned long)rsa, false);
}

TEST_SUITE(tls)
{
	/*
	 * The test works in process context, so cfg_pool is used
	 * for all the MPI computations.
	 */
	ttls_mpool_init();

	TEST_RUN(mpi, alloc_init);
	TEST_RUN(mpi, read_write);
	TEST_RUN(mpi, copy);
	TEST_RUN(mpi, safe_cond);
	TEST_RUN(mpi, bitop);
	TEST_RUN(mpi, elementary);
	TEST_RUN(mpi, consts);
	TEST_RUN(mpi, mul_div_simple);
	TEST_RUN(mpi, big);
	TEST_RUN(tls, ecp);
	TEST_RUN(tls, rsa);

	ttls_mpool_exit();
}
