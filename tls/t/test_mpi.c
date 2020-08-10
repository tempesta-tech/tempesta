/**
 *		Tempesta TLS multi-precission integer functional test
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
/* mpool.c DHM routines, util.h requires ECP. */
#include "../bignum.c"
#include "../ciphersuites.c"
#include "../dhm.c"
#include "../asn1.c"
#include "../ec_p256.c"
#include "../ecp.c"
#include "../mpool.c"
#include "util.h"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP384_G = {};
const TlsEcpGrp CURVE25519_G = {};

static void
mpi_alloc_init(void)
{
	TlsMpi *A;
	unsigned long p[7] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0, 0 };

	A = ttls_mpi_alloc_stack_init(0);

	/* Grow empty MPI by zero - must remain the same. */
	ttls_mpi_alloc(A, 0);
	EXPECT_ZERO(A->used);
	EXPECT_ZERO(A->limbs);
	EXPECT_ZERO(A->_off);
	EXPECT_TRUE(A->s == 1);

	/* Calculate correct @A->used from invalid size assumption. */
	ttls_mpi_init_next(A, 7);
	memcpy(MPI_P(A), p, CIL * 7);
	mpi_fixup_used(A, 7);
	EXPECT_TRUE(A->used == 5);
	EXPECT_TRUE(A->limbs == 7);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(MPI_P(A)[4] == 5 && MPI_P(A)[5] == 0 && MPI_P(A)[6] == 0);

	/* Backward fixing up @used - exact point must remain the same. */
	MPI_P(A)[0] = MPI_P(A)[1] = 1;
	mpi_fixup_used(A, 2);
	EXPECT_TRUE(A->used == 2);
	EXPECT_FALSE(ttls_mpi_empty(A));

	ttls_mpi_pool_cleanup_ctx((unsigned long)A, false);
}

static void
mpi_read_write(void)
{
	int i;
	short save_off;
	TlsMpi A;
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

	ttls_mpi_alloca_init(&A, 14);
	ttls_mpi_read_binary(&A, mpi_data, 111);
	/* 112 / 8 = 14 - necessary limbs to store 111 bytes. */
	EXPECT_TRUE(A.used == 14);
	EXPECT_TRUE(A.limbs == 14);
	EXPECT_TRUE(A.s == 1);
	EXPECT_TRUE(MPI_P(&A)[0] == 0x84a0f53a2447a51eUL);
	EXPECT_TRUE(MPI_P(&A)[1] == 0xf130879b56c61de5UL);
	EXPECT_TRUE(MPI_P(&A)[2] == 0x370c1a305caf3b5bUL);
	EXPECT_TRUE(MPI_P(&A)[11] == 0x859e857ea95a0351UL);
	EXPECT_TRUE(MPI_P(&A)[12] == 0xd6b56ff9829a5e8bUL);
	EXPECT_TRUE(MPI_P(&A)[13] == 0x602ab7eca597a3UL);

	/* Some bit operation tests for this data. */
	EXPECT_EQ(ttls_mpi_bitlen(&A), 887);
	EXPECT_EQ(ttls_mpi_lsb(&A), 1);

	EXPECT_ZERO(ttls_mpi_write_binary(&A, buf, 118));
	EXPECT_ZERO(memcmp(buf, "\x00\x00\x00\x00\x00\x00\x00", 7));
	EXPECT_ZERO(memcmp(buf + 7, mpi_data, 111));

	/* Write exact number of bytes. */
	memset(buf, 0, 118);
	EXPECT_ZERO(ttls_mpi_write_binary(&A, buf, 111));
	EXPECT_ZERO(memcmp(buf, mpi_data, 111));
	EXPECT_ZERO(memcmp(buf + 111, "\x00\x00\x00\x00\x00\x00\x00", 7));

	/* Too short buffer writting. */
	memset(buf, 0, 118);
	EXPECT_EQ(ttls_mpi_write_binary(&A, buf, 1), -ENOSPC);
	for (i = 0; i < 118; ++i)
		EXPECT_ZERO(buf[i]);

	/* Read 1 byte. */
	save_off = A._off;
	ttls_mpi_read_binary(&A, mpi_data, 1);
	EXPECT_ZERO(memcmp(MPI_P(&A), mpi_data, 1));
	EXPECT_TRUE(A.used == 1);
	EXPECT_TRUE(A.limbs == 14);
	EXPECT_TRUE(A._off == save_off);
	EXPECT_TRUE(A.s == 1);

	/* No reading at all. */
	ttls_mpi_read_binary(&A, mpi_data, 0);
	EXPECT_ZERO(A.used);
	EXPECT_ZERO(A.s);
	EXPECT_TRUE(A.limbs == 14);
	EXPECT_TRUE(A._off == save_off);

	/* No writting on empty MPI. */
	memset(buf, 0, 118);
	EXPECT_ZERO(ttls_mpi_write_binary(&A, buf, 0));
	for (i = 0; i < 118; ++i)
		EXPECT_ZERO(buf[i]);

	/* Curve 25519 parameter A. */
	ttls_mpi_read_binary(&A, "\x01\xDB\x42", 3);
	EXPECT_MPI(&A, 1, 0x1db42UL);
}

static void
mpi_copy(void)
{
	size_t bits;
	short save_off;
	TlsMpi *A, *B;

	A = ttls_mpi_alloc_stack_init(TTLS_MPI_MAX_SIZE / CIL);
	B = ttls_mpi_alloc_stack_init(TTLS_MPI_MAX_SIZE / CIL);

	ttls_mpi_lset(A, -5);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(A->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_FALSE(A->_off == 0);
	EXPECT_TRUE(MPI_P(A)[0] == 5L);
	EXPECT_TRUE(A->s == -1);
	save_off = A->_off;

	ttls_mpi_copy(A, B);
	EXPECT_TRUE(A->used == 0);
	EXPECT_TRUE(A->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_TRUE(A->s == 1);

	ttls_mpi_lset(A, -1L);
	ttls_mpi_copy(B, A);
	EXPECT_TRUE(B->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(B->_off != 0);
	EXPECT_MPI(B, 1, 1L);
	EXPECT_TRUE(B->s == -1);
	save_off = B->_off;

	ttls_mpi_fill_random(A, TTLS_MPI_MAX_SIZE);
	EXPECT_TRUE(A->used == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(A->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(A->_off == save_off);
	EXPECT_TRUE(A->s == 1);
	bits = ttls_mpi_bitlen(A);

	ttls_mpi_copy(B, A);
	EXPECT_TRUE(B->used == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(B->limbs == TTLS_MPI_MAX_SIZE / CIL);
	EXPECT_TRUE(B->_off == save_off);
	EXPECT_TRUE(B->s == 1);
	EXPECT_EQ(ttls_mpi_bitlen(B), bits);

	ttls_mpi_pool_cleanup_ctx(0, false);
}

static void
mpi_safe_cond(void)
{
	TlsMpi *A, *B;
	short save_offA, save_offB;
	unsigned long valB0;

	A = ttls_mpi_alloc_stack_init(25);
	B = ttls_mpi_alloc_stack_init(0);

	ttls_mpi_lset(A, -0x1122334455667788L);
	ttls_mpi_fill_random(B, 200); /* 25 limbs */
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

	ttls_mpi_pool_cleanup_ctx(0, true);
}

static void
mpi_bitop(void)
{
	TlsMpi A;
	unsigned long *save_ptr;

	ttls_mpi_alloca_init(&A, 12);

	ttls_mpi_read_binary(&A, "\xEF\xE0\x21\xC2\x64\x5F\xD1\xDC"
				 "\x58\x6E\x69\x18\x4A\xF4\xA3\x1E"
				 "\xD5\xF5\x3E\x93\xB5\xF1\x23\xFA"
				 "\x41\x68\x08\x67\xBA\x11\x01\x31"
				 "\x94\x4F\xE7\x95\x2E\x25\x17\x33"
				 "\x77\x80\xCB\x0D\xB8\x0E\x61\xAA"
				 "\xE7\xC8\xDD\xC6\xC5\xC6\xAA\xDE"
				 "\xB3\x4E\xB3\x8A\x2F\x40\xD5\xE6",
				 64); /* 512 bits */
	EXPECT_ZERO(ttls_mpi_get_bit(&A, 512));
	EXPECT_TRUE(ttls_mpi_get_bit(&A, 300) == 0);
	EXPECT_TRUE(ttls_mpi_get_bit(&A, 299) == 1);
	EXPECT_EQ(ttls_mpi_bitlen(&A), 512);
	EXPECT_EQ(ttls_mpi_lsb(&A), 1);

	ttls_mpi_set_bit(&A, 300, 1);
	ttls_mpi_set_bit(&A, 299, 0);
	EXPECT_TRUE(ttls_mpi_get_bit(&A, 300) == 1);
	EXPECT_TRUE(ttls_mpi_get_bit(&A, 299) == 0);
	EXPECT_EQ(ttls_mpi_bitlen(&A), 512);
	EXPECT_EQ(ttls_mpi_lsb(&A), 1);

	/* Access to the limbs by pointer as well as by offset. */
	save_ptr = MPI_P(&A);

	ttls_mpi_set_bit(&A, 600, 1);
	EXPECT_TRUE(ttls_mpi_get_bit(&A, 600) == 1);
	EXPECT_TRUE(A.used == 10);
	EXPECT_TRUE(A.limbs == 12);
	EXPECT_TRUE(MPI_P(&A) == save_ptr);
	EXPECT_TRUE(A.s == 1);
	EXPECT_TRUE(MPI_P(&A)[0] == 0xb34eb38a2f40d5e6UL);
	EXPECT_TRUE(MPI_P(&A)[7] == 0xefe021c2645fd1dcUL);
	EXPECT_TRUE(MPI_P(&A)[8] == 0);
	EXPECT_TRUE(MPI_P(&A)[9] == 1 << 24);
	EXPECT_EQ(ttls_mpi_bitlen(&A), 601);
	EXPECT_EQ(ttls_mpi_lsb(&A), 1);

	ttls_mpi_shift_r(&A, 71);
	EXPECT_TRUE(A.used == 9);
	EXPECT_TRUE(A.limbs == 12);
	EXPECT_TRUE(MPI_P(&A) == save_ptr);
	EXPECT_TRUE(A.s == 1);
	/* (0x7780cb0db80e61aa << (128-71)) | (0xe7c8ddc6c5c6aade >> (71-64)) */
	EXPECT_TRUE(MPI_P(&A)[0] == 0x55cf91bb8d8b8d55UL);
	EXPECT_TRUE(MPI_P(&A)[7] == 0);
	EXPECT_TRUE(MPI_P(&A)[8] == 1 << (24 - (71 - 64)));
	EXPECT_EQ(ttls_mpi_bitlen(&A), 601 - 71);
	EXPECT_EQ(ttls_mpi_lsb(&A), 0);

	/* No allocation - shift in-place. */
	ttls_mpi_shift_l(&A, &A, 59);
	EXPECT_TRUE(A.used == 10);
	EXPECT_TRUE(A.limbs == 12);
	EXPECT_TRUE(MPI_P(&A) == save_ptr);
	EXPECT_TRUE(A.s == 1);
	EXPECT_TRUE(MPI_P(&A)[0] == 0xa800000000000000UL);
	EXPECT_TRUE(MPI_P(&A)[7] == 0xefe021c2645fdUL);
	EXPECT_TRUE(MPI_P(&A)[8] == 0);
	EXPECT_TRUE(MPI_P(&A)[9] == 1 << (24 - (71 - 59)));
	EXPECT_EQ(ttls_mpi_bitlen(&A), 601 - 71 + 59);
	EXPECT_EQ(ttls_mpi_lsb(&A), 59);

	/* Allocated a new limb - data copying. */
	ttls_mpi_shift_l(&A, &A, 65);
	EXPECT_TRUE(A.used == 11);
	EXPECT_TRUE(A.limbs == 12);
	EXPECT_TRUE(MPI_P(&A) == save_ptr);
	EXPECT_TRUE(A.s == 1);
	EXPECT_TRUE(MPI_P(&A)[0] == 0);
	/* 0xefe021c2645fdUL << 1 */
	EXPECT_TRUE(MPI_P(&A)[8] == 0x1dfc04384c8bfaUL);
	EXPECT_TRUE(MPI_P(&A)[9] == 0);
	EXPECT_TRUE(MPI_P(&A)[10] == 1 << (24 - (71 - 59) + 1));
	EXPECT_EQ(ttls_mpi_bitlen(&A), 601 - 71 + 59 + 65);
	EXPECT_EQ(ttls_mpi_lsb(&A), 59 + 65);
}

/*
 * Test specific constants and operations uncovered by other tests and where
 * bugs were discovered. The numbers are taken from debug messags produced by
 * ttls_mpi_dump() - note that the function prints limbs and bytes in then in
 * reverse order
 */
static void
mpi_consts(void)
{
	TlsMpi *A, *B;

	A = ttls_mpi_alloc_stack_init(5);
	B = ttls_mpi_alloc_stack_init(5);

	ttls_mpi_read_binary(A, "\x01\x77\x63\x34\xb6\xde\x8c\x09"
				"\x0b\x92\x92\xe4\xbd\xd3\x70\xcc"
				"\x08\xe8\xd0\x6a\xc9\xc6\x36\x29"
				"\x80",
				25);
	ttls_mpi_read_binary(B, "\xff\xff\xff\xff\xff\xff\xff\xff"
				"\xff\xff\xff\xff\xff\xff\xff\xfe"
				"\xff\xff\xff\xff\xff\xff\xff\xff",
				24);
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(A->used == 3);
	ttls_mpi_read_binary(B, "\x77\x63\x34\xb6\xde\x8c\x09\x0b"
				"\x92\x92\xe4\xbd\xd3\x70\xcc\x09"
				"\xe8\xd0\x6a\xc9\xc6\x36\x29\x81",
				24);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);

	ttls_mpi_read_binary(A, "\x98\xf6\xb8\x4e\x29\xbe\xf2\xb1"
				"\x81\x81\x9a\x5e\x0e\x36\x90\xd8"
				"\x33\xb6\x99\x48\x5d\x69\x4d\xd1"
				"\x00\x2a\xe5\x6c\x42\x6b\x3f\x8d",
				32);
	ttls_mpi_read_binary(B, "\x00\x00\x00\x00\x00\x00\x00\x01"
				"\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00",
				40);
	ttls_mpi_sub_abs(A, B, A);
	EXPECT_TRUE(A->s == 1);
	EXPECT_TRUE(A->used == 4);
	ttls_mpi_read_binary(B, "\x67\x09\x47\xb1\xd6\x41\x0d\x4e"
				"\x7e\x7e\x65\xa1\xf1\xc9\x6f\x27"
				"\xcc\x49\x66\xb7\xa2\x96\xb2\x2e"
				"\xff\xd5\x1a\x93\xbd\x94\xc0\x73",
				32);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);

	ttls_mpi_pool_cleanup_ctx((unsigned long)A, false);
}

static void
mpi_mul_div_simple(void)
{
	TlsMpi *a, *b, *d, *r;

	a = ttls_mpi_alloc_stack_init(7);
	b = ttls_mpi_alloc_stack_init(7);
	r = ttls_mpi_alloc_stack_init(1); /* enough for % 8 */
	d = ttls_mpi_alloc_stack_init(0);

	ttls_mpi_read_binary(a, "\x66\x13\xf2\x61\x62\x22\x3d\xf4"
				"\x88\xe9\xcd\x48\xcc\x13\x2c\x7a"
				"\x0a\xc9\x3c\x70\x1b\x00\x1b\x09"
				"\x2e\x4e\x5b\x9f\x73\xbc\xd2\x7b"
				"\x9e\xe5\x0d\x06\x57\xc7\x7f\x37"
				"\x4e\x90\x3c\xdf\xa4\xc6\x42",
				47);
	ttls_mpi_copy(b, a);

	ttls_mpi_shift_l(a, a, 11);
	ttls_mpi_mul_uint(b, b, 2048);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(a, b) == 0);
	EXPECT_TRUE(a->used == 7);

	ttls_mpi_lset(d, 8);
	ttls_mpi_shift_r(b, 3);
	ttls_mpi_div_mpi(a, r, a, d);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(a, b) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_int(r, 0) == 0);

	ttls_mpi_pool_cleanup_ctx((unsigned long)a, true);
}

static void
mpi_big(void)
{
#define GCD_PAIR_COUNT	3
	int i;
	static const int gcd_pairs[GCD_PAIR_COUNT][3] = {
		{693, 609, 21},
		{1764, 868, 28},
		{768454923, 542167814, 1}
	};
	TlsMpi *A, *E, *N, *X, *Y, *U, *V;

	A = ttls_mpi_alloc_stack_init(8);
	N = ttls_mpi_alloc_stack_init(6);
	E = ttls_mpi_alloc_stack_init(8);
	X = ttls_mpi_alloc_stack_init(8 + 6);
	Y = ttls_mpi_alloc_stack_init(6);
	U = ttls_mpi_alloc_stack_init(14);
	V = ttls_mpi_alloc_stack_init(6 + N->limbs * 2);

	ttls_mpi_read_binary(A, "\xEF\xE0\x21\xC2\x64\x5F\xD1\xDC"
				"\x58\x6E\x69\x18\x4A\xF4\xA3\x1E"
				"\xD5\xF5\x3E\x93\xB5\xF1\x23\xFA"
				"\x41\x68\x08\x67\xBA\x11\x01\x31"
				"\x94\x4F\xE7\x95\x2E\x25\x17\x33"
				"\x77\x80\xCB\x0D\xB8\x0E\x61\xAA"
				"\xE7\xC8\xDD\xC6\xC5\xC6\xAA\xDE"
				"\xB3\x4E\xB3\x8A\x2F\x40\xD5\xE6",
				64);
	ttls_mpi_read_binary(N, "\x00\x66\xA1\x98\x18\x6C\x18\xC1"
				"\x0B\x2F\x5E\xD9\xB5\x22\x75\x2A"
				"\x98\x30\xB6\x99\x16\xE5\x35\xC8"
				"\xF0\x47\x51\x8A\x88\x9A\x43\xA5"
				"\x94\xB6\xBE\xD2\x7A\x16\x8D\x31"
				"\xD4\xA5\x2F\x88\x92\x5A\xA8\xF5",
				48);
	ttls_mpi_read_binary(U, "\x60\x2A\xB7\xEC\xA5\x97\xA3\xD6"
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
				111);
	ttls_mpi_mul_mpi(X, A, N);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);

	ttls_mpi_read_binary(U, "\x02\x56\x56\x73\x36\x05\x9E\x52"
				"\xCA\xE2\x29\x25\x47\x47\x05\xF3"
				"\x9A\x94",
				18);
	ttls_mpi_read_binary(V, "\x66\x13\xF2\x61\x62\x22\x3D\xF4"
				"\x88\xE9\xCD\x48\xCC\x13\x2C\x7A"
				"\x0A\xC9\x3C\x70\x1B\x00\x1B\x09"
				"\x2E\x4E\x5B\x9F\x73\xBC\xD2\x7B"
				"\x9E\xE5\x0D\x06\x57\xC7\x7F\x37"
				"\x4E\x90\x3C\xDF\xA4\xC6\x42",
				47);
	ttls_mpi_div_mpi(X, Y, A, N);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(Y, V) == 0);

	ttls_mpi_read_binary(E, "\xB2\xE7\xEF\xD3\x70\x75\xB9\xF0"
				"\x3F\xF9\x89\xC7\xC5\x05\x1C\x20"
				"\x34\xD2\xA3\x23\x81\x02\x51\x12"
				"\x7E\x7B\xF8\x62\x5A\x4F\x49\xA5"
				"\xF3\xE2\x7F\x4D\xA8\xBD\x59\xC4"
				"\x7D\x6D\xAA\xBA\x4C\x81\x27\xBD"
				"\x5B\x5C\x25\x76\x32\x22\xFE\xFC"
				"\xCF\xC3\x8B\x83\x23\x66\xC2\x9E",
				64);
	ttls_mpi_read_binary(U, "\x36\xE1\x39\xAE\xA5\x52\x15\x60"
				"\x9D\x28\x16\x99\x8E\xD0\x20\xBB"
				"\xBD\x96\xC3\x78\x90\xF6\x51\x71"
				"\xD9\x48\xE9\xBC\x7C\xBA\xA4\xD9"
				"\x32\x5D\x24\xD6\xA3\xC1\x27\x10"
				"\xF1\x0A\x09\xFA\x08\xAB\x87",
				47);
	/* Pre-compute RR as R^2 mod N, use V as it's not needed any more. */
	ttls_mpi_lset(V, 1);
	ttls_mpi_shift_l(V, V, N->used * 2 * BIL);
	ttls_mpi_mod_mpi(V, V, N);
	EXPECT_ZERO(ttls_mpi_exp_mod(X, A, E, N, V));
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);

	ttls_mpi_read_binary(U, "\x00\x3A\x0A\xAE\xDD\x7E\x78\x4F"
				"\xC0\x7D\x8F\x9E\xC6\xE3\xBF\xD5"
				"\xC3\xDB\xA7\x64\x56\x36\x3A\x10"
				"\x86\x96\x22\xEA\xC2\xDD\x84\xEC"
				"\xC5\xB8\xA7\x4D\xAC\x4D\x09\xE0"
				"\x3B\x5E\x0B\xE7\x79\xF2\xDF\x61",
				48);
	ttls_mpi_inv_mod(X, A, N);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(X, U) == 0);

	for (i = 0; i < GCD_PAIR_COUNT; i++) {
		ttls_mpi_lset(X, gcd_pairs[i][0]);
		ttls_mpi_lset(Y, gcd_pairs[i][1]);

		ttls_mpi_gcd(A, X, Y);

		EXPECT_TRUE(ttls_mpi_cmp_int(A, gcd_pairs[i][2]) == 0);
	}

	ttls_mpi_pool_cleanup_ctx((unsigned long)X, false);
	ttls_mpi_pool_cleanup_ctx((unsigned long)A, true);
#undef GCD_PAIR_COUNT
}

int
main(int argc, char *argv[])
{
	/*
	 * The test works in process context, so cfg_pool is used
	 * for all the MPI computations.
	 */
	BUG_ON(ttls_mpool_init());

	mpi_alloc_init();
	mpi_read_write();
	mpi_copy();
	mpi_safe_cond();
	mpi_bitop();
	mpi_consts();
	mpi_mul_div_simple();
	mpi_big();

	ttls_mpool_exit();

	printf("success\n");

	return 0;
}
