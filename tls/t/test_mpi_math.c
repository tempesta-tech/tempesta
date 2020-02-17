/**
 *		Tempesta TLS multi-precission integer arithmetics unit test
 *
 * The test is responsibe for plain operations non involving MPI pool
 * allocations, which are the subject for test in test_mpi.c.
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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

/*
 * Big integers are the core of any cryptographic calls, so we can't call
 * ttls_mpool_init() and ttls_mpool_exit() in the test as we do this in
 * test_mpi.c since the calls create crypto contexts envolving big integers,
 * so if there is some bug in big integers, then we crash on the initialization
 * phase instead of a particular test. Thus we mock the memory underlying layer
 * for MPI in the test.
 */
#define ttls_mpool_alloc_stack(n)	malloc(n)

void
ttls_mpi_pool_cleanup_ctx(unsigned long addr, bool zero)
{
	WARN(1, "Should not be called in the test."
		" Maybe move the test to test_mpi.c?\n");
}

int
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n, bool tail)
{
	WARN(1, "Should not be called in the test."
		" Maybe move the test to test_mpi.c?\n");
	return -1;
}

#include "../bignum.c"

static void
mpi_cmp(void)
{
	TlsMpi *A, *B;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(8)));

	ttls_mpi_lset(A, -5);
	ttls_mpi_lset(B, -3);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) < 0);

	ttls_mpi_lset(B, -5);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	ttls_mpi_lset(B, 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) < 0);

	ttls_mpi_lset(B, 3);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) < 0);

	ttls_mpi_lset(A, 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) > 0);

	ttls_mpi_lset(A, 3);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	ttls_mpi_lset(A, 0);
	ttls_mpi_lset(B, 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	A->s = -1;
	A->used = 2;
	MPI_P(A)[0] = 0;
	MPI_P(A)[1] = 5;
	ttls_mpi_lset(B, -3);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) < 0);

	B->s = -1;
	B->used = 2;
	MPI_P(B)[0] = 0;
	MPI_P(B)[1] = 5;
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	ttls_mpi_lset(B, 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) < 0);

	ttls_mpi_lset(B, 3);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(B, A) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) < 0);

	A->s = B->s = 1;
	A->used = B->used = 2;
	MPI_P(A)[0] = MPI_P(B)[0] = 0;
	MPI_P(A)[1] = MPI_P(B)[1] = 5;
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	A->s = B->s = 1;
	A->used = B->used = 6;
	MPI_P(A)[0] = 0xddd15241b1d6cc2c;
	MPI_P(A)[1] = 0x5e6dd03b73b3aa02;
	MPI_P(A)[2] = 0x29b21c36bcafe9fc;
	MPI_P(A)[3] = 0xf5cc3e47406cadcc;
	MPI_P(A)[4] = 0xf905dd38dbaeb071;
	MPI_P(A)[5] = 0x25f1dc853306b4d;
	MPI_P(B)[0] = 0x2f5de5c3735b99dd;
	MPI_P(B)[1] = 0x6d0bc1736c62138b;
	MPI_P(B)[2] = 0xff07e3a6fb3219bf;
	MPI_P(B)[3] = 0x886848fae4fbb71d;
	MPI_P(B)[4] = 0xe51b242c40f59fe6;
	MPI_P(B)[5] = 0x74377a3bc14fc4a;
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(B, A) > 0);

	free(A);
	free(B);
}

static void
mpi_add(void)
{
	TlsMpi *A, *B;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(16)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(16)));

	/* ttls_mpi_lset() works with signed values, so initialize raw memory. */
	ttls_mpi_lset(A, 0);
	ttls_mpi_lset(B, 0);
	MPI_P(A)[0] = ULONG_MAX;
	MPI_P(B)[0] = ULONG_MAX;
	ttls_mpi_add_abs(A, B, A);
	EXPECT_TRUE(A->used == 2);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 1);

	ttls_mpi_add_int(A, A, 1);
	EXPECT_TRUE(A->used == 2);
	EXPECT_TRUE(MPI_P(A)[0] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(A)[1] == 1);

	ttls_mpi_add_int(A, A, 1);
	EXPECT_TRUE(A->used == 2);
	EXPECT_TRUE(MPI_P(A)[0] == 0);
	EXPECT_TRUE(MPI_P(A)[1] == 2);

	B->used = 4;
	MPI_P(B)[0] = ULONG_MAX;
	MPI_P(B)[1] = ULONG_MAX;
	MPI_P(B)[2] = ULONG_MAX;
	MPI_P(B)[3] = ULONG_MAX;
	ttls_mpi_add_abs(A, B, A);
	EXPECT_TRUE(A->used == 5);
	EXPECT_TRUE(MPI_P(A)[0] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(A)[1] == 1);
	EXPECT_TRUE(MPI_P(A)[2] == 0);
	EXPECT_TRUE(MPI_P(A)[3] == 0);
	EXPECT_TRUE(MPI_P(A)[4] == 1);

	B->used = 8;
	MPI_P(B)[4] = ULONG_MAX;
	MPI_P(B)[5] = ULONG_MAX;
	MPI_P(B)[6] = ULONG_MAX;
	MPI_P(B)[7] = ULONG_MAX;
	ttls_mpi_add_abs(A, A, B);
	EXPECT_TRUE(A->used == 9);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 1);
	EXPECT_TRUE(MPI_P(A)[2] == 0);
	EXPECT_TRUE(MPI_P(A)[3] == 0);
	EXPECT_TRUE(MPI_P(A)[4] == 1);
	EXPECT_TRUE(MPI_P(A)[5] == 0);
	EXPECT_TRUE(MPI_P(A)[6] == 0);
	EXPECT_TRUE(MPI_P(A)[7] == 0);
	EXPECT_TRUE(MPI_P(A)[8] == 1);

	ttls_mpi_add_int(A, A, 3);
	EXPECT_TRUE(A->used == 9);
	EXPECT_TRUE(MPI_P(A)[0] == 1);
	EXPECT_TRUE(MPI_P(A)[1] == 2);
	EXPECT_TRUE(MPI_P(A)[2] == 0);
	EXPECT_TRUE(MPI_P(A)[3] == 0);
	EXPECT_TRUE(MPI_P(A)[4] == 1);
	EXPECT_TRUE(MPI_P(A)[5] == 0);
	EXPECT_TRUE(MPI_P(A)[6] == 0);
	EXPECT_TRUE(MPI_P(A)[7] == 0);
	EXPECT_TRUE(MPI_P(A)[8] == 1);

	B->used = 15;
	MPI_P(B)[8] = ULONG_MAX;
	MPI_P(B)[9] = ULONG_MAX;
	MPI_P(B)[10] = ULONG_MAX;
	MPI_P(B)[11] = ULONG_MAX;
	MPI_P(B)[12] = ULONG_MAX;
	MPI_P(B)[13] = ULONG_MAX;
	MPI_P(B)[14] = ULONG_MAX;
	MPI_P(B)[15] = ULONG_MAX;
	ttls_mpi_add_abs(A, B, A);
	EXPECT_TRUE(A->used == 16);
	EXPECT_TRUE(MPI_P(A)[0] == 0);
	EXPECT_TRUE(MPI_P(A)[1] == 2);
	EXPECT_TRUE(MPI_P(A)[2] == 0);
	EXPECT_TRUE(MPI_P(A)[3] == 0);
	EXPECT_TRUE(MPI_P(A)[4] == 1);
	EXPECT_TRUE(MPI_P(A)[5] == 0);
	EXPECT_TRUE(MPI_P(A)[6] == 0);
	EXPECT_TRUE(MPI_P(A)[7] == 0);
	EXPECT_TRUE(MPI_P(A)[8] == 1);
	EXPECT_TRUE(MPI_P(A)[9] == 0);
	EXPECT_TRUE(MPI_P(A)[10] == 0);
	EXPECT_TRUE(MPI_P(A)[11] == 0);
	EXPECT_TRUE(MPI_P(A)[12] == 0);
	EXPECT_TRUE(MPI_P(A)[13] == 0);
	EXPECT_TRUE(MPI_P(A)[14] == 0);
	EXPECT_TRUE(MPI_P(A)[15] == 1);

	free(A);
	free(B);
}

static void
mpi_sub(void)
{
	TlsMpi *A, *B, *X;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(8)));
	EXPECT_FALSE(!(X = ttls_mpi_alloc_stack_init(8)));

	ttls_mpi_lset(A, 7);
	ttls_mpi_lset(B, 1);
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 6);

	A->used = 2;
	MPI_P(A)[0] = 0;
	MPI_P(A)[1] = 1;
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0xffffffffffffffff);

	A->used = 4;
	MPI_P(A)[0] = 1;
	MPI_P(A)[1] = 0;
	MPI_P(A)[2] = 0;
	MPI_P(A)[3] = 1;
	B->used = 3;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 1;
	MPI_P(B)[2] = 1;
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_TRUE(A->used == 3);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[2] == 0xfffffffffffffffe);

	ttls_mpi_sub_abs(A, A, B);
	EXPECT_TRUE(A->used == 3);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffb);
	EXPECT_TRUE(MPI_P(A)[1] == 0xfffffffffffffffd);
	EXPECT_TRUE(MPI_P(A)[2] == 0xfffffffffffffffd);

	A->used = 7;
	MPI_P(A)[0] = 1;
	MPI_P(A)[1] = 0;
	MPI_P(A)[2] = 0;
	MPI_P(A)[3] = 1;
	MPI_P(A)[4] = 1;
	MPI_P(A)[5] = 1;
	MPI_P(A)[6] = 1;
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_TRUE(A->used == 7);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[3] == 0);
	EXPECT_TRUE(MPI_P(A)[4] == 1);
	EXPECT_TRUE(MPI_P(A)[5] == 1);
	EXPECT_TRUE(MPI_P(A)[6] == 1);

	A->used = 7;
	MPI_P(A)[0] = 1;
	MPI_P(A)[1] = 0;
	MPI_P(A)[2] = 0;
	MPI_P(A)[3] = 1;
	MPI_P(A)[4] = 1;
	MPI_P(A)[5] = 1;
	MPI_P(A)[6] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 7);
	EXPECT_TRUE(MPI_P(X)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[1] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[3] == 0);
	EXPECT_TRUE(MPI_P(X)[4] == 1);
	EXPECT_TRUE(MPI_P(X)[5] == 1);
	EXPECT_TRUE(MPI_P(X)[6] == 1);

	B->used = 4;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 0;
	MPI_P(B)[2] = 1;
	MPI_P(B)[3] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 7);
	EXPECT_TRUE(MPI_P(X)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[1] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[3] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[4] == 0);
	EXPECT_TRUE(MPI_P(X)[5] == 1);
	EXPECT_TRUE(MPI_P(X)[6] == 1);

	B->used = 5;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 0;
	MPI_P(B)[2] = 1;
	MPI_P(B)[3] = 1;
	MPI_P(B)[4] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 7);
	EXPECT_TRUE(MPI_P(X)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[1] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[3] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[4] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[5] == 0);
	EXPECT_TRUE(MPI_P(X)[6] == 1);

	B->used = 6;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 0;
	MPI_P(B)[2] = 1;
	MPI_P(B)[3] = 0;
	MPI_P(B)[4] = 1;
	MPI_P(B)[5] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 7);
	EXPECT_TRUE(MPI_P(X)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[1] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[3] == 0);
	EXPECT_TRUE(MPI_P(X)[4] == 0);
	EXPECT_TRUE(MPI_P(X)[5] == 0);
	EXPECT_TRUE(MPI_P(X)[6] == 1);

	B->used = 7;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 1;
	MPI_P(B)[2] = 0;
	MPI_P(B)[3] = 0;
	MPI_P(B)[4] = 1;
	MPI_P(B)[5] = 1;
	MPI_P(B)[6] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 3);
	EXPECT_TRUE(MPI_P(X)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[1] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(X)[2] == 0xffffffffffffffff);

	A->used = 4;
	MPI_P(A)[0] = 0xf51fa592df86231dUL;
	MPI_P(A)[1] = 0xe58b178153c2eec8UL;
	MPI_P(A)[2] = 0x18187a0a2c774a36UL;
	MPI_P(A)[3] = 1;
	B->used = 3;
	MPI_P(B)[0] = 0xc47a48d09535309dUL;
	MPI_P(B)[1] = 0xcc2f0502286858ceUL;
	MPI_P(B)[2] = 0x09dd51b1dc04ec91UL;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0x30a55cc24a50f280UL);
	EXPECT_TRUE(MPI_P(X)[1] == 0x195c127f2b5a95faUL);
	EXPECT_TRUE(MPI_P(X)[2] == 0x0e3b285850725da5UL);
	EXPECT_TRUE(MPI_P(X)[3] == 1);

	A->used = 6;
	MPI_P(A)[0] = 0xd2f380525326609UL;
	MPI_P(A)[1] = 0xcb7991aee015bd8eUL;
	MPI_P(A)[2] = 0x28b9ffddb7e203bbUL;
	MPI_P(A)[3] = 0x7e348742256864eaUL;
	MPI_P(A)[4] = 0xf905dd38dbaeb071UL;
	MPI_P(A)[5] = 0x9a2956c0f456798UL;
	B->used = 6;
	MPI_P(B)[0] = 0x2f5de5c3735b99ddUL;
	MPI_P(B)[1] = 0x6d0bc1736c62138bUL;
	MPI_P(B)[2] = 0xff07e3a6fb3219bfUL;
	MPI_P(B)[3] = 0x886848fae4fbb71dUL;
	MPI_P(B)[4] = 0xe51b242c40f59fe6UL;
	MPI_P(B)[5] = 0x74377a3bc14fc4aUL;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_TRUE(X->used == 6);
	EXPECT_TRUE(MPI_P(X)[0] == 0xddd15241b1d6cc2cUL);
	EXPECT_TRUE(MPI_P(X)[1] == 0x5e6dd03b73b3aa02UL);
	EXPECT_TRUE(MPI_P(X)[2] == 0x29b21c36bcafe9fcUL);
	EXPECT_TRUE(MPI_P(X)[3] == 0xf5cc3e47406cadccUL);
	EXPECT_TRUE(MPI_P(X)[4] == 0x13eab90c9ab9108aUL);
	EXPECT_TRUE(MPI_P(X)[5] == 0x25f1dc853306b4eUL);

	free(A);
	free(B);
	free(X);
}

static void
mpi_shift(void)
{
	TlsMpi *X;

	EXPECT_FALSE(!(X = ttls_mpi_alloc_stack_init(9)));

	ttls_mpi_lset(X, 1);
	ttls_mpi_shift_l(X, 17);
	EXPECT_TRUE(X->used == 1);
	EXPECT_TRUE(MPI_P(X)[0] == 0x20000);

	ttls_mpi_shift_r(X, 15);
	EXPECT_TRUE(X->used == 1);
	EXPECT_TRUE(MPI_P(X)[0] == 0x4);

	ttls_mpi_shift_l(X, 61);
	EXPECT_TRUE(X->used == 1);
	EXPECT_TRUE(MPI_P(X)[0] == 0x8000000000000000);

	ttls_mpi_shift_r(X, 63);
	EXPECT_TRUE(X->used == 1);
	EXPECT_TRUE(MPI_P(X)[0] == 1);

	ttls_mpi_shift_l(X, 64);
	EXPECT_TRUE(X->used == 2);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 1);

	ttls_mpi_shift_r(X, 64);
	EXPECT_TRUE(X->used == 1);
	EXPECT_TRUE(MPI_P(X)[0] == 1);

	MPI_P(X)[0] = 0xffffffffffffffffUL;
	ttls_mpi_shift_l(X, 60);
	EXPECT_TRUE(X->used == 2);
	EXPECT_TRUE(MPI_P(X)[0] == 0xf000000000000000UL);
	EXPECT_TRUE(MPI_P(X)[1] == 0x0fffffffffffffffUL);

	X->used = 3;
	MPI_P(X)[2] = 0x8;
	ttls_mpi_shift_r(X, 4);
	EXPECT_TRUE(X->used == 2);
	EXPECT_TRUE(MPI_P(X)[0] == 0xff00000000000000UL);
	EXPECT_TRUE(MPI_P(X)[1] == 0x80ffffffffffffffUL);

	ttls_mpi_shift_l(X, 320);
	EXPECT_TRUE(X->used == 7);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0);
	EXPECT_TRUE(MPI_P(X)[2] == 0);
	EXPECT_TRUE(MPI_P(X)[3] == 0);
	EXPECT_TRUE(MPI_P(X)[4] == 0);
	EXPECT_TRUE(MPI_P(X)[5] == 0xff00000000000000UL);
	EXPECT_TRUE(MPI_P(X)[6] == 0x80ffffffffffffffUL);

	ttls_mpi_shift_r(X, 256);
	EXPECT_TRUE(X->used == 3);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0xff00000000000000UL);
	EXPECT_TRUE(MPI_P(X)[2] == 0x80ffffffffffffffUL);

	ttls_mpi_shift_r(X, 1);
	EXPECT_TRUE(X->used == 3);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0xff80000000000000UL);
	EXPECT_TRUE(MPI_P(X)[2] == 0x407fffffffffffffUL);

	ttls_mpi_shift_l(X, 1);
	EXPECT_TRUE(X->used == 3);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0xff00000000000000UL);
	EXPECT_TRUE(MPI_P(X)[2] == 0x80ffffffffffffffUL);

	ttls_mpi_shift_l(X, 257);
	EXPECT_TRUE(X->used == 8);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0);
	EXPECT_TRUE(MPI_P(X)[2] == 0);
	EXPECT_TRUE(MPI_P(X)[3] == 0);
	EXPECT_TRUE(MPI_P(X)[4] == 0);
	EXPECT_TRUE(MPI_P(X)[5] == 0xfe00000000000000UL);
	EXPECT_TRUE(MPI_P(X)[6] == 0x01ffffffffffffffUL);
	EXPECT_TRUE(MPI_P(X)[7] == 1);

	ttls_mpi_shift_r(X, 251);
	EXPECT_TRUE(X->used == 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0xc000000000000000UL);
	EXPECT_TRUE(MPI_P(X)[2] == 0x3fffffffffffffffUL);
	EXPECT_TRUE(MPI_P(X)[3] == 0x20);

	ttls_mpi_shift_l(X, 4);
	EXPECT_TRUE(X->used == 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0);
	EXPECT_TRUE(MPI_P(X)[2] == 0xfffffffffffffffcUL);
	EXPECT_TRUE(MPI_P(X)[3] == 0x203);

	ttls_mpi_shift_l(X, 60);
	EXPECT_TRUE(X->used == 5);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0);
	EXPECT_TRUE(MPI_P(X)[2] == 0xc000000000000000UL);
	EXPECT_TRUE(MPI_P(X)[3] == 0x3fffffffffffffffUL);
	EXPECT_TRUE(MPI_P(X)[4] == 0x20);

	ttls_mpi_shift_r(X, 6);
	EXPECT_TRUE(X->used == 4);
	EXPECT_TRUE(MPI_P(X)[0] == 0);
	EXPECT_TRUE(MPI_P(X)[1] == 0);
	EXPECT_TRUE(MPI_P(X)[2] == 0xff00000000000000UL);
	EXPECT_TRUE(MPI_P(X)[3] == 0x80ffffffffffffffUL);

	free(X);
}

static void
mpi_elementary(void)
{
	TlsMpi *A, *B;
	unsigned long *save_ptr;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(2)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(2)));

	ttls_mpi_lset(A, -1);
	ttls_mpi_lset(B, 1);
	EXPECT_TRUE(ttls_mpi_cmp_int(A, -1) == 0);
	EXPECT_TRUE(ttls_mpi_cmp_int(A, -10) > 0);
	EXPECT_TRUE(ttls_mpi_cmp_int(A, 0) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	ttls_mpi_add_int(B, B, 1);
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
	ttls_mpi_add_abs(B, B, A);
	EXPECT_TRUE(ttls_mpi_cmp_int(B, LONG_MAX) > 0);
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B) == save_ptr);
	EXPECT_TRUE(MPI_P(B)[0] == 0);
	EXPECT_TRUE(MPI_P(B)[1] == 1);

	EXPECT_ZERO(ttls_mpi_copy(A, B));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(A, B));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(A, A));

	ttls_mpi_add_mpi(B, B, A);
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B)[0] == 0);
	EXPECT_TRUE(MPI_P(B)[1] == 2);

	save_ptr = MPI_P(A);
	ttls_mpi_sub_int(A, A, 2);
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(A->limbs == 2);
	EXPECT_TRUE(MPI_P(A) == save_ptr);
	EXPECT_TRUE(MPI_P(A)[0] == ULONG_MAX - 1);

	ttls_mpi_sub_mpi(B, B, A);
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B)[0] == 2);
	EXPECT_TRUE(MPI_P(B)[1] == 1);

	A->s = -1; /* have no signed integer multiplication */
	ttls_mpi_sub_mpi(B, B, A);
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);
	EXPECT_TRUE(MPI_P(B)[0] == 0);
	EXPECT_TRUE(MPI_P(B)[1] == 2);

	ttls_mpi_sub_abs(B, B, A);
	EXPECT_TRUE(B->used == 2);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);
	EXPECT_TRUE(MPI_P(B)[0] == 2);
	EXPECT_TRUE(MPI_P(B)[1] == 1);

	ttls_mpi_sub_abs(B, B, A);
	EXPECT_TRUE(ttls_mpi_cmp_mpi(A, B) < 0);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) > 0);
	EXPECT_TRUE(B->s == 1);

	ttls_mpi_lset(A, 0);
	ttls_mpi_sub_mpi(A, A, B);
	EXPECT_TRUE(ttls_mpi_cmp_abs(A, B) == 0);

	free(A);
	free(B);
}

int
main(int argc, char *argv[])
{
	mpi_cmp();
	mpi_add();
	mpi_sub();
	mpi_shift();
	mpi_elementary();

	printf("success\n");

	return 0;
}
