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
	BUG();
}

int
ttls_mpi_pool_alloc_mpi(TlsMpi *x, size_t n)
{
	BUG();
}

void
ttls_mpi_pool_free(void *ctx)
{
	BUG();
}

TlsMpiPool *
ttls_mpool(void *addr)
{
	BUG();
}

#include "../bignum.c"
#include "util.h"

/* Mock irrelevant groups. */
const TlsEcpGrp SECP256_G = {};
const TlsEcpGrp SECP384_G = {};
const TlsEcpGrp CURVE25519_G = {};

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
	EXPECT_TRUE(B->used == 1);
	EXPECT_MPI(A, 2, 0xfffffffffffffffe, 1);

	ttls_mpi_add_int(A, A, 1);
	EXPECT_MPI(A, 2, 0xffffffffffffffff, 1);

	ttls_mpi_add_int(A, A, 1);
	EXPECT_MPI(A, 2, 0, 2);

	B->used = 4;
	MPI_P(B)[0] = ULONG_MAX;
	MPI_P(B)[1] = ULONG_MAX;
	MPI_P(B)[2] = ULONG_MAX;
	MPI_P(B)[3] = ULONG_MAX;
	ttls_mpi_add_abs(A, B, A);
	EXPECT_MPI(A, 5, 0xffffffffffffffff, 1, 0, 0, 1);

	B->used = 8;
	MPI_P(B)[4] = ULONG_MAX;
	MPI_P(B)[5] = ULONG_MAX;
	MPI_P(B)[6] = ULONG_MAX;
	MPI_P(B)[7] = ULONG_MAX;
	ttls_mpi_add_abs(A, A, B);
	EXPECT_MPI(A, 9, 0xfffffffffffffffe, 1, 0, 0, 1, 0, 0, 0, 1);

	ttls_mpi_add_int(A, A, 3);
	EXPECT_MPI(A, 9, 1, 2, 0, 0, 1, 0, 0, 0, 1);

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
	EXPECT_MPI(A, 16, 0, 2, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1);

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
	EXPECT_TRUE(B->used == 1);
	EXPECT_MPI(A, 1, 6);

	A->used = 2;
	MPI_P(A)[0] = 0;
	MPI_P(A)[1] = 1;
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_MPI(A, 1, 0xffffffffffffffff);

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
	EXPECT_MPI(A, 3, 0xfffffffffffffffe, 0xfffffffffffffffe,
			 0xfffffffffffffffe);

	ttls_mpi_sub_abs(A, A, B);
	EXPECT_MPI(A, 3, 0xfffffffffffffffb, 0xfffffffffffffffd,
			 0xfffffffffffffffd);

	A->used = 7;
	MPI_P(A)[0] = 1;
	MPI_P(A)[1] = 0;
	MPI_P(A)[2] = 0;
	MPI_P(A)[3] = 1;
	MPI_P(A)[4] = 1;
	MPI_P(A)[5] = 1;
	MPI_P(A)[6] = 1;
	ttls_mpi_sub_abs(A, A, B);
	EXPECT_MPI(A, 7, 0xfffffffffffffffe, 0xfffffffffffffffe,
			 0xfffffffffffffffe, 0, 1, 1, 1);

	A->used = 7;
	MPI_P(A)[0] = 1;
	MPI_P(A)[1] = 0;
	MPI_P(A)[2] = 0;
	MPI_P(A)[3] = 1;
	MPI_P(A)[4] = 1;
	MPI_P(A)[5] = 1;
	MPI_P(A)[6] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_MPI(X, 7, 0xfffffffffffffffe, 0xfffffffffffffffe,
			 0xfffffffffffffffe, 0, 1, 1, 1);

	B->used = 4;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 0;
	MPI_P(B)[2] = 1;
	MPI_P(B)[3] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_MPI(X, 7, 0xfffffffffffffffe, 0xffffffffffffffff,
			 0xfffffffffffffffe, 0xffffffffffffffff, 0, 1, 1);

	B->used = 5;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 0;
	MPI_P(B)[2] = 1;
	MPI_P(B)[3] = 1;
	MPI_P(B)[4] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_MPI(X, 7, 0xfffffffffffffffe, 0xffffffffffffffff,
			 0xfffffffffffffffe, 0xffffffffffffffff,
			 0xffffffffffffffff, 0, 1);

	B->used = 6;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 0;
	MPI_P(B)[2] = 1;
	MPI_P(B)[3] = 0;
	MPI_P(B)[4] = 1;
	MPI_P(B)[5] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_MPI(X, 7, 0xfffffffffffffffe, 0xffffffffffffffff,
			 0xfffffffffffffffe, 0, 0, 0, 1);

	B->used = 7;
	MPI_P(B)[0] = 3;
	MPI_P(B)[1] = 1;
	MPI_P(B)[2] = 0;
	MPI_P(B)[3] = 0;
	MPI_P(B)[4] = 1;
	MPI_P(B)[5] = 1;
	MPI_P(B)[6] = 1;
	ttls_mpi_sub_abs(X, A, B);
	EXPECT_MPI(X, 3, 0xfffffffffffffffe, 0xfffffffffffffffe,
			 0xffffffffffffffff);

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
	EXPECT_MPI(X, 4, 0x30a55cc24a50f280UL, 0x195c127f2b5a95faUL,
			 0x0e3b285850725da5UL, 1);

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
	EXPECT_MPI(X, 6, 0xddd15241b1d6cc2cUL, 0x5e6dd03b73b3aa02UL,
			 0x29b21c36bcafe9fcUL, 0xf5cc3e47406cadccUL,
			 0x13eab90c9ab9108aUL, 0x25f1dc853306b4eUL);

	free(A);
	free(B);
	free(X);
}

static void
mpi_shift(void)
{
	TlsMpi *X, *Y;

	EXPECT_FALSE(!(X = ttls_mpi_alloc_stack_init(9)));
	EXPECT_FALSE(!(Y = ttls_mpi_alloc_stack_init(9)));

	ttls_mpi_lset(X, 1);
	ttls_mpi_shift_l(Y, X, 17);
	EXPECT_MPI(Y, 1, 0x20000);

	ttls_mpi_shift_r(Y, 15);
	EXPECT_MPI(Y, 1, 0x4);

	ttls_mpi_shift_l(X, Y, 61);
	EXPECT_MPI(X, 1, 0x8000000000000000);

	ttls_mpi_shift_r(X, 63);
	EXPECT_MPI(X, 1, 1);

	ttls_mpi_shift_l(Y, X, 64);
	EXPECT_MPI(Y, 2, 0, 1);

	ttls_mpi_shift_r(Y, 64);
	EXPECT_TRUE(Y->used == 1);
	EXPECT_TRUE(MPI_P(Y)[0] == 1);

	MPI_P(Y)[0] = 0xffffffffffffffffUL;
	ttls_mpi_shift_l(X, Y, 60);
	EXPECT_MPI(X, 2, 0xf000000000000000UL, 0x0fffffffffffffffUL);

	X->used = 3;
	MPI_P(X)[2] = 0x8;
	ttls_mpi_shift_r(X, 4);
	EXPECT_MPI(X, 2, 0xff00000000000000UL, 0x80ffffffffffffffUL);

	ttls_mpi_shift_l(Y, X, 320);
	EXPECT_MPI(Y, 7, 0, 0, 0, 0, 0, 0xff00000000000000UL,
			 0x80ffffffffffffffUL);

	ttls_mpi_shift_r(Y, 256);
	EXPECT_MPI(Y, 3, 0, 0xff00000000000000UL, 0x80ffffffffffffffUL);

	ttls_mpi_shift_r(Y, 1);
	EXPECT_MPI(Y, 3, 0, 0xff80000000000000UL, 0x407fffffffffffffUL);

	ttls_mpi_shift_l(X, Y, 1);
	EXPECT_MPI(X, 3, 0, 0xff00000000000000UL, 0x80ffffffffffffffUL);

	ttls_mpi_shift_l(Y, X, 257);
	EXPECT_MPI(Y, 8, 0, 0, 0, 0, 0, 0xfe00000000000000UL,
			 0x01ffffffffffffffUL, 1);

	ttls_mpi_shift_r(Y, 251);
	EXPECT_MPI(Y, 4, 0, 0xc000000000000000UL, 0x3fffffffffffffffUL, 0x20);

	ttls_mpi_shift_l(X, Y, 4);
	EXPECT_MPI(X, 4, 0, 0, 0xfffffffffffffffcUL, 0x203);

	ttls_mpi_shift_l(X, X, 60);
	EXPECT_MPI(X, 5, 0, 0, 0xc000000000000000UL, 0x3fffffffffffffffUL,
			 0x20);

	ttls_mpi_shift_r(X, 6);
	EXPECT_MPI(X, 4, 0, 0, 0xff00000000000000UL, 0x80ffffffffffffffUL);

	free(X);
	free(Y);
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
	EXPECT_MPI(B, 1, 2);
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
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(MPI_P(B) == save_ptr);
	EXPECT_MPI(B, 2, 0, 1);

	ttls_mpi_copy(A, B);
	EXPECT_ZERO(ttls_mpi_cmp_mpi(A, B));
	EXPECT_ZERO(ttls_mpi_cmp_mpi(A, A));

	ttls_mpi_add_mpi(B, B, A);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_MPI(B, 2, 0, 2);

	save_ptr = MPI_P(A);
	ttls_mpi_sub_int(A, A, 2);
	EXPECT_TRUE(A->limbs == 2);
	EXPECT_TRUE(MPI_P(A) == save_ptr);
	EXPECT_MPI(A, 1, ULONG_MAX - 1);

	ttls_mpi_sub_mpi(B, B, A);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_MPI(B, 2, 2, 1);

	A->s = -1; /* have no signed integer multiplication */
	ttls_mpi_sub_mpi(B, B, A);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);
	EXPECT_MPI(B, 2, 0, 2);

	ttls_mpi_sub_abs(B, B, A);
	EXPECT_TRUE(B->limbs == 2);
	EXPECT_TRUE(B->s == 1);
	EXPECT_MPI(B, 2, 2, 1);

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

static void
ecp_mod256(void)
{
	TlsMpi *X = ttls_mpi_alloc_stack_init(8);

	ttls_mpi_lset(X, 0);

	MPI_P(X)[0] = 1;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 1, 0, 0, 0);

	MPI_P(X)[0] = 0xfffffffffffffffeUL;
	MPI_P(X)[1] = 0xffffffffUL;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0xffffffff00000001UL;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xfffffffffffffffeUL, 0xffffffffUL,
			 0, 0xffffffff00000001UL);

	MPI_P(X)[0] = 0xffffffffffffffffUL;
	MPI_P(X)[1] = 0xffffffffUL;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0xffffffff00000001UL;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0, 0, 0, 0);

	MPI_P(X)[0] = 0;
	MPI_P(X)[1] = 0x100000000UL;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0xffffffff00000001UL;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 1, 0, 0, 0);

	MPI_P(X)[0] = 1;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0;
	MPI_P(X)[4] = 1;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 2, 0xffffffff00000000, 0xffffffffffffffff,
			 0xfffffffeUL);

	MPI_P(X)[0] = 0x0000000100000002;
	MPI_P(X)[1] = 0x0000000300000004;
	MPI_P(X)[2] = 0x0000000500000006;
	MPI_P(X)[3] = 0x0000000700000008;
	MPI_P(X)[4] = 0x000000090000000a;
	MPI_P(X)[5] = 0x0000000b0000000c;
	MPI_P(X)[6] = 0x0000000d0000000e;
	MPI_P(X)[7] = 0x0000000f00000011;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xffffffdaffffffde, 0x1fffffffedUL, 0x3900000038UL,
			 0x0c00000053UL);

	MPI_P(X)[0] = 0x81049834a729f046;
	MPI_P(X)[1] = 0x8e8ccd3064d562a6;
	MPI_P(X)[2] = 0x9571db50f3374ad4;
	MPI_P(X)[3] = 0x9ce41a936065fb64;
	MPI_P(X)[4] = 0xc123e496517641f8;
	MPI_P(X)[5] = 0x77fc879a14c43d96;
	MPI_P(X)[6] = 0xa10f6b7f64496e90;
	MPI_P(X)[7] = 0x106c3d3c1c31371c;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x24f66bf9203d7e0eUL, 0xc521c13a23e947ffUL,
			 0x939e9894443213e3UL, 0x8d8574ff64476023UL);

	MPI_P(X)[0] = 0xffffffffffffffff;
	MPI_P(X)[1] = 0xffffffffffffffff;
	MPI_P(X)[2] = 0xffffffffffffffff;
	MPI_P(X)[3] = 0xffffffffffffffff;
	MPI_P(X)[4] = 0xffffffff;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0xffffffffffffffff;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x200000004UL, 0xfffffffb00000000UL,
			 0xfffffffdfffffffcUL, 0x4fffffff9UL);

	MPI_P(X)[0] = 0xaaaaaaaaaaaaaaaa;
	MPI_P(X)[1] = 0x5555555555555555;
	MPI_P(X)[2] = 0x7777777777777777;
	MPI_P(X)[3] = 0xffffffffffffffff;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xaaaaaaaaaaaaaaabUL, 0x5555555455555555UL,
			 0x7777777777777777UL, 0xfffffffeUL);

	MPI_P(X)[0] = 0xffffffff00000001;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0xffffffff;
	MPI_P(X)[3] = 0xffffffffffffffff;
	MPI_P(X)[4] = 0;
	MPI_P(X)[5] = 0;
	MPI_P(X)[6] = 0;
	MPI_P(X)[7] = 0;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xffffffff00000002UL, 0xffffffff00000000UL,
			 0xfffffffeUL, 0xfffffffeUL);

	MPI_P(X)[0] = 0;
	MPI_P(X)[1] = 0;
	MPI_P(X)[2] = 0;
	MPI_P(X)[3] = 0;
	MPI_P(X)[4] = 0xffffffffffffffff;
	MPI_P(X)[5] = 0xffffffffffffffff;
	MPI_P(X)[6] = 0xffffffffffffffff;
	MPI_P(X)[7] = 0xffffffffffffffff;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x2UL, 0xfffffffcffffffffUL, 0xfffffffffffffffeUL,
			 0x3fffffffeUL);

	/*
	 * The tests at the below check the corner cases of the FIPS 186-3 D.2
	 * modular reduction (64-bit little endian, less significant to most
	 * significant limbs storage):
	 *
	 *  c1 c0  c3 c2  c5 c4  c7 c6  c9 c8  c11 c10  c13 c12  c15 c14
	 */
	MPI_P(X)[0] = 0x0000000000000000UL;
	MPI_P(X)[1] = 0x0000000000000000UL;
	MPI_P(X)[2] = 0x0000000000000000UL;
	MPI_P(X)[3] = 0x0000000000000000UL;
	MPI_P(X)[4] = 0xffffffff00000000UL;
	MPI_P(X)[5] = 0xffffffffffffffffUL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0x0000000000000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xfffffffdfffffffeUL, 0x00000000fffffffeUL,
			 0x0000000200000002UL, 0x0000000000000004UL);

	MPI_P(X)[0] = 0x0000000000000000UL;
	MPI_P(X)[1] = 0x0000000000000000UL;
	MPI_P(X)[2] = 0x0000000000000000UL;
	MPI_P(X)[3] = 0x0000000000000000UL;
	MPI_P(X)[4] = 0xffffffff00000000UL;
	MPI_P(X)[5] = 0xffffffff00000000UL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0x0000000000000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xfffffffeffffffffUL, 0xfffffffefffffffeUL,
			 0x0000000200000000UL, 0x0000000000000004UL);

	MPI_P(X)[0] = 0x0000000000000000UL;
	MPI_P(X)[1] = 0x0000000000000000UL;
	MPI_P(X)[2] = 0x0000000000000000UL;
	MPI_P(X)[3] = 0x0000000000000000UL;
	MPI_P(X)[4] = 0xffffffff00000000UL;
	MPI_P(X)[5] = 0xffffffff00000000UL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0xffffffff00000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x0000000000000002UL, 0xfffffffbffffffffUL,
			 0x00000000ffffffffUL, 0x0000000200000000UL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x0000000000000000UL;
	MPI_P(X)[2] = 0x0000000000000000UL;
	MPI_P(X)[3] = 0x0000000000000000UL;
	MPI_P(X)[4] = 0xffffffff00000000UL;
	MPI_P(X)[5] = 0xffffffff00000000UL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0xffffffff00000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0xffffffffaaaaaaacUL, 0xfffffffbffffffffUL,
			 0x00000000ffffffffUL, 0x0000000200000000UL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x0000000000000000UL;
	MPI_P(X)[2] = 0x0000000000000000UL;
	MPI_P(X)[3] = 0x0000000000000000UL;
	MPI_P(X)[4] = 0xffffffff00000000UL;
	MPI_P(X)[5] = 0x3333333300000000UL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0xffffffff00000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x0000000077777778UL, 0x6666666333333334UL,
			 0xccccccccfffffffeUL, 0xccccccce00000000UL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x3333333322222222UL;
	MPI_P(X)[2] = 0x5555555544444444UL;
	MPI_P(X)[3] = 0xffffffffffffffffUL;
	MPI_P(X)[4] = 0xffffffff00000000UL;
	MPI_P(X)[5] = 0x3333333300000000UL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0xffffffff00000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x0000000077777779UL, 0x9999999555555556UL,
			 0x2222222244444442UL, 0xccccccceffffffffUL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x3333333322222222UL;
	MPI_P(X)[2] = 0x5555555544444444UL;
	MPI_P(X)[3] = 0xffffffffffffffffUL;
	MPI_P(X)[4] = 0x00000000ffffffffUL;
	MPI_P(X)[5] = 0x3333333300000000UL;
	MPI_P(X)[6] = 0xffffffffffffffffUL;
	MPI_P(X)[7] = 0xffffffff00000000UL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x000000017777777aUL, 0x9999999455555555UL,
			 0x2222222344444441UL, 0xcccccccefffffffeUL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x3333333322222222UL;
	MPI_P(X)[2] = 0x5555555544444444UL;
	MPI_P(X)[3] = 0xffffffffffffffffUL;
	MPI_P(X)[4] = 0x11111111ffffffffUL;
	MPI_P(X)[5] = 0x3333333300000000UL;
	MPI_P(X)[6] = 0xccccccccffffffffUL;
	MPI_P(X)[7] = 0xffffffffeeeeeeeeUL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x55555556ccccccd1UL, 0x5555554e99999999UL,
			 0x99999999bbbbbbb8UL, 0x0000000588888884UL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x3333333322222222UL;
	MPI_P(X)[2] = 0x5555555544444444UL;
	MPI_P(X)[3] = 0xffffffffffffffffUL;
	MPI_P(X)[4] = 0x11111111ffffffffUL;
	MPI_P(X)[5] = 0x0101010100000000UL;
	MPI_P(X)[6] = 0x01020304ffffffffUL;
	MPI_P(X)[7] = 0xffffffffeeeeeeeeUL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x21201f1fcac9c8cbUL, 0x2526272333323130UL,
			 0x3436383a24262827UL, 0xfdfcfbfebcbdbebbUL);

	MPI_P(X)[0] = 0xffffffffaaaaaaaaUL;
	MPI_P(X)[1] = 0x3333333322222222UL;
	MPI_P(X)[2] = 0x5555555544444444UL;
	MPI_P(X)[3] = 0xffffffffffffffffUL;
	MPI_P(X)[4] = 0x11111111ffffffffUL;
	MPI_P(X)[5] = 0x0101010100000000UL;
	MPI_P(X)[6] = 0x0000000000000000UL;
	MPI_P(X)[7] = 0xffffffffeeeeeeeeUL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x22222223cbcbcbcfUL, 0x2424242034343435UL,
			 0x323232302222221fUL, 0xfefeff02bbbbbbb6UL);

	MPI_P(X)[0] = 0xffffffffffffffffUL;
	MPI_P(X)[1] = 0xffffffffffffffffUL;
	MPI_P(X)[2] = 0xffffffffffffffffUL;
	MPI_P(X)[3] = 0xffffffffffffffffUL;
	MPI_P(X)[4] = 0x00000000ffffffffUL;
	MPI_P(X)[5] = 0x0000000000000000UL;
	MPI_P(X)[6] = 0x0000000000000000UL;
	MPI_P(X)[7] = 0xffffffffffffffffUL;
	ecp_mod_p256_x86_64(MPI_P(X));
	EXPECT_MPI(X, 4, 0x0000000200000004UL, 0xfffffffb00000000UL,
			 0xfffffffdfffffffcUL, 0x00000004fffffff9UL);

	free(X);
}

static void
ecp_sub_mod256(void)
{
	TlsMpi *A, *B, *X;
	unsigned long *a, *b, *x;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(4)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(4)));
	EXPECT_FALSE(!(X = ttls_mpi_alloc_stack_init(4)));

	ttls_mpi_lset(A, 1);
	ttls_mpi_lset(B, 1);
	ttls_mpi_lset(X, 0);
	A->used = 4;
	B->used = 4;
	X->used = 4;
	a = MPI_P(A);
	b = MPI_P(B);
	x = MPI_P(X);

	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 0, 0, 0, 0);

	MPI_P(A)[0] = 2;
	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 1, 0, 0, 0);
	mpi_sub_mod_p256_x86_64_4(x, b, a);
	EXPECT_MPI(X, 4, 0xfffffffffffffffeUL, 0x00000000ffffffffUL,
			 0x0000000000000000UL, 0xffffffff00000001UL);

	MPI_P(A)[0] = 0;
	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 0xfffffffffffffffeUL, 0x00000000ffffffffUL,
			 0x0000000000000000UL, 0xffffffff00000001UL);
	mpi_sub_mod_p256_x86_64_4(x, b, a);
	EXPECT_MPI(X, 4, 1, 0, 0, 0);

	MPI_P(B)[0] = 0;
	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 0, 0, 0, 0);

	MPI_P(A)[0] = 0xfffffffffffffffeUL;
	MPI_P(A)[1] = 0xffffffffUL;
	MPI_P(A)[2] = 0;
	MPI_P(A)[3] = 0xffffffff00000001UL;
	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 0xfffffffffffffffeUL, 0x00000000ffffffffUL,
			 0x0000000000000000UL, 0xffffffff00000001UL);
	mpi_sub_mod_p256_x86_64_4(x, b, a);
	EXPECT_MPI(X, 4, 1, 0, 0, 0);

	MPI_P(B)[0] = 1;
	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 0xfffffffffffffffdUL, 0x00000000ffffffffUL,
			 0x0000000000000000UL, 0xffffffff00000001UL);
	mpi_sub_mod_p256_x86_64_4(x, b, a);
	EXPECT_MPI(X, 4, 2, 0, 0, 0);

	MPI_P(B)[0] = 0x81049834a729f046;
	MPI_P(B)[1] = 0x8e8ccd3064d562a6;
	MPI_P(B)[2] = 0x9571db50f3374ad4;
	MPI_P(B)[3] = 0x9ce41a936065fb64;
	mpi_sub_mod_p256_x86_64_4(x, a, b);
	EXPECT_MPI(X, 4, 0x7efb67cb58d60fb8UL, 0x717332d09b2a9d59UL,
			 0x6a8e24af0cc8b52bUL, 0x631be56b9f9a049cUL);
	mpi_sub_mod_p256_x86_64_4(x, b, a);
	EXPECT_MPI(X, 4, 0x81049834a729f047UL, 0x8e8ccd3064d562a6UL,
			 0x9571db50f3374ad4UL, 0x9ce41a936065fb64UL);

	mpi_sub_mod_p256_x86_64_4(x, x, b);
	EXPECT_MPI(X, 4, 0x0000000000000001UL, 0x0000000000000000UL,
			 0x0000000000000000UL, 0x0000000000000000UL);
	mpi_sub_mod_p256_x86_64_4(x, x, a);
	EXPECT_MPI(X, 4, 2, 0, 0, 0);

	free(A);
	free(B);
	free(X);
}

int
main(int argc, char *argv[])
{
	mpi_cmp();
	mpi_add();
	mpi_sub();
	mpi_shift();
	mpi_elementary();
	ecp_mod256();
	ecp_sub_mod256();

	printf("success\n");

	return 0;
}
