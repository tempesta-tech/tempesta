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
mpi_add(void)
{
	TlsMpi *A, *B;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(16)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(16)));

	/* ttls_mpi_lset() works with signed values, so initialize raw memory. */
	EXPECT_ZERO(ttls_mpi_lset(A, 0));
	EXPECT_ZERO(ttls_mpi_lset(B, 0));
	MPI_P(A)[0] = ULONG_MAX;
	MPI_P(B)[0] = ULONG_MAX;
	EXPECT_ZERO(ttls_mpi_add_abs(A, B, A));
	EXPECT_TRUE(A->used == 2);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 1);

	EXPECT_ZERO(ttls_mpi_add_int(A, A, 1));
	EXPECT_TRUE(A->used == 2);
	EXPECT_TRUE(MPI_P(A)[0] == 0xffffffffffffffff);
	EXPECT_TRUE(MPI_P(A)[1] == 1);

	EXPECT_ZERO(ttls_mpi_add_int(A, A, 1));
	EXPECT_TRUE(A->used == 2);
	EXPECT_TRUE(MPI_P(A)[0] == 0);
	EXPECT_TRUE(MPI_P(A)[1] == 2);

	B->used = 4;
	MPI_P(B)[0] = ULONG_MAX;
	MPI_P(B)[1] = ULONG_MAX;
	MPI_P(B)[2] = ULONG_MAX;
	MPI_P(B)[3] = ULONG_MAX;
	EXPECT_ZERO(ttls_mpi_add_abs(A, B, A));
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
	EXPECT_ZERO(ttls_mpi_add_abs(A, A, B));
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

	EXPECT_ZERO(ttls_mpi_add_int(A, A, 3));
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
	EXPECT_ZERO(ttls_mpi_add_abs(A, B, A));
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
	TlsMpi *A, *B;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(16)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(16)));

	EXPECT_ZERO(ttls_mpi_lset(A, 7));
	EXPECT_ZERO(ttls_mpi_lset(B, 1));
	EXPECT_ZERO(ttls_mpi_sub_abs(A, A, B));
	EXPECT_TRUE(A->used == 1);
	EXPECT_TRUE(B->used == 1);
	EXPECT_TRUE(MPI_P(A)[0] == 6);

	A->used = 2;
	MPI_P(A)[0] = 0;
	MPI_P(A)[1] = 1;
	EXPECT_ZERO(ttls_mpi_sub_abs(A, A, B));
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
	EXPECT_ZERO(ttls_mpi_sub_abs(A, A, B));
	EXPECT_TRUE(A->used == 3);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[2] == 0xfffffffffffffffe);

	EXPECT_ZERO(ttls_mpi_sub_abs(A, A, B));
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
	EXPECT_ZERO(ttls_mpi_sub_abs(A, A, B));
	EXPECT_TRUE(A->used == 7);
	EXPECT_TRUE(MPI_P(A)[0] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[1] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[2] == 0xfffffffffffffffe);
	EXPECT_TRUE(MPI_P(A)[3] == 0);
	EXPECT_TRUE(MPI_P(A)[4] == 1);
	EXPECT_TRUE(MPI_P(A)[5] == 1);
	EXPECT_TRUE(MPI_P(A)[6] == 1);

	/*
	 * TODO #1064: test high level subtraction:
	 * -- getting negative value
	 */

	free(A);
	free(B);
}

/**
 * Just a bunch of some simple operations on the same MPIs to check that
 * there are no side effects.
 *
 * Make sure that all the operations above are in the test as well.
 */
static void
mpi_elementary(void)
{
	TlsMpi *A, *B;
	unsigned long *save_ptr;

	EXPECT_FALSE(!(A = ttls_mpi_alloc_stack_init(2)));
	EXPECT_FALSE(!(B = ttls_mpi_alloc_stack_init(2)));

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

	free(A);
	free(B);
}

int
main(int argc, char *argv[])
{
	mpi_add();
	mpi_sub();
	mpi_elementary();

	printf("success\n");

	return 0;
}
