/**
 *		Tempesta TLS big integer assembly unit test
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
#include "../bignum_asm.h"

#define VEC_SZ		64
#define ALL_VECS_SZ	(VEC_SZ * 3)

static bool
__memchk(unsigned long *x, unsigned long val, size_t size)
{
	int i;

	for (i = 0; i < size; ++i)
		if (x[i] != val)
			return false;
	return true;
}

#if 0
/*
 * TODO test mpi multiplication of size 16 and more to test all the flows:
 * 16-16-8-2 16-1 16 8-3 3 1 0
 */
static void
test_mpi_mul(void)
{
	unsigned long __b[ALL_VECS_SZ];
	unsigned long *A = __b, *B = &__b[VEC_SZ], *R = &__b[VEC_SZ * 2];

	bzero(__b, sizeof(__b));
	A[0] = 0x1;
	mpi_mul_x86_64(1, 0, A, B, R);
	EXPECT_TRUE(A[0] == 0x1);
	EXPECT_TRUE(__memchk(&A[1], 0, ALL_VECS_SZ - 1));
}
#endif

int
main(int argc, char *argv[])
{
	//test_mpi_mul();

	printf("success\n");

	return 0;
}
