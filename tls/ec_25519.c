/**
 *		Tempesta TLS
 *
 * Elliptic curve 25519 (Montgomery).
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Size of p255 in terms of unsigned long */
#define P255_WIDTH	  (255 / 8 / sizeof(unsigned long) + 1)

/**
 * TODO #1335 this code left from mbed TLS - rework it.
 *
 * Fast quasi-reduction modulo p255 = 2^255 - 19.
 * Write N as A0 + 2^255 A1, return A0 + 19 * A1.
 */
void
ecp_mod_p255(TlsMpi *N)
{
	size_t n;
	TlsMpi *M;

	BUG_ON(N->used < P255_WIDTH);

	M = ttls_mpi_alloc_stack_init(P255_WIDTH + 2);

	/* M = A1 */
	M->used = N->used - (P255_WIDTH - 1);
	if (M->used > P255_WIDTH + 1)
		M->used = P255_WIDTH + 1;
	n = M->used * CIL;
	memcpy_fast(MPI_P(M), MPI_P(N) + P255_WIDTH - 1, n);
	bzero_fast((char *)MPI_P(M) + n, (P255_WIDTH + 2) * CIL - n);
	ttls_mpi_shift_r(M, 255 % BIL);

	/* N = A0 */
	ttls_mpi_set_bit(N, 255, 0);
	N->used = P255_WIDTH;

	/* N = A0 + 19 * A1 */
	ttls_mpi_mul_uint(M, M, 19);
	ttls_mpi_add_abs(N, N, M);
}

/*
 * Specialized function for creating the Curve25519 group
 */
void
ecp_use_curve25519(TlsEcpGrp *grp)
{
	/* Actually (A + 2) / 4 */
	ttls_mpi_read_binary(&grp->A, "\x01\xDB\x42", 3);

	/* P = 2^255 - 19 */
	ttls_mpi_lset(&grp->P, 1);
	ttls_mpi_shift_l(&grp->P, 255);
	ttls_mpi_sub_int(&grp->P, &grp->P, 19);

	/*
	 * Y intentionaly isn't set, since we use x/z coordinates.
	 * This is used as a marker to identify Montgomery curves -
	 * see ecp_get_type().
	 */
	ttls_mpi_lset(&grp->G.X, 9);
	ttls_mpi_lset(&grp->G.Z, 1);

	/* Actually, the required msb for private keys */
	grp->bits = 254;
}
