/**
 *		Tempesta TLS
 *
 * Elliptic curve NIST secp384r1.
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
#include "ecp.h"

/*
 * Domain parameters for secp384r1.
 * The constants are in little-endian order to be directly copied into MPIs.
 */
const unsigned long secp384r1_p[] = {
	0xffffffffUL, 0xffffffff00000000UL, 0xfffffffffffffffeUL,
	0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
};
const unsigned long secp384r1_b[] = {
	0x2a85c8edd3ec2aefUL, 0xc656398d8a2ed19dUL, 0x0314088f5013875aUL,
	0x181d9c6efe814112UL, 0x988e056be3f82d19UL, 0xb3312fa7e23ee7e4UL
};
const unsigned long secp384r1_gx[] = {
	0x3a545e3872760ab7UL, 0x5502f25dbf55296cUL, 0x59f741e082542a38UL,
	0x6e1d3b628ba79b98UL, 0x8eb1c71ef320ad74UL, 0xaa87ca22be8b0537UL
};
const unsigned long secp384r1_gy[] = {
	0x7a431d7c90ea0e5fUL, 0x0a60b1ce1d7e819dUL, 0xe9da3113b5f0b8c0UL,
	0xf8f41dbd289a147cUL, 0x5d9e98bf9292dc29UL, 0x3617de4a96262c6fUL
};
const unsigned long secp384r1_n[] = {
	0xecec196accc52973UL, 0x581a0db248b0a77aUL, 0xc7634d81f4372ddfUL,
	0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
};

/*
 * TODO #1335 this code left from mbed TLS, rework it like it's done for p256.
 *
 * Fast reduction modulo the primes used by the NIST curves.
 *
 * Compared to the way things are presented in FIPS 186-3 D.2,
 * we proceed in columns, from right (least significant chunk) to left,
 * adding chunks to N in place, and keeping a carry for the next chunk.
 * This avoids moving things around in memory, and uselessly adding zeros,
 * compared to the more straightforward, line-oriented approach.
 *
 * For these primes, we need to handle data in chunks of 32 bits.
 * This makes it more complicated if we use 64 bits limbs in MPI,
 * which prevents us from using a uniform access method as for p192.
 *
 * So, we define a mini abstraction layer to access 32 bit chunks,
 * load them in 'cur' for work, and store them back from 'cur' when done.
 *
 * While at it, also define the size of N in terms of 32-bit chunks.
 */
#define MAX32	N->used * 2
#define A(j)	j % 2							\
		? (uint32_t)(MPI_P(N)[j / 2] >> 32)			\
		: (uint32_t)(MPI_P(N)[j / 2])
#define STORE32								\
do {									\
	if (i % 2) {							\
		MPI_P(N)[i / 2] &= 0x00000000FFFFFFFF;			\
		MPI_P(N)[i / 2] |= (unsigned long)cur << 32;		\
	} else {							\
		MPI_P(N)[i / 2] &= 0xFFFFFFFF00000000;			\
		MPI_P(N)[i / 2] |= (unsigned long)cur;			\
	}								\
} while (0)

static inline void
add32(uint32_t *dst, uint32_t src, signed char *carry)
{
	*dst += src;
	*carry += (*dst < src);
}
#define ADD(j)	add32(&cur, A(j), &c);

static inline void
sub32(uint32_t *dst, uint32_t src, signed char *carry)
{
	*carry -= (*dst < src);
	*dst -= src;
}

#define SUB(j)	sub32(&cur, A(j), &c);

#define INIT()								\
	uint32_t i = 0, cur;						\
	signed char c = 0, cc;						\
	if (N->used < N->limbs)						\
		bzero_fast(MPI_P(N) + N->used, (N->limbs - N->used) * CIL);\
	cur = A(i);

#define NEXT								\
	STORE32;							\
	i++;								\
	cur = A(i);							\
	cc = c;								\
	c = 0;								\
	if (cc < 0)							\
		sub32(&cur, -cc, &c);					\
	else								\
		add32(&cur, cc, &c);

#define LAST(bits)							\
	STORE32;							\
	i++;								\
	cur = c > 0 ? c : 0;						\
	STORE32;							\
	cur = 0;							\
	while (++i < MAX32)						\
		STORE32;						\
	mpi_fixup_used(N, N->limbs);					\
	if (c < 0)							\
		fix_negative(N, c, bits);

/*
 * If the result is negative, we get it in the form c * 2^(bits + 32) + N,
 * with c negative and N positive shorter than 'bits'.
 */
static inline void
fix_negative(TlsMpi *N, signed char c, const size_t bits)
{
	TlsMpi C;

	ttls_mpi_alloca_init(&C, bits / BIL + 1);
	C.used = bits / BIL + 1;
	bzero_fast(MPI_P(&C), C.used * CIL);

	/* C = - c * 2^(bits + 32) */
	MPI_P(&C)[C.limbs - 1] = (unsigned long)-c;

	/* N = -(C - N) */
	ttls_mpi_sub_abs(N, &C, N);
	N->s = -1;
}

/*
 * Fast quasi-reduction modulo p384 (FIPS 186-3 D.2.4)
 */
void
ecp_mod_p384(TlsMpi *N)
{
	INIT();

	/* A0 */
	ADD(12); ADD(21); ADD(20);
	SUB(23);
	NEXT;
	/* A1 */
	ADD(13); ADD(22); ADD(23);
	SUB(12); SUB(20);
	NEXT;
	/* A2 */
	ADD(14); ADD(23);
	SUB(13); SUB(21);
	NEXT;
	/* A3 */
	ADD(15); ADD(12); ADD(20); ADD(21);
	SUB(14); SUB(22); SUB(23);
	NEXT;
	/* A4 */
	ADD(21); ADD(21); ADD(16); ADD(13); ADD(12); ADD(20); ADD(22);
	SUB(15); SUB(23); SUB(23);
	NEXT;
	/* A5 */
	ADD(22); ADD(22); ADD(17); ADD(14); ADD(13); ADD(21); ADD(23);
	SUB(16);
	NEXT;
	/* A6 */
	ADD(23); ADD(23); ADD(18); ADD(15); ADD(14); ADD(22);
	SUB(17);
	NEXT;
	/* A7 */
	ADD(19); ADD(16); ADD(15); ADD(23);
	SUB(18);
	NEXT;
	/* A8 */
	ADD(20); ADD(17); ADD(16);
	SUB(19);
	NEXT;
	/* A9 */
	ADD(21); ADD(18); ADD(17);
	SUB(20);
	NEXT;
	/* A10 */
	ADD(22); ADD(19); ADD(18);
	SUB(21);
	NEXT;
	/* A11 */
	ADD(23); ADD(20); ADD(19);
	SUB(22);

	LAST(384);
}
