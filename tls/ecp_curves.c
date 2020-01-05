/**
 *		Tempesta TLS
 *
 * Elliptic curves over GF(p): curve-specific data and functions.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
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
#include "tls_internal.h"

#define BYTES_TO_T_UINT_8(a, b, c, d, e, f, g, h)	\
	((unsigned long)a <<  0) |			\
	((unsigned long)b <<  8) |			\
	((unsigned long)c << 16) |			\
	((unsigned long)d << 24) |			\
	((unsigned long)e << 32) |			\
	((unsigned long)f << 40) |			\
	((unsigned long)g << 48) |			\
	((unsigned long)h << 56)

/*
 * The constants are in little-endian order to be directly copied into MPIs.
 */

/* Domain parameters for secp256r1. */
static const unsigned long secp256r1_p[] = {
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00),
	BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
	BYTES_TO_T_UINT_8(0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
};
static const unsigned long secp256r1_b[] = {
	BYTES_TO_T_UINT_8(0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B),
	BYTES_TO_T_UINT_8(0xF6, 0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65),
	BYTES_TO_T_UINT_8(0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3),
	BYTES_TO_T_UINT_8(0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A),
};
static const unsigned long secp256r1_gx[] = {
	BYTES_TO_T_UINT_8(0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4),
	BYTES_TO_T_UINT_8(0xA0, 0x33, 0xEB, 0x2D, 0x81, 0x7D, 0x03, 0x77),
	BYTES_TO_T_UINT_8(0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8),
	BYTES_TO_T_UINT_8(0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B),
};
static const unsigned long secp256r1_gy[] = {
	BYTES_TO_T_UINT_8(0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB),
	BYTES_TO_T_UINT_8(0xCE, 0x5E, 0x31, 0x6B, 0x57, 0x33, 0xCE, 0x2B),
	BYTES_TO_T_UINT_8(0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E),
	BYTES_TO_T_UINT_8(0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F),
};
static const unsigned long secp256r1_n[] = {
	BYTES_TO_T_UINT_8(0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3),
	BYTES_TO_T_UINT_8(0x84, 0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
};

/* Domain parameters for secp384r1. */
static const unsigned long secp384r1_p[] = {
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00),
	BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
};
static const unsigned long secp384r1_b[] = {
	BYTES_TO_T_UINT_8(0xEF, 0x2A, 0xEC, 0xD3, 0xED, 0xC8, 0x85, 0x2A),
	BYTES_TO_T_UINT_8(0x9D, 0xD1, 0x2E, 0x8A, 0x8D, 0x39, 0x56, 0xC6),
	BYTES_TO_T_UINT_8(0x5A, 0x87, 0x13, 0x50, 0x8F, 0x08, 0x14, 0x03),
	BYTES_TO_T_UINT_8(0x12, 0x41, 0x81, 0xFE, 0x6E, 0x9C, 0x1D, 0x18),
	BYTES_TO_T_UINT_8(0x19, 0x2D, 0xF8, 0xE3, 0x6B, 0x05, 0x8E, 0x98),
	BYTES_TO_T_UINT_8(0xE4, 0xE7, 0x3E, 0xE2, 0xA7, 0x2F, 0x31, 0xB3),
};
static const unsigned long secp384r1_gx[] = {
	BYTES_TO_T_UINT_8(0xB7, 0x0A, 0x76, 0x72, 0x38, 0x5E, 0x54, 0x3A),
	BYTES_TO_T_UINT_8(0x6C, 0x29, 0x55, 0xBF, 0x5D, 0xF2, 0x02, 0x55),
	BYTES_TO_T_UINT_8(0x38, 0x2A, 0x54, 0x82, 0xE0, 0x41, 0xF7, 0x59),
	BYTES_TO_T_UINT_8(0x98, 0x9B, 0xA7, 0x8B, 0x62, 0x3B, 0x1D, 0x6E),
	BYTES_TO_T_UINT_8(0x74, 0xAD, 0x20, 0xF3, 0x1E, 0xC7, 0xB1, 0x8E),
	BYTES_TO_T_UINT_8(0x37, 0x05, 0x8B, 0xBE, 0x22, 0xCA, 0x87, 0xAA),
};
static const unsigned long secp384r1_gy[] = {
	BYTES_TO_T_UINT_8(0x5F, 0x0E, 0xEA, 0x90, 0x7C, 0x1D, 0x43, 0x7A),
	BYTES_TO_T_UINT_8(0x9D, 0x81, 0x7E, 0x1D, 0xCE, 0xB1, 0x60, 0x0A),
	BYTES_TO_T_UINT_8(0xC0, 0xB8, 0xF0, 0xB5, 0x13, 0x31, 0xDA, 0xE9),
	BYTES_TO_T_UINT_8(0x7C, 0x14, 0x9A, 0x28, 0xBD, 0x1D, 0xF4, 0xF8),
	BYTES_TO_T_UINT_8(0x29, 0xDC, 0x92, 0x92, 0xBF, 0x98, 0x9E, 0x5D),
	BYTES_TO_T_UINT_8(0x6F, 0x2C, 0x26, 0x96, 0x4A, 0xDE, 0x17, 0x36),
};
static const unsigned long secp384r1_n[] = {
	BYTES_TO_T_UINT_8(0x73, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC),
	BYTES_TO_T_UINT_8(0x7A, 0xA7, 0xB0, 0x48, 0xB2, 0x0D, 0x1A, 0x58),
	BYTES_TO_T_UINT_8(0xDF, 0x2D, 0x37, 0xF4, 0x81, 0x4D, 0x63, 0xC7),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
	BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
};

/*
 * Fast reduction modulo the primes used by the NIST curves.
 *
 * Compared to the way things are presented in FIPS 186-3 D.2,
 * we proceed in columns, from right (least significant chunk) to left,
 * adding chunks to N in place, and keeping a carry for the next chunk.
 * This avoids moving things around in memory, and uselessly adding zeros,
 * compared to the more straightforward, line-oriented approach.
 *
 * For this prime we need to handle data in chunks of 64 bits.
 * Since this is always a multiple of our basic unsigned long, we can
 * use a unsigned long * to designate such a chunk, and small loops to handle it.
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

/*
 * Helpers for addition and subtraction of chunks, with signed carry.
 */
static inline void
add32(uint32_t *dst, uint32_t src, signed char *carry)
{
	*dst += src;
	*carry += (*dst < src);
}

static inline void
sub32(uint32_t *dst, uint32_t src, signed char *carry)
{
	*carry -= (*dst < src);
	*dst -= src;
}

#define ADD(j)	add32(&cur, A(j), &c);
#define SUB(j)	sub32(&cur, A(j), &c);

/* Helpers for the main 'loop'. */
#define INIT()								\
	size_t i = 0;							\
	uint32_t cur;							\
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
		MPI_CHK(fix_negative(N, c, bits));

/*
 * If the result is negative, we get it in the form c * 2^(bits + 32) + N,
 * with c negative and N positive shorter than 'bits'.
 */
static inline int
fix_negative(TlsMpi *N, signed char c, const size_t bits)
{
	TlsMpi C;

	ttls_mpi_alloca_init(&C, bits / BIL + 1);
	C.used = bits / BIL + 1;
	bzero_fast(MPI_P(&C), C.used * CIL);

	/* C = - c * 2^(bits + 32) */
	MPI_P(&C)[C.limbs - 1] = (unsigned long)-c;

	/* N = -(C - N) */
	MPI_CHK(ttls_mpi_sub_abs(N, &C, N));
	N->s = -1;

	return 0;
}

/*
 * Fast quasi-reduction modulo p256 (FIPS 186-3 D.2.3).
 * TODO #1064 the most mathematic hot spot - called enourmously many times.
 */
static int
ecp_mod_p256(TlsMpi *N)
{
	INIT();

	/* A0 */
	ADD(8); ADD(9);
	SUB(11); SUB(12); SUB(13); SUB(14);
	NEXT;
	/* A1 */
	ADD(9); ADD(10);
	SUB(12); SUB(13); SUB(14); SUB(15);
	NEXT;
	/* A2 */
	ADD(10); ADD(11);
	SUB(13); SUB(14); SUB(15);
	NEXT;
	/* A3 */
	ADD(11); ADD(11); ADD(12); ADD(12); ADD(13);
	SUB(15); SUB(8); SUB(9);
	NEXT;
	/* A4 */
	ADD(12); ADD(12); ADD(13); ADD(13); ADD(14);
	SUB(9); SUB(10);
	NEXT;
	/* A5 */
	ADD(13); ADD(13); ADD(14); ADD(14); ADD(15);
	SUB(10); SUB(11);
	NEXT;
	/* A6 */
	ADD(14); ADD(14); ADD(15); ADD(15); ADD(14); ADD(13);
	SUB(8); SUB(9);
	NEXT;
	/* A7 */
	ADD(15); ADD(15); ADD(15); ADD(8);
	SUB(10); SUB(11); SUB(12); SUB(13);

	LAST(256);

	return 0;
}

/*
 * Fast quasi-reduction modulo p384 (FIPS 186-3 D.2.4)
 */
static int ecp_mod_p384(TlsMpi *N)
{
	INIT();

	/* A0 */
	ADD(12); ADD(21); ADD(20);
	SUB(23);
	NEXT;
	/* A2 */
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

	return 0;
}

#undef A
#undef STORE32
#undef MAX32
#undef INIT
#undef NEXT
#undef LAST

/* Size of p255 in terms of unsigned long */
#define P255_WIDTH	  (255 / 8 / sizeof(unsigned long) + 1)

/**
 * Fast quasi-reduction modulo p255 = 2^255 - 19.
 * Write N as A0 + 2^255 A1, return A0 + 19 * A1.
 */
static int
ecp_mod_p255(TlsMpi *N)
{
	int r;
	size_t n;
	TlsMpi *M;

	if (N->used < P255_WIDTH)
		return 0;
	if (!(M = ttls_mpi_alloc_stck_init(P255_WIDTH + 2)))
		return -ENOMEM;

	/* M = A1 */
	M->used = N->used - (P255_WIDTH - 1);
	if (M->used > P255_WIDTH + 1)
		M->used = P255_WIDTH + 1;
	n = M->used * CIL;
	memcpy(MPI_P(M), MPI_P(N) + P255_WIDTH - 1, n);
	memset((char *)MPI_P(M) + n, 0, (P255_WIDTH + 2) * CIL - n);
	if ((r = ttls_mpi_shift_r(M, 255 % BIL)))
		return r;

	/* N = A0 */
	if ((r = ttls_mpi_set_bit(N, 255, 0)))
		return r;
	N->used = P255_WIDTH;

	/* N = A0 + 19 * A1 */
	if ((r = ttls_mpi_mul_uint(M, M, 19)))
		return r;
	return ttls_mpi_add_abs(N, N, M);
}

/**
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof unsigned long).
 */
static int
ecp_mpi_load(TlsMpi *X, const unsigned long *p, size_t len)
{
	size_t const limbs = len / CIL;

	if (__mpi_alloc(X, limbs))
		return -ENOMEM;

	X->s = 1;
	X->limbs = X->used = limbs;
	memcpy(MPI_P(X), p, len);

	return 0;
}

/*
 * Make group available from embedded constants
 */
static int
ecp_group_load(TlsEcpGrp *grp, const unsigned long *p,  size_t plen,
	       const unsigned long *b,  size_t blen,
	       const unsigned long *gx, size_t gxlen,
	       const unsigned long *gy, size_t gylen,
	       const unsigned long *n,  size_t nlen)
{
	int i;

	if (ecp_mpi_load(&grp->P, p, plen)
	    || ecp_mpi_load(&grp->B, b, blen)
	    || ecp_mpi_load(&grp->G.X, gx, gxlen)
	    || ecp_mpi_load(&grp->G.Y, gy, gylen)
	    || ecp_mpi_load(&grp->N, n, nlen))
		return -ENOMEM;

	grp->h = 1;
	grp->pbits = ttls_mpi_bitlen(&grp->P);
	grp->nbits = ttls_mpi_bitlen(&grp->N);

	/*
	 * Most of the time the point is normalized, so Z stores 1, but
	 * is some calculations the size can grow up to the curve size.
	 */
	if (__mpi_alloc(&grp->G.Z, grp->nbits / BIL)
	    || ttls_mpi_lset(&grp->G.Z, 1))
		return -ENOMEM;

	/*
	 * ecp_normalize_jac_many() performs multiplication on X and Y
	 * coordinates, so we need double sizes.
	 */
	for (i = 0; i < ARRAY_SIZE(grp->T); i++)
		if (__mpi_alloc(&grp->T[i].X, grp->G.X.limbs * 2)
		    || __mpi_alloc(&grp->T[i].Y, grp->G.Y.limbs * 2))
			return -ENOMEM;
	/*
	 * Allocate Z coordinates separately to shrink them later,
	 * see __mpool_ecp_shrink_tz().
	 */
	for (i = 0; i < ARRAY_SIZE(grp->T); i++)
		if (__mpi_alloc(&grp->T[i].Z, grp->G.Z.limbs))
			return -ENOMEM;

	return 0;
}

/*
 * Specialized function for creating the Curve25519 group
 */
static int
ecp_use_curve25519(TlsEcpGrp *grp)
{
	/* Actually (A + 2) / 4 */
	MPI_CHK(ttls_mpi_read_binary(&grp->A, "\x01\xDB\x42", 3));

	/* P = 2^255 - 19 */
	MPI_CHK(ttls_mpi_lset(&grp->P, 1));
	MPI_CHK(ttls_mpi_shift_l(&grp->P, 255));
	MPI_CHK(ttls_mpi_sub_int(&grp->P, &grp->P, 19));
	grp->pbits = ttls_mpi_bitlen(&grp->P);

	/*
	 * Y intentionaly isn't set, since we use x/z coordinates.
	 * This is used as a marker to identify Montgomery curves -
	 * see ecp_get_type().
	 */
	MPI_CHK(ttls_mpi_lset(&grp->G.X, 9));
	MPI_CHK(ttls_mpi_lset(&grp->G.Z, 1));

	/* Actually, the required msb for private keys */
	grp->nbits = 254;

	return 0;
}

/**
 * Set a group using well-known domain parameters.
 *
 * @id should be a value of RFC 8422's NamedCurve (see ecp_supported_curves).
 */
int
ttls_ecp_group_load(TlsEcpGrp *grp, ttls_ecp_group_id id)
{
#define LOAD_GROUP(G)	ecp_group_load(grp, G##_p, sizeof(G##_p),	\
					    G##_b, sizeof(G##_b),	\
					    G##_gx, sizeof(G##_gx),	\
					    G##_gy, sizeof(G##_gy),	\
					    G##_n, sizeof(G##_n))

	grp->id = id;

	switch(id) {
	case TTLS_ECP_DP_SECP256R1:
		grp->modp = ecp_mod_p256;
		return LOAD_GROUP(secp256r1);
	case TTLS_ECP_DP_SECP384R1:
		grp->modp = ecp_mod_p384;
		return LOAD_GROUP(secp384r1);
	case TTLS_ECP_DP_CURVE25519:
		T_WARN("Try to load ECP group for unsupported Curve25519.\n");
		grp->modp = ecp_mod_p255;
		return ecp_use_curve25519(grp);
	default:
		grp->id = 0;
		return TTLS_ERR_ECP_FEATURE_UNAVAILABLE;
	}
#undef LOAD_GROUP
}
