/**
 *		Tempesta TLS
 *
 * Multi-precision integer library.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
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
#ifndef TTLS_BIGNUM_H
#define TTLS_BIGNUM_H

#include <linux/random.h>

#define TTLS_MPI_CHK(f)							\
do {									\
	if (WARN_ON_ONCE((ret = f)))					\
		goto cleanup;						\
} while (0)

#define MPI_CHK(f)							\
	if (WARN_ON_ONCE((f)))						\
		return -EDOM;

/*
 * Maximum size MPIs are allowed to grow to in number of limbs.
 * We operate with 16 bit unsigned values, which can be shifted by 6
 * (number of bits in long, 64).
 */
#define TTLS_MPI_MAX_LIMBS			0x3FF

/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * (Default: 512 bytes => 4096 bits, Maximum tested: 2048 bytes => 16384 bits)
 *
 * Note: Calculations can temporarily result in larger MPIs. So the number
 * of limbs required (TTLS_MPI_MAX_LIMBS) is higher.
 */
#define TTLS_MPI_MAX_SIZE			1024

#define LSHIFT			3		/* limb bytes shift */
#define BSHIFT			(LSHIFT + 3)	/* limb bits shift */
#define CIL			(1 << LSHIFT)	/* chars in limb */
#define LMASK			(CIL - 1)
#define BIL			(CIL << 3)	/* bits in limb */
#define BIH			(CIL << 2)	/* half limb size */
#define BMASK			(BIL - 1)
#define BITS_TO_LIMBS(n)	(((n) + BIL - 1) >> BSHIFT)
#define CHARS_TO_LIMBS(n)	(((n) + CIL - 1) >> LSHIFT)

/**
 * MPI structure.
 *
 * Limbs are stored in little endian order, i.e. head of limbs list contains
 * less significant limb. Each limb is stored in native architecture byte
 * order.
 *
 * @s		- integer sign;
 * @used	- used limbs;
 * @limbs	- total # of limbs;
 * @_off	- offset of limbs array remote memory;
 *
 * MPI is placed in relatively small areas of memory (PK context pages or
 * per-cpu pages for temporal calculations withing single handshake FSM state),
 * so @_off is typically quite small.
 */
typedef struct {
	short		s;
	unsigned short	used;
	unsigned short	limbs;
	unsigned short	_off;
} __attribute__((packed)) TlsMpi;

#define MPI_P(m)	((unsigned long *)((unsigned char *)(m) + (m)->_off))

/**
 * MPI memory pool.
 *
 * @order	- page order of the underneath memory area;
 * @curr	- offset of free memory area for MPI allocations.
 */
typedef struct {
	unsigned int		order;
	unsigned int		curr;
} TlsMpiPool;

void ttls_mpi_init(TlsMpi *X);
TlsMpi *ttls_mpi_alloc_tmp_init(size_t nblimbs);
void ttls_mpi_free(TlsMpi *X);
int __mpi_alloc(TlsMpi *X, size_t nblimbs);
bool ttls_mpi_initialized(const TlsMpi *X);
void mpi_fixup_used(TlsMpi *X, size_t n);
int ttls_mpi_copy_alloc(TlsMpi *X, const TlsMpi *Y, bool need_alloc);
int ttls_mpi_copy(TlsMpi *X, const TlsMpi *Y);
size_t ttls_mpi_size(const TlsMpi *X);

int ttls_mpi_read_binary(TlsMpi *X, const unsigned char *buf, size_t buflen);
int ttls_mpi_write_binary(const TlsMpi *X, unsigned char *buf, size_t buflen);
int ttls_mpi_fill_random(TlsMpi *X, size_t size);

int ttls_mpi_safe_cond_assign(TlsMpi *X, const TlsMpi *Y, unsigned char assign);
int ttls_mpi_safe_cond_swap(TlsMpi *X, TlsMpi *Y, unsigned char swap);

int ttls_mpi_lset(TlsMpi *X, long z);

int ttls_mpi_shift_l(TlsMpi *X, size_t count);
int ttls_mpi_shift_r(TlsMpi *X, size_t count);
int ttls_mpi_get_bit(const TlsMpi *X, size_t pos);
int ttls_mpi_set_bit(TlsMpi *X, size_t pos, unsigned char val);
size_t ttls_mpi_lsb(const TlsMpi *X);
size_t ttls_mpi_bitlen(const TlsMpi *X);

int ttls_mpi_cmp_abs(const TlsMpi *X, const TlsMpi *Y);
int ttls_mpi_cmp_mpi(const TlsMpi *X, const TlsMpi *Y);
int ttls_mpi_cmp_int(const TlsMpi *X, long z);

int ttls_mpi_add_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
int ttls_mpi_add_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
int ttls_mpi_add_int(TlsMpi *X, const TlsMpi *A, long b);

int ttls_mpi_sub_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
int ttls_mpi_sub_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
int ttls_mpi_sub_int(TlsMpi *X, const TlsMpi *A, long b);

int ttls_mpi_mul_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
int ttls_mpi_mul_uint(TlsMpi *X, const TlsMpi *A, unsigned long b);
int ttls_mpi_div_mpi(TlsMpi *Q, TlsMpi *R, const TlsMpi *A, const TlsMpi *B);
int ttls_mpi_mod_mpi(TlsMpi *R, const TlsMpi *A, const TlsMpi *B);

int ttls_mpi_exp_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *E,
		     const TlsMpi *N, TlsMpi *_RR);
int ttls_mpi_inv_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *N);
int ttls_mpi_gcd(TlsMpi *G, const TlsMpi *A, const TlsMpi *B);

#ifdef DEBUG
/**
 * There are a lot of MPI operations used around, so Tempesta TLS becomes
 * unusable if all MPIs are dumped, so following pattern should be used:
 *
 *	__mpi_do_dump = true;
 *	....
 *	some crypto operation to be debugged, e.g. ttls_ecp_mul()
 *	...
 *	__mpi_do_dump = false;
 *
 * So if you instrument ttls_ecp_mul(), then only MPIs participating in
 * particular call ttls_ecp_mul() will be printed, leaving all other
 * ttls_ecp_mul() silent.
 */
extern bool __mpi_do_dump;

void ttls_mpi_dump(const TlsMpi *X, const char *prefix);
void __log_mpis(size_t n, const char *msg, ...);

#define TTLS_MPI_DUMP_ONCE(X, prefix)					\
do {									\
	__mpi_do_dump = true;						\
	ttls_mpi_dump(X, prefix);					\
	__mpi_do_dump = false;						\
} while (0)

#define T_DBG_MPI1(msg, x1)		__log_mpis(1, msg, #x1, x1)
#define T_DBG_MPI2(msg, x1, x2)		__log_mpis(2, msg, #x1, x1, #x2, x2)
#define T_DBG_MPI3(msg, x1, x2, x3)					\
	__log_mpis(3, msg, #x1, x1, #x2, x2, #x3, x3)
#define T_DBG_MPI4(msg, x1, x2, x3, x4)					\
	__log_mpis(3, msg, #x1, x1, #x2, x2, #x3, x3, #x4, x4)

#else
#define T_DBG_MPI1(...)
#define T_DBG_MPI2(...)
#define T_DBG_MPI3(...)
#define T_DBG_MPI4(...)
#define TTLS_MPI_DUMP_ONCE(...)
#endif /* DEBUG */

#endif
