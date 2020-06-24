/**
 *		Tempesta TLS
 *
 * Multi-precision integer library.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
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

#if DBG_TLS == 0
#undef DEBUG
#endif

#define TTLS_MPI_CHK(f)							\
do {									\
	if (WARN((ret = (f)), #f " returns %d", ret))			\
		goto cleanup;						\
} while (0)

#define MPI_CHK(f)							\
do {									\
	if (WARN_ON_ONCE((f)))						\
		return -EDOM;						\
} while (0)

/*
 * Maximum size of MPIs allowed in bits and bytes for user-MPIs.
 * 512 bytes is enough for RSA 4096 bits, the maximum used for root CAs.
 * If some security overkill is required, then one should use EC providing more
 * security with smaller MPIs.
 *
 * Note: Calculations can temporarily result in larger MPIs. So the number
 * of limbs required (TTLS_MPI_MAX_LIMBS) gives x4 larger limit.
 */
#define TTLS_MPI_MAX_SIZE	512
#define TTLS_MPI_MAX_LIMBS	256

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
 * @_off	- offset of limbs array remote memory. Can be negative for MPIs
 *		  allocated on the stack;
 *
 * MPI is placed in relatively small areas of memory (PK context pages or
 * per-cpu pages for temporal calculations withing single handshake FSM state),
 * so @_off is typically quite small.
 */
typedef struct {
	short		s;
	unsigned short	used;
	unsigned short	limbs;
	short		_off;
} __attribute__((packed)) TlsMpi;

#define MPI_P(m)	((unsigned long *)((unsigned char *)(m) + (m)->_off))

/**
 * MPI memory pool.
 *
 * @order	- page order of the underneath memory area;
 * @curr	- offset of free memory area for MPI allocations;
 * @tmp_tail	- offset of reclaimable memory area for allocations.
 */
typedef struct {
	unsigned int		order;
	unsigned short		curr;
	unsigned short		curr_tail;
} TlsMpiPool;

/**
 * Initialize an MPI at memory by pointer @X with preallocated space for @nlimbs
 * and return a pointer to a next MPI in the same memory region.
 *
 * Note that sizeof(TlsMPI) == sizeof(long) (a limb), so MPIs are always
 * properly aligned.
 *
 * Used for multiple MPI allocations and initializations when
 * ttls_mpi_alloc_stack_init() may cost too much.
 *
 * Place the function in the header to allow the compiler to optimize out
 * unused return value if a caller doesn't care about it.
 */
static inline TlsMpi *
ttls_mpi_init_next(TlsMpi *X, size_t nlimbs)
{
	X->s = 1;
	X->used = 0;
	X->limbs = nlimbs;
	X->_off = nlimbs ? sizeof(TlsMpi) : 0;

	return (TlsMpi *)((char *)X + sizeof(TlsMpi) + nlimbs * CIL);
}

/*
 * While the kernel stack can be up to 4 pages in size, we limit the whole
 * stack allocations by one page to avoid stack overflow (we may need it for
 * other calls). Use paged per-cpu MPI pool if more memory for temporary MPIs
 * is required.
 */
#define ttls_mpi_alloca_init(X, ln)					\
do {									\
	unsigned long p, x = (unsigned long)(X);			\
	p = (unsigned long)__builtin_alloca((ln) * CIL);		\
	WARN_ON_ONCE(p + (ln) * CIL > x || p + PAGE_SIZE < x);		\
	(X)->_off = (short)(p - x);					\
	(X)->s = 1;							\
	(X)->used = 0;							\
	(X)->limbs = ln;						\
} while (0)

TlsMpi *ttls_mpi_alloc_stack_init(size_t nlimbs);
void ttls_mpi_alloc(TlsMpi *X, size_t nblimbs);
void ttls_mpi_alloc_tmp(TlsMpi *X, size_t nblimbs);
void ttls_mpi_reset(TlsMpi *X);

void mpi_fixup_used(TlsMpi *X, size_t n);
void ttls_mpi_copy_alloc(TlsMpi *X, const TlsMpi *Y, bool need_alloc);
size_t ttls_mpi_size(const TlsMpi *X);

void ttls_mpi_read_binary(TlsMpi *X, const unsigned char *buf, size_t buflen);
int ttls_mpi_write_binary(const TlsMpi *X, unsigned char *buf, size_t buflen);
void ttls_mpi_fill_random(TlsMpi *X, size_t size);

void ttls_mpi_safe_cond_assign(TlsMpi *X, const TlsMpi *Y, unsigned char assign);
int ttls_mpi_safe_cond_swap(TlsMpi *X, TlsMpi *Y, unsigned char swap);

void ttls_mpi_lset(TlsMpi *X, long z);

void ttls_mpi_shift_l(TlsMpi *X, size_t count);
void ttls_mpi_shift_r(TlsMpi *X, size_t count);
int ttls_mpi_get_bit(const TlsMpi *X, size_t pos);
void ttls_mpi_set_bit(TlsMpi *X, size_t pos, unsigned char val);
size_t ttls_mpi_lsb(const TlsMpi *X);
size_t ttls_mpi_bitlen(const TlsMpi *X);

int ttls_mpi_cmp_abs(const TlsMpi *X, const TlsMpi *Y);
int ttls_mpi_cmp_mpi(const TlsMpi *X, const TlsMpi *Y);
int ttls_mpi_cmp_int(const TlsMpi *X, long z);

void ttls_mpi_add_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
void ttls_mpi_add_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
void ttls_mpi_add_int(TlsMpi *X, const TlsMpi *A, long b);

void ttls_mpi_sub_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
void ttls_mpi_sub_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
void ttls_mpi_sub_int(TlsMpi *X, const TlsMpi *A, long b);

void ttls_mpi_mul_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B);
void ttls_mpi_mul_uint(TlsMpi *X, const TlsMpi *A, unsigned long b);
void ttls_mpi_div_mpi(TlsMpi *Q, TlsMpi *R, const TlsMpi *A, const TlsMpi *B);
void ttls_mpi_mod_mpi(TlsMpi *R, const TlsMpi *A, const TlsMpi *B);

int ttls_mpi_exp_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *E,
		     const TlsMpi *N, TlsMpi *_RR);
int ttls_mpi_inv_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *N);
void ttls_mpi_gcd(TlsMpi *G, const TlsMpi *A, const TlsMpi *B);

static inline bool
ttls_mpi_empty(const TlsMpi *X)
{
	return !X->used;
}

static inline void
ttls_mpi_copy(TlsMpi *X, const TlsMpi *Y)
{
	BUG_ON(X == Y);
	ttls_mpi_copy_alloc(X, Y, X->limbs < Y->used);
}

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

#else /* No debugging */

#define T_DBG_MPI1(...)
#define T_DBG_MPI2(...)
#define T_DBG_MPI3(...)
#define T_DBG_MPI4(...)
#define TTLS_MPI_DUMP_ONCE(...)

#endif /* DEBUG */

#endif
