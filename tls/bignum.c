/*
 *		Tempesta TLS
 *
 * Multi-precision integer library.
 *
 * The following sources were referenced in the design of this Multi-precision
 * Integer library:
 *
 * [1] Handbook of Applied Cryptography - 1997
 *     Menezes, van Oorschot and Vanstone
 *
 * [2] Multi-Precision Math, Tom St Denis
 *
 * [3] GNU Multi-Precision Arithmetic Library
 *     https://gmplib.org/manual/index.html
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
#include <linux/bitops.h>

#include "lib/str.h"
#include "bignum.h"
#include "mpool.h"
#include "tls_internal.h"

/* Can be used for constant MPIs only! */
#define DECLARE_MPI_AUTO(name, size)					\
	TlsMpi name = { .limbs = size, .used = size };			\
	unsigned long __p[size];					\
	name._off = (short)((unsigned long)__p - (unsigned long)&name);

/* Maximum sliding window size in bits used for modular exponentiation. */
#define MPI_W_SZ		6

/**
 * Allocate an MPI on the stack and initialize it with the required limbs in
 * one shot.
 *
 * The most MPI functions allocate required memory if necessary, but they can
 * do this for initialized MPI, so if the first call after the initalization
 * allocates less memory than all the following, then we're in trouble and
 * have to call __mpi_alloc() right after the initialization and before the
 * first usage. This function makes this simpler.
 */
TlsMpi *
ttls_mpi_alloc_stck_init(size_t nlimbs)
{
	TlsMpi *X;

	X = ttls_mpool_alloc_stack(sizeof(TlsMpi) + nlimbs * CIL);
	if (unlikely(!X))
		return NULL;

	ttls_mpi_init_next(X, nlimbs);

	return X;
}

/**
 * Technically, the function is equal ttls_mpi_init_next(), so the MPI becomes
 * invalid and ttls_mpi_empty() returns true for it. However, if at some
 * point we decide to write something here, we won't request a new memory chunk.
 */
void
ttls_mpi_free(TlsMpi *X)
{
	if (unlikely(!X))
		return;

	if (X->_off) {
		X->used = 0;
		X->s = 0;
	}
}

static int
__mpi_alloc(TlsMpi *X, size_t nlimbs, bool tail)
{
	int new_off;

	if (likely(X->limbs >= nlimbs))
		return 0;

	/*
	 * Reallocation must be called on MPI initialization only and only once
	 * for an MPI - we don't want to copy the MPI data for reallocation.
	 */
	if (WARN(X->limbs,
		 "Try to grow MPI of size %u to %lu\n", X->limbs, nlimbs))
		return -ENOMEM;
	if (WARN_ON_ONCE(nlimbs > TTLS_MPI_MAX_LIMBS))
		return -ENOMEM;

	new_off = ttls_mpi_pool_alloc_mpi(X, nlimbs * CIL, tail);
	if (new_off <= 0)
		return -ENOMEM;

	X->limbs = nlimbs;
	X->_off = new_off;

	return 0;
}

int
ttls_mpi_alloc(TlsMpi *X, size_t nlimbs)
{
	return __mpi_alloc(X, nlimbs, false);
}

int
ttls_mpi_alloc_tmp(TlsMpi *X, size_t nlimbs)
{
	return __mpi_alloc(X, nlimbs, true);
}

/**
 * Set proper @X->used. Move from @n towards first limb and throw out all zeros.
 */
void
mpi_fixup_used(TlsMpi *X, size_t n)
{
	if (unlikely(n > X->limbs))
		n = X->limbs;
	/*
	 * Leave the least significant limb even if it's zero to represent
	 * zero valued MPI.
	 */
	for (X->used = n; X->used > 1 && !MPI_P(X)[X->used - 1]; )
		--X->used;
}

int
ttls_mpi_copy_alloc(TlsMpi *X, const TlsMpi *Y, bool need_alloc)
{
	if (unlikely(!Y->_off)) {
		WARN_ON_ONCE(Y->used);
		WARN_ON_ONCE(Y->s != 1);

		X->used = 0;
		X->s = 1;

		return 0;
	}

	if (need_alloc)
		if (ttls_mpi_alloc(X, Y->used))
			return -ENOMEM;
	memcpy_fast(MPI_P(X), MPI_P(Y), Y->used * CIL);
	X->s = Y->s;
	X->used = Y->used;

	return 0;
}

int
ttls_mpi_copy(TlsMpi *X, const TlsMpi *Y)
{
	if (unlikely(X == Y))
		return 0;

	return ttls_mpi_copy_alloc(X, Y, X->limbs < Y->used);
}

/**
 * Safe conditional assignment X = Y if @assign is 1.
 *
 * This function avoids leaking any information about whether the assignment was
 * done or not (the above code may leak information through branch prediction
 * and/or memory access patterns analysis). Leaking information about the
 * respective sizes of X and Y is ok however.
 */
int
ttls_mpi_safe_cond_assign(TlsMpi *X, const TlsMpi *Y, unsigned char assign)
{
	int i;

	/* Make sure assign is 0 or 1 in a time-constant manner. */
	assign = (assign | (unsigned char)-assign) >> 7;

	if (ttls_mpi_alloc(X, Y->used))
		return -ENOMEM;

	X->s = X->s * (1 - assign) + Y->s * assign;
	X->used = X->used * (1 - assign) + Y->used * assign;

	for (i = 0; i < Y->used; i++)
		MPI_P(X)[i] = MPI_P(X)[i] * (1 - assign) + MPI_P(Y)[i] * assign;

	return 0;
}

/**
 * Conditionally swap X and Y, without leaking information about whether the
 * swap was made or not. Here it is not ok to simply swap the pointers, which
 * would lead to different memory access patterns when X and Y are used
 * afterwards.
 */
int
ttls_mpi_safe_cond_swap(TlsMpi *X, TlsMpi *Y, unsigned char swap)
{
	unsigned short used;
	int s, i;

	if (X == Y)
		return 0;

	/* Make sure swap is 0 or 1 in a time-constant manner. */
	swap = (swap | (unsigned char)-swap) >> 7;

	if (WARN_ON_ONCE(X->limbs < Y->used || Y->limbs < X->used))
		return -ENOMEM;

	s = X->s;
	X->s = X->s * (1 - swap) + Y->s * swap;
	Y->s = Y->s * (1 - swap) + s * swap;

	used = X->used;
	X->used = X->used * (1 - swap) + Y->used * swap;
	Y->used = Y->used * (1 - swap) + used * swap;

	used = max_t(unsigned short, X->used, Y->used);
	for (i = 0; i < used; i++) {
		unsigned long tmp = MPI_P(X)[i];
		MPI_P(X)[i] = MPI_P(X)[i] * (1 - swap) + MPI_P(Y)[i] * swap;
		MPI_P(Y)[i] = MPI_P(Y)[i] * (1 - swap) + tmp * swap;
	}

	return 0;
}

/**
 * Set value from integer.
 */
int
ttls_mpi_lset(TlsMpi *X, long z)
{
	if (ttls_mpi_alloc(X, 1))
		return -ENOMEM;

	X->used = 1;
	if (z < 0) {
		MPI_P(X)[0] = -z;
		X->s = -1;
	} else {
		MPI_P(X)[0] = z;
		X->s = 1;
	}

	return 0;
}

int
ttls_mpi_get_bit(const TlsMpi *X, size_t pos)
{
	if ((X->used << BSHIFT) <= pos)
		return 0;

	return (MPI_P(X)[pos >> BSHIFT] >> (pos & BMASK)) & 0x01;
}

/**
 * Set a bit to a specific value of 0 or 1.
 *
 * Will grow X if necessary to set a bit to 1 in a not yet existing limb.
 * Will not grow if bit should be set to 0.
 */
int
ttls_mpi_set_bit(TlsMpi *X, size_t pos, unsigned char val)
{
	size_t off = pos >> BSHIFT;
	size_t idx = pos & BMASK;

	WARN_ON_ONCE(val != 0 && val != 1);

	if (unlikely(X->used << BSHIFT <= pos)) {
		if (!val)
			return 0;
		if (WARN_ON_ONCE(X->limbs << BSHIFT <= pos))
			return -ENOMEM;
		bzero_fast(&MPI_P(X)[X->used], (off - X->used + 1) << LSHIFT);
		X->used = off + 1;
	}

	MPI_P(X)[off] &= ~((unsigned long)0x01 << idx);
	MPI_P(X)[off] |= (unsigned long)val << idx;

	return 0;
}

/**
 * Return the number of less significant zero-bits, which is equal to the
 * position of the first less significant bit.
 *
 * WARNING: this doesn't work with ttls_mpi_set_bit() called with @pos out of
 * X->used and value 0.
 */
size_t
ttls_mpi_lsb(const TlsMpi *X)
{
	size_t i;

	for (i = 0 ; i < X->used; i++) {
		if (!MPI_P(X)[i])
			continue;
		return (i * BIL) + __ffs(MPI_P(X)[i]);
	}

	return 0;
}

size_t
ttls_mpi_bitlen(const TlsMpi *X)
{
	if (!X->used || !MPI_P(X)[X->used - 1])
		return 0;

	/*
	 * Number of full limbs plus number of less significant non-zero bits.
	 */
	return (X->used - 1) * BIL + fls64(MPI_P(X)[X->used - 1]);
}

/*
 * Return the total size in bytes
 */
size_t
ttls_mpi_size(const TlsMpi *X)
{
	return (ttls_mpi_bitlen(X) + 7) >> 3;
}

/**
 * Left-shift: X <<= count.
 *
 * TODO #1064 stupid 2*n algorithm, do this in one shot.
 */
int
ttls_mpi_shift_l(TlsMpi *X, size_t count)
{
	size_t v0, t1, old_used = X->used, i = ttls_mpi_bitlen(X);
	unsigned long r0 = 0, r1, *p = MPI_P(X);

	if (unlikely(!i))
		return 0;

	v0 = count >> BSHIFT;
	t1 = count & BMASK;
	i += count;

	if (WARN_ON_ONCE((X->limbs << BSHIFT) < i))
		return -ENOSPC;

	X->used = BITS_TO_LIMBS(i);
	if (old_used < X->used)
		bzero_fast(p + old_used, (X->used - old_used) * CIL);

	/* Shift by count / limb_size. */
	if (v0 > 0) {
		for (i = X->used; i > v0; i--)
			p[i - 1] = p[i - v0 - 1];
		for ( ; i > 0; i--)
			p[i - 1] = 0;
	}

	/* shift by count % limb_size. */
	if (t1 > 0) {
		for (i = v0; i < X->used; i++) {
			r1 = p[i] >> (BIL - t1);
			p[i] <<= t1;
			p[i] |= r0;
			r0 = r1;
		}
	}

	return 0;
}

/**
 * Right-shift: X >>= count.
 *
 * TODO #1064 stupid 2*n algorithm, do this in one shot.
 */
int
ttls_mpi_shift_r(TlsMpi *X, size_t count)
{
	size_t i, v0, v1;
	unsigned long r0 = 0, r1;

	if (unlikely(!X->used || !MPI_P(X)[X->used - 1])) {
		WARN_ON_ONCE(X->used > 1);
		return 0;
	}

	v0 = count >> BSHIFT;
	v1 = count & BMASK;

	if (v0 > X->used || (v0 == X->used && v1 > 0))
		return ttls_mpi_lset(X, 0);

	/*
	 * Shift by count / limb_size - remove least significant limbs.
	 * There could be garbage after last used limb, so be careful.
	 */
	if (v0 > 0) {
		X->used -= v0;
		for (i = 0; i < X->used; i++)
			MPI_P(X)[i] = MPI_P(X)[i + v0];
	}

	/* Shift by count % limb_size. */
	if (v1 > 0) {
		for (i = X->used; i > 0; i--) {
			r1 = MPI_P(X)[i - 1] << (BIL - v1);
			MPI_P(X)[i - 1] >>= v1;
			MPI_P(X)[i - 1] |= r0;
			r0 = r1;
		}
		if (!MPI_P(X)[X->used - 1])
			--X->used;
	}

	return 0;
}

#ifdef DEBUG
/**
 * Dump MPI content, including unused limbs, for debugging.
 */
bool __mpi_do_dump = false;

void
ttls_mpi_dump(const TlsMpi *X, const char *prefix)
{
	if (!__mpi_do_dump)
		return;

	pr_info("MPI(%pK, p=%pK) %s DUMP: s=%d used=%u limbs=%u off=%d\n",
		X, MPI_P(X), prefix, X->s, X->used, X->limbs, X->_off);
	print_hex_dump(KERN_INFO, "    ", DUMP_PREFIX_OFFSET, 16, 1, MPI_P(X),
		       X->limbs * sizeof(long), true);
}

/**
 * Prints @msg for all debug layers.
 * Print argeuments on 3rd debug layer as list of @n pairs
 * <const char *name, const TlsMpi *X>.
 */
void
__log_mpis(size_t n, const char *msg, ...)
{
	T_DBG("%s\n", msg);
#if DEBUG == 3
	{
		va_list args;

		va_start(args, msg);
		while (n--)
			/* Put the args on the stack in reverse order. */
			ttls_mpi_dump(va_arg(args, const TlsMpi *),
				      va_arg(args, const char *));
		va_end(args);
	}
#endif
}
#endif /* DEBUG */

/**
 * Import X from unsigned binary data.
 * The bytes are read in reverse order and stored as big endian.
 */
int
ttls_mpi_read_binary(TlsMpi *X, const unsigned char *buf, size_t buflen)
{
	size_t i = buflen, l = 0, j;
	size_t const limbs = CHARS_TO_LIMBS(buflen);

	if (unlikely(!buflen))
		return 0;
	if (ttls_mpi_alloc(X, limbs))
		return -ENOMEM;

	X->s = 1;
	while (i >= CIL) {
		i -= CIL;
		MPI_P(X)[l] = cpu_to_be64(*(long *)(buf + i));
		++l;
	}
	if (i) {
		/* Read last, probably incomplete, limb if any. */
		MPI_P(X)[l] = 0;
		for (j = 0; i > 0; i--, j += 8)
			MPI_P(X)[l] |= ((unsigned long)buf[i - 1]) << j;
	}

	mpi_fixup_used(X, limbs);

	return 0;
}

/**
 * Export X into unsigned binary data, big endian.
 * Always fills the whole buffer, which will start with zeros if the number
 * is smaller.
 */
int
ttls_mpi_write_binary(const TlsMpi *X, unsigned char *buf, size_t buflen)
{
	size_t i, l, b, n = ttls_mpi_size(X);

	if (buflen < n)
		return -ENOSPC;

	for (i = buflen, l = 0; l < X->used && i >= CIL; ++l) {
		i -= CIL;
		*(unsigned long *)(buf + i) = cpu_to_be64(MPI_P(X)[l]);
	}

	WARN_ON_ONCE(l == X->used - 1 && i < n % CIL);

	if (i && l == X->used - 1)
		for (b = 0, n %= CIL; n > 0; i--, n--, b += 8)
			buf[i - 1] = (unsigned char)(MPI_P(X)[l] >> b);
	if (i)
		memset(buf, 0, i);

	return 0;
}

/**
 * Fill X with @size bytes of random.
 *
 * Use a temporary bytes representation to make sure the result is the same
 * regardless of the platform endianness (useful when f_rng is actually
 * deterministic, eg for tests).
 */
int
ttls_mpi_fill_random(TlsMpi *X, size_t size)
{
	size_t limbs = CHARS_TO_LIMBS(size);
	size_t rem = limbs * CIL - size;

	if (WARN_ON_ONCE(size > TTLS_MPI_MAX_SIZE))
		return -EINVAL;

	if (ttls_mpi_alloc(X, limbs))
		return -ENOMEM;

	ttls_rnd(MPI_P(X), size);
	if (rem > 0)
		memset((char *)MPI_P(X) + size, 0, rem);
	X->used = limbs;
	X->s = 1;

	return 0;
}

/**
 * Compare unsigned values.
 */
int
ttls_mpi_cmp_abs(const TlsMpi *X, const TlsMpi *Y)
{
	int i;

	if (!X->used && !Y->used)
		return 0;

	if (X->used > Y->used)
		return 1;
	if (Y->used > X->used)
		return -1;

	for (i = X->used - 1; i >= 0; i--) {
		if (MPI_P(X)[i] == MPI_P(Y)[i])
			continue;
		return MPI_P(X)[i] > MPI_P(Y)[i] ? 1 : -1;
	}

	return 0;
}

/*
 * Compare signed values.
 */
int
ttls_mpi_cmp_mpi(const TlsMpi *X, const TlsMpi *Y)
{
	int i;

	if (!X->used && !Y->used)
		return 0;

	if (X->used > Y->used)
		return X->s;
	if (Y->used > X->used)
		return -Y->s;

	if (X->s > 0 && Y->s < 0)
		return 1;
	if (Y->s > 0 && X->s < 0)
		return -1;

	for (i = X->used - 1; i >= 0; i--) {
		if (MPI_P(X)[i] == MPI_P(Y)[i])
			continue;
		return MPI_P(X)[i] > MPI_P(Y)[i] ? X->s : -X->s;
	}

	return 0;
}

/**
 * Compare MPI with a signed value.
 */
int
ttls_mpi_cmp_int(const TlsMpi *X, long z)
{
	if (X->used > 1)
		return X->s;
	if (!X->used)
		return z == 0 ? 0 : z < 0 ? 1 : -1;

	if (z < 0) {
		if (X->s > 0)
			return 1;
		z = -z;
	} else {
		if (X->s < 0)
			return -1;
	}

	/* Modular comparison. */
	return z == MPI_P(X)[0] ? 0 : MPI_P(X)[0] > z ? X->s : -X->s;
}

/**
 * Unsigned addition: X = |A| + |B|
 *
 * @A and @B must be different, but either of them can accept the result @X.
 */
int
ttls_mpi_add_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	size_t i;
	unsigned long *a, *b, *x, c = 0;

	BUG_ON(A == B);
	if (X == B) {
		const TlsMpi *T = A;
		A = X;
		B = T;
	}

	/* X should always be positive as a result of unsigned additions. */
	X->s = 1;

	if (WARN_ON_ONCE(X->limbs < max_t(unsigned short, A->used, B->used)))
		return -ENOSPC;
	X->used = A->used;

	a = MPI_P(A);
	b = MPI_P(B);
	x = MPI_P(X);
	/* TODO #1064 move out condition from under the loop. */
	for (i = 0; i < B->used; i++, a++, b++, x++) {
		if (i == X->used) {
			++X->used;
			*x = c;
		} else {
			*x = *a + c;
		}
		c = *x < c;
		*x += *b;
		c += *x < *b;
	}
	for ( ; c; i++, a++, x++) {
		BUG_ON(i >= X->limbs);
		if (i == X->used) {
			++X->used;
			*x = c;
		} else {
			*x = *a + c;
		}
		c = *x < c;
	}
	if (X != A && X->used > i)
		memcpy_fast(x, a, (X->used - i) * CIL);

	return 0;
}

/**
 * Subtract @b from @a and write result to @r, @a_len > @b_len.
 * Either @a or @b can be referenced by @r.
 */
static void
__mpi_sub(unsigned long *a, size_t a_len, unsigned long *b, size_t b_len,
	  unsigned long *r)
{
	unsigned long c = 0, z, b_tmp, *b_end = b + b_len, *a_end = a + a_len;

	BUG_ON(a_len < b_len);

	for ( ; b < b_end; a++, b++, r++) {
		z = *a < c;
		b_tmp = *b;
		*r = *a - c;
		c = (*r < b_tmp) + z;
		*r -= b_tmp;
	}
	while (c) {
		z = *a < c;
		*r = *a - c;
		c = z;
		a++;
		r++;
	}
	BUG_ON(a > a_end);
	memcpy_fast(r, a, (a_end - a) * CIL);
}

/**
 * Unsigned subtraction: X = |A| - |B| (HAC 14.9).
 * @X may reference either @A or @B.
 */
int
ttls_mpi_sub_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	if (ttls_mpi_cmp_abs(A, B) < 0)
		return -EINVAL;

	if (ttls_mpi_alloc(X, A->used))
		return -ENOMEM;

	__mpi_sub(MPI_P(A), A->used, MPI_P(B), B->used, MPI_P(X));

	/* X should always be positive as a result of unsigned subtractions. */
	X->s = 1;
	mpi_fixup_used(X, A->used);

	return 0;
}

/**
 * Signed addition: X = A + B
 */
int
ttls_mpi_add_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	int r, s = A->s;

	if (A->s * B->s < 0) {
		if (ttls_mpi_cmp_abs(A, B) >= 0) {
			if ((r = ttls_mpi_sub_abs(X, A, B)))
				return r;
			X->s = s;
		} else {
			if ((r = ttls_mpi_sub_abs(X, B, A)))
				return r;
			X->s = -s;
		}
	} else {
		if ((r = ttls_mpi_add_abs(X, A, B)))
			return r;
		X->s = s;
	}

	return 0;
}

/**
 * Signed subtraction: X = A - B
 */
int
ttls_mpi_sub_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	int r, s = A->s;

	if (A->s * B->s > 0) {
		if (ttls_mpi_cmp_abs(A, B) >= 0) {
			if ((r = ttls_mpi_sub_abs(X, A, B)))
				return r;
			X->s = s;
		} else {
			if ((r = ttls_mpi_sub_abs(X, B, A)))
				return r;
			X->s = -s;
		}
	} else {
		if ((r = ttls_mpi_add_abs(X, A, B)))
			return r;
		X->s = s;
	}

	return 0;
}

/**
 * Signed addition: X = A + b
 */
int
ttls_mpi_add_int(TlsMpi *X, const TlsMpi *A, long b)
{
	DECLARE_MPI_AUTO(_B, 1);
	MPI_P(&_B)[0] = (b < 0) ? -b : b;
	_B.s = (b < 0) ? -1 : 1;

	return ttls_mpi_add_mpi(X, A, &_B);
}

/**
 * Signed subtraction: X = A - b
 */
int
ttls_mpi_sub_int(TlsMpi *X, const TlsMpi *A, long b)
{
	DECLARE_MPI_AUTO(_B, 1);
	MPI_P(&_B)[0] = (b < 0) ? -b : b;
	_B.s = (b < 0) ? -1 : 1;
	_B.limbs = _B.used = 1;

	return ttls_mpi_sub_mpi(X, A, &_B);
}

/*
 * TODO #1064 see MULADDC_HUIT optimization in original mbedTLS; use AVX2.
 */
#define MULADDC_INIT							\
	asm(	"xorq	%%r8, %%r8	\n\t"

#define MULADDC_CORE							\
		"movq	(%%rsi), %%rax	\n\t"				\
		"mulq	%%rbx		\n\t"				\
		"addq	$8, %%rsi	\n\t"				\
		"addq	%%rcx, %%rax	\n\t"				\
		"movq	%%r8, %%rcx	\n\t"				\
		"adcq	$0, %%rdx	\n\t"				\
		"nop			\n\t"				\
		"addq	%%rax, (%%rdi)	\n\t"				\
		"adcq	%%rdx, %%rcx	\n\t"				\
		"addq	$8, %%rdi	\n\t"

#define MULADDC_STOP							\
		: "+c" (c), "+D" (d), "+S" (s)				\
		: "b" (b)						\
		: "rax", "rdx", "r8"					\
	);

/**
 * Multiplies vector @s of size @n by scalar @b and stores result in vector @d.
 */
static void
__mpi_mul(size_t n, const unsigned long *s, unsigned long *d, unsigned long b)
{
	unsigned long c = 0;

	for ( ; n >= 16; n -= 16) {
		MULADDC_INIT
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE

		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_STOP
	}
	for ( ; n >= 8; n -= 8) {
		MULADDC_INIT
		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE

		MULADDC_CORE MULADDC_CORE
		MULADDC_CORE MULADDC_CORE
		MULADDC_STOP
	}
	for ( ; n > 0; n--) {
		MULADDC_INIT
		MULADDC_CORE
		MULADDC_STOP
	}

	do {
		*d += c;
		c = *d < c;
		d++;
	} while (c);
}

/**
 * Baseline multiplication: X = A * B  (HAC 14.12).
 *
 * All the arguments may reference the same MPI.
 */
int
ttls_mpi_mul_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	size_t i = A->used, j = B->used;
	TlsMpi T;

	if (X == A) {
		ttls_mpi_alloca_init(&T, A->used);
		if (ttls_mpi_copy_alloc(&T, A, false))
			return -ENOMEM;
		if (A == B)
			B = &T;
		A = &T;
	}
	else if (X == B) {
		ttls_mpi_alloca_init(&T, B->used);
		if (ttls_mpi_copy_alloc(&T, B, false))
			return -ENOMEM;
		B = &T;
	}

	if (ttls_mpi_alloc(X, i + j))
		return -ENOMEM;
	bzero_fast(MPI_P(X), CIL * (i + j));
	X->used = i + j;

	for ( ; j > 0; j--)
		__mpi_mul(i, MPI_P(A), MPI_P(X) + j - 1, MPI_P(B)[j - 1]);

	mpi_fixup_used(X, X->used);

	X->s = A->s * B->s;

	return 0;
}

/*
 * Baseline multiplication: X = A * b
 */
int
ttls_mpi_mul_uint(TlsMpi *X, const TlsMpi *A, unsigned long b)
{
	DECLARE_MPI_AUTO(_B, 1);
	_B.s = 1;
	MPI_P(&_B)[0] = b;

	return ttls_mpi_mul_mpi(X, A, &_B);
}

/**
 * Unsigned integer divide - double unsigned long dividend, @u1/@u0,
 * and unsigned long divisor, @d.
 */
static unsigned long
ttls_int_div_int(unsigned long u1, unsigned long u0, unsigned long d,
		 unsigned long *r)
{
	const unsigned long radix = 1UL << BIH;
	const unsigned long uint_halfword_mask = (1UL << BIH) - 1;
	unsigned long d0, d1, q0, q1, rAX, r0;
	unsigned long u0_msw, u0_lsw;
	size_t s;

	/* Check for overflow. */
	if (!d || u1 >= d) {
		if (r)
			*r = ~0UL;
		return ~0UL;
	}

	/*
	 * Algorithm D, Section 4.3.1 - The Art of Computer Programming
	 *   Vol. 2 - Seminumerical Algorithms, Knuth.
	 */

	/* Normalize the divisor, d, and dividend, u0, u1. */
	s = BIL - fls64(d);
	d = d << s;

	u1 = u1 << s;
	u1 |= (u0 >> (BIL - s)) & (-(long)s >> (BIL - 1));
	u0 =  u0 << s;

	d1 = d >> BIH;
	d0 = d & uint_halfword_mask;

	u0_msw = u0 >> BIH;
	u0_lsw = u0 & uint_halfword_mask;

	/* Find the first quotient and remainder. */
	q1 = u1 / d1;
	r0 = u1 - d1 * q1;

	while (q1 >= radix || (q1 * d0 > radix * r0 + u0_msw)) {
		--q1;
		r0 += d1;
		if (r0 >= radix)
			break;
	}

	rAX = (u1 * radix) + (u0_msw - q1 * d);
	q0 = rAX / d1;
	r0 = rAX - q0 * d1;

	while (q0 >= radix || (q0 * d0 > radix * r0 + u0_lsw)) {
		--q0;
		r0 += d1;
		if (r0 >= radix)
			break;
	}

	if (r)
		*r = (rAX * radix + u0_lsw - q0 * d) >> s;

	return q1 * radix + q0;
}

/**
 * Division by TlsMpi: A = Q * B + R  (HAC 14.20).
 *
 * @Q - destination MPI for the quotient.
 * @R - destination MPI for the rest value.
 * @A - left-hand MPI.
 * @B - right-hand MPI.
 */
int
ttls_mpi_div_mpi(TlsMpi *Q, TlsMpi *R, const TlsMpi *A, const TlsMpi *B)
{
	int r;
	size_t i, n, t, k;
	TlsMpi X, Y, Z, T1, T2;

	if (!ttls_mpi_cmp_int(B, 0)) {
		T_DBG_MPI1("Division by zero", B);
		TTLS_MPI_DUMP_ONCE(B, "B/zero");
		return -EINVAL;
	}
	if (!ttls_mpi_cmp_int(B, 1)) {
		if (Q)
			if (ttls_mpi_copy(Q, A))
				return -ENOMEM;
		if (R)
			if (ttls_mpi_lset(R, 0))
				return -ENOMEM;
		return 0;
	}
	if (ttls_mpi_cmp_abs(A, B) < 0) {
		if (Q)
			if (ttls_mpi_lset(Q, 0))
				return -ENOMEM;
		if (R)
			if (ttls_mpi_copy(R, A))
				return -ENOMEM;
		return 0;
	}

	if (!Q) {
		ttls_mpi_alloca_init(&Z, A->used);
		Q = &Z;
	}

	ttls_mpi_alloca_init(&X, A->used + 1);
	ttls_mpi_alloca_init(&Y, A->used + 1);
	ttls_mpi_alloca_init(&T1, 3 + A->used);
	ttls_mpi_alloca_init(&T2, 3);
	if (ttls_mpi_copy_alloc(&X, A, false)
	    || ttls_mpi_copy_alloc(&Y, B, false))
		return -ENOMEM;
	X.s = Y.s = 1;

	/* Initialize Q after copying A to X in case of Q == A. */
	if (Q != &Z && ttls_mpi_alloc(Q, A->used))
		return -ENOMEM;
	Q->used = A->used;
	bzero_fast(MPI_P(Q), Q->used * CIL);

	k = ttls_mpi_bitlen(&Y) & BMASK;
	if (k < BIL - 1) {
		k = BIL - 1 - k;
		if (ttls_mpi_shift_l(&X, k) || ttls_mpi_shift_l(&Y, k))
			return -ENOMEM;
	} else {
		k = 0;
	}

	n = X.used - 1;
	t = Y.used - 1;

	if (ttls_mpi_shift_l(&Y, BIL * (n - t)))
		return -ENOMEM;
	while (ttls_mpi_cmp_mpi(&X, &Y) >= 0) {
		MPI_P(Q)[n - t]++;
		if ((r = ttls_mpi_sub_mpi(&X, &X, &Y)))
			return r;
	}
	if (ttls_mpi_shift_r(&Y, BIL * (n - t)))
		return -ENOMEM;

	for (i = n; i > t; i--) {
		MPI_P(Q)[i - t - 1] = MPI_P(&X)[i] >= MPI_P(&Y)[t]
				      ? 0
				      : ttls_int_div_int(MPI_P(&X)[i],
							 MPI_P(&X)[i - 1],
							 MPI_P(&Y)[t], NULL)
					+ 1;

		T2.s = 1;
		MPI_P(&T2)[0] = (i < 2) ? 0 : MPI_P(&X)[i - 2];
		MPI_P(&T2)[1] = (i < 1) ? 0 : MPI_P(&X)[i - 1];
		MPI_P(&T2)[2] = MPI_P(&X)[i];
		mpi_fixup_used(&T2, 3);

		/*
		 * TODO #1064 inadequately many iterations - use binary search
		 * for value of [i - t - 1]th limb.
		 */
		do {
			MPI_P(Q)[i - t - 1]--;

			T1.s = 1;
			T1.used = 2; /* overwrite previous multiplication */
			MPI_P(&T1)[0] = (t < 1) ? 0 : MPI_P(&Y)[t - 1];
			MPI_P(&T1)[1] = MPI_P(&Y)[t];
			mpi_fixup_used(&T1, 2);
			if (ttls_mpi_mul_uint(&T1, &T1, MPI_P(Q)[i - t - 1]))
				return -ENOMEM;
		} while (ttls_mpi_cmp_mpi(&T1, &T2) > 0);

		if ((r = ttls_mpi_mul_uint(&T1, &Y, MPI_P(Q)[i - t - 1]))
		    || (r = ttls_mpi_shift_l(&T1,  BIL * (i - t - 1)))
		    || (r = ttls_mpi_sub_mpi(&X, &X, &T1)))
			return r;

		if (ttls_mpi_cmp_int(&X, 0) < 0) {
			if (ttls_mpi_copy(&T1, &Y)
			    || ttls_mpi_shift_l(&T1, BIL * (i - t - 1))
			    || ttls_mpi_add_mpi(&X, &X, &T1))
				return -ENOMEM;
			MPI_P(Q)[i - t - 1]--;
		}
	}

	if (Q != &Z) {
		Q->s = A->s * B->s;
		mpi_fixup_used(Q, Q->used);
	}
	if (R) {
		if (ttls_mpi_shift_r(&X, k))
			return -ENOMEM;
		mpi_fixup_used(&X, X.used);
		X.s = A->s;
		if (ttls_mpi_copy(R, &X))
			return -ENOMEM;
		if (ttls_mpi_cmp_int(R, 0) == 0)
			R->s = 1;
	}

	return 0;
}

/**
 * Modulo: R = A mod B.
 *
 * @R - destination MPI for the rest value.
 * @A - left-hand MPI.
 * @B - right-hand MPI.
 */
int
ttls_mpi_mod_mpi(TlsMpi *R, const TlsMpi *A, const TlsMpi *B)
{
	int r;

	if (ttls_mpi_cmp_int(B, 0) < 0) {
		T_DBG_MPI1("Negative modulo", B);
		return -EINVAL;
	}

	if ((r = ttls_mpi_div_mpi(NULL, R, A, B)))
		return r;

	while (ttls_mpi_cmp_int(R, 0) < 0)
		if ((r = ttls_mpi_add_mpi(R, R, B)))
			return r;

	while (ttls_mpi_cmp_mpi(R, B) >= 0)
		if ((r = ttls_mpi_sub_mpi(R, R, B)))
			return r;

	return 0;
}

/**
 * Fast Montgomery initialization (thanks to Tom St Denis).
 */
static void
__mpi_montg_init(unsigned long *mm, const TlsMpi *N)
{
	unsigned long x, m0 = MPI_P(N)[0];
	unsigned int i;

	x = m0;
	x += ((m0 + 2) & 4) << 1;

	for (i = BIL; i >= 8; i /= 2)
		x *= 2 - (m0 * x);

	*mm = ~x + 1;
}

/**
 * Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36).
 */
static int
__mpi_montmul(TlsMpi *A, const TlsMpi *B, const TlsMpi *N, unsigned long mm,
	      TlsMpi *T)
{
	size_t i, n, m;
	unsigned long u0, u1, *d;

	BUG_ON(T->limbs < N->used + 1);
	bzero_fast(MPI_P(T), T->limbs * CIL);

	d = MPI_P(T);
	n = N->used;
	m = (B->used < n) ? B->used : n;

	for (i = 0; i < n; i++) {
		/* T = (T + u0*B + u1*N) / 2^BIL */
		u0 = MPI_P(A)[i];
		u1 = (d[0] + u0 * MPI_P(B)[0]) * mm;

		__mpi_mul(m, MPI_P(B), d, u0);
		__mpi_mul(n, MPI_P(N), d, u1);

		*d++ = u0;
		d[n + 1] = 0;
	}
	mpi_fixup_used(T, T->limbs);

	memcpy_fast(MPI_P(A), d, (n + 1) * CIL);
	mpi_fixup_used(A, n + 1);

	if (ttls_mpi_cmp_abs(A, N) >= 0) {
		__mpi_sub(MPI_P(A), A->used, MPI_P(N), N->used, MPI_P(A));
		mpi_fixup_used(A, A->used);
	} else {
		/* Prevent timing attacks. */
		__mpi_sub(MPI_P(T), T->used, MPI_P(A), A->used, MPI_P(T));
		mpi_fixup_used(T, T->used);
	}

	return 0;
}

/**
 * Montgomery reduction: A = A * R^-1 mod N
 */
static int
__mpi_montred(TlsMpi *A, const TlsMpi *N, unsigned long mm, TlsMpi *T)
{
	DECLARE_MPI_AUTO(U, 1);
	U.s = 1;
	MPI_P(&U)[0] = 1;

	return __mpi_montmul(A, &U, N, mm, T);
}

/**
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85).
 *
 * @X	- destination MPI;
 * @A	- left-hand MPI
 * @E	- exponent MPI;
 * @N	- modular MPI
 * @RR	- speed-up MPI used for recalculations.
 *
 * @RR is used to avoid re-computing R * R mod N across multiple calls,
 * which speeds up things a bit.
 */
int
ttls_mpi_exp_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *E, const TlsMpi *N,
		 TlsMpi *RR)
{
	int ret = -ENOMEM, neg;
	size_t i, j, nblimbs, bufsize = 0, nbits = 0, wbits = 0, wsize;
	unsigned long ei, mm, state = 0;
	TlsMpi T, Apos, *W;

	BUILD_BUG_ON(MPI_W_SZ < 6);
	if (ttls_mpi_cmp_int(N, 0) <= 0 || !(MPI_P(N)[0] & 1))
		return -EINVAL;
	if (ttls_mpi_cmp_int(E, 0) < 0)
		return -EINVAL;

	/* Init temps and window size. */
	j = N->used + 1;
	if (WARN_ON_ONCE(X->limbs < j))
		return -ENOMEM;
	__mpi_montg_init(&mm, N);
	ttls_mpi_alloca_init(&T, j * 2);
	if (!(W = ttls_mpool_alloc_stack(sizeof(TlsMpi) * (1 << MPI_W_SZ))))
		return -ENOMEM;
	bzero_fast(W, sizeof(TlsMpi) * (1 << MPI_W_SZ));
	if (ttls_mpi_alloc(&W[1], j))
		goto cleanup;

	i = ttls_mpi_bitlen(E);
	wsize = (i > 671) ? 6
		: (i > 239) ? 5
		  : (i >  79) ? 4
		    : (i >  23) ? 3
		      : 1;

	/* Compensate for negative A (and correct at the end). */
	neg = (A->s == -1);
	if (neg) {
		ttls_mpi_alloca_init(&Apos, A->used);
		TTLS_MPI_CHK(ttls_mpi_copy_alloc(&Apos, A, false));
		Apos.s = 1;
		A = &Apos;
	}

	/*
	 * If 1st call, pre-compute R^2 mod N
	 */
	BUG_ON(!RR);
	if (unlikely(ttls_mpi_empty(RR))) {
		TTLS_MPI_CHK(ttls_mpi_alloc(RR, N->used * 2 + 1));
		TTLS_MPI_CHK(ttls_mpi_lset(RR, 1));
		TTLS_MPI_CHK(ttls_mpi_shift_l(RR, N->used * 2 * BIL));
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(RR, RR, N));
	}

	/* W[1] = A * R^2 * R^-1 mod N = A * R mod N */
	if (ttls_mpi_cmp_mpi(A, N) >= 0)
		TTLS_MPI_CHK(ttls_mpi_mod_mpi(&W[1], A, N));
	else
		TTLS_MPI_CHK(ttls_mpi_copy(&W[1], A));

	TTLS_MPI_CHK(__mpi_montmul(&W[1], RR, N, mm, &T));

	/* X = R^2 * R^-1 mod N = R mod N */
	TTLS_MPI_CHK(ttls_mpi_copy(X, RR));
	TTLS_MPI_CHK(__mpi_montred(X, N, mm, &T));

	if (wsize > 1) {
		/* W[1 << (wsize - 1)] = W[1] ^ (wsize - 1) */
		j =  1 << (wsize - 1);

		TTLS_MPI_CHK(ttls_mpi_alloc(&W[j], N->used + 1));
		TTLS_MPI_CHK(ttls_mpi_copy(&W[j], &W[1]));

		for (i = 0; i < wsize - 1; i++)
			TTLS_MPI_CHK(__mpi_montmul(&W[j], &W[j], N, mm, &T));

		/* W[i] = W[i - 1] * W[1] */
		for (i = j + 1; i < (1 << wsize); i++) {
			TTLS_MPI_CHK(ttls_mpi_alloc(&W[i], N->used + 1));
			TTLS_MPI_CHK(ttls_mpi_copy(&W[i], &W[i - 1]));
			TTLS_MPI_CHK(__mpi_montmul(&W[i], &W[1], N, mm, &T));
		}
	}

	nblimbs = E->used;
	while (1) {
		if (!bufsize) {
			if (!nblimbs)
				break;
			nblimbs--;
			bufsize = sizeof(unsigned long) << 3;
		}

		bufsize--;

		ei = (MPI_P(E)[nblimbs] >> bufsize) & 1;

		/* Skip leading 0s. */
		if (!ei && !state)
			continue;

		if (!ei && state == 1) {
			/* Out of window, square X. */
			TTLS_MPI_CHK(__mpi_montmul(X, X, N, mm, &T));
			continue;
		}

		/* Add ei to current window. */
		state = 2;

		nbits++;
		wbits |= (ei << (wsize - nbits));

		if (nbits == wsize) {
			/* X = X^wsize R^-1 mod N . */
			for (i = 0; i < wsize; i++)
				TTLS_MPI_CHK(__mpi_montmul(X, X, N, mm, &T));

			/* X = X * W[wbits] R^-1 mod N. */
			TTLS_MPI_CHK(__mpi_montmul(X, &W[wbits], N, mm, &T));

			state--;
			nbits = 0;
			wbits = 0;
		}
	}

	/* Process the remaining bits. */
	for (i = 0; i < nbits; i++) {
		TTLS_MPI_CHK(__mpi_montmul(X, X, N, mm, &T));

		wbits <<= 1;
		if (wbits & (1 << wsize))
			TTLS_MPI_CHK(__mpi_montmul(X, &W[1], N, mm, &T));
	}

	/* X = A^E * R * R^-1 mod N = A^E mod N. */
	TTLS_MPI_CHK(__mpi_montred(X, N, mm, &T));

	if (neg && E->used && (MPI_P(E)[0] & 1)) {
		X->s = -1;
		TTLS_MPI_CHK(ttls_mpi_add_mpi(X, N, X));
	}

cleanup:
	ttls_mpi_pool_cleanup_ctx((unsigned long)W, false);
	return ret;
}

/**
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 */
int
ttls_mpi_gcd(TlsMpi *G, const TlsMpi *A, const TlsMpi *B)
{
	size_t lz, lzt;
	TlsMpi TA, TB;

	ttls_mpi_alloca_init(&TA, A->used);
	ttls_mpi_alloca_init(&TB, B->used);
	MPI_CHK(ttls_mpi_copy_alloc(&TA, A, false));
	MPI_CHK(ttls_mpi_copy_alloc(&TB, B, false));

	lz = ttls_mpi_lsb(A);
	lzt = ttls_mpi_lsb(B);
	if (lzt < lz)
		lz = lzt;

	MPI_CHK(ttls_mpi_shift_r(&TA, lz));
	MPI_CHK(ttls_mpi_shift_r(&TB, lz));

	TA.s = TB.s = 1;

	while (ttls_mpi_cmp_int(&TA, 0)) {
		MPI_CHK(ttls_mpi_shift_r(&TA, ttls_mpi_lsb(&TA)));
		MPI_CHK(ttls_mpi_shift_r(&TB, ttls_mpi_lsb(&TB)));

		if (ttls_mpi_cmp_mpi(&TA, &TB) >= 0) {
			MPI_CHK(ttls_mpi_sub_abs(&TA, &TA, &TB));
			MPI_CHK(ttls_mpi_shift_r(&TA, 1));
		} else {
			MPI_CHK(ttls_mpi_sub_abs(&TB, &TB, &TA));
			MPI_CHK(ttls_mpi_shift_r(&TB, 1));
		}
	}

	MPI_CHK(ttls_mpi_shift_l(&TB, lz));

	return ttls_mpi_copy(G, &TB);
}

/**
 * Modular inverse: X = A^-1 mod N  (HAC 14.61 / 14.64).
 *
 * Used in RSA, so there quite a few probably large numbers.
 */
int
ttls_mpi_inv_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *N)
{
	int ret;
	TlsMpi *G, *TA, *TU, *U1, *U2, *TB, *TV, *V1, *V2;

	if (ttls_mpi_cmp_int(N, 1) <= 0)
		return -EINVAL;

	G = ttls_mpool_alloc_stack(sizeof(TlsMpi) * 9
				   + (N->used * 8 + 4) * CIL);
	if (!G)
		return -ENOMEM;
	TA = ttls_mpi_init_next(G, 0);

	TTLS_MPI_CHK(ttls_mpi_gcd(G, A, N));
	TTLS_MPI_CHK(ttls_mpi_cmp_int(G, 1));

	TB = ttls_mpi_init_next(TA, N->used);
	TU = ttls_mpi_init_next(TB, N->used);
	TV = ttls_mpi_init_next(TU, N->used);
	U1 = ttls_mpi_init_next(TV, N->used);
	U2 = ttls_mpi_init_next(U1, N->used + 1);
	V1 = ttls_mpi_init_next(U2, N->used + 1);
	V2 = ttls_mpi_init_next(V1, N->used + 1);
	ttls_mpi_init_next(V2, N->used + 1);

	TTLS_MPI_CHK(ttls_mpi_mod_mpi(TA, A, N));
	TTLS_MPI_CHK(ttls_mpi_copy(TU, TA));
	TTLS_MPI_CHK(ttls_mpi_copy(TB, N));
	TTLS_MPI_CHK(ttls_mpi_copy(TV, N));

	TTLS_MPI_CHK(ttls_mpi_lset(U1, 1));
	TTLS_MPI_CHK(ttls_mpi_lset(U2, 0));
	TTLS_MPI_CHK(ttls_mpi_lset(V1, 0));
	TTLS_MPI_CHK(ttls_mpi_lset(V2, 1));

	do {
		while (!(MPI_P(TU)[0] & 1)) {
			TTLS_MPI_CHK(ttls_mpi_shift_r(TU, 1));
			if ((MPI_P(U1)[0] & 1) || (MPI_P(U2)[0] & 1)) {
				TTLS_MPI_CHK(ttls_mpi_add_mpi(U1, U1, TB));
				TTLS_MPI_CHK(ttls_mpi_sub_mpi(U2, U2, TA));
			}
			TTLS_MPI_CHK(ttls_mpi_shift_r(U1, 1));
			TTLS_MPI_CHK(ttls_mpi_shift_r(U2, 1));
		}

		while (!(MPI_P(TV)[0] & 1)) {
			TTLS_MPI_CHK(ttls_mpi_shift_r(TV, 1));
			if ((MPI_P(V1)[0] & 1) || (MPI_P(V2)[0] & 1)) {
				TTLS_MPI_CHK(ttls_mpi_add_mpi(V1, V1, TB));
				TTLS_MPI_CHK(ttls_mpi_sub_mpi(V2, V2, TA));
			}
			TTLS_MPI_CHK(ttls_mpi_shift_r(V1, 1));
			TTLS_MPI_CHK(ttls_mpi_shift_r(V2, 1));
		}

		if (ttls_mpi_cmp_mpi(TU, TV) >= 0) {
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(TU, TU, TV));
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(U1, U1, V1));
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(U2, U2, V2));
		} else {
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(TV, TV, TU));
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(V1, V1, U1));
			TTLS_MPI_CHK(ttls_mpi_sub_mpi(V2, V2, U2));
		}
	} while (ttls_mpi_cmp_int(TU, 0));

	while (ttls_mpi_cmp_int(V1, 0) < 0)
		TTLS_MPI_CHK(ttls_mpi_add_mpi(V1, V1, N));

	while (ttls_mpi_cmp_mpi(V1, N) >= 0)
		TTLS_MPI_CHK(ttls_mpi_sub_mpi(V1, V1, N));

	ret = ttls_mpi_copy(X, V1);

cleanup:
	ttls_mpi_pool_cleanup_ctx((unsigned long)G, false);
	return ret;
}
