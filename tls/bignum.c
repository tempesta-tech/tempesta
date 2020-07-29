/*
 *		Tempesta TLS
 *
 * Multi-precision integer library.
 *
 * The following sources were referenced in the design of this Multi-precision
 * Integer library:
 *
 * [1] Handbook of Applied Cryptography, Chapter 14,
 *     Menezes, van Oorschot and Vanstone, 1997.
 *
 * [2] Multi-Precision Math, Tom St Denis
 *
 * [3] WolfSSL library, https://github.com/wolfSSL/wolfssl/
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
ttls_mpi_alloc_stack_init(size_t nlimbs)
{
	TlsMpi *X;

	X = ttls_mpool_alloc_stack(sizeof(TlsMpi) + nlimbs * CIL);
	BUG_ON(!X);

	ttls_mpi_init_next(X, nlimbs);

	return X;
}

void
ttls_mpi_alloc(TlsMpi *X, size_t nlimbs)
{
	if (likely(X->limbs >= nlimbs))
		return;

	/*
	 * Reallocation must be called on MPI initialization only and only once
	 * for an MPI - we don't want to copy the MPI data for reallocation.
	 */
	BUG_ON(X->limbs);
	BUG_ON(nlimbs > TTLS_MPI_MAX_LIMBS);

	X->limbs = nlimbs;
	X->_off = ttls_mpi_pool_alloc_mpi(X, nlimbs * CIL);
}

/**
 * Set proper @X->used. Move from @n towards first limb and throw out all zeros.
 */
void
mpi_fixup_used(TlsMpi *X, size_t n)
{
	unsigned long *x = MPI_P(X);

	/*
	 * Leave the least significant limb even if it's zero to represent
	 * zero valued MPI.
	 */
	while (n > 1 && !x[n - 1])
		--n;
	X->used = n;
}

void
ttls_mpi_copy_alloc(TlsMpi *X, const TlsMpi *Y, bool need_alloc)
{
	if (unlikely(!Y->_off)) {
		WARN_ON_ONCE(Y->used);
		WARN_ON_ONCE(Y->s != 1);

		X->used = 0;
		X->s = 1;

		return;
	}

	if (need_alloc) {
		ttls_mpi_alloc(X, Y->used);
	} else {
		BUG_ON(X->limbs < Y->used);
	}
	memcpy_fast(MPI_P(X), MPI_P(Y), Y->used * CIL);
	X->s = Y->s;
	X->used = Y->used;
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
void
ttls_mpi_lset(TlsMpi *X, long z)
{
	ttls_mpi_alloc(X, 1);

	X->used = 1;
	if (z < 0) {
		MPI_P(X)[0] = -z;
		X->s = -1;
	} else {
		MPI_P(X)[0] = z;
		X->s = 1;
	}
}

int
ttls_mpi_get_bit(const TlsMpi *X, size_t pos)
{
	if ((X->used << BSHIFT) <= pos)
		return 0;

	return (MPI_P(X)[pos >> BSHIFT] >> (pos & BMASK)) & 1;
}

/**
 * Set a bit to a specific value of 0 or 1.
 *
 * Will grow X if necessary to set a bit to 1 in a not yet existing limb.
 * Will not grow if bit should be set to 0.
 */
void
ttls_mpi_set_bit(TlsMpi *X, size_t pos, unsigned char val)
{
	size_t off = pos >> BSHIFT;
	size_t idx = pos & BMASK;

	WARN_ON_ONCE(val != 0 && val != 1);

	if (unlikely(X->used << BSHIFT <= pos)) {
		if (!val)
			return;
		BUG_ON(X->limbs << BSHIFT <= pos);
		bzero_fast(&MPI_P(X)[X->used], (off - X->used + 1) << LSHIFT);
		X->used = off + 1;
	}

	MPI_P(X)[off] &= ~((unsigned long)0x01 << idx);
	MPI_P(X)[off] |= (unsigned long)val << idx;
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
 * The most frequent shift is for 1 bit.
 * All the shifts for more than 64 bits are for integer number of limbs,
 * so the straightforward 2n algorithm is fine to make the each case simpler.
 */
void
ttls_mpi_shift_l(TlsMpi *X, const TlsMpi *A, size_t count)
{
	size_t limbs, bits, old_used = A->used;
	unsigned long *x = MPI_P(X), *a = MPI_P(A);

	if (WARN_ON_ONCE(!count || !old_used))
		return;

	limbs = count >> BSHIFT;
	bits = count & BMASK;

	/*
	 * By the call of the function we don't know how many bits are set
	 * in the MPI, so any left shift can increase number of required limbs.
	 * While here we calculate the resulting number of bits to properly
	 * set X->used, the extra limb allows up to use the same assembly
	 * routine and do not care about zeroing the most significant limb.
	 */
	BUG_ON(X->limbs < old_used + limbs + 1);

	X->s = A->s;
	X->used = BITS_TO_LIMBS(ttls_mpi_bitlen(A) + count);

	/* Shift by count / limb_size. */
	if (unlikely(limbs > 0)) {
		if (X == A || !bits) {
			memmove(x + limbs, a, old_used * CIL);
			a += limbs;
		}
		bzero_fast(x, limbs * CIL);
		x += limbs;
	}

	/* Shift by count % limb_size. */
	if (likely(bits > 0)) {
		if (likely(old_used == 4))
			mpi_shift_l_x86_64_4(x, a, bits);
		else
			mpi_shift_l_x86_64(x, a, old_used, bits);
	}
}

/**
 * Right-shift: X >>= count.
 *
 * The most frequent shift is 1 bit for 4-limbs MPI.
 * All the shifts for more than 64 bits are for integer number of limbs,
 * so the straightforward 2n algorithm is fine to make the each case simpler.
 */
void
ttls_mpi_shift_r(TlsMpi *X, size_t count)
{
	size_t limbs, bits;
	unsigned long *x = MPI_P(X);

	if (!count)
		return;

	/*
	 * The most frequent case for SECP 256 - default and recommended
	 * elliptic curve.
	 */
	if (likely(count < 64 && X->used == 4)) {
		mpi_shift_r_x86_64_4(x, count);
		X->used -= !x[X->used - 1];
		goto zero_sign;
	}

	if (!X->used || !x[X->used - 1])
		return;

	limbs = count >> BSHIFT;
	bits = count & BMASK;

	/*
	 * Shift by count / limb_size - remove least significant limbs.
	 * There could be garbage after last used limb, so be careful.
	 */
	if (unlikely(limbs > 0)) {
		if (limbs >= X->used) {
			ttls_mpi_lset(X, 0);
			return;
		} else {
			X->used -= limbs;
			memmove(x, x + limbs, X->used * CIL);
		}
	}

	/* Shift by count % limb_size. */
	if (likely(bits > 0)) {
		if (X->used == 4)
			mpi_shift_r_x86_64_4(x, bits);
		else
			mpi_shift_r_x86_64(x, X->used, bits);
		X->used -= !x[X->used - 1];
	}
zero_sign:
	if (X->used == 1 && !x[0])
		X->s = 1;
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
		       X->limbs * CIL, true);
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
void
ttls_mpi_read_binary(TlsMpi *X, const unsigned char *buf, size_t buflen)
{
	size_t i = buflen, l = 0, j;
	size_t const limbs = CHARS_TO_LIMBS(buflen);

	if (unlikely(!buflen)) {
		/* Reset the MPI. */
		X->s = 0;
		X->used = 0;
		return;
	}
	ttls_mpi_alloc(X, limbs);

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
void
ttls_mpi_fill_random(TlsMpi *X, size_t size)
{
	size_t limbs = CHARS_TO_LIMBS(size);
	size_t rem = limbs * CIL - size;

	BUG_ON(size > TTLS_MPI_MAX_SIZE);

	ttls_mpi_alloc(X, limbs);

	ttls_rnd(MPI_P(X), size);
	if (rem > 0)
		memset((char *)MPI_P(X) + size, 0, rem);
	X->used = limbs;
	X->s = 1;
}

int
ttls_mpi_cmp_abs(const TlsMpi *X, const TlsMpi *Y)
{
	int i;

	if (X->used != Y->used)
		return (int)X->used - (int)Y->used;

	for (i = X->used - 1; i >= 0; i--) {
		if (MPI_P(X)[i] == MPI_P(Y)[i])
			continue;
		return MPI_P(X)[i] > MPI_P(Y)[i] ? 1 : -1;
	}

	return 0;
}

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
		return -z;

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
void
ttls_mpi_add_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	int r;

	BUG_ON(A == B);
	BUG_ON(X->limbs < max_t(unsigned short, A->used, B->used));

	if (B->used > A->used) {
		const TlsMpi *T = A;
		A = B;
		B = T;
	}

	r = mpi_add_x86_64(MPI_P(X), X->limbs, MPI_P(B), B->used,
			   MPI_P(A), A->used);
	BUG_ON(r <= 0);
	X->used = r;

	/* X should always be positive as a result of unsigned additions. */
	X->s = 1;
}

/**
 * Unsigned subtraction: X = |A| - |B|.
 * @X may reference either @A or @B.
 */
void
ttls_mpi_sub_abs(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	register unsigned int o_sz, a_sz = A->used, b_sz = B->used;
	register unsigned long *x = MPI_P(X), *a = MPI_P(A), *b = MPI_P(B);

	BUG_ON(X->limbs < A->used);

	/*
	 * Call special implementations for the most frequent cases in EC
	 * arithmetics.
	 */
	o_sz = (a_sz << 16) + b_sz;
	if (likely(o_sz == 0x00040004)) {
		mpi_sub_x86_64_4_4(x, b, a);
	}
	else if (likely(o_sz == 0x00050004)) {
		mpi_sub_x86_64_5_4(x, b, a);
	}
	else if (o_sz == 0x00030003) {
		mpi_sub_x86_64_3_3(x, b, a);
	}
	else if (o_sz == 0x00020002) {
		mpi_sub_x86_64_2_2(x, b, a);
	}
	else if (o_sz == 0x00010001) {
		*x = *a - *b;
	}
	else {
		mpi_sub_x86_64(x, b, a, b_sz, a_sz);
	}

	/* X should always be positive as a result of unsigned subtractions. */
	X->s = 1;
	mpi_fixup_used(X, a_sz);
}

/**
 * Signed addition: X = A + B
 */
void
ttls_mpi_add_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	int s = A->s;

	if (s != B->s) {
		int cmp = ttls_mpi_cmp_abs(A, B);
		if (cmp == 0) {
			X->s = 1;
			X->used = 1;
			MPI_P(X)[0] = 0;
		}
		else if (cmp > 0) {
			ttls_mpi_sub_abs(X, A, B);
			X->s = s;
		}
		else {
			ttls_mpi_sub_abs(X, B, A);
			X->s = -s;
		}
	} else {
		ttls_mpi_add_abs(X, A, B);
		X->s = s;
	}
}

/**
 * Signed subtraction: X = A - B
 */
void
ttls_mpi_sub_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	int s = A->s;

	if (s == B->s) {
		int cmp = ttls_mpi_cmp_abs(A, B);
		if (cmp == 0) {
			X->s = 1;
			X->used = 1;
			MPI_P(X)[0] = 0;
		}
		else if (cmp > 0) {
			ttls_mpi_sub_abs(X, A, B);
			X->s = s;
		}
		else {
			ttls_mpi_sub_abs(X, B, A);
			X->s = -s;
		}
	} else {
		ttls_mpi_add_abs(X, A, B);
		X->s = s;
	}
}

/**
 * Signed addition: X = A + b
 */
void
ttls_mpi_add_int(TlsMpi *X, const TlsMpi *A, long b)
{
	DECLARE_MPI_AUTO(_B, 1);
	MPI_P(&_B)[0] = (b < 0) ? -b : b;
	_B.s = (b < 0) ? -1 : 1;

	ttls_mpi_add_mpi(X, A, &_B);
}

/**
 * Signed subtraction: X = A - b
 */
void
ttls_mpi_sub_int(TlsMpi *X, const TlsMpi *A, long b)
{
	unsigned long *a = MPI_P(A);

	BUG_ON(b < 0 || X->s != 1);

	if (likely(A->used > 1)) {
		mpi_sub_x86_64(MPI_P(X), &b, a, 1, A->used);
		mpi_fixup_used(X, A->used);
	}
	else if (likely(*a >= (unsigned long)b)) {
		ttls_mpi_lset(X, *a - b);
	}
	else {
		ttls_mpi_lset(X, b - *a);
		X->s = -1;
	}
}

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
 * Baseline multiplication: X = A * B.
 *
 * All the arguments may reference the same MPI.
 *
 * TODO #1064 the function is used for squaring which is inefficient, so
 * implement a normal squaring. (Gather statistics how many square calls
 * and for which sizes).
 * See "Speeding up Big-Numbers Squaring", S.Gueron and V.Krasnov, 2012.
 */
void
ttls_mpi_mul_mpi(TlsMpi *X, const TlsMpi *A, const TlsMpi *B)
{
	size_t i = A->used, j = B->used;
	TlsMpi T;

	if (X == A) {
		ttls_mpi_alloca_init(&T, A->used);
		ttls_mpi_copy_alloc(&T, A, false);
		if (A == B)
			B = &T;
		A = &T;
	}
	else if (X == B) {
		ttls_mpi_alloca_init(&T, B->used);
		ttls_mpi_copy_alloc(&T, B, false);
		B = &T;
	}
	BUG_ON(X->limbs < i + j);

	bzero_fast(MPI_P(X), CIL * (i + j));
	X->used = i + j;

	for ( ; j > 0; j--)
		__mpi_mul(i, MPI_P(A), MPI_P(X) + j - 1, MPI_P(B)[j - 1]);

	mpi_fixup_used(X, X->used);

	X->s = A->s * B->s;
}

/*
 * Baseline multiplication: X = A * b
 */
void
ttls_mpi_mul_uint(TlsMpi *X, const TlsMpi *A, unsigned long b)
{
	DECLARE_MPI_AUTO(_B, 1);
	_B.s = 1;
	MPI_P(&_B)[0] = b;

	ttls_mpi_mul_mpi(X, A, &_B);
}

void
ttls_mpi_mul_int(TlsMpi *X, const TlsMpi *A, long b)
{
	DECLARE_MPI_AUTO(_B, 1);

	if (b >= 0) {
		_B.s = 1;
		MPI_P(&_B)[0] = b;
	} else {
		_B.s = -1;
		MPI_P(&_B)[0] = -b;
	}

	ttls_mpi_mul_mpi(X, A, &_B);
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
 * Used in RSA, so pretty big MPIs are possible.
 *
 * @Q - destination MPI for the quotient.
 * @R - destination MPI for the rest value.
 * @A - left-hand MPI.
 * @B - right-hand MPI.
 */
void
ttls_mpi_div_mpi(TlsMpi *Q, TlsMpi *R, const TlsMpi *A, const TlsMpi *B)
{
	size_t i, n, t, k;
	TlsMpi *X, *Y, *Z = NULL, *T1, *T2;

	if (WARN_ON_ONCE(!ttls_mpi_cmp_int(B, 0)))
		return;

	if (!ttls_mpi_cmp_int(B, 1)) {
		if (Q && Q != A)
			ttls_mpi_copy(Q, A);
		if (R)
			ttls_mpi_lset(R, 0);
		return;
	}
	if (ttls_mpi_cmp_abs(A, B) < 0) {
		if (Q)
			ttls_mpi_lset(Q, 0);
		if (R && R != A)
			ttls_mpi_copy(R, A);
		return;
	}

	X = ttls_mpi_alloc_stack_init(A->used + 1);
	Y = ttls_mpi_alloc_stack_init(A->used + 2);
	T1 = ttls_mpi_alloc_stack_init(3 + A->used);
	T2 = ttls_mpi_alloc_stack_init(3);
	if (!Q) {
		Z = ttls_mpi_alloc_stack_init(A->used);
		Q = Z;
	}

	ttls_mpi_copy_alloc(X, A, false);
	ttls_mpi_copy_alloc(Y, B, false);
	X->s = Y->s = 1;

	/* Initialize Q after copying A to X in case of Q == A. */
	if (Q != Z)
		ttls_mpi_alloc(Q, A->used);
	Q->used = A->used;
	bzero_fast(MPI_P(Q), Q->used * CIL);

	k = ttls_mpi_bitlen(Y) & BMASK;
	if (k < BIL - 1) {
		k = BIL - 1 - k;
		ttls_mpi_shift_l(X, X, k);
		ttls_mpi_shift_l(Y, Y, k);
	} else {
		k = 0;
	}

	n = X->used - 1;
	t = Y->used - 1;

	ttls_mpi_shift_l(Y, Y, BIL * (n - t));
	while (ttls_mpi_cmp_mpi(X, Y) >= 0) {
		MPI_P(Q)[n - t]++;
		ttls_mpi_sub_mpi(X, X, Y);
	}
	/* TODO #1064: use temp var and drop it instead of shift_r. */
	ttls_mpi_shift_r(Y, BIL * (n - t));

	for (i = n; i > t; i--) {
		MPI_P(Q)[i - t - 1] = MPI_P(X)[i] >= MPI_P(Y)[t]
				      ? 0
				      : ttls_int_div_int(MPI_P(X)[i],
							 MPI_P(X)[i - 1],
							 MPI_P(Y)[t], NULL)
					+ 1;

		T2->s = 1;
		MPI_P(T2)[0] = (i < 2) ? 0 : MPI_P(X)[i - 2];
		MPI_P(T2)[1] = (i < 1) ? 0 : MPI_P(X)[i - 1];
		MPI_P(T2)[2] = MPI_P(X)[i];
		mpi_fixup_used(T2, 3);

		/*
		 * TODO #1064 inadequately many iterations - use binary search
		 * for value of [i - t - 1]th limb.
		 */
		do {
			MPI_P(Q)[i - t - 1]--;

			T1->s = 1;
			T1->used = 2; /* overwrite previous multiplication */
			MPI_P(T1)[0] = (t < 1) ? 0 : MPI_P(Y)[t - 1];
			MPI_P(T1)[1] = MPI_P(Y)[t];
			mpi_fixup_used(T1, 2);
			ttls_mpi_mul_uint(T1, T1, MPI_P(Q)[i - t - 1]);
		} while (ttls_mpi_cmp_mpi(T1, T2) > 0);

		ttls_mpi_mul_uint(T1, Y, MPI_P(Q)[i - t - 1]);
		if (i - t - 1)
			ttls_mpi_shift_l(T1, T1, BIL * (i - t - 1));
		ttls_mpi_sub_mpi(X, X, T1);

		if (ttls_mpi_cmp_int(X, 0) < 0) {
			ttls_mpi_copy(T1, Y);
			if (i - t - 1)
				ttls_mpi_shift_l(T1, T1, BIL * (i - t - 1));
			ttls_mpi_add_mpi(X, X, T1);
			MPI_P(Q)[i - t - 1]--;
		}
	}

	if (Q != Z) {
		Q->s = A->s * B->s;
		mpi_fixup_used(Q, Q->used);
	}
	if (R) {
		ttls_mpi_shift_r(X, k);
		mpi_fixup_used(X, X->used);
		X->s = A->s;
		ttls_mpi_copy(R, X);
		if (ttls_mpi_cmp_int(R, 0) == 0)
			R->s = 1;
	}

	ttls_mpi_pool_cleanup_ctx((unsigned long)X, false);
}

/**
 * Modulo: R = A mod B.
 *
 * @R - destination MPI for the rest value.
 * @A - left-hand MPI.
 * @B - right-hand MPI.
 */
void
ttls_mpi_mod_mpi(TlsMpi *R, const TlsMpi *A, const TlsMpi *B)
{
	BUG_ON(B->s < 0);

	/*
	 * TODO #1064 since reminder is only used, an optimized algorithm
	 * might be used. See "Faster Remainder by Direct Computation
	 * Applications to Compilers and Software Libraries" by Lemire, 2019.
	 *
	 * Besides this function, ttls_mpi_div_mpi() is used in RSA only and
	 * for quotient only, so a more optimized division for quotient only
	 * probably can be used.
	 */
	ttls_mpi_div_mpi(NULL, R, A, B);

	while (unlikely(R->s < 0))
		ttls_mpi_add_mpi(R, R, B);

	while (ttls_mpi_cmp_mpi(R, B) >= 0)
		ttls_mpi_sub_mpi(R, R, B);
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
		mpi_sub_x86_64(MPI_P(A), MPI_P(N), MPI_P(A), N->used, A->used);
		mpi_fixup_used(A, A->used);
	} else {
		/* Prevent timing attacks. */
		mpi_sub_x86_64(MPI_P(T), MPI_P(A), MPI_P(T), A->used, T->used);
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
	W = ttls_mpool_alloc_stack(sizeof(TlsMpi) * (1 << MPI_W_SZ));
	bzero_fast(W, sizeof(TlsMpi) * (1 << MPI_W_SZ));
	ttls_mpi_alloc(&W[1], j);

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
		ttls_mpi_copy_alloc(&Apos, A, false);
		Apos.s = 1;
		A = &Apos;
	}

	/*
	 * If 1st call, pre-compute R^2 mod N
	 */
	BUG_ON(!RR);
	if (unlikely(ttls_mpi_empty(RR))) {
		ttls_mpi_alloc(RR, N->used * 2 + 2);
		ttls_mpi_lset(RR, 1);
		ttls_mpi_shift_l(RR, RR, N->used * 2 * BIL);
		ttls_mpi_mod_mpi(RR, RR, N);
	}

	/* W[1] = A * R^2 * R^-1 mod N = A * R mod N */
	if (ttls_mpi_cmp_mpi(A, N) >= 0)
		ttls_mpi_mod_mpi(&W[1], A, N);
	else
		ttls_mpi_copy(&W[1], A);

	TTLS_MPI_CHK(__mpi_montmul(&W[1], RR, N, mm, &T));

	/* X = R^2 * R^-1 mod N = R mod N */
	ttls_mpi_copy(X, RR);
	TTLS_MPI_CHK(__mpi_montred(X, N, mm, &T));

	if (wsize > 1) {
		/* W[1 << (wsize - 1)] = W[1] ^ (wsize - 1) */
		j =  1 << (wsize - 1);

		ttls_mpi_alloc(&W[j], N->used + 1);
		ttls_mpi_copy(&W[j], &W[1]);

		for (i = 0; i < wsize - 1; i++)
			TTLS_MPI_CHK(__mpi_montmul(&W[j], &W[j], N, mm, &T));

		/* W[i] = W[i - 1] * W[1] */
		for (i = j + 1; i < (1 << wsize); i++) {
			ttls_mpi_alloc(&W[i], N->used + 1);
			ttls_mpi_copy(&W[i], &W[i - 1]);
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
		ttls_mpi_add_mpi(X, N, X);
	}

cleanup:
	ttls_mpi_pool_cleanup_ctx((unsigned long)W, false);
	return ret;
}

/**
 * Greatest common divisor: G = gcd(A, B)  (HAC 14.54)
 * Used in RSA only.
 */
void
ttls_mpi_gcd(TlsMpi *G, const TlsMpi *A, const TlsMpi *B)
{
	size_t lz, lzt;
	TlsMpi TA, TB;

	ttls_mpi_alloca_init(&TA, A->used);
	ttls_mpi_alloca_init(&TB, B->used + 1);
	ttls_mpi_copy_alloc(&TA, A, false);
	ttls_mpi_copy_alloc(&TB, B, false);

	lz = ttls_mpi_lsb(A);
	lzt = ttls_mpi_lsb(B);
	if (lzt < lz)
		lz = lzt;

	ttls_mpi_shift_r(&TA, lz);
	ttls_mpi_shift_r(&TB, lz);

	TA.s = TB.s = 1;

	while (ttls_mpi_cmp_int(&TA, 0)) {
		ttls_mpi_shift_r(&TA, ttls_mpi_lsb(&TA));
		ttls_mpi_shift_r(&TB, ttls_mpi_lsb(&TB));

		if (ttls_mpi_cmp_mpi(&TA, &TB) >= 0) {
			ttls_mpi_sub_abs(&TA, &TA, &TB);
			ttls_mpi_shift_r(&TA, 1);
		} else {
			ttls_mpi_sub_abs(&TB, &TB, &TA);
			ttls_mpi_shift_r(&TB, 1);
		}
	}

	if (lz)
		ttls_mpi_shift_l(G, &TB, lz);
	else
		ttls_mpi_copy(G, &TB);
}

/**
 * Modular inverse X = A^-1 mod N , based on binary extended Euclidean algorithm
 * (HAC 14.61 / 14.64). This is a generic implementation, not optimized for
 * odd and/or prime moduli.
 *
 * Used in RSA, so there are quite a few probably large numbers.
 */
void
ttls_mpi_inv_mod(TlsMpi *X, const TlsMpi *A, const TlsMpi *N)
{
	TlsMpi *TA, *TU, *U1, *U2, *TV, *V1, *V2;

	TA = ttls_mpool_alloc_stack((sizeof(TlsMpi) + N->used) * 7 * CIL);
	TU = ttls_mpi_init_next(TA, N->used);
	TV = ttls_mpi_init_next(TU, N->used);
	U1 = ttls_mpi_init_next(TV, N->used);
	U2 = ttls_mpi_init_next(U1, N->used + 1);
	V1 = ttls_mpi_init_next(U2, N->used + 1);
	V2 = ttls_mpi_init_next(V1, N->used + 1);
	ttls_mpi_init_next(V2, N->used + 1);

	ttls_mpi_mod_mpi(TA, A, N);
	ttls_mpi_copy(TU, TA);
	ttls_mpi_copy(TV, N);

	ttls_mpi_lset(U1, 1);
	ttls_mpi_lset(U2, 0);
	ttls_mpi_lset(V1, 0);
	ttls_mpi_lset(V2, 1);

	do {
		while (!(MPI_P(TU)[0] & 1)) {
			ttls_mpi_shift_r(TU, 1);
			if ((MPI_P(U1)[0] & 1) || (MPI_P(U2)[0] & 1)) {
				ttls_mpi_add_mpi(U1, U1, N);
				ttls_mpi_sub_mpi(U2, U2, TA);
			}
			ttls_mpi_shift_r(U1, 1);
			ttls_mpi_shift_r(U2, 1);
		}

		while (!(MPI_P(TV)[0] & 1)) {
			ttls_mpi_shift_r(TV, 1);
			if ((MPI_P(V1)[0] & 1) || (MPI_P(V2)[0] & 1)) {
				ttls_mpi_add_mpi(V1, V1, N);
				ttls_mpi_sub_mpi(V2, V2, TA);
			}
			ttls_mpi_shift_r(V1, 1);
			ttls_mpi_shift_r(V2, 1);
		}

		if (ttls_mpi_cmp_mpi(TU, TV) >= 0) {
			ttls_mpi_sub_mpi(TU, TU, TV);
			ttls_mpi_sub_mpi(U1, U1, V1);
			ttls_mpi_sub_mpi(U2, U2, V2);
		} else {
			ttls_mpi_sub_mpi(TV, TV, TU);
			ttls_mpi_sub_mpi(V1, V1, U1);
			ttls_mpi_sub_mpi(V2, V2, U2);
		}
	} while (!ttls_mpi_eq_0(TU));

	while (ttls_mpi_cmp_int(V1, 0) < 0)
		ttls_mpi_add_mpi(V1, V1, N);

	while (ttls_mpi_cmp_mpi(V1, N) >= 0)
		ttls_mpi_sub_mpi(V1, V1, N);

	ttls_mpi_copy(X, V1);
}
