/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2015-2019 Tempesta Technologies, INC.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __LIB_HASH_H__
#define __LIB_HASH_H__

#include <linux/types.h>

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;

typedef struct {
	u64 lo;
	u64 hi;
} u128_acc;

struct i128_acc {
	u64 lo;
	s64 hi;
};

static inline u128_acc
u64_to_u128(u64 val)
{
	u128_acc v;

	v.lo = val;
	v.hi = 0;

	return v;
}

static inline __int128
u128_to_int128(u128_acc val)
{
	return (((__int128)val.hi) << 64) | val.lo;
}

/*
 * Add two 128-bit unsigned integers.
 * Carry from the low 64 bits is propagatedinto the high 64 bits.
 */
static inline u128_acc
u128_add_u128(u128_acc a, u128_acc b)
{
	u128_acc r;

	r.lo = a.lo + b.lo;
	/*
	 * Detect carry from low 64-bit addition:
	 *
	 * If overflow occurred, the result became smaller than
	 * both operands.
	 */
	r.hi = a.hi + b.hi + (r.lo < a.lo);

	return r;
}

/*
 * Subtract two 128-bit unsigned integers with proper borrow
 * propagation from low 64-bit part to high 64-bit part.
 */
static inline u128_acc
u128_sub_u128(const u128_acc a, const u128_acc b)
{
	u128_acc r;

	r.lo = a.lo - b.lo;

	/*
	 * Borrow detection:
	 *
	 * If a->lo < b->lo, subtraction underflowed,
	 * so we must borrow 1 from the high part.
	 */
	r.hi = a.hi - b.hi - (a.lo < b.lo);

	return r;
}

/*
 * Multiply two u64 values and return the full 128-bit product.
 */
static inline u128_acc
u128_u64_mult_u64(u64 v1, u64 v2)
{
	u128_acc r;
	u64 a0, a1;
	u64 b0, b1;
	u64 p0, p1, p2, p3;
	u64 carry;

	/* Split operands into 32-bit halves. */
	a0 = (u32)v1;
	a1 = v1 >> 32;

	b0 = (u32)v2;
	b1 = v2 >> 32;

	/*
	 * Compute partial products:
	 *
         *          a1 a0
	 *        x b1 b0
	 *        --------
	 *          a0*b0     (p0)
	 *       a0*b1 << 32  (p1)
	 *       a1*b0 << 32  (p2)
	 *    a1*b1 << 64     (p3)
	 */
	p0 = a0 * b0;
	p1 = a0 * b1;
	p2 = a1 * b0;
	p3 = a1 * b1;

	/* Construct low 64 bits. */
	r.lo = p0 + (p1 << 32);
	carry = (r.lo < p0);
	r.lo += (p2 << 32);

	if (r.lo < (p2 << 32))
		carry++;

	/* Construct high 64 bits. */
	r.hi = p3 + (p1 >> 32) + (p2 >> 32) + carry;

	return r;
}

/*
 * Divide a 128-bit unsigned integer by a 64-bit divisor.
 *
 * Dividend:
 *
 *     value = (hi << 64) | lo
 *
 * Returns:
 *
 *     quotient = value / divisor
 *
 * as a 128-bit value.
 *
 * If @rem is not NULL:
 *
 *     *rem = value % divisor
 *
 * This implementation performs classic binary long division
 * and does not rely on compiler-provided __int128 division helpers,
 * which are not implemented in linux kernel.
 */
static inline u128_acc
u128_div_u64(const u128_acc v, u64 divisor, u64 *rem)
{
	u128_acc q = { 0, 0 };
	u64 r = 0;
	int i;

	/*
	 * Process dividend bits from MSB (127)
	 * to LSB (0).
	 */
	for (i = 127; i >= 0; i--) {

		/*
		 * Shift remainder left by one bit.
		 */
		r <<= 1;

		/* Append next dividend bit. */
		if (i >= 64)
			r |= (v.hi >> (i - 64)) & 1ULL;
		else
			r |= (v.lo >> i) & 1ULL;

		/*
		 * If remainder is large enough, subtract divisor and set
		 * corresponding quotient bit.
		 */
		if (r >= divisor) {
			r -= divisor;

			if (i >= 64)
				q.hi |= 1ULL << (i - 64);
			else
				q.lo |= 1ULL << i;
		}
	}

	if (rem)
		*rem = r;

	return q;
}

/*
 * Shift a 128-bit unsigned integer left by @shift bits.
 *
 * Valid shift range: 0..127.
 */
static inline u128_acc
u128_left_shift_u32(const u128_acc v, u32 shift)
{
	u128_acc r = { 0, 0 };

	if (shift >= 128)
		return r;

	if (!shift)
		return v;

	if (shift >= 64) {
		r.hi = v.lo << (shift - 64);
		r.lo = 0;

		return r;
	}

	r.hi = (v.hi << shift) | (v.lo >> (64 - shift));
	r.lo = v.lo << shift;

	return r;
}

/*
 * Shift a 128-bit unsigned integer right by @shift bits.
 *
 * Valid shift range: 0..127.
 */
static inline u128_acc
u128_right_shift_u32(const u128_acc v, u32 shift)
{
	u128_acc r = { 0, 0 };

	if (shift >= 128)
		return r;

	if (!shift)
		return v;

	if (shift >= 64) {
		r.lo = v.hi >> (shift - 64);
		r.hi = 0;

		return r;
	}

	r.lo = (v.lo >> shift) | (v.hi << (64 - shift));
	r.hi = v.hi >> shift;

	return r;
}

static inline int
u128_cmp(const u128_acc a, const u128_acc b)
{
	if (a.hi < b.hi)
		return -1;
	if (a.hi > b.hi)
		return 1;

	if (a.lo < b.lo)
		return -1;
	if (a.lo > b.lo)
		return 1;

	return 0;
}

/*
 * Compute floor(sqrt(v)).
 *
 * Returns the largest u64 x such that:
 *
 *     x * x <= v
 */
static inline u64
u128_sqrt(const u128_acc v)
{
	u64 left = 0;
	u64 right = UINT64_MAX;
	u64 result = 0;

	while (left <= right) {
		u64 mid;
		u128_acc sq;
		int cmp;

		mid = left + ((right - left) >> 1);
		sq = u128_u64_mult_u64(mid, mid);
		cmp = u128_cmp(sq, v);

		if (cmp <= 0) {
			/*
			 * mid^2 <= v
			 *
			 * mid is a valid candidate.
			 * Try to find a larger one.
			 */
			result = mid;

			if (mid == UINT64_MAX)
				break;

			left = mid + 1;
		} else {
			/*
			 * mid^2 > v
			 *
			 * Search lower half.
			 */
			if (!mid)
				break;

			right = mid - 1;
		}
	}

	return result;
}

/*
 * Compute absolute value of a signed 64-bit integer.
 *
 * Works correctly for INT64_MIN as well because
 * the result is returned as unsigned.
 */
static inline u64
i64_abs_u64(int64_t v)
{
	if (v >= 0)
		return (u64)v;

	return (u64)(-(v + 1)) + 1;
}

/*
 * Negate a signed 128-bit value stored in two's-complement form.
 */
static inline i128_acc
i128_neg(i128_acc v)
{
	i128_acc r;

	r.lo = ~v.lo + 1;
	r.hi = ~v.hi;

	if (r.lo == 0)
		r.hi++;

	return r;
}

/*
 * Convert unsigned 128-bit value to signed 128-bit container.
 */
static inline i128_acc
u128_to_i128(u128_acc v)
{
	i128_acc r;

	r.lo = v.lo;
	r.hi = (s64)v.hi;

	return r;
}

/*
 * Multiply two signed 64-bit values.
 *
 * The multiplication itself is performed using
 * the existing unsigned 64x64->128 implementation.
 *
 * Sign is applied afterwards using two's complement.
 */
static inline i128_acc
i64_mul_i64(int64_t a, int64_t b)
{
	u64 abs_a;
	u64 abs_b;
	bool negative;
	u128_acc mag;
	i128_acc result;

	negative = ((a < 0) ^ (b < 0));

	abs_a = i64_abs_u64(a);
	abs_b = i64_abs_u64(b);

	mag = u128_u64_mult_u64(abs_a, abs_b);

	result = u128_to_i128(mag);

	if (negative)
		result = i128_neg(result);

	return result;
}

static inline i128_acc
i128_add_i128(i128_acc a, i128_acc b)
{
	i128_acc r;

	r.lo = a.lo + b.lo;
	r.hi = a.hi + b.hi;

	if (r.lo < a.lo)
		r.hi++;

	return r;
}

static inline i128_acc
i128_right_shift_u32(i128_acc v, u32 shift)
{
	if (shift >= 128)
		return (i128_acc){
			.lo = 0,
			.hi = (v.hi < 0) ? -1 : 0,
		};

	if (shift >= 64) {
		u32 s = shift - 64;

		v.lo = (u64)(v.hi >> s);
		v.hi = (v.hi < 0) ? -1 : 0;

		return v;
	}

	v.lo = (v.lo >> shift) |
	       ((u64)v.hi << (64 - shift));

	v.hi >>= shift;

	return v;
}

static inline u128_acc
i128_to_u128(i128_acc v)
{
	u128_acc r;

	r.lo = v.lo;
	r.hi = (u64)v.hi;

	return r;
}

static inline i128_acc
i128_i64_mult_i64(int64_t a, int64_t b)
{
	u64 abs_a;
	u64 abs_b;
	bool neg;
	u128_acc mag;
	i128_acc r;

	neg = ((a < 0) ^ (b < 0));

	abs_a = (a < 0) ? -(u64)a : (u64)a;
	abs_b = (b < 0) ? -(u64)b : (u64)b;

	mag = u128_u64_mult_u64(abs_a, abs_b);

	r.lo = mag.lo;
	r.hi = (s64)mag.hi;

	if (neg)
		r = i128_neg(r);

	return r;
}

static inline __int128
i128_to_int128(i128_acc v)
{
	/*
	 * Reconstruct signed 128-bit value from
	 * high and low 64-bit words.
	 *
	 * hi already contains the sign bit.
	 */
	return ((__int128)v.hi << 64) | v.lo;
}

#endif /* __LIB_HASH_H__ */