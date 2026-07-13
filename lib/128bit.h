/**
 *		Tempesta kernel library
 *
 * Portable 128-bit arithmetic helpers.
 *
 * This header provides a minimal implementation of unsigned 128-bit
 * arithmetic for kernel code without relying on compiler-specific
 * __int128 support or runtime division helpers.
 *
 * Supported operations:
 *   - 128/64 division;
 *   - integer square root;
 *
 * The implementation is intended for statistics, counters and rate
 * calculations where intermediate values may exceed 64 bits.
 *
 * Copyright (C) 2026 Tempesta Technologies, INC.
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

#ifndef __LIB_128BIT_H__
#define __LIB_128BIT_H__

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/bug.h>

static inline u128
u128_div_u32(u128 num, u32 divisor)
{
	u128 res = 0;
	u128 cur = 0;

	BUG_ON(!divisor);

	/*
	 * Iterate over all 128 dividend bits.
	 *
	 * Bit 127 is the most significant bit of v.hi.
	 * Bit 0   is the least significant bit of v.lo.
	 */
	for (int i = 127; i >= 0; --i) {
		/*
		 * Equivalent to:
		 *
		 *     cur = cur * 2
		 *
		 * We are making room for the next dividend bit,
		 * exactly like multiplying the current partial value
		 * by the radix before bringing down the next digit in
		 * ordinary long division.
		 */
		cur <<= 1;
		/*
		 * Extract the next dividend bit and append it to
		 * the low end of the remainder.
		 *
		 *     r = (cur << 1) | next_dividend_bit
		 */
		cur |= (num >> i) & 1;

		 /*
		 * At this point cur contains the partial dividend formed
		 * from all bits processed so far.
		 *
		 * If the divisor fits into the current remainder,
		 * then the current quotient bit must be 1.
		 *
		 * Example:
		 *
		 *     cur = 25
		 *     divisor = 10
		 *
		 * Then:
		 *
		 *     quotient_bit = 1
		 *     cur = 25 - 10 = 15
		 *
		 * The updated remainder is carried into the next
		 * iteration.
		 */
		if (cur >= divisor) {
			cur -= divisor;
			/*
			 * Set quotient bit corresponding to the
			 * currently processed dividend position.
			 *
			 * Since we are traversing bits from MSB to
			 * LSB, the bit index in the quotient is the
			 * same as the current dividend bit index.
			 */
			res |= ((u128)(1) << i);
		}
	}

	return res;
}

/*
 * Compute the integer square root of a 128-bit unsigned value.
 *
 * We need to find the largest u64 value x such that:
 *
 *     x * x <= v
 *
 * Since:
 *
 *     sqrt(U128_MAX) < 2^64
 *
 * the result always fits into u64 and can be searched in the range:
 *
 *     [0, U64_MAX]
 *
 * The function uses binary search.
 *
 * Search invariant:
 *
 *   - every value <= result is known to satisfy:
 *
 *         x^2 <= v
 *
 *   - every value > right is known to satisfy:
 *
 *         x^2 > v
 *
 * On each iteration:
 *
 *   1. Pick the middle point.
 *   2. Compute mid^2 as a full 128-bit value.
 *   3. Compare it with v.
 *   4. If mid^2 <= v, remember mid as a valid answer and
 *      continue searching for a larger one.
 *   5. Otherwise search the lower half.
 *
 * Example:
 *
 *     v = 111
 *
 *     left  = 0
 *     right = 18446744073709551615
 *
 * Eventually the search narrows to:
 *
 *         [10, 11]
 *
 * because:
 *
 *         10^2 = 100 <= 111
 *         11^2 = 121 > 111
 *
 * Therefore:
 *
 *         sqrt(111) = 10
 *
 * Return:
 *
 *     floor(sqrt(v))
 */
static inline u64
u128_sqrt(const u128 v)
{
	/*
	 * Current binary search range.
	 *
	 * The true answer is guaranteed to lie somewhere
	 * inside [left, right].
	 */
	u64 left = 0;
	u64 right = U64_MAX;

	/*
	 * Best valid answer found so far.
	 *
	 * Whenever we discover a value whose square does
	 * not exceed v, we store it here.
	 */
	u64 result = 0;

	while (left <= right) {
		u64 mid;
		u128 sq;

		/*
		 * Midpoint calculation written this way to avoid
		 * possible overflow of:
		 *
		 *     (left + right) / 2
		 */
		mid = left + ((right - left) >> 1);
		sq = (u128)mid * (u128)mid;

		/*
		 * Compare:
		 *
		 *     mid^2 ? v
		 *
		 * Result:
		 *
		 *     < 0 : mid^2 < v
		 *       0 : mid^2 = v
		 *     > 0 : mid^2 > v
		 */

		if (sq <= v) {
			/*
			 * mid^2 <= v
			 *
			 * Therefore mid is a valid square root
			 * candidate.
			 *
			 * Remember it and try to find a larger
			 * valid value in the upper half.
			 */
			result = mid;

			/*
			 * Prevent overflow of:
			 *
			 *     left = mid + 1
			 *
			 * when mid already equals U64_MAX.
			 */
			if (mid == U64_MAX)
				break;

			/*
			 * Discard the lower half including mid.
			 *
			 * All values <= mid are no better than the
			 * candidate we already have.
			 */
			left = mid + 1;
		} else {
			/*
			 * mid^2 > v
			 *
			 * mid is too large to be the answer.
			 *
			 * The square root, if it exists, must be
			 * strictly smaller than mid.
			 */
			if (!mid)
				break;

			/*
			 * Search the lower half.
			 */
			right = mid - 1;
		}
	}

	/*
	 * The largest value discovered such that:
	 *
	 *     result^2 <= v
	 */
	return result;
}

#endif /* __LIB_128BIT_H__ */
