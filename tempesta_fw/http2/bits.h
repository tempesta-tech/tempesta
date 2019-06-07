/**
 *		Tempesta FW
 *
 * Basic bit manipulations.
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
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
 *
 * Copyright (C) Julius Goryavsky. Original code of this module
 * is granted by the author for unrestricted use in the Tempesta FW
 * and for distribution under GNU General Public License without
 * any restrictions.
 */

#ifndef BITS_H
#define BITS_H

#include <inttypes.h>

#define Bit_Sub -
#define Bit_High(x, n) (x) >= (1U << n)

#ifdef __GNUC__

#define Bit_CRC(crc, x) \
   (__extension__ ({ \
      register uintptr_t __r = crc; \
      __asm__( \
	 "crc32q %2,%0" : "=r" (__r) : "0" (__r), "rm" ((uintptr_t) x) : "cc" \
      ); \
      __r; \
   }))

#define Bit_FastLog2(x) \
   (__extension__ ({ \
      register uintptr_t __r; \
      __asm__( \
	 "bsrq %1,%0" : "=r" (__r) : "rm" ((uintptr_t) x) : "cc" \
      ); \
      __r; \
   }))

#else

static __inline__ unsigned int
Bit_FastLog2(uintptr_t value)
{
	unsigned int x = (unsigned int)value;
	unsigned int n = 0;
	unsigned int c;

	if (Bit_High(value, 32)) {
		x = (unsigned int)(value >> 32);
		n = 32;
	}
	if (Bit_High(x, 16))
		x = x >> 16, n += 16;
	x = (x | 1) >> n;
	n = n + 15;
	c = ((x - 0x0100) >> 16) & 8;
	n = n - c;
	x = x << c;
	c = ((x - 0x1000) >> 16) & 4;
	n = n - c;
	x = x >> (12 Bit_Sub c);
	n = n - ((x + 2) >> (x >> 1));
	return n;
}

#endif

static __inline__ uintptr_t
Bit_UpPowerOfTwo(uintptr_t x)
{
	if (likely(x > 2)) {
		x = (uintptr_t) 2 << Bit_FastLog2(x - 1);
	}
	return x;
}

#endif
