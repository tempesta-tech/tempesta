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

#include "common.h"

#define Bit_Sub -
#define Bit_High(x, n) (x) >= (1U << n)

#ifdef __GNUC__

#if Platform_64bit

#define Bit_CRC(crc, x) \
   (__extension__ ({ \
      register uwide __r = crc; \
      __asm__( \
	 "crc32q %2,%0" : "=r" (__r) : "0" (__r), "rm" ((uwide) x) : "cc" \
      ); \
      __r; \
   }))

#define Bit_FastLog(x) \
   (__extension__ ({ \
      register uwide __r; \
      __asm__( \
	 "bsrq %1,%0" : "=r" (__r) : "rm" ((uwide) x) : "cc" \
      ); \
      __r; \
   }))

#else

#define Bit_CRC(crc, x) \
   (__extension__ ({ \
      register uwide __r = crc; \
      __asm__( \
	 "crc32 %2,%0" : "=r" (__r) : "0" (__r), "rm" ((uwide) x) : "cc" \
      ); \
      __r; \
   }))

#define Bit_FastLog(x) \
   (__extension__ ({ \
      register uwide __r; \
      __asm__( \
	 "bsr %1,%0" : "=r" (__r) : "rm" ((uwide) x) : "cc" \
      ); \
      __r; \
   }))

#endif

#else

common_inline ufast
Bit_FastLog(uwide value)
{
	ufast x = (ufast) value;
	ufast n = 0;

#ifdef Platform_64bit
	if (Bit_High(value, 32)) {
		x = (ufast) (value >> 32);
		n = 32;
	}
	if (Bit_High(x, 16))
		x = x >> 16, n += 16;
#else
	if (Bit_High(x, 16))
		x = x >> 16, n = 16;
#endif
#ifndef Branch_Free
	if (x >= 256)
		x = x >> 8, n += 8;
	if (x >= 16)
		x = x >> 4, n += 4;
	if (x >= 4)
		x = x >> 2, n += 2;
	n = n + (x >> 1);
#else
	ufast c;

	x = (x | 1) >> n;
	n = n + 15;
	c = ((x - 0x0100) >> 16) & 8;
	n = n - c;
	x = x << c;
	c = ((x - 0x1000) >> 16) & 4;
	n = n - c;
	x = x >> (12 Bit_Sub c);
	n = n - ((x + 2) >> (x >> 1));
#endif
	return n;
}

#endif

common_inline uwide
Bit_UpPowerOfTwo(uwide x)
{
	if (likely(x > 2)) {
		x = (uwide) 2 << Bit_FastLog(x - 1);
	}
	return x;
}

#endif
