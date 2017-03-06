/**
 *		Tempesta FW
 *
 * Conversion between little and big endian numbers.
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

#ifndef COMMON_NETCONV_H
#define COMMON_NETCONV_H

#include "common.h"
#include "rotate.h"

#define SwapBytes16_Defined
#define SwapBytes32_Defined
#ifdef Platform_64bit
	#define SwapBytes64_Defined
#else
	#define SwapBytesDWide_Defined
#endif

#ifdef _MSC_VER
	#ifndef __INTRIN_H_
		#pragma warning(push, 4)
		#pragma warning(disable: 4255 4668)
		#include <intrin.h>
		#pragma warning(pop)
	#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef Platform_64bit

#ifdef __GNUC__
	#define SwapBytes16F(x) \
		(__extension__ ({ \
			register uint __r = (uint16) x; \
			__asm__( \
				"xchgb %b0,%h0" : "=Q" (__r) : "0" (__r) \
			); \
			__r; \
		}))
	#ifdef Compiler_GCC43
		#define SwapBytes32F(x) (uint32) __builtin_bswap32(x)
		#define SwapBytes64(x) (uint64) __builtin_bswap64(x)
	#else
		#define SwapBytes32F(x) \
			(__extension__ ({ \
				register uint __r = x; \
				__asm__( \
					"bswapl %0" : "=R" (__r) : "0" (__r) \
				); \
				__r; \
			}))
		#define SwapBytes64(x) \
			(__extension__ ({ \
				register uwide __r = x; \
				__asm__( \
					"bswapq %0" : "=r" (__r) : "0" (__r) \
				); \
				__r; \
			}))
	#endif
	#define SwapBytesDWide_Defined
	#define SwapBytesDWide(x) \
		(__extension__ ({ \
			uint128 __x = x; \
			uint128 __r; \
			__asm__( \
				"bswapq %0\n\t" \
				"bswapq %1" : \
				"=&r" (__r.High), "=&r" (__r.Low) : \
				"0" (__x.Low), "1" (__x.High) \
			); \
			__r; \
		}))
#elif defined(_MSC_VER)
	#define SwapBytes16F(x) (ushort) _byteswap_ushort(x)
	#define SwapBytes32F(x) (uint) _byteswap_ulong(x)
	#define SwapBytes64(x) (uwide) _byteswap_uint64(x)
#else
	#error Unsupported compiler...
#endif

#else

#ifdef _MSC_VER
	#define SwapBytes16F(x) (uint) _byteswap_ushort(x)
	#define SwapBytes32F(x) (uint) _byteswap_ulong(x)
	#define SwapBytesDWide(x) (uint64) _byteswap_uint64(x)
#elif defined(__GNUC__)
	#define SwapBytes16F(x) \
		(__extension__ ({ \
			register uint __r = (uint16) x; \
			__asm__( \
				"xchgb %b0,%h0" : "=q" (__r) : "0" (__r) \
			); \
			__r; \
		}))
	#ifdef Compiler_GCC43
		#define SwapBytes32F(x) (uint32) __builtin_bswap32(x)
		#define SwapBytesDWide(x) (uint64) __builtin_bswap64(x)
	#else
		#define SwapBytes32F(x) \
			(__extension__ ({ \
				register uint __r = x; \
				__asm__( \
					"bswap %0" : "=r" (__r) : "0" (__r) \
				); \
				__r; \
			}))
		#define SwapBytesDWide(x) \
			(__extension__ ({ \
				register uint64 __r; \
				register uint __x; \
				register uint __y; \
				__asm__( \
					"bswap %0\n\t" \
					"bswap %1" : \
					"=a" (__x), "=d" (__y) : "A" (x) \
				); \
				__asm__("" : "=A" (__r) : "d" (__x), "a" (__y)); \
				__r; \
			}))
	#endif
#else
	#error Unsupported compiler...
#endif

#endif

#ifdef __cplusplus
}
#endif

#ifdef __GNUC__
	#define SwapBytes16C(x) \
		(uint) (((uint8) ((x) >> 8)) | \
			((uint8)  (x) << 8))
	#define SwapBytes32C(x) \
		(uint) (((uint8)  (x) << 24) | \
		       (((uint32) (x) & 0x0000FF00U) << 8) | \
		       (((uint32) (x) & 0x00FF0000U) >> 8) | \
			((uint8) ((x) >> 24)))
	#define SwapBytes16(x) \
		(__builtin_constant_p((uint16) (x)) ? \
			SwapBytes16C(x) : SwapBytes16F(x))
	#define SwapBytes32(x) \
		(__builtin_constant_p((uint32) (x)) ? \
			SwapBytes32C(x) : SwapBytes32F(x))
	#ifndef SwapBytesDWide_Defined
		#if defined(Platform_64bit) || defined(Hardware_Swap)
			#define SwapBytesDWide_Defined
			#ifdef Internal_dwide
				#define SwapBytesDWide(x) \
					(__extension__ ({ \
						udwide __x = x; \
						((udwide) SwapBytes((uwide) __x) << Bit_Capacity) | \
							  SwapBytes((uwide) (__x >> Bit_Capacity)); \
					}))
			#else
				#define SwapBytesDWide(x) \
					(__extension__ ({ \
						udwide __x = x; \
						udwide __r; \
						__r.Low = SwapBytes(__x.High); \
						__r.High = SwapBytes(__x.Low); \
						__r; \
					}))
			#endif
		#endif
	#endif
#else
	#define SwapBytes16 SwapBytes16F
	#define SwapBytes32 SwapBytes32F
#endif

#ifdef Platform_32bit
   #define SwapBytes SwapBytes32
   #define SwapBytes64 SwapBytesDWide
#else
   #define SwapBytes SwapBytes64
   #define SwapBytes128 SwapBytesDWide
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SwapBytes16_Defined
	Attribute_Const common_inline ufast
	SwapBytes16F (const ufast x)
	{
		return Bit_Join8(x & 0xFF, (x & 0xFF00) >> 8);
	}
#endif

#ifndef SwapBytes32_Defined

#ifndef Compiler_Rotate
	Attribute_Const common_inline ufast
	SwapBytes32F (const uint32 x)
	{
		return Bit_Shift(x, 24,
		       Bit_Join8(x & 0xFF00,
			       ((x >> 8) & 0xFF00) |
				(x >> 24)));
	}
#else
	Attribute_Const common_inline ufast
	SwapBytes32F (const ufast x)
	{
		ufast y = Bit_Join8(x & 0x00FF00FF, (x >> 8) & 0x00FF00FF);
		return Rotate32_Left(y, 16);
	}
#endif

#endif

#ifdef Platform_64bit

#ifndef SwapBytes64_Defined

Attribute_Const common_inline uint64
SwapBytes64 (const uint64 x)
{
	uint64 y;
	y = Bit_Join8(x & 0x00FF00FF00FF00FF, (x >> 8) & 0x00FF00FF00FF00FF);
	y = Bit_Shift(y & 0x0000FFFF0000FFFF, 16, (y >> 16) & 0x0000FFFF0000FFFF);
	#ifdef Compiler_Rotate64
		return Rotate_Left(y, 32);
	#else
		return Bit_Shift(y, 32, y >> 32);
	#endif
}

#endif

#endif

#ifndef SwapBytesDWide_Defined

#if defined(Platform_64bit) || defined(Hardware_Swap)

#define SwapBytesDWide_Defined

Attribute_Const common_inline udwide
SwapBytesDWide (const udwide x)
{
	#ifdef Internal_dwide
		return ((udwide) SwapBytes((uwide) x) << Bit_Capacity) |
				 SwapBytes((uwide) (x >> Bit_Capacity));
	#else
		udwide r;
		r.Low = SwapBytes(x.High);
		r.High = SwapBytes(x.Low);
		return r;
	#endif
}

#endif

#endif

#ifndef SwapBytesDWide_Defined

Attribute_Const common_inline
uint64 SwapBytesDWide (const uint64 x)
{
	#ifdef Internal_int64
		uint a = (uint) (x >> 32);
		uint b = (uint) x;
	#else
		uint64 r;
		uint a = x.Low;
		uint b = x.High;
	#endif
	#ifndef Compiler_Rotate
		a = Bit_Shift(a, 24,
		    Bit_Join8(a & 0xFF00,
			    ((a >> 8) & 0xFF00) |
			     (a >> 24)));
		b = Bit_Shift(b, 24,
		    Bit_Join8(b & 0xFF00,
			    ((b >> 8) & 0xFF00) |
			     (b >> 24)));
	#else
		a = Bit_Join8(a & 0x00FF00FF, (a >> 8) & 0x00FF00FF);
		b = Bit_Join8(b & 0x00FF00FF, (b >> 8) & 0x00FF00FF);
		a = Rotate32_Left(a, 16);
		b = Rotate32_Left(b, 16);
	#endif
	#ifdef Internal_int64
		return ((uint64) b << 32) | a;
	#else
		r.Low = b;
		r.High = a;
		return r;
	#endif
}

#endif

#ifdef __cplusplus
}
#endif

#ifdef Platform_Little
	#define Little16(x) (x)
	#define Little32(x) (x)
	#define Little64(x) (x)
	#define LittleShort(x) (x)
	#define LittleInt(x) (x)
	#define LittleWide(x) (x)
	#define LittleDWide(x) (x)
	#define Big16 SwapBytes16
	#define Big32 SwapBytes32
	#define Big64 SwapBytes64
	#define BigShort SwapBytes16
	#ifdef Platform_Int32bit
		#define BigInt SwapBytes32
	#else
		#define BigInt SwapBytes64
	#endif
	#define BigWide SwapBytes
	#define BigDWide SwapBytesDWide
	#ifdef Platform_64bit
		#define Little128(x) (x)
		#define Big128 SwapBytes128
	#endif
#else
	#define Big16(x) (x)
	#define Big32(x) (x)
	#define Big64(x) (x)
	#define BigShort(x) (x)
	#define BigInt(x) (x)
	#define BigWide(x) (x)
	#define BigDWide(x) (x)
	#define Little16 SwapBytes16
	#define Little32 SwapBytes32
	#define Little64 SwapBytes64
	#define LittleShort SwapBytes16
	#ifdef Platform_Int32bit
		#define LittleInt SwapBytes32
	#else
		#define LittleInt SwapBytes64
	#endif
	#define LittleWide SwapBytes
	#define LittleDWide SwapBytesDWide
	#ifdef Platform_64bit
		#define Big128(x) (x)
		#define Little128 SwapBytes128
	#endif
#endif

#define NetShort Big16
#define NetInt	 Big32
#define NetLong  Big64
#define NetWide  BigWide
#define NetDWide BigDWide

#endif
