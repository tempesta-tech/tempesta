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

#ifndef COMMON_H
#define COMMON_H

/*
 * Platform_x86: must be specified to enable x86-specific optimizations.
 */
#define Platform_x86

/*
 * Platform_32bit: 32-bit platform.
 * Platform_64bit: 64-bit platform.
 */
#define Platform_32bit

/*
 * Platform_Little: little-endian platform.
 * Platform_Big: big-endian platform.
 */
#define Platform_Little

/*
 * Hardware_Predicates: hardware support for boolean predicates.
 */
#define Hardware_Predicates

/*
 * Hardware_Conditional: hardware support for conditional move.
 */
#define Hardware_Conditional

/*
 * Hardware_Carry: hardware support carry flag.
 */
#define Hardware_Carry

/*
 * Hardware_Carry: hardware rotate.
 */
#define Hardware_Rotate

/*
 * Hardware_ShiftAdd: mask of available shifts in the hardware
 * shift-add command (LEA on x86):
 */
#define Hardware_ShiftAdd 15

/*
 * Hardware_Swap: hardware swap registers.
 */
#define Hardware_Swap

/*
 * Hardware_Remainder: hardware remainder of integer division.
 */
#define Hardware_Remainder

/*
 * Hardware_MultiplyLong: hardware multiply long.
 */
#define Hardware_MultiplyLong

/*
 * Hardware_Log2: hardware integer logarithm.
 */
#define Hardware_Log2

/*
 * Hardware_TrailZero: hardware counting of trailing zeros.
 */
#define Hardware_TrailZero

/*
 * Hardware_LeadZero: hardware counting of leading zeros.
 */
#define Hardware_LeadZero

/*
 * Hardware_Population: hardware population count.
 */
#define Hardware_Population

/*
 * Hardware_CRC32: hardware CRC-32 calculation.
 */
#define Hardware_CRC32

/*
 * Hardware_AES: hardware AES rounds.
 */
#define Hardware_AES

/*
 * Hardware_AndNot: hardware and-not.
 */
#define Hardware_AndNot

/*
 * Hardware_BarrelShifter: processor have full-functional
 * barrel shifter available on instruction level.
 */
/* #define Hardware_BarrelShifter */

#ifndef Hardware_ShiftAdd
	#ifdef Hardware_BarrelShifter
		#ifdef Platform_32bit
			#define Hardware_ShiftAdd 0xFFFFFFFE
		#else
			#define Hardware_ShiftAdd 0xFFFFFFFFFFFFFFFE
		#endif
	#else
		#define Hardware_ShiftAdd 0
	#endif
#endif

#define High_Bit32 0x80000000

#ifdef Platform_32bit
	#define Bit_Capacity 32
	#define Bit_Capacity_Log 5
	#define Word_Size 4
	#define High_Bit 0x80000000
#else
	#define Bit_Capacity 64
	#define Bit_Capacity_Log 6
	#define Word_Size 8
	#define High_Bit 0x8000000000000000
#endif

/*
 * Maximal available length in the shift instructions:
 */
#define Shift_Length (Bit_Capacity - 1)

/*
 * Platform_Alignment: plafrom requires aligned access to the memory.
 */
/* #define Platform_Alignment */

/*
 * Integer logarithm-related definitions,
 * which may be derived from main specification:
 */
#ifdef Hardware_LeadZero
	#define Hardware_FastLog2
#elif defined(Hardware_Log2)
	#define Hardware_FastLog2
	#ifndef Hardware_LeadOnes
		#define Hardware_Log2Only
	#endif
#elif defined(Hardware_LeadOnes)
	#define Hardware_FastLog2
	#define Hardware_LeadOnesOnly
#endif

#if defined(Fast_Log2) || \
    defined(Hardware_Population) || \
    defined(Hardware_LeadZeroBytes)
	#define Hardware_QuickLog2
#endif

/*
 * Macros to use LEA on the x86, barrel shifter and other
 * hardware-specific instructions istead of "|" if suitable:
 */

#if Hardware_ShiftAdd & 1
	#define Bit_Add(x, y) ((x) + (y))
#else
	#define Bit_Add(x, y) ((x) | (y))
#endif

#if Hardware_ShiftAdd & 2
	#define Bit_Join1(x, y) (((x) << 1) + (y))
#else
	#define Bit_Join1(x, y) (((x) << 1) | (y))
#endif

#if Hardware_ShiftAdd & 4
	#define Bit_Join2(x, y) (((x) << 2) + (y))
#else
	#define Bit_Join2(x, y) (((x) << 2) | (y))
#endif

#if Hardware_ShiftAdd & 8
	#define Bit_Join3(x, y) (((x) << 3) + (y))
#else
	#define Bit_Join3(x, y) (((x) << 3) | (y))
#endif

#if Hardware_ShiftAdd & 16
	#define Bit_Join4(x, y) (((x) << 4) + (y))
#else
	#define Bit_Join4(x, y) (((x) << 4) | (y))
#endif

#if Hardware_ShiftAdd & 256
	#define Bit_Join8(x, y) (((x) << 8) + (y))
#else
	#define Bit_Join8(x, y) (((x) << 8) | (y))
#endif

#if Hardware_ShiftAdd & ~0x11E
	#define Bit_Shift(x, y, z) (((x) << (y)) + (z))
#else
	#define Bit_Shift(x, y, z) (((x) << (y)) | (z))
#endif

#define Bit_Join Bit_Shift

/*
 * Optimal values for current hardware:
 */
#define Multiply_Throughput 1
#define Multiply_Latency64 4
#define Divide_Latency64 95
#define Divide_Latency32 22

#ifdef Platform_32bit
	#define Multiply_Latency Multiply_Latency32
	#define Divide_Latency Divide_Latency32
#else
	#define Multiply_Latency Multiply_Latency64
	#ifndef Multiply_Latency32
		#define Multiply_Latency32 Multiply_Latency64
	#endif
	#define Divide_Latency Divide_Latency64
	#ifndef Divide_Latency32
		#define Divide_Latency32 Divide_Latency64
	#endif
#endif

#ifndef Multiply_Latency16
	#define Multiply_Latency16 Multiply_Latency32
#endif

#ifndef Multiply_Latency8
	#define Multiply_Latency8 Multiply_Latency16
#endif

#ifndef Divide_Latency16
	#define Divide_Latency16 Divide_Latency32
#endif

#ifndef Divide_Latency8
	#define Divide_Latency8 Divide_Latency16
#endif

#ifndef Multiply_Throughput
	#define Multiply_Throughput Multiply_Latency
#endif

#ifndef Multiply_Add_Latency
	#ifdef Hardware_MultiplyAdd
		#define Multiply_Add_Latency Multiply_Latency
	#else
		#define Multiply_Add_Latency (Multiply_Latency + 1)
	#endif
#endif

#ifndef Multiply_Chain_Latency
	#define Multiply_Chain_Latency Multiply_Add_Latency
#endif

#ifndef Multiply_High_Latency
	#ifdef Hardware_MultiplyHigh
		#define Multiply_High_Latency Multiply_Latency
	#elif defined(Hardware_MultiplyLong)
		#define Multiply_High_Latency Multiply_Long_Latency
	#endif
#endif

#ifndef Multiply_Long_Latency
	#ifdef Hardware_MultiplyLong
		#define Multiply_Long_Latency Multiply_Latency
	#elif defined(Hardware_MultiplyHigh)
		#define Multiply_Long_Latency \
			(Multiply_Throughput + Multiply_High_Latency)
	#endif
#endif

/*
 * Some compiler-specific settings:
 */
#ifdef __GNUC__
	#ifndef __cplusplus
		#define common_inline static __inline__
	#endif
	#if defined(__EMX__) && ! defined(__STRICT_ANSI__)
		#define Compiler_Rotate
	#endif
	#define Internal_int64
	typedef long long int64;
	typedef unsigned long long uint64;
	#define Attribute_Const __attribute__((const))
	#define Attribute_NoReturn __attribute__((noreturn))
	#if __GNUC__ >= 3
		#define Attribute_Allocate __attribute__((malloc))
		#define Attribute_Pure __attribute__((pure))
		#define Attribute_Clean __attribute__((pure))
		#define Attribute_Printf(x, y) __attribute__((format(printf, x, y)))
		#define Attribute_Align(x) __attribute__((aligned(x)))
	#endif
	#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
		#define Compiler_GCC44
	#endif
	#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
		#define Compiler_GCC43
	#endif
	#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
		#define Compiler_GCC34
	#endif
	#if __GNUC__ >= 4
		#define Compiler_Restrict
		#define Opt_Likely(x) __builtin_expect(x, 1)
		#define Opt_Unlikely(x) __builtin_expect(x, 0)
	#endif
#elif defined(_MSC_VER)
	#pragma once
	#pragma warning(disable: 4711 4464)
	#pragma warning(disable: 4055 4100 4127 4242 4244 4514 4710 4820)
	#ifndef _CRT_SECURE_NO_DEPRECATE
		#define _CRT_SECURE_NO_DEPRECATE
	#endif
	#ifdef Platform_Emulator
		#pragma warning(disable: 4244)
	#endif
	#define common_cdecl __cdecl
	#ifndef _POSIX_
		#define Compiler_Rotate
		#define Compiler_Rotate64
	#endif
	#ifndef __cplusplus
		#define common_inline static __inline
	#endif
	#define Internal_int64
	typedef __int64 int64;
	typedef unsigned __int64 uint64;
	#if _MSC_VER >= 1400
		#if _INTEGRAL_MAX_BITS >= 128
			#define Internal_int128
			typedef __int128 int128;
			typedef unsigned __int128 uint128;
		#endif
		#define Attribute_Allocate __declspec(restrict)
		#define Attribute_NoAlias __declspec(noalias)
		#define Attribute_Clean  __declspec(noalias)
		#define Compiler_Restrict
	#endif
	#define Attribute_Align(x) __declspec(align(x))
	#define Attribute_NoReturn __declspec(noreturn)
#endif

#ifndef common_cdecl
#define common_cdecl
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL (void *) 0
#endif
#endif

#ifdef __cplusplus
	#define common_inline inline
#endif

#define local_function common_inline

#ifndef Compiler_Restrict
	#define __restrict
#endif

#ifdef _MSC_VER
	#define __restrict_fixed
#else
	#define __restrict_fixed __restrict
#endif

#if ! defined(__INT_MAX__) || \
	     (__INT_MAX__ == 0x7FFFFFFF)
	#define Platform_Int32bit
#endif

#ifdef Platform_64bit
	#if ! defined(__LONG_MAX__) || \
		     (__LONG_MAX__ != 0x7FFFFFFF)
		#define Platform_Long64bit
	#endif
#endif

#ifdef Platform_64bit
	#ifndef Internal_int64
		#define Internal_int64
		typedef long int64;
		typedef unsigned long uint64;
	#endif
#endif

#ifdef Platform_Int32bit
	typedef int int32;
	typedef unsigned int uint32;
#else
	typedef __int32 int32;
	typedef unsigned __int32 uint32;
#endif

typedef short	       int16;
typedef signed char    int8;
typedef unsigned short uint16;
typedef unsigned char  uint8;

#ifdef Platform_32bit
	typedef int wide;
	typedef unsigned int uwide;
#else
	typedef int64 wide;
	typedef uint64 uwide;
#endif

#ifdef Platform_x86
	typedef int fast;
	typedef unsigned int ufast;
	#define Fast_Capacity 32
#else
	typedef wide fast;
	typedef uwide ufast;
	#define Fast_Capacity Bit_Capacity
#endif

#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE)
	#define Platform_SysTypes
#endif

#ifdef Platform_SysTypes
	#ifndef _SYS_TYPES_H
		#include <sys/types.h>
	#endif
	typedef unsigned char uchar;
#else
	typedef unsigned char  uchar;
	typedef unsigned short ushort;
	typedef unsigned int   uint;
	typedef unsigned long  ulong;
#endif

#ifndef __RPCNDR_H__
   typedef unsigned char byte;
#endif

#ifndef __cplusplus
	#ifndef bool
		typedef unsigned char bool;
	#endif
	#define true 1
	#define false 0
#endif

/*
 * Common definitions for compiler-specific optimization attributes:
 */

#ifndef Attribute_Allocate
	#define Attribute_Allocate
#endif

#ifndef Attribute_NoAlias
	#define Attribute_NoAlias
#endif

#ifndef Attribute_Pure
	#define Attribute_Pure
#endif

#ifndef Attribute_Clean
	#define Attribute_Clean
#endif

#ifndef Attribute_OutOnly
	#define Attribute_OutOnly
#endif

#ifndef Attribute_Const
	#define Attribute_Const Attribute_Clean
#endif

#ifndef Attribute_Printf
	#define Attribute_Printf(x, y)
#endif

#ifdef Attribute_Align
	#define Compiler_Align
#else
	#define Attribute_Align(x)
#endif

#ifndef Attribute_NoReturn
	#define Attribute_NoReturn
#endif

#ifndef Opt_Likely
	#define Opt_Likely(x) (x)
#endif

#ifndef Opt_Unlikely
	#define Opt_Unlikely(x) (x)
#endif

/*
 * Remove aliasing effects from the pointer, because ANSI-compliant
 * compiler should assume that any  pointer to a union, which containing
 * "char", potentially overlap with any other pointers in the program:
 */
typedef union {
	char  c;
	void *p;
} AntiAliasType;

#define AntiAliasLink(x) ((AntiAliasType *) (x))->p

/* Double-wide integer types: */

#ifdef Platform_32bit
	#ifdef Internal_int64
		#define Internal_dwide
		typedef int64 dwide;
		typedef uint64 udwide;
	#endif
#else
	#ifdef Internal_int128
		#define Internal_dwide
		typedef int128 dwide;
		typedef uint128 udwide;
	#endif
#endif

#ifdef Internal_int64
	#define MakeConst64(x, y) (((uint64) (x) << 32) | (y))
#else
	#define MakeConst64 MakeConstDWide
#endif

#ifdef Internal_dwide
	#define MakeConstDWide(x, y) (((udwide) (x) << Bit_Capacity) | (y))
#else
/*
 * Software implementation of double-wide integes.
 * For example, GCC does not support 128-bit integers:
 */
	#ifdef Platform_Big
		typedef struct {
			wide  High;
			uwide Low;
		} dwide;
		typedef struct {
			uwide High;
			uwide Low;
		} udwide;
		#define MakeConstDWide(x, y) {x, y}
	#else
		typedef struct {
			uwide Low;
			wide  High;
		} dwide;
		typedef struct {
			uwide Low;
			uwide High;
		} udwide;
		#define MakeConstDWide(x, y) {y, x}
	#endif
	#ifdef Platform_32bit
		typedef dwide int64;
		typedef udwide uint64;
	#else
		typedef dwide int128;
		typedef udwide uint128;
	#endif
#endif

#endif
