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

#ifndef COMMON_ROTATE_H
#define COMMON_ROTATE_H

#include "common.h"

#ifdef Compiler_Rotate
	#ifdef _MSC_VER
		#ifndef __INTRIN_H_
			#pragma warning(push, 4)
			#pragma warning(disable: 4255 4668)
			#include <intrin.h>
			#pragma warning(pop)
		#endif
	#else
		#include <stdlib.h>
	#endif
	#define Rotate32_Defined
	#define Rotate32_Left _rotl
	#define Rotate32_Right _rotr
	#ifdef Compiler_Rotate64
		#define Rotate64_Defined
		#ifdef _MSC_VER
			#define Rotate64_Left _rotl64
			#define Rotate64_Right _rotr64
		#else
			#define Rotate64_Left _lrotl
			#define Rotate64_Right _lrotr
		#endif
	#endif
#endif

#ifdef Platform_32bit
	#define Rotate_Defined
	#define Rotate_Left Rotate32_Left
	#define Rotate_Right Rotate32_Right
	#ifdef Rotate64_Defined
		#define Rotate_Double_Defined
		#define Rotate_Double_Left Rotate64_Left
		#define Rotate_Double_Right Rotate64_Right
	#else
		#define Rotate64_Left Rotate_Double_Left
		#define Rotate64_Right Rotate_Double_Right
	#endif
#else
	#ifdef Rotate64_Defined
		#define Rotate_Defined
		#define Rotate_Left Rotate64_Left
		#define Rotate_Right Rotate64_Right
	#else
		#define Rotate64_Left Rotate_Left
		#define Rotate64_Right Rotate_Right
	#endif
	#define Rotate128_Left Rotate_Double_Left
	#define Rotate128_Right Rotate_Double_Right
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef Rotate32_Defined

Attribute_Const common_inline ufast
Rotate32_Left (const uint32 x, const ufast Shift)
{
#if Shift_Length < 32
	if (Shift) {
#endif
	#if defined(Hardware_Rotate) || Hardware_ShiftAdd <= 1
		return (uint32) (x << Shift) | ((uwide) x >> (32 - Shift));
	#else
		return (uint32) (x << Shift) + ((uwide) x >> (32 - Shift));
	#endif
#if Shift_Length < 32
	}
	else {
		return x;
	}
#endif
}

Attribute_Const common_inline ufast
Rotate32_Right (const uint32 x, const ufast Shift)
{
#if Shift_Length < 32
	if (Shift) {
#endif
	#if defined(Hardware_Rotate) || Hardware_ShiftAdd <= 1
		return (x >> Shift) | (uint32) ((uwide) x << (32 - Shift));
	#else
		return (x >> Shift) + (uint32) ((uwide) x << (32 - Shift));
	#endif
#if Shift_Length < 32
	}
	else {
		return x;
	}
#endif
}

#endif

#ifndef Rotate_Defined

Attribute_Const common_inline uwide
Rotate_Left (const uwide x, const ufast Shift)
{
#if Shift_Length < Bit_Capacity
	if (Shift) {
#endif
	#if defined(Hardware_Rotate) || Hardware_ShiftAdd <= 1
		return (x << Shift) | (x >> (Bit_Capacity - Shift));
	#else
		return (x << Shift) + (x >> (Bit_Capacity - Shift));
	#endif
#if Shift_Length < Bit_Capacity
	}
	else {
		return x;
	}
#endif
}

Attribute_Const common_inline uwide
Rotate_Right (const uwide x, const ufast Shift)
{
#if Shift_Length < Bit_Capacity
	if (Shift) {
#endif
	#if defined(Hardware_Rotate) || Hardware_ShiftAdd <= 1
		return (x >> Shift) | (x << (Bit_Capacity - Shift));
	#else
		return (x >> Shift) + (x << (Bit_Capacity - Shift));
	#endif
#if Shift_Length < Bit_Capacity
	}
	else {
		return x;
	}
#endif
}

#endif

#ifndef Rotate_Double_Defined

#ifdef Internal_dwide

#define Rotate_Double_Defined

Attribute_Const common_inline udwide
Rotate_Double_Left (const udwide x, const ufast Shift)
{
#if Shift_Length < Bit_Capacity
	if (Shift) {
#endif
		return (x << Shift) | (x >> (2 * Bit_Capacity - Shift));
#if Shift_Length < Bit_Capacity
	}
	else {
		return x;
	}
#endif
}

Attribute_Const common_inline udwide
Rotate_Double_Right (const udwide x, const ufast Shift)
{
#if Shift_Length < Bit_Capacity
	if (Shift) {
#endif
		return (x << (2 * Bit_Capacity - Shift)) | (x >> Shift);
#if Shift_Length < Bit_Capacity
	}
	else {
		return x;
	}
#endif
}

#else

Attribute_Const common_inline udwide
Rotate_Double_Left (const udwide x, const ufast Shift)
{
	udwide r = x;
	int Offset = Bit_Capacity - Shift;
	if (Offset > 0) {
		#if Shift_Length < Bit_Capacity
		if (Shift) {
		#endif
			r.Low  = Bit_Shift(r.Low,  Shift, r.High >> Offset);
			r.High = Bit_Shift(r.High, Shift, r.Low  >> Offset);
		#if Shift_Length < Bit_Capacity
		}
		#endif
	}
	else {
		const uint Bias = Offset + Bit_Capacity;
		Offset = -Offset;
		r.Low  = Bit_Shift(r.High, Offset, r.Low  >> Bias);
		r.High = Bit_Shift(r.Low,  Offset, r.High >> Bias);
	}
	return r;
}

Attribute_Const common_inline udwide
Rotate_Double_Right (const udwide x, const ufast Shift)
{
	udwide r = x;
	int Offset = Bit_Capacity - Shift;
	if (Offset > 0) {
		#if Shift_Length < Bit_Capacity
		if (Shift) {
		#endif
			r.Low  = Bit_Shift(r.High, Offset, r.Low  >> Shift);
			r.High = Bit_Shift(r.Low,  Offset, r.High >> Shift);
		#if Shift_Length < Bit_Capacity
		}
		#endif
	}
	else {
		const uint Bias = Offset + Bit_Capacity;
		Offset = -Offset;
		r.Low  = Bit_Shift(r.Low,  Bias, r.High >> Offset);
		r.High = Bit_Shift(r.High, Bias, r.Low	>> Offset);
	}
	return r;
}

#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
