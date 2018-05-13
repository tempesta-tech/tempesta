/**
 * \file bn_mul.h
 *
 * \brief Multi-precision integer library
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *	  Multiply source vector [s] with b, add result
 *	   to destination vector [d] and set carry c.
 */
#ifndef MBEDTLS_BN_MUL_H
#define MBEDTLS_BN_MUL_H

#include "bignum.h"

#define MULADDC_INIT						\
	asm(									\
		"xorq   %%r8, %%r8		  \n\t"

#define MULADDC_CORE						\
		"movq   (%%rsi), %%rax	  \n\t"   \
		"mulq   %%rbx			   \n\t"   \
		"addq   $8,	  %%rsi	  \n\t"   \
		"addq   %%rcx,   %%rax	  \n\t"   \
		"movq   %%r8,	%%rcx	  \n\t"   \
		"adcq   $0,	  %%rdx	  \n\t"   \
		"nop						\n\t"   \
		"addq   %%rax,   (%%rdi)	\n\t"   \
		"adcq   %%rdx,   %%rcx	  \n\t"   \
		"addq   $8,	  %%rdi	  \n\t"

#define MULADDC_STOP						\
		: "+c" (c), "+D" (d), "+S" (s)	  \
		: "b" (b)						   \
		: "rax", "rdx", "r8"				\
	);

#endif /* bn_mul.h */
