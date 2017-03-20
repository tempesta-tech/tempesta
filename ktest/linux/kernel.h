/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2015-2017 Tempesta Technologies.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __KERNEL_H__
#define __KERNEL_H__

#include <stdio.h>

#include "compiler.h"

#ifndef NDEBUG
#define DEBUG 1
#endif

#ifndef ENOMEM
#define ENOMEM		1
#endif

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))

#define pr_err(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	fprintf(stdout, fmt, ##__VA_ARGS__)

/* asm/cache.h */
#ifndef L1_CACHE_BYTES
#define L1_CACHE_BYTES 64
#endif

#define SMP_CACHE_BYTES L1_CACHE_BYTES
#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned

#endif /* __KERNEL_H__ */
