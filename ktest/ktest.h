/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * This is Ktest super header aggregating all the headers, so to use the
 * framework you only need to include this one header.
 *
 * Copyright (C) 2020-2025 Tempesta Technologies, Inc.
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
#ifndef __KTEST_H__
#define __KTEST_H__

/* Don't include lib/str.h */
#define __LIB_STR_H__

#include <linux/types.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "asm/fpu/api.h"
#include "asm/sync_bitops.h"
#include "crypto/hash.h"
#include "crypto/sha.h"
#include "linux/atomic.h"
#include "linux/bitops.h"
#include "linux/bug.h"
#include "linux/compiler.h"
#include "linux/kernel.h"
#include "linux/percpu.h"
#include "linux/preempt.h"
#include "linux/skbuff.h"
#include "linux/slab.h"
#include "linux/spinlock.h"
#include "linux/scatterlist.h"
#include "linux/threads.h"
#include "net/tls.h"

#ifndef BANNER
#define BANNER	"ktest"
#endif

/* Redefine flex array from linux kernel. */
#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)

#define __DECLARE_FLEX_ARRAY(TYPE, NAME)	\
	struct {				\
		struct { } __empty_ ## NAME;	\
		TYPE NAME[];			\
	}

/* Redefine Tempesta performance-optimized library routines. */
#ifndef memcpy_fast
#define memcmp_fast(a, b, n)	memcmp(a, b, n)
#define memcpy_fast(a, b, n)	memcpy(a, b, n)
#define bzero_fast(a, n)	bzero(a, n)
#endif

#endif /* __KTEST_H__ */
