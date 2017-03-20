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
#ifndef __COMPILER_H__
#define __COMPILER_H__

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

/* asm/types.h */
#define BITS_PER_LONG	64

#define likely(e)	__builtin_expect((e), 1)
#define unlikely(e)	__builtin_expect((e), 0)

#define BUG_ON(c)	assert(!(c))
#define BUG()		abort()

#define __percpu

#endif /* __COMPILER_H__ */
