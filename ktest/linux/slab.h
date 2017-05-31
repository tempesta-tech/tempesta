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
#ifndef __SLAB_H__
#define __SLAB_H__

#include <stdlib.h>

#include "atomic.h"
#include "compiler.h"
#include "kernel.h"
#include "percpu.h"
#include "spinlock.h"
#include "threads.h"

/* asm/page.h */
#define PAGE_SIZE	4096UL

#define kfree(p)	free(p)

#endif /* __SLAB_H__ */
