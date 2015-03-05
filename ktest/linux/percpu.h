/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2015 Tempesta Technologies.
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
#ifndef __PERCPU_H__
#define __PERCPU_H__

#include <stdlib.h>

/* 32 should be enough for testing. */
#define NR_CPUS				32

#define alloc_percpu(s)			calloc(NR_CPUS, sizeof(s))
#define free_percpu(p)			free(p)
#define for_each_possible_cpu(c)	for (c = 0; c < NR_CPUS; ++c)
#define per_cpu_ptr(a, c)		&(a)[c]
#define this_cpu_ptr(a)			(&(a)[__thr_id])

#endif /* __PERCPU_H__ */
