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
#ifndef __THREADS_H__
#define __THREADS_H__

#include "kernel.h"

/*
 * In user space all threads have different identifiers,
 * so there is no problems with preemption.
 */
#define local_bh_disable()
#define local_bh_enable()

static size_t __thr_max = 0;
static size_t __thread __thr_id;

static int
spawn_thread(pthread_t *thr_id, void *(func)(void *data), void *arg)
{
	__thr_id = __atomic_fetch_add(&__thr_max, 1, __ATOMIC_SEQ_CST);
	return pthread_create(thr_id, NULL, func, arg);
}

#endif /* __THREADS_H__ */
