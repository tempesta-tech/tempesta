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
#ifndef __THREADS_H__
#define __THREADS_H__

#include <stdlib.h>

#include "kernel.h"

/*
 * In user space all threads have different identifiers,
 * so there is no problems with preemption.
 */
#define local_bh_disable()
#define local_bh_enable()

static size_t __thr_max = 0;
static size_t __thread __thr_id;

typedef struct {
	void *data;
	void *(*f_ptr)(void *);
} __ThrData;

static void *
__thr_func_wrapper(void *data)
{
	__ThrData *d = data;
	void *ret = NULL;

	__thr_id = __atomic_fetch_add(&__thr_max, 1, __ATOMIC_SEQ_CST);
	BUG_ON(__thr_max >= NR_CPUS);

	if (d->f_ptr)
		ret = d->f_ptr(d->data);

	free(d);

	return ret;
}

static inline int
spawn_thread(pthread_t *thr_id, void *(func)(void *), void *arg)
{
	__ThrData *d = malloc(sizeof(__ThrData));
	if (!d)
		return -ENOMEM;

	d->data = arg;
	d->f_ptr = func;

	return pthread_create(thr_id, NULL, __thr_func_wrapper, d);
}

#endif /* __THREADS_H__ */
