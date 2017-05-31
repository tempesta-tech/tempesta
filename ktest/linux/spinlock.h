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
#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <pthread.h>

#include "kernel.h"

typedef pthread_mutex_t	spinlock_t;

#define __RAW_SPIN_LOCK_UNLOCKED(lock)	PTHREAD_MUTEX_INITIALIZER

#define spin_lock_init(lock)		pthread_mutex_init(lock, NULL)
#define spin_lock(lock)			pthread_mutex_lock(lock)
#define spin_trylock(lock)		(!pthread_mutex_trylock(lock))
#define spin_unlock(lock)		pthread_mutex_unlock(lock)

/*
 * Pthread doesn't have RW spin-locks,
 * so just use semaphores to test concurrency.
 */
typedef pthread_rwlock_t rwlock_t;

#define rwlock_init(lock)		pthread_rwlock_init(lock, NULL)
#define write_lock_bh(lock)		pthread_rwlock_wrlock(lock)
#define write_unlock_bh(lock)		pthread_rwlock_unlock(lock)
#define read_lock_bh(lock)		pthread_rwlock_rdlock(lock)
#define read_unlock_bh(lock)		pthread_rwlock_unlock(lock)

#endif /* __SPINLOCK_H__ */
