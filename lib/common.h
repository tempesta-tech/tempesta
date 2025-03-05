/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2019 Tempesta Technologies, Inc.
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
 */
#ifndef __LIB_COMMON_H__
#define __LIB_COMMON_H__

#include <linux/percpu.h>
#include <linux/timer.h>
#include <linux/time.h>

/* Per-CPU cached timestamp */
static DEFINE_PER_CPU(long, tfw_ts_cache);

/* Update timer */
static struct timer_list tfw_ts_timer;

/* Timer interval: 1 second */
#define TFW_TS_UPDATE_INTERVAL (HZ)

/**
 * Timer callback to update the cached timestamp across all CPUs.
 */
static void
tfw_ts_update_timer(struct timer_list *t)
{
	struct timespec64 ts;
	int cpu;
	
	/* Get the current timestamp */
	ktime_get_real_ts64(&ts);
	
	/* Update the timestamp on all CPUs */
	for_each_online_cpu(cpu) {
		per_cpu(tfw_ts_cache, cpu) = ts.tv_sec;
	}
	
	/* Reschedule the timer */
	mod_timer(&tfw_ts_timer, jiffies + TFW_TS_UPDATE_INTERVAL);
}

/**
 * Initialize the timestamp caching system.
 * Should be called during module initialization.
 */
static inline int
tfw_ts_cache_init(void)
{
	struct timespec64 ts;
	int cpu;
	
	/* Initialize the initial timestamp value */
	ktime_get_real_ts64(&ts);
	
	/* Set the initial value for all CPUs */
	for_each_online_cpu(cpu) {
		per_cpu(tfw_ts_cache, cpu) = ts.tv_sec;
	}
	
	/* Setup the timer */
	timer_setup(&tfw_ts_timer, tfw_ts_update_timer, 0);
	mod_timer(&tfw_ts_timer, jiffies + TFW_TS_UPDATE_INTERVAL);
	
	return 0;
}

/**
 * Clean up the timestamp caching system.
 * Should be called during module cleanup.
 */
static inline void
tfw_ts_cache_exit(void)
{
	del_timer_sync(&tfw_ts_timer);
}

/**
 * Get current timestamp in seconds.
 * Always returns the cached value, which is updated by the timer.
 */
static inline long
tfw_current_timestamp(void)
{
	return this_cpu_read(tfw_ts_cache);
}

#endif /* __LIB_COMMON_H__ */
