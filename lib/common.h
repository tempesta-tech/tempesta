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
#include <linux/time.h>

#define TFW_TS_REFRESH_INTERVAL (HZ)

/**
 * Get current timestamp with ktime_get_real_ts64 interface.
 * Uses per-CPU cached timestamps in softirq context.
 * WARNING: Must be called from softirq context only.
 */
static inline void
tfw_current_timestamp_ts64(struct timespec64 *ts)
{
	static DEFINE_PER_CPU(struct timespec64, tfw_cached_ts);
	static DEFINE_PER_CPU(unsigned long, tfw_ts_last_update);

	WARN_ON_ONCE(!in_softirq());

	struct timespec64 *cached_ts = this_cpu_ptr(&tfw_cached_ts);
	unsigned long *last_update = this_cpu_ptr(&tfw_ts_last_update);
	unsigned long now = jiffies;

	if (unlikely(time_after(now,
				*last_update + TFW_TS_REFRESH_INTERVAL)))
	{
		ktime_get_real_ts64(cached_ts);
		*last_update = now;
	}

	*ts = *cached_ts;
}

/**
 * Get current timestamp in seconds.
 * Uses per-CPU cached timestamps in softirq context.
 * WARNING: Must be called from softirq context only.
 */
static inline long
tfw_current_timestamp(void)
{
	struct timespec64 ts;

	tfw_current_timestamp_ts64(&ts);
	return ts.tv_sec;
}

/**
 * Get current timestamp - real-time version.
 * For use outside of softirq context or when precise real-time is needed.
 * WARNING: Must be called from process context only.
 */
static inline struct timespec64
tfw_current_timestamp_real(void)
{
	struct timespec64 ts;

	WARN_ON_ONCE(in_softirq());

	ktime_get_real_ts64(&ts);
	return ts;
}

#endif /* __LIB_COMMON_H__ */
