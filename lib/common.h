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

#include <linux/interrupt.h>

#ifdef CONFIG_SECURITY_TEMPESTA
/* Get current timestamp in secs.*/
static inline long
tfw_current_timestamp(void)
{
	/*
	 * Use kernel-cached timestamp when in softirq context.
	 * The timestamp is updated once per softirq batch in handle_softirqs().
	 * This provides significant performance improvement by avoiding multiple
	 * expensive ktime_get_real_ts64() calls per softirq batch.
	 */
	if (likely(in_serving_softirq()))
		return softirq_current_timestamp();
	
	/* Fallback to direct call outside softirq context */
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	return ts.tv_sec;
}

#else
/* Fallback implementation when Tempesta is not enabled */
static inline long
tfw_current_timestamp(void)
{
	struct timespec64 ts;
	ktime_get_real_ts64(&ts);
	return ts.tv_sec;
}
#endif /* CONFIG_SECURITY_TEMPESTA */

#endif /* __LIB_COMMON_H__ */
