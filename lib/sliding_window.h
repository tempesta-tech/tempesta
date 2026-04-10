/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2026 Tempesta Technologies, INC.
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
#ifndef __LIB_SLIDING_WINDOW_H__
#define __LIB_SLIDING_WINDOW_H__

#define TFW_SLIDING_WINDOW 8

/**
 * Monotonically increasing time quantums. The configured @tframe
 * is divided by TFW_SLIDING_WINDOW slots to get the quantums granularity.
 */
static inline unsigned int
tfw_time_quantum(unsigned short tframe)
{
	return jiffies / tframe;
}

static inline bool
tfw_time_in_frame(const unsigned long tcur, const unsigned long tprev)
{
	return time_before(tcur, tprev + TFW_SLIDING_WINDOW);
}

#define TFW_SUMM_IN_FRAME(tcur, tprev, lambda)				\
do {									\
	int iter;							\
									\
	for (iter = 0; iter < TFW_SLIDING_WINDOW; iter++) {		\
		if (tfw_time_in_frame(tcur, tprev)) {			\
			lambda;						\
		}							\
	}								\
} while(0)

#endif /* __LIB_SLIDING_WINDOW_H__ */