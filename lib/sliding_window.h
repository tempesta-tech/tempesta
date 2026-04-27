/**
 *		Tempesta kernel library
 *
 * Sliding window rate estimation library.
 *
 * This file implements a lightweight sliding window counter used for
 * approximate rate calculation in hot paths. The implementation avoids
 * expensive operations (such as division or modulo) in the update path
 * and performs only a single division in the read path.
 *
 * The algorithm maintains two counters:
 *  - current window counter (@curr_count)
 *  - previous window counter (@prev_count)
 *
 * Instead of aligning time to fixed global boundaries, the window is
 * anchored at the moment of the first observed event (@epoch_start) and
 * then advances in window-sized steps. This may cause the window to drift
 * relative to absolute time, but significantly reduces computational cost
 * and is acceptable for rate estimation purposes.
 *
 * On each update:
 *  - if still within the current window, @curr_count is incremented;
 *  - if one window has elapsed, @curr_count is rotated into @prev_count;
 *  - if more than one window has elapsed, history is dropped.
 *
 * The resulting rate is computed using linear interpolation between the
 * current and previous windows:
 *
 *   rate ~= curr_count + prev_count * (window_size - age) / window_size
 *
 * where @age is the time elapsed since the start of the current window.
 *
 * Similar techniques are widely used in high-performance systems, see:
 *   https://blog.cloudflare.com/counting-things-a-lot-of-different-things/
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

/**
 * Sliding window counters for approximate rate calculation.
 *
 * @curr_count	- number of events observed in the current window;
 * @prev_count	- number of events from the previous window, used to
 *		  approximate a smooth transition between windows;
 * @epoch_start	- timestamp (in seconds) marking the start of the
 *		  current window. The algorithm advances this value
 *		  in window-sized increments;
 * @window	- size of window in seconds;
 */
typedef struct {
	u64 curr_count;
	u64 prev_count;
	u64 epoch_start;
	u32 window;
} TfwSlidingWindow;

static inline void
tfw_sliding_window_init(TfwSlidingWindow *w, u32 window)
{
	w->curr_count = 0;
	w->prev_count = 0;
	w->epoch_start = 0;
	w->window = window;
}

/**
 * Update sliding window counters.
 *
 * Should be called for each new event (events).
 *
 * The window is anchored at @epoch_start and advances in fixed-size
 * steps of @window seconds.
 *
 * Update rules:
 *  - if still within the current window, increment @curr_count;
 *  - if one full window has elapsed, rotate @curr_count into
 *    @prev_count and start a new window;
 *  - if more than one window has elapsed, drop history
 *    (@prev_count = 0).
 */
static inline void
tfw_sliding_window_update(TfwSlidingWindow *w, unsigned int count)
{
	u64 now = ktime_get_seconds();
	u64 delta;

	if (unlikely(!w->epoch_start)) {
		w->epoch_start = now;
		w->curr_count = count;
		return;
	}

	delta = now - w->epoch_start;
	if (delta < w->window) {
		w->curr_count += count;
	} else if (delta < 2 * w->window) {
		w->prev_count = w->curr_count;
		w->curr_count = count;
		w->epoch_start = w->epoch_start + w->window;
	} else {
		w->prev_count = 0;
		w->curr_count = count;
		w->epoch_start = now;
	}
}

/**
 * Return approximate number of events within the sliding window.
 *
 * The value is computed using linear interpolation between the current
 * and previous windows:
 *
 *   total ~= curr_count + prev_count * (window - age) / window
 *
 * where @age is the time elapsed since @epoch_start.
 *
 * Depending on how much time has passed:
 *  - if within the current window, both @curr_count and @prev_count
 *    contribute to the result.
 *  - if exactly one window has elapsed, only the previous window
 *    contributes.
 *  - if more than one window has elapsed, the window is considered
 *    empty and 0 is returned.
 */
static inline u64
tfw_sliding_window_get_total(TfwSlidingWindow *w)
{
	u64 now = ktime_get_seconds();
	u64 age, delta;
	u64 curr, prev;

	if (unlikely(w->epoch_start == 0))
		return 0;

	delta = now - w->epoch_start;
	if (delta < w->window) {
		curr = w->curr_count;
		prev = w->prev_count;
		age = delta;
	} else if (delta < 2 * w->window) {
		curr = 0;
		prev = w->curr_count;
		age = delta - w->window;
	} else {
		return 0;
	}

	return curr + ((prev * (w->window - age)) / w->window);
}

#endif /* __LIB_SLIDING_WINDOW_H__ */