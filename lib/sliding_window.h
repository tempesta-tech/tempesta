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

typedef struct {
	u64 curr_count;
	u64 prev_count;
	u64 epoch;
} TfwSlidingWindow;

static inline void
tfw_sliding_window_update(TfwSlidingWindow *w, u64 window_secs,
			  unsigned int count)
{
	u64 now = ktime_get_seconds();
	u64 curr_epoch = now / window_secs;
	u64 delta;

	if (unlikely(!w->epoch)) {
		w->epoch = curr_epoch;
		w->curr_count = count;
		return;
	}

	delta = curr_epoch - w->epoch;
	if (!delta) {
		w->curr_count += count;
		return;
	}

	w->prev_count = (delta == 1 ? w->curr_count : 0);
	w->curr_count = count;
	w->epoch = curr_epoch;
}

static inline u64
tfw_sliding_window_get_total(TfwSlidingWindow *w, u64 window_secs)
{
	u64 now = ktime_get_seconds();
	u64 curr_epoch = now / window_secs;
	u64 age, delta;
	u64 curr, prev;

	if (unlikely(w->epoch == 0))
		return 0;

	delta = curr_epoch - w->epoch;
	if (delta == 0) {
		curr = w->curr_count;
		prev = w->prev_count;
	} else if (delta == 1) {
		curr = 0;
		prev = w->curr_count;
	} else {
		return 0;
	}
	age = now % window_secs;

	return curr + prev * (window_secs - age) / window_secs;
}

#endif /* __LIB_SLIDING_WINDOW_H__ */