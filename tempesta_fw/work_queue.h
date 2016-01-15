/**
 *		Tempesta FW
 *
 * Copyright (C) 2016 Tempesta Technologies, Inc.
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
#ifndef __TFW_WORK_QUEUE_H__
#define __TFW_WORK_QUEUE_H__

typedef struct __ThrPos {
	atomic64_t		tail, head;
} __ThrPos;

typedef struct {
	__ThrPos __percpu	*thr_pos;
	void			**array;
	atomic64_t		head ____cacheline_aligned;
	atomic64_t		tail ____cacheline_aligned;
	atomic64_t		last_head ____cacheline_aligned;
	atomic64_t		last_tail ____cacheline_aligned;
} TfwRBQueue;

int tfw_wq_si_init(TfwRBQueue *wq);
void tfw_wq_si_destroy(TfwRBQueue *wq);
int tfw_wq_si_push(TfwRBQueue *wq, void *ptr);
void *tfw_wq_si_pop(TfwRBQueue *wq);

#endif /* __TFW_WORK_QUEUE_H__ */
