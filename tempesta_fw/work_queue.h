/**
 *		Tempesta FW
 *
 * Copyright (C) 2016-2017 Tempesta Technologies, Inc.
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

#include <linux/interrupt.h>
#include <linux/irq_work.h>

#include "log.h"

typedef struct {
	long			_[4];
} __WqItem;

#define WQ_ITEM_SZ		sizeof(__WqItem)
#define TFW_WQ_CHECKSZ(t)	BUILD_BUG_ON(sizeof(t) != WQ_ITEM_SZ)

typedef struct __ThrPos {
	atomic64_t		tail, head;
} __ThrPos;

typedef struct {
	__ThrPos __percpu	*thr_pos;
	__WqItem		*array;
	atomic64_t		head ____cacheline_aligned;
	atomic64_t		tail ____cacheline_aligned;
	atomic64_t		last_head ____cacheline_aligned;
	atomic64_t		last_tail ____cacheline_aligned;
} TfwRBQueue;

int tfw_wq_init(TfwRBQueue *wq, int node);
void tfw_wq_destroy(TfwRBQueue *wq);
int __tfw_wq_push(TfwRBQueue *wq, void *ptr, bool sync);
int tfw_wq_pop(TfwRBQueue *wq, void *buf);

static inline int
tfw_wq_push(TfwRBQueue *q, void *ptr, int cpu, struct irq_work *work,
	    void (*local_cpu_cb)(struct irq_work *), bool sync)
{
	int r = __tfw_wq_push(q, ptr, sync);
	if (unlikely(r))
		return r;

	if (smp_processor_id() != cpu)
		irq_work_queue_on(work, cpu);
	else
		local_cpu_cb(work);

	return 0;
}

static inline int
tfw_wq_size(TfwRBQueue *q)
{
	long long t = atomic64_read(&q->tail);
	long long h = atomic64_read(&q->head);

	return t > h ? 0 : h - t;
}

#endif /* __TFW_WORK_QUEUE_H__ */
