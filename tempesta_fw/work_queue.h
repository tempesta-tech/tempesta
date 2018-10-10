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

typedef struct {
	atomic64_t __percpu	*heads;
	__WqItem		*array;
	long			last_head;
	atomic64_t		head ____cacheline_aligned;
	atomic64_t		tail ____cacheline_aligned;
	unsigned long		flags;
} TfwRBQueue;

enum {
	/* Enable IPI generation. */
	TFW_QUEUE_B_IPI = 0
};

#define TFW_WQ_IPI_SYNC(size_cb, wq)				\
do {								\
	set_bit(TFW_QUEUE_B_IPI, &(wq)->flags);			\
	smp_mb__after_atomic();					\
	if (!size_cb(wq))					\
		return;						\
	clear_bit(TFW_QUEUE_B_IPI, &(wq)->flags);		\
} while (0)

int tfw_wq_init(TfwRBQueue *wq, int node);
void tfw_wq_destroy(TfwRBQueue *wq);
long __tfw_wq_push(TfwRBQueue *wq, void *ptr);
int tfw_wq_pop_ticket(TfwRBQueue *wq, void *buf, long *ticket);

static inline int
tfw_wq_size(TfwRBQueue *q)
{
	long t = atomic64_read(&q->tail);
	long h = atomic64_read(&q->head);

	return t > h ? 0 : h - t;
}

static inline void
tfw_raise_softirq(int cpu, struct irq_work *work,
		  void (*local_cpu_cb)(struct irq_work *))
{
	if (smp_processor_id() != cpu)
		irq_work_queue_on(work, cpu);
	else
		local_cpu_cb(work);
}

static inline long
tfw_wq_push(TfwRBQueue *q, void *ptr, int cpu, struct irq_work *work,
	    void (*local_cpu_cb)(struct irq_work *))
{
	long ticket = __tfw_wq_push(q, ptr);
	if (unlikely(ticket))
		return ticket;
	/*
	 * The atomic operation is 'atomic64_cmpxchg()' in
	 * '__tfw_wq_push()' above.
	 */
	smp_mb__after_atomic();

	if (test_bit(TFW_QUEUE_B_IPI, &q->flags))
		tfw_raise_softirq(cpu, work, local_cpu_cb);

	return 0;
}

static inline int
tfw_wq_pop(TfwRBQueue *wq, void *buf)
{
	return tfw_wq_pop_ticket(wq, buf, NULL);
}

#endif /* __TFW_WORK_QUEUE_H__ */
