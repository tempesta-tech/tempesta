/**
 *		Tempesta FW
 *
 * MPSC queue on lock-free ring buffer. Read design description for more
 * complicated MPMC case at http://www.linuxjournal.com/content/lock-free- \
 * multi-producer-multi-consumer-queue-ring-buffer .
 *
 * Copyright (C) 2016-2025 Tempesta Technologies, Inc.
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
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include "work_queue.h"

int
tfw_wq_init(TfwRBQueue *q, size_t qsize, int node)
{
	if (!is_power_of_2(qsize)) {
		pr_err("Tempesta FW: work_queue size (%zu) must be a power of 2.\n", qsize);
		return -EINVAL;
	}
	q->qsize = qsize;
	atomic64_set(&q->head, 0);
	atomic64_set(&q->tail, 0);
	set_bit(TFW_QUEUE_IPI, &q->flags);

	/* Fallback to vmalloc for large queue sizes (> 128k items) */
	q->array = kvmalloc_node(qsize * WQ_ITEM_SZ, GFP_KERNEL, node);
	if (!q->array) {
		return -ENOMEM;
	}

	return 0;
}

void
tfw_wq_destroy(TfwRBQueue *q)
{
	/* Ensure that there is no pending work. */
	WARN_ON_ONCE(tfw_wq_size(q));

	kvfree(q->array);
}

/**
 * If there is no space in the queue, then current head value is returned
 * to be used as a ticket for trunstilie synchronization. Since we have QSZ
 * free slots, then the ticket value is always greater than 0.
 */
long
__tfw_wq_push(TfwRBQueue *q, void *ptr)
{
	long head, tail;
	int budget = 10;

	/*
	 * Producers can run on the same CPU (softirq and user space process),
	 * so they will write to the same q->thr_pos[cpu_id].
	 * This way we have to disable preemtion.
	 */
	local_bh_disable();

	for (head = atomic64_read(&q->head); ; head = atomic64_read(&q->head)) {
		tail = atomic64_read(&q->tail);

		/* Check if the queue is full */
		if (unlikely(head >= tail + q->qsize)) {
			if (head == tail + q->qsize) {
				/* Allow a small budget for transient fullness */
				if (--budget) {
					cpu_relax();
					continue;
				}
				goto full_out;
			}

			WARN_ONCE(head > tail + q->qsize, "Work queue head ahead of tail + size");
			cpu_relax();
			continue;
		}

		if (atomic64_cmpxchg(&q->head, head, head + 1) == head)
			break;
		cpu_relax();
	}

	memcpy(&q->array[head & (q->qsize - 1)], ptr, WQ_ITEM_SZ);
	wmb();

	head = 0;
full_out:
	local_bh_enable();
	return head;
}

/**
 * Sets tail value to be compared with current turnstile ticket, so
 * @ticket is the identifier of currently successfully pop()'ed item or an item
 * to be pop()'ed next time.
 */
int
tfw_wq_pop_ticket(TfwRBQueue *q, void *buf, long *ticket)
{
	int r = -EBUSY;
	long tail, head;

	local_bh_disable();

	tail = atomic64_read(&q->tail);
	head = atomic64_read(&q->head);

	/* Check if the queue is empty */
	if (unlikely(tail >= head)) {
		goto out;
	}

	memcpy(buf, &q->array[tail & (q->qsize - 1)], WQ_ITEM_SZ);
	mb();

	/*
	 * Since only one CPU writes @tail, then use faster atomic write
	 * instead of increment.
	 */
	atomic64_set(&q->tail, tail + 1);
	r = 0;
out:
	local_bh_enable();
	if (ticket)
		*ticket = tail;
	return r;
}
