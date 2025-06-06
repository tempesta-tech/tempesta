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
		T_ERR("Work queue size must be a power of 2, got %zu\n", qsize);
		return -EINVAL;
	}

	q->qsize = qsize;
	atomic64_set(&q->head, 0);
	q->tail = 0;
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
 * Push an item to the queue.
 * If there is no space in the queue, then a positive value is returned
 * to be used as a ticket for trunstilie synchronization. Since we have QSZ
 * free slots, then the ticket value is always greater than 0.
 */
long
__tfw_wq_push(TfwRBQueue *q, void *ptr)
{
	long head, tail;
	int retries = 0;
	const int max_retries = 10;

	/*
	 * Multiple producers can run on the same CPU (softirq and user space
	 * process), so we need to disable preemption.
	 */
	local_bh_disable();

	do {
		head = atomic64_read(&q->head);
		tail = READ_ONCE(q->tail);  /* Single consumer, no atomic needed */

		/* Check if queue is full */
		if (unlikely(head - tail >= q->qsize)) {
			/*
			 * Small retry budget to handle transient fullness
			 * (consumer might be processing right now)
			 */
			if (++retries <= max_retries) {
				cpu_relax();
				continue;
			}
			local_bh_enable();
			return head - tail;  /* Return positive value for turnstile */
		}

		/*
		 * There is an empty slot to push a new item.
		 * Acquire the current head position and move the global head.
		 * If current head position is acquired by a competing
		 * producer, then read the current head and try again.
		 */
		if (atomic64_cmpxchg(&q->head, head, head + 1) == head)
			break;  /* Successfully reserved a slot */

		cpu_relax();
		retries = 0;  /* Reset retries on progress */
	} while (1);

	/* Copy data to the reserved slot */
	memcpy(&q->array[head & (q->qsize - 1)], ptr, WQ_ITEM_SZ);
	smp_wmb();  /* Ensure data is visible before consumer can read it */

	local_bh_enable();
	return 0;
}

/**
 * Sets tail value to be compared with current turnstile ticket, so
 * @ticket is the identifier of currently successfully pop()'ed item or an item
 * to be pop()'ed next time.
 */
int
tfw_wq_pop_ticket(TfwRBQueue *q, void *buf, long *ticket)
{
	long tail, head;

	/*
	 * Single consumer - no locking needed if called from single context.
	 * We're always called from tasklet context, so no additional
	 * synchronization is required.
	 */
	tail = q->tail;
	head = smp_load_acquire(&q->head);  /* Pairs with smp_wmb() in push */

	/* Check if queue is empty */
	if (unlikely(tail >= head))
		return -EBUSY;

	/* Read data from the queue */
	memcpy(buf, &q->array[tail & (q->qsize - 1)], WQ_ITEM_SZ);

	/*
	 * Ensure data is read before updating tail.
	 * Use smp_store_release to ensure all reads complete before
	 * the tail update is visible to producers.
	 */
	smp_store_release(&q->tail, tail + 1);

	/*
	 * Compiler barrier to ensure tail update completes before
	 * we potentially re-enable interrupts or return.
	 */
	barrier();

	if (ticket)
		*ticket = tail;

	return 0;
}
