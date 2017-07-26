/**
 *		Tempesta FW
 *
 * MPSC queue on lock-free ring buffer. Read design description for more
 * complicated MPMC case at http://www.linuxjournal.com/content/lock-free- \
 * multi-producer-multi-consumer-queue-ring-buffer .
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
#include <linux/percpu.h>
#include <linux/slab.h>

#include "work_queue.h"

/*
 * The queue size shouldn't be too large to avoid a live lock at
 * a consumer side. Now it's twice as large as netdev budget.
 */
#define QSZ		2048
#define QMASK		(QSZ - 1)

int
tfw_wq_init(TfwRBQueue *q, int node)
{
	int cpu;

	q->heads = alloc_percpu(atomic64_t);
	if (!q->heads)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		atomic64_t *local_head = per_cpu_ptr(q->heads, cpu);
		atomic64_set(local_head, LLONG_MAX);
	}
	q->last_head = 0;
	atomic64_set(&q->head, 0);
	atomic64_set(&q->tail, 0);

	q->array = kmalloc_node(QSZ * WQ_ITEM_SZ, GFP_KERNEL, node);
	if (!q->array) {
		free_percpu(q->heads);
		return -ENOMEM;
	}

	return 0;
}

void
tfw_wq_destroy(TfwRBQueue *q)
{
	/* Ensure that there is no peding work. */
	BUG_ON(tfw_wq_size(q));

	kfree(q->array);
	free_percpu(q->heads);
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
	atomic64_t *head_local;

	/*
	 * Producers can run on the same CPU (softirq and user space process),
	 * so they will write to the same q->thr_pos[cpu_id].
	 * This way we have to disable preemtion.
	 */
	local_bh_disable();

	head_local = this_cpu_ptr(q->heads);
	while (1) {
		head = atomic64_read(&q->head);
		tail = atomic64_read(&q->tail);
		BUG_ON(head > tail + QSZ);
		if (unlikely(head == tail + QSZ))
			goto full_out;

		/*
		 * There is an empty slot to push a new item.
		 * Set a guard for current position and move global head -
		 * try to acquire current head. If current head position is
		 * acquired by a competing poroducer, then try again.
		 */
		atomic64_set(head_local, head);
		if (atomic64_cmpxchg(&q->head, head, head + 1) == head)
			break;
	}

	memcpy(&q->array[head & QMASK], ptr, WQ_ITEM_SZ);
	wmb();

	head = 0;
full_out:
	/* Now it's safe to release current head position. */
	atomic64_set(head_local, LONG_MAX);
	local_bh_enable();
	return head;
}

/**
 * Sets tail value to be compared with current turnstile ticket, so
 * @ticket is the identifier of currently successully pop()'ed item or an item
 * to be pop()'ed next time.
 */
int
tfw_wq_pop_ticket(TfwRBQueue *q, void *buf, long *ticket)
{
	int cpu, r = -EBUSY;
	long tail;

	local_bh_disable();

	tail = atomic64_read(&q->tail);
	BUG_ON(tail > q->last_head);
	if (unlikely(tail == q->last_head)) {
		/*
		 * Actualize @last_head from heads of all current
		 * producers. We do it here since atomic reads are
		 * faster than updates and we can do this only when
		 * we need a new value, i.e. not so frequently.
		 * Don't support switching off cpus in runtime.
		 */
		q->last_head = atomic64_read(&q->head);
		for_each_online_cpu(cpu) {
			atomic64_t *head_local = per_cpu_ptr(q->heads, cpu);
			long curr_h = atomic64_read(head_local);

			/* Force compiler to use curr_h only once. */
			barrier();
			if (curr_h < q->last_head)
				q->last_head = curr_h;
		}

		/* Second try. */
		BUG_ON(tail > q->last_head);
		if (tail == q->last_head)
			goto out;
	}

	memcpy(buf, &q->array[tail & QMASK], WQ_ITEM_SZ);
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
