/**
 *		Tempesta FW
 *
 * Handling ring buffers mapped to userspace.
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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

#include "ringbuffer.h"
#include "lib/str.h"
#include <linux/types.h>
#include <asm/io.h>
#include <linux/log2.h>
#include <linux/cpumask.h>

typedef struct {
	TfwRingbuffer *rb;
	struct page *pg;
	atomic_t unmapped;
} TfwRingbufferArea;

#define AREA_SIZE(size) (size + TFW_RINGBUFFER_DATA_OFFSET)
#define RBA_AREA_SIZE(rba) AREA_SIZE((rba)->rb->size)

static DEFINE_PER_CPU(TfwRingbufferArea, rb_area);
static bool proc_file_is_open;

int
tfw_ringbuffer_write(TfwStr **strs, unsigned int count)
{
	TfwRingbufferArea *rba = this_cpu_ptr(&rb_area);
	TfwRingbuffer *rb = rba->rb;
	unsigned int i;
	u64 head, tail;
	u32 full_size = 0;

	if (atomic_read(&rba->unmapped))
		return -EAGAIN;

	preempt_disable();

	head = rb->head;
	tail = smp_load_acquire(&rb->tail);

	for (i = 0; i < count; ++i)
		full_size += strs[i]->len;

	if (head - tail + full_size >= rb->size) {
		preempt_enable();
		return -ENOMEM;
	}

	for (i = 0; i < count; ++i) {
		TfwStr *c, *end;

		TFW_STR_FOR_EACH_CHUNK(c, strs[i], end) {
			char *data = c->data;
			u32 len = c->len;

			while (len) {
				u32 mhead, cur_len;

				mhead = head & rb->mask;
				cur_len = min(len, rb->size - mhead);

				memcpy_fast(rb->data + mhead, data, cur_len);
				data += cur_len;
				head += cur_len;
				len -= cur_len;
			}
		}
	}

	smp_store_release(&rb->head, head);
	smp_mb();

	preempt_enable();

	return 0;
}

int
tfw_ringbuffer_file_open(struct inode *ino, struct file *filp)
{
	if (proc_file_is_open)
		return -EBUSY;
	proc_file_is_open = true;
	return 0;
}

int
tfw_ringbuffer_file_close(struct inode *ino, struct file *filp)
{
	int cpu;
	proc_file_is_open = false;
	for_each_online_cpu(cpu) {
		TfwRingbufferArea *rba = per_cpu_ptr(&rb_area, cpu);
		atomic_set(&rba->unmapped, 1);
	}
	return 0;
}

int
tfw_ringbuffer_file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	TfwRingbufferArea *rba, *this_rba = this_cpu_ptr(&rb_area);
	unsigned long pfn, size, area_size, area_pages;
	int cpu;

	area_size = RBA_AREA_SIZE(this_rba);
	size = vma->vm_end - vma->vm_start;
	if (size > area_size)
		return -EINVAL;

	area_pages = area_size / PAGE_SIZE;

	cpu = vma->vm_pgoff / area_pages;
	if (cpu >= num_online_cpus())
		return -EINVAL;

	rba = per_cpu_ptr(&rb_area, cpu);
	pfn = page_to_pfn(rba->pg);

	if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot))
		return -EAGAIN;

	if (size == area_size)
		atomic_set(&rba->unmapped, 0);

	return 0;
}

void
tfw_ringbuffer_test_set_unmapped(int unmapped)
{
	int cpu;
	for_each_online_cpu(cpu) {
		TfwRingbufferArea *rba = per_cpu_ptr(&rb_area, cpu);
		atomic_set(&rba->unmapped, unmapped);
	}
}

int
tfw_ringbuffer_test_read(char *data, u32 size)
{
	u32 head, tail;
	int cpu;

	for_each_online_cpu(cpu) {
		TfwRingbufferArea *rba = per_cpu_ptr(&rb_area, cpu);
		TfwRingbuffer *rb = rba->rb;
		u32 size_for_cpu;

		head = smp_load_acquire(&rb->head);
		tail = rb->tail;

		size_for_cpu = min(size, head - tail);
		size -= size_for_cpu;

		while (size_for_cpu) {
			u32 mtail, cur_size;

			mtail = tail & rb->mask;

			cur_size = min(size_for_cpu, rb->size - mtail);
			memcpy_fast(data, rb->data + mtail, size_for_cpu);
			data += cur_size;
			tail += cur_size;
			size_for_cpu -= cur_size;
		}

		smp_store_release(&rb->tail, tail);
		smp_mb();
	}

	return size;
}

int
tfw_ringbuffer_init(unsigned int size)
{
	int cpu, res;
	unsigned int order;

	if (size < TFW_RINGBUFFER_MIN_SIZE
		|| size > TFW_RINGBUFFER_MAX_SIZE
		|| !is_power_of_2(size))
		return -EINVAL;

	order = get_order(AREA_SIZE(size));

	for_each_online_cpu(cpu) {
		TfwRingbufferArea *rba = per_cpu_ptr(&rb_area, cpu);

		rba->pg = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, order);
		if (rba->pg == NULL) {
			res = -ENOMEM;
			goto err;
		}

		rba->rb = (TfwRingbuffer *)page_address(rba->pg);

		rba->rb->size = size;
		rba->rb->mask = size - 1;
		rba->rb->head = 0;
		rba->rb->tail = 0;
		rba->rb->cpu = cpu;
		rba->rb->max_cpu_num = num_online_cpus();

		atomic_set(&rba->unmapped, 1);
	}

	return 0;

err:
	tfw_ringbuffer_cleanup();

	return res;
}

void
tfw_ringbuffer_cleanup(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		TfwRingbufferArea *rba = per_cpu_ptr(&rb_area, cpu);
		atomic_set(&rba->unmapped, 1);
		if (rba->pg) {
			__free_pages(rba->pg, get_order(RBA_AREA_SIZE(rba)));
			rba->pg = NULL;
		}
	}
}
