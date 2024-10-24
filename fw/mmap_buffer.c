/**
 *		Tempesta FW
 *
 * Handling ring buffers is_ready to user space.
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

#include "mmap_buffer.h"
#include "lib/str.h"
#include <linux/types.h>
#include <linux/log2.h>
#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/io.h>
#include <asm/page.h>

/*
 * We can't pass TfwMmapBufferHolder pointer to the file operations handlers.
 * Let's store these pointers, and find them by filenames in the open handler.
 */
#define MAX_HOLDERS 4
static TfwMmapBufferHolder *holders[MAX_HOLDERS];
static int holders_cnt;

static int dev_file_open(struct inode *ino, struct file *filp);
static int dev_file_close(struct inode *ino, struct file *filp);
static int dev_file_mmap(struct file *filp, struct vm_area_struct *vma);
static void dev_file_vm_close(struct vm_area_struct *vma);

static const struct file_operations dev_fops = {
	.open  = dev_file_open,
	.release  = dev_file_close,
	.mmap  = dev_file_mmap,
};

static const struct vm_operations_struct dev_vm_ops = {
	.close = dev_file_vm_close
};

void
tfw_mmap_buffer_get_room(TfwMmapBufferHolder *holder,
						 char **part1, unsigned int *size1,
						 char **part2, unsigned int *size2)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);
	u64 head, tail;

	*size2 = 0;

	if (!atomic_read(&buf->is_ready)) {
		*size1 = 0;
		return;
	}

	head = buf->head % buf->size;
	tail = smp_load_acquire(&buf->tail) % buf->size;

	*part1 = buf->data + head;

	if (head < tail) {
		*size1 = tail - head - 1;
		return;
	}

	if (unlikely(head == 0)) {
		*size1 = buf->size - 1;
	} else {
		*size1 = buf->size - head;
		*part2 = buf->data;
		*size2 = tail - 1;
	}
}

void
tfw_mmap_buffer_commit(TfwMmapBufferHolder *holder, unsigned int size)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);

	smp_store_release(&buf->head, buf->head + size);
}

static int
dev_file_open(struct inode *ino, struct file *filp)
{
	TfwMmapBufferHolder *holder;
	int i;

	for (i = 0; i < holders_cnt; ++i) {
		if (strcmp(holders[i]->dev_name, (char *)filp->f_path.dentry->d_iname) == 0) {
			holder = holders[i];
			goto found;
		}
	}

	return -EINVAL;

found:
	if (atomic_read(&holder->is_freeing))
		return -ENOENT;
	if (atomic_read(&holder->dev_is_opened))
		return -EBUSY;

	atomic_set(&holder->dev_is_opened, 1);
	filp->private_data = holder;

	return 0;
}

static int
dev_file_close(struct inode *ino, struct file *filp)
{
	TfwMmapBufferHolder *holder = filp->private_data;

	atomic_set(&holder->dev_is_opened, 0);
	return 0;
}

/*
 * This function handles the mapping of ring buffers into user space. Each
 * buffer should be mapped by user space with an offset calculated as
 * full_buffer_size * cpu_num, where full_buffer_size is the size of buffer data
 * plus TFW_MMAP_BUFFER_DATA_OFFSET; cpu_num is a number of CPU in a row. This
 * allows determining which CPU's buffer should be mapped based on the offset.
 */
static int
dev_file_mmap(struct file *filp, struct vm_area_struct *vma)
{
	TfwMmapBufferHolder *holder = filp->private_data;
	TfwMmapBuffer *buf, *this_buf = *this_cpu_ptr(holder->buf);
	unsigned long pfn, size, buf_size, buf_pages;
	int cpu_num, cpu_id;

	buf_size = TFW_MMAP_BUFFER_FULL_SIZE(this_buf->size);
	size = vma->vm_end - vma->vm_start;
	if (size > buf_size)
		return -EINVAL;

	buf_pages = buf_size / PAGE_SIZE;

#define NTH_ONLINE_CPU(n) ({ \
	int cpu, res = -1, i = 0; \
	for_each_online_cpu(cpu) { \
		if (i == n) { \
			res = cpu; \
			break; \
		} \
		++i; \
	} \
	res; \
})

	cpu_num = vma->vm_pgoff / buf_pages;
	cpu_id = NTH_ONLINE_CPU(cpu_num);
	if (cpu_id < 0)
		return -EINVAL;

	buf = *per_cpu_ptr(holder->buf, cpu_id);
	pfn = page_to_pfn(virt_to_page(buf));

	if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot))
		return -EAGAIN;

	vma->vm_ops = &dev_vm_ops;
	(void)dev_vm_ops;

	if (size == buf_size)
		atomic_set(&buf->is_ready, 1);

	return 0;

#undef NTH_ONLINE_CPU
}

static void dev_file_vm_close(struct vm_area_struct *vma)
{
	TfwMmapBufferHolder *holder = vma->vm_file->private_data;
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);

	atomic_set(&buf->is_ready, 0);
}

TfwMmapBufferHolder *
tfw_mmap_buffer_create(const char *filename, unsigned int size)
{
	TfwMmapBufferHolder *holder;
	unsigned int order;
	int cpu;

	if (size < TFW_MMAP_BUFFER_MIN_SIZE
		|| size > TFW_MMAP_BUFFER_MAX_SIZE
		|| !is_power_of_2(size))
		return NULL;

	if (filename && strlen(filename) >= TFW_MMAP_BUFFER_MAX_NAME_LEN - 1)
		return NULL;

	holder = kmalloc(sizeof(TfwMmapBufferHolder) +
					 sizeof(struct page *) * num_online_cpus(),
					 GFP_KERNEL);
	if (!holder)
		return NULL;

	order = get_order(size);

	holder->dev_major = -1;
	holder->buf = (TfwMmapBuffer **)alloc_percpu_gfp(sizeof(TfwMmapBuffer *),
													 GFP_KERNEL);
	atomic_set(&holder->dev_is_opened, 0);
	atomic_set(&holder->is_freeing, 0);

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf, **bufp;

		holder->pg[cpu] = alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL, order);
		if (holder->pg[cpu] == NULL)
			goto err;

		buf = (TfwMmapBuffer *)page_address(holder->pg[cpu]);
		buf->size = TFW_MMAP_BUFFER_DATA_SIZE(size);
		buf->head = 0;
		buf->tail = 0;
		buf->cpu = cpu;
		bufp = per_cpu_ptr(holder->buf, cpu);
		*bufp = buf;
		atomic_set(&buf->is_ready, 0);
	}

	if (filename) { /* do not create the file in unit tests */
		holder->dev_major = register_chrdev(0, filename, &dev_fops);
		if (holder->dev_major < 0) {
			T_WARN("Registering char device failed for %s\n", filename);
			goto err;
		}

		holder->dev_class = class_create(THIS_MODULE, filename);
		device_create(holder->dev_class, NULL,
					  MKDEV(holder->dev_major, 0), NULL, filename);
		strscpy(holder->dev_name, filename, sizeof(holder->dev_name));
		holders[holders_cnt++] = holder;
	}

	return holder;

err:
	tfw_mmap_buffer_free(holder);

	return NULL;
}

void
tfw_mmap_buffer_free(TfwMmapBufferHolder *holder)
{
	int cpu;

	if (!holder)
		return;

	atomic_set(&holder->is_freeing, 1);

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf = *per_cpu_ptr(holder->buf, cpu);
		/* Notify user space that it have to close the file */
		atomic_set(&buf->is_ready, 0);
	}

	/* Wait till user space closes the file */
	while (atomic_read(&holder->dev_is_opened))
		schedule();

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf = *per_cpu_ptr(holder->buf, cpu);

		if (holder->pg[cpu]) {
			__free_pages(holder->pg[cpu],
						 get_order(TFW_MMAP_BUFFER_FULL_SIZE(buf->size)));
			holder->pg[cpu] = NULL;
		}
	}

	if (holder->dev_major > 0) {
		device_destroy(holder->dev_class, MKDEV(holder->dev_major, 0));
		class_destroy(holder->dev_class);
		unregister_chrdev(holder->dev_major, holder->dev_name);
	}

	kfree(holder);
}
