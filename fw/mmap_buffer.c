/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2025 Tempesta Technologies, Inc.
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
#include <asm/page.h>
#include <linux/types.h>
#include <linux/log2.h>
#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/vmalloc.h>

#include "mmap_buffer.h"
#include "lib/str.h"
#include "lib/fault_injection_alloc.h"

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

static int
dev_file_open(struct inode *ino, struct file *filp)
{
	TfwMmapBufferHolder *holder;
	int i;

	for (i = 0; i < holders_cnt; ++i) {
		if (strcmp(holders[i]->dev_name,
			   (char *)filp->f_path.dentry->d_iname) == 0) {
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
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);
	unsigned long pfn, size, area_size, user_addr;
	int cpu_num, cpu_id, i;

	size = vma->vm_end - vma->vm_start;

#define FULL_SIZE TFW_MMAP_BUFFER_FULL_SIZE(buf->size)

	if (size == TFW_MMAP_BUFFER_DATA_OFFSET)
		area_size = size;
	else if (size == FULL_SIZE)
		area_size = FULL_SIZE;
	else
		return -EINVAL;

#define NTH_ONLINE_CPU(n) ({		\
	int cpu, res = -1, i = 0;	\
	for_each_online_cpu(cpu) {	\
		if (i == n) {		\
			res = cpu;	\
			break;		\
		}			\
		++i;			\
	}				\
	res;				\
})

	cpu_num = vma->vm_pgoff / (area_size / PAGE_SIZE);
	cpu_id = NTH_ONLINE_CPU(cpu_num);
	if (cpu_id < 0)
		return -EINVAL;

	buf = *per_cpu_ptr(holder->buf, cpu_id);

	pfn = page_to_pfn(holder->mem[cpu_id].buf_page);
	if (remap_pfn_range(vma, vma->vm_start, pfn,
			    TFW_MMAP_BUFFER_DATA_OFFSET, vma->vm_page_prot))
		return -EAGAIN;

	if (area_size == FULL_SIZE) { /* entire buffer is mapping */
		pfn = page_to_pfn(holder->mem[cpu_id].data_page);
		user_addr = vma->vm_start + TFW_MMAP_BUFFER_DATA_OFFSET;
		for (i = 0; i < 2; ++i) {
			if (remap_pfn_range(vma, user_addr, pfn, buf->size,
					    vma->vm_page_prot)) {
				return -EAGAIN;
			}
			user_addr += buf->size;
		}

		vma->vm_ops = &dev_vm_ops;
		atomic_set(&buf->is_ready, 1);
	}

	return 0;

#undef NTH_ONLINE_CPU
#undef FULL_SIZE
}

static void
dev_file_vm_close(struct vm_area_struct *vma)
{
	TfwMmapBufferHolder *holder = vma->vm_file->private_data;
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);

	atomic_set(&buf->is_ready, 0);
}

TfwMmapBufferHolder *
tfw_mmap_buffer_create(const char *filename, unsigned int size)
{
	TfwMmapBufferHolder *holder;
	struct page **page_ptr = NULL;
	unsigned int order, i, page_cnt;
	int cpu;

	if (size < TFW_MMAP_BUFFER_MIN_SIZE
	    || size > TFW_MMAP_BUFFER_MAX_SIZE
	    || !is_power_of_2(size))
		return NULL;

	if (filename && strlen(filename) >= TFW_MMAP_BUFFER_MAX_NAME_LEN - 1)
		return NULL;

	if (holders_cnt + 1 > MAX_HOLDERS)
		return NULL;

	holder = tfw_kzalloc(sizeof(TfwMmapBufferHolder) +
			     sizeof(TfwMMapBufferMem) * num_online_cpus(),
			     GFP_KERNEL);
	if (!holder)
		return NULL;

	order = get_order(size);

	holder->dev_major = -1;
	holder->size = size;
	holder->buf = (TfwMmapBuffer **)alloc_percpu_gfp(sizeof(TfwMmapBuffer *),
							 GFP_KERNEL);
	if (!holder->buf)
		goto err;

	atomic_set(&holder->dev_is_opened, 0);
	atomic_set(&holder->is_freeing, 0);

	page_cnt = size / PAGE_SIZE;
	/*
	 * Allocate pages for double mapping and a page for buffer control
	 * structure.
	 */
	page_ptr = tfw_kmalloc((page_cnt * 2 + 1) * sizeof(struct page *),
			       GFP_KERNEL);
	if (!page_ptr)
		goto err;

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf, **bufp;

		holder->mem[cpu].buf_page = alloc_pages_node(cpu_to_node(cpu),
							     GFP_KERNEL, 0);
		if (holder->mem[cpu].buf_page == NULL)
			goto err;

		holder->mem[cpu].data_page = alloc_pages_node(cpu_to_node(cpu),
							      GFP_KERNEL, order);
		if (holder->mem[cpu].data_page == NULL)
			goto err;

		page_ptr[0] = holder->mem[cpu].buf_page;
		for (i = 0; i < page_cnt; ++i) {
			page_ptr[i + 1] = &holder->mem[cpu].data_page[i];
			page_ptr[i + page_cnt + 1] = &holder->mem[cpu].data_page[i];
		}

		buf = (TfwMmapBuffer *)vmap(page_ptr, page_cnt * 2 + 1, VM_MAP,
					    PAGE_KERNEL);
		if (!buf)
			goto err;

		buf->size = holder->size;
		buf->mask = holder->size - 1;
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
			T_ERR("Registering char device failed for %s\n",
			      filename);
			goto err;
		}
		holder->dev_class = class_create(filename);
		if (IS_ERR(holder->dev_class)) {
			T_ERR("Class creation failed for %s\n", filename);
			goto err;
		}
		holder->dev = device_create(holder->dev_class, NULL,
					    MKDEV(holder->dev_major, 0),
					    NULL, filename);
		if (IS_ERR(holder->dev)) {
			T_ERR("Device creation failed for %s\n", filename);
			goto err;
		}
		strscpy(holder->dev_name, filename, sizeof(holder->dev_name));
		holders[holders_cnt++] = holder;
	}

	kfree(page_ptr);

	return holder;

err:
	kfree(page_ptr);
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

	if (!holder->buf)
		goto free_holder;

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf = *per_cpu_ptr(holder->buf, cpu);
		/* Notify user space that it have to close the file */
		if (buf)
			atomic_set(&buf->is_ready, 0);
	}

	/* Wait till user space closes the file */
	while (atomic_read(&holder->dev_is_opened))
		schedule();

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf = *per_cpu_ptr(holder->buf, cpu);

		if (buf)
			vunmap(buf);

		if (holder->mem[cpu].buf_page)
			__free_pages(holder->mem[cpu].buf_page, 0);
		if (holder->mem[cpu].data_page)
			__free_pages(holder->mem[cpu].data_page,
				     get_order(holder->size));
	}

	if (!IS_ERR_OR_NULL(holder->dev))
		device_destroy(holder->dev_class, MKDEV(holder->dev_major, 0));
	if (!IS_ERR_OR_NULL(holder->dev_class))
		class_destroy(holder->dev_class);
	if (holder->dev_major > 0)
		unregister_chrdev(holder->dev_major, holder->dev_name);

	free_percpu(holder->buf);
free_holder:
	kfree(holder);
}
