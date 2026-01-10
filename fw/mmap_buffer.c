/**
 *		Tempesta FW
 *
 * Copyright (C) 2024-2026 Tempesta Technologies, Inc.
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
	unsigned long size, area_size, user_addr;
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

	if (vm_insert_page(vma, vma->vm_start, holder->mem[cpu_id][0]))
		return -EAGAIN;

	if (area_size == FULL_SIZE) { /* entire buffer is mapping */
		user_addr = vma->vm_start + TFW_MMAP_BUFFER_DATA_OFFSET;
		for (i = 0; i < 2; ++i) {
			unsigned long nr_pages = (buf->size >> PAGE_SHIFT);
			if (vm_insert_pages(vma, user_addr,
					    holder->mem[cpu_id] + 1,
					    &nr_pages)) {
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

/* Modified version of vm_area_alloc_pages(). */
static unsigned int
tfw_mmap_buffer_alloc_pages(gfp_t gfp, int nid, unsigned int order,
			    unsigned int nr_pages, struct page **pages,
			    unsigned int nr_allocated)
{
	struct page *page;
	int i;

	/*
	 * For order-0 pages we make use of bulk allocator, if
	 * the page array is partly or not at all populated due
	 * to fails, fallback to a single page allocator that is
	 * more permissive.
	 */
	if (!order) {
		while (nr_allocated < nr_pages) {
			unsigned int nr, nr_pages_request;

			/*
			 * A maximum allowed request is hard-coded and is 100
			 * pages per call. That is done in order to prevent a
			 * long preemption off scenario in the bulk-allocator
			 * so the range is [1:100].
			 */
			nr_pages_request = min(100U, nr_pages - nr_allocated);

			nr = alloc_pages_bulk_array_node(gfp, nid,
							 nr_pages_request,
							 pages + nr_allocated);

			nr_allocated += nr;
			cond_resched();

			/*
			 * If zero or pages were obtained partly,
			 * fallback to a single page allocator.
			 */
			if (nr != nr_pages_request)
				break;
		}
	}

	/* High-order pages or fallback path if "bulk" fails. */
	while (nr_allocated < nr_pages) {
		if (!(gfp & __GFP_NOFAIL) && fatal_signal_pending(current))
			break;

		page = alloc_pages_node(nid, gfp, order);

		if (unlikely(!page))
			break;

		/*
		 * High-order allocations must be able to be treated as
		 * independent small pages by callers (as they can with
		 * small-page vmallocs). Some drivers do their own refcounting
		 * on vmalloc_to_page() pages, some use page->mapping,
		 * page->lru, etc.
		 */
		if (order)
			split_page(page, order);

		/*
		 * Careful, we allocate and map page-order pages, but
		 * tracking is done per PAGE_SIZE page so as to keep the
		 * vm_struct APIs independent of the physical/mapped size.
		 */
		for (i = 0; i < (1U << order); i++)
			pages[nr_allocated + i] = page + i;

		cond_resched();
		nr_allocated += 1U << order;
	}

	return nr_allocated;
}

static void
tfw_mmap_buffer_free_pages(struct page **pages, unsigned int nr_pages)
{
	if (!pages)
		return;

	for (int i = 0; i < nr_pages; i++)
		__free_page(pages[i]);
	vfree(pages);
}

/**
 * Allocate complete buffer including metadata page and array that contains
 * all those pages.
 *
 * Allocates enough pages for the buffer plus one metadata page, also
 * alocates array that contains all allocated pages. The size of this array
 * is *double* count of all pages excluding metadata page, the first half
 * of the array contains allocated pages. The second half is just *copy*
 * of the first part. Do copy because each our buffer is mapped twice
 * in memory. Returns array ready for vmap. The first page in the resulted
 * array is metadat page, the rest are data pages. @array_size is the *total*
 * size of the resulted array.
 *
 * At first try to allocate high-order pages, then rollback to per-page
 * allocation.
 */
static struct page **
tfw_mmap_buffer_alloc(int nid, unsigned int size, unsigned int *array_size)
{
	unsigned int nr_allocated = 0, shift = PAGE_SHIFT, order;
	const unsigned int head_offset = 1;
	const unsigned int nr_need_pages = size >> PAGE_SHIFT;
	const unsigned int pages_array_size = nr_need_pages * 2 + head_offset;
	struct page **pages = vmalloc(pages_array_size * sizeof(struct page *));
	struct page *head_page;

	if (unlikely(!pages))
		return NULL;

	if (size >= PMD_SIZE)
		shift = PMD_SHIFT;
	order = shift - PAGE_SHIFT;

	/* Allocate metadata page. */
	head_page = alloc_pages_node(nid, GFP_KERNEL, 0);
	if (unlikely(!head_page)) {
		vfree(pages);
		return NULL;
	}
	pages[0] = head_page;

again:
	/* Use __GFP_NORETRY to not trigger OOM killer on failure. */
	nr_allocated = tfw_mmap_buffer_alloc_pages(GFP_KERNEL | __GFP_NORETRY,
						   nid, order,
						   nr_need_pages,
						   pages + head_offset,
						   nr_allocated);
	/* First try high order allocation and then fallback to per page. */
	if (nr_allocated != nr_need_pages) {
		if (order > 0) {
			order = 0;
			goto again;
		}

		tfw_mmap_buffer_free_pages(pages, nr_allocated);
		return NULL;
	}

	memcpy_fast(pages + nr_allocated + head_offset, pages + head_offset,
		    nr_need_pages * sizeof(struct page *));
	*array_size = pages_array_size;
	return pages;
}

TfwMmapBufferHolder *
tfw_mmap_buffer_create(const char *filename, unsigned int size)
{
	TfwMmapBufferHolder *holder;
	unsigned int page_cnt;
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
			     sizeof(struct page *) * num_online_cpus(),
			     GFP_KERNEL);
	if (!holder)
		return NULL;

	holder->dev_major = -1;
	holder->size = size;
	holder->buf = (TfwMmapBuffer **)alloc_percpu_gfp(sizeof(TfwMmapBuffer *),
							 GFP_KERNEL);
	if (!holder->buf)
		goto err;

	atomic_set(&holder->dev_is_opened, 0);
	atomic_set(&holder->is_freeing, 0);

	for_each_online_cpu(cpu) {
		TfwMmapBuffer *buf, **bufp;
		struct page **page_ptr = NULL;

		page_ptr = tfw_mmap_buffer_alloc(cpu_to_node(cpu), size,
						 &page_cnt);
		if (unlikely(!page_ptr)) {
			T_ERR("Can't allocate mmap_buffer with size %u.", size);
			goto err;
		}

		buf = vmap(page_ptr, page_cnt, VM_MAP, PAGE_KERNEL);
		if (!buf) {
			tfw_mmap_buffer_free_pages(page_ptr, page_cnt);
			goto err;
		}

		holder->mem[cpu] = page_ptr;

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

		if (!buf)
			continue;

		/* Num data pages + one metada page. */
		unsigned int nr_pages = (buf->size >> PAGE_SHIFT) + 1;

		vunmap(buf);
		tfw_mmap_buffer_free_pages(holder->mem[cpu], nr_pages);
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
