/**
 *		Tempesta FW
 *
 * Tempesta ring buffers.
 * The overall concept behind is to implement a highly efficient, lock-free
 * data transfer mechanism between the kernel and user space using per-CPU
 * ring buffers. These buffers allow each CPU to handle its own data stream
 * independently, minimizing contention and avoiding the overhead of
 * traditional system calls or copying data between kernel and user space.
 *
 * Each CPU has its own ring buffer that is memory-mapped into user space.
 * This design allows CPU-specific user-space threads to read data directly
 * from the buffer without any need for synchronization with other CPUs. It
 * reduces the complexity and overhead associated with locks or atomic
 * operations across multiple CPUs.
 *
 * The communication between the kernel and user space is lockless. The kernel
 * manages the write pointer (head), while user space manages the read pointer
 * (tail). Each side only modifies its own pointer, preventing race conditions
 * and eliminating the need for locking mechanisms.
 *
 * Since the ring buffers are memory-mapped into user space, data does not need
 * to be copied between the kernel and user space. Instead, user-space threads
 * can directly access the data in the kernel’s memory, greatly improving
 * performance by avoiding the overhead of traditional system calls and memory
 * copying.
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
#ifndef __TFW_RINGBUFFER_H__
#define __TFW_RINGBUFFER_H__

#ifdef __KERNEL__

#include <linux/mm.h>
#include <linux/fs.h>
#include "str.h"

#else /* __KERNEL__ */

#include <stdint.h>

#define u32 uint32_t
#define u64 uint64_t

#endif /* __KERNEL__ */

#define TFW_RINGBUFFER_DATA_OFFSET 4096
#define TFW_RINGBUFFER_MIN_SIZE    4096
#define TFW_RINGBUFFER_MAX_SIZE    (4096 * 4096)

typedef struct {
	u64 head;
	u64 tail;
	u32 mask;
	u32 size;
	u32 cpu;
	u32 max_cpu_num;
	char userspace_data[256];
	char __aligned(TFW_RINGBUFFER_DATA_OFFSET) data[];
} TfwRingbuffer;

#ifdef __KERNEL__

int tfw_ringbuffer_write(TfwStr **strs, unsigned int count);
int tfw_ringbuffer_file_open(struct inode *ino, struct file *filp);
int tfw_ringbuffer_file_close(struct inode *ino, struct file *filp);
int tfw_ringbuffer_file_mmap(struct file *filp, struct vm_area_struct *vma);
void tfw_ringbuffer_test_set_unmapped(int unmapped);
int tfw_ringbuffer_test_read(char *data, u32 size);
int tfw_ringbuffer_init(unsigned int size);
void tfw_ringbuffer_cleanup(void);

#endif /* __KERNEL__ */

#endif /* __TFW_RINGBUFFER_H__ */
