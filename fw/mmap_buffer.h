/**
 *		Tempesta FW
 *
 * Tempesta ring buffers mmaped to user space.
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
 * to be copied between the kernel and user space. Instead, user space threads
 * can directly access the data in the kernel’s memory, greatly improving
 * performance by avoiding the overhead of traditional system calls and memory
 * copying.
 *
 * The ring buffer is mapped twice in memory to create two consecutive memory
 * regions. This allows reads across the end of the buffer and the beginning of
 * the buffer as if they are one contiguous block. By doing so, we simplify
 * handling of wrap-around cases, enabling seamless reading of split segments
 * as a single continuous segment.
 *
 * Motivation for not using existing kernel ring buffers
 *
 * While the Linux kernel provides several ring buffer implementations, none of
 * them are a perfect fit for our current use case. Below is an overview of the
 * existing ring buffers, along with the reasons they were not chosen for our
 * task:
 *  * relay (relayfs):
 *      We need to handle records of varying length, which makes determining
 *      the subbuffer size inefficient. Additionally, both relay_reserve() and
 *      relay_write() require the length of data to be known in advance, which
 *      would force us to traverse the data twice. Furthermore, while relay
 *      provides a sleeping mechanism (allowing user-space to use poll()),
 *      kernel-side sleeping cannot be used in softirq context, which is a
 *      limitation for our needs.
 *
 *  * New generic ring buffer (still unmerged):
 *      This implementation also involves sleepable functions, making it
 *      incompatible with the softirq context. Moreover, it does not natively
 *      support per-CPU mode, which would require us to manually implement this
 *      functionality.
 *
 *  * perf ring buffer:
 *      This implementation also involves sleepable functions, making it
 *      incompatible with the softirq context. Also it looks hard to decouple
 *      necessary functionality from perf-specific mechanisms.
 *
 *  * io_uring:
 *      While very capable, io_uring introduces additional overhead with its SQ
 *      and CQ mechanisms, which are not needed for our simpler use case. Our
 *      goal is to minimize complexity, and io_uring adds unnecessary layers of
 *      interaction.
 *
 *  * packet_ring_buffer (used in packet mmap):
 *      This buffer is specifically optimized for page-sized network frames and
 *      is not designed for the generic transmission of smaller,
 *      variable-length records. Our use case requires handling multiple
 *      records per page, making this ring buffer inefficient.
 *
 *  * tracefs ring buffer:
 *      Like the packet_ring_buffer, this buffer is primarily designed for
 *      page-level operations.
 *
 *  * BPF ring buffer
 *      Involves sleepable functions, making it incompatible with the softirq
 *      context. Also, bpf_ringbuf_reserve() requires the length of data to be
 *      known in advance, which would force us to traverse the data twice.
 *
 * Note:  Certain functions used during the initialization and freeing of
 * mmap_buffer may sleep. It is assumed that mmap_buffer will be initialized
 * at module start and freed at module stop, so repeated initialization or
 * freeing is not expected.
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
#ifndef __TFW_MMAP_BUFFER_H__
#define __TFW_MMAP_BUFFER_H__

#ifdef __KERNEL__

#include "str.h"
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/cdev.h>

#else /* __KERNEL__ */

#include <stdint.h>

#define u32 uint32_t
#define u64 uint64_t

#endif /* __KERNEL__ */

#define TFW_MMAP_BUFFER_DATA_OFFSET	PAGE_SIZE
#define TFW_MMAP_BUFFER_MIN_SIZE	PAGE_SIZE
#define TFW_MMAP_BUFFER_MAX_SIZE	(1024 * 1024 * 128)
#define TFW_MMAP_BUFFER_DEFAULT_SIZE	TFW_MMAP_BUFFER_MIN_SIZE
#define TFW_MMAP_BUFFER_MIN_SIZE_STR	"4096"
#define TFW_MMAP_BUFFER_MAX_SIZE_STR	"128M"

#define TFW_MMAP_BUFFER_MAX_NAME_LEN 32

#define TFW_MMAP_BUFFER_FULL_SIZE(size) (TFW_MMAP_BUFFER_DATA_OFFSET + size * 2)

/**
 * @head	- Head offset where the next data write will happen;
 * @tail	- tail offset where the next data read will happen;
 * @size	- size of the ring buffer data in bytes;
 * @mask	- limits head and tail to the buffer size (a power of two), replacing
 *		  mod for faster indexing;
 * @cpu		- ID of the CPU tied to this buffer;
 * @is_ready	- indicates that the buffer is mapped to user space and ready
 *		  both for writing and reading. Resetting this field signals to
 *		  user space that it should stop reading, unmap and close the file;
 * @data	- points to the data start.
 */
typedef struct {
	u64		head;
	u64		tail;
	u32		size;
	u32		mask;
	u32		cpu;
#ifdef __KERNEL__
	atomic_t	is_ready;
#else
	int		is_ready;
#endif
	char __attribute__((aligned(TFW_MMAP_BUFFER_DATA_OFFSET))) data[];
} TfwMmapBuffer;

#ifdef __KERNEL__

/**
 * @buf			- Per CPU pointers to store pointers to buffers;
 * @dev_name		- name of the device in /dev;
 * @size		- size of the memory allocated to every buffer;
 * @dev_is_opened	- indicates that the device is opened bu user space;
 * @is_freeing		- indicates that freeing process started, It's
 *			  necessary to exclude repeated file opening;
 * @dev			- device structure of the device in /dev;
 * @dev_major		- the major number of the device in /dev;
 * @dev_class		- the class of the device;
 * @mem			- array of allocated pages. The first page is metada
 *                        page the rest are data pages.
 */
typedef struct {
	TfwMmapBuffer __percpu	**buf;
	char			dev_name[TFW_MMAP_BUFFER_MAX_NAME_LEN];
	unsigned int		size;
	atomic_t		dev_is_opened;
	atomic_t		is_freeing;
	struct device		*dev;
	int			dev_major;
	struct class		*dev_class;
	DECLARE_FLEX_ARRAY(struct page **, mem);
} TfwMmapBufferHolder;

/*
 * The function 'tfw_mmap_buffer_get_room()' returns the size of the memory
 * region available for writing. Internal state of the buffer (i.e., head or
 * tail positions) is not modified at this time. As a result, the writing
 * process can be interrupted at any time, and this function can be called
 * again to request space for another element without affecting previous calls.
 *
 * Once the data has been successfully written, 'tfw_mmap_buffer_commit()' must
 * be called, passing the actual size of the written data. This function
 * updates the buffer's internal state to reflect the new data and make the
 * written space unavailable for further writing.
 */
static __always_inline unsigned int
tfw_mmap_buffer_get_room(TfwMmapBufferHolder *holder, char **data)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);

	*data = buf->data + (buf->head & buf->mask);

	return buf->size - (buf->head - smp_load_acquire(&buf->tail)) - 1;
}

static __always_inline int
tfw_mmap_buffer_commit(TfwMmapBufferHolder *holder, unsigned int size)
{
	TfwMmapBuffer *buf = *this_cpu_ptr(holder->buf);
	u64 tail;

	tail = smp_load_acquire(&buf->tail);
	if (unlikely(buf->head + size - tail >= buf->size - 1))
		return -ENOMEM;

	smp_store_release(&buf->head, buf->head + size);

	return 0;
}

TfwMmapBufferHolder *tfw_mmap_buffer_create(const char *filename,
					    unsigned int size);
void tfw_mmap_buffer_free(TfwMmapBufferHolder *holder);

#endif /* __KERNEL__ */

#endif /* __TFW_MMAP_BUFFER_H__ */
