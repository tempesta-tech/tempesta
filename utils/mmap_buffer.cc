/**
 *		Tempesta FW
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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>

#include "mmap_buffer.h"

constexpr size_t WAIT_FOR_READINESS = 10; /* ms */

TfwMmapBufferReader::TfwMmapBufferReader(unsigned int ncpu, int fd,
					 void *private_data,
					 TfwMmapBufferReadCallback cb)
{
	unsigned int area_size;

	callback = cb;
	is_running = false;
	this->private_data = private_data;

	get_buffer_size(fd);

	area_size = TFW_MMAP_BUFFER_FULL_SIZE(size);

	buf = (TfwMmapBuffer *)mmap(NULL, area_size, PROT_READ|PROT_WRITE,
				    MAP_SHARED, fd, area_size * ncpu);
	if (buf == MAP_FAILED)
		throw std::runtime_error("Failed to map buffer");
}

TfwMmapBufferReader::~TfwMmapBufferReader()
{
	assert(munmap(buf, TFW_MMAP_BUFFER_FULL_SIZE(size)) == 0);
}

void
TfwMmapBufferReader::run()
{
	int r;

	while (1) {
		if (__atomic_load_n(&buf->is_ready, __ATOMIC_ACQUIRE)) {
			is_running = true;
			r = read();
			if (r == 0)
				continue;
		} else {
			if (is_running) {
				is_running = false;
				break;
			}
		}

		std::this_thread::sleep_for(
			std::chrono::milliseconds(WAIT_FOR_READINESS));
	}

}

unsigned int
TfwMmapBufferReader::get_cpu_id()
{
	return buf->cpu;
}

void
TfwMmapBufferReader::get_buffer_size(int fd)
{
	buf = (TfwMmapBuffer *)mmap(NULL, TFW_MMAP_BUFFER_DATA_OFFSET,
				    PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		throw std::runtime_error("Failed to get buffers info");

	size = buf->size;

	munmap(buf, TFW_MMAP_BUFFER_DATA_OFFSET);
}

int
TfwMmapBufferReader::read()
{
	u64 head, tail;

	head = __atomic_load_n(&buf->head, __ATOMIC_ACQUIRE);
	tail = buf->tail;

	if (head - tail == 0)
		return -EAGAIN;

	callback(buf->data + (tail & buf->mask), head - tail, private_data);

	__atomic_store_n(&buf->tail, head, __ATOMIC_RELEASE);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);

	return 0;
}
