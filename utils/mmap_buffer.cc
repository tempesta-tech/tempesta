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
#include "error.h"

constexpr size_t WAIT_FOR_READINESS = 10; /* ms */

TfwMmapBufferReader::TfwMmapBufferReader(unsigned int ncpu, int fd,
					 void *private_data_,
					 TfwMmapBufferReadCallback cb)
{
	unsigned int area_size;

	callback_ = cb;
	is_running_ = false;
	this->private_data_ = private_data_;

	get_buffer_size(fd);

	area_size = TFW_MMAP_BUFFER_FULL_SIZE(size_);

	buf_ = (TfwMmapBuffer *)mmap(NULL, area_size, PROT_READ|PROT_WRITE,
				    MAP_SHARED, fd, area_size * ncpu);
	if (buf_ == MAP_FAILED)
		throw Except("Failed to map buffer");
}

TfwMmapBufferReader::~TfwMmapBufferReader()
{
	assert(munmap(buf_, TFW_MMAP_BUFFER_FULL_SIZE(size_)) == 0);
}

void
TfwMmapBufferReader::run(std::atomic<bool> *stop_flag)
{
	int r;

	while (1) {
		if (stop_flag->load(std::memory_order_acquire)) {
			__atomic_store_n(&buf_->is_ready, 1, __ATOMIC_RELEASE);
			break;
		}

		if (__atomic_load_n(&buf_->is_ready, __ATOMIC_ACQUIRE)) {
			is_running_ = true;
			r = read();
			if (r == 0)
				continue;
		} else {
			if (is_running_) {
				is_running_ = false;
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
	return buf_->cpu;
}

void
TfwMmapBufferReader::get_buffer_size(int fd)
{
	buf_ = (TfwMmapBuffer *)mmap(NULL, TFW_MMAP_BUFFER_DATA_OFFSET,
				    PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf_ == MAP_FAILED)
		throw Except("Failed to get buffers info");

	size_ = buf_->size;

	munmap(buf_, TFW_MMAP_BUFFER_DATA_OFFSET);
}

int
TfwMmapBufferReader::read()
{
	u64 head, tail;

	head = __atomic_load_n(&buf_->head, __ATOMIC_ACQUIRE);
	tail = buf_->tail;

	if (head - tail == 0)
		return -EAGAIN;

	callback_(buf_->data + (tail & buf_->mask), head - tail, private_data_);

	__atomic_store_n(&buf_->tail, head, __ATOMIC_RELEASE);

	return 0;
}
