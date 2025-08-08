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

#include "mmap_buffer.hh"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <pthread.h>
#include <sched.h>

#include <cassert>
#include <chrono>
#include <cstring>
#include <thread>

#include "error.hh"

constexpr std::chrono::milliseconds wait_for_readyness(10);

namespace {

uint32_t
get_buffer_size(const int fd)
{
	void *buf = mmap(NULL, TFW_MMAP_BUFFER_DATA_OFFSET,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		throw Except("Failed to get buffers info");

	const uint32_t size = static_cast<const TfwMmapBuffer *>(buf)->size;

	munmap(buf, TFW_MMAP_BUFFER_DATA_OFFSET);

	return size;
}

} // namespace

TfwMmapBufferReader::TfwMmapBufferReader(unsigned int ncpu, int fd, Callback cb)
    : buf_(nullptr), size_(get_buffer_size(fd)), is_running_(false),
      callback_(std::move(cb))
{
	const size_t len = TFW_MMAP_BUFFER_FULL_SIZE(size_);
	const __off_t offset = static_cast<__off_t>(len) * ncpu;

	buf_ = static_cast<TfwMmapBuffer *>(
		mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset));
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
	while (true) {
		if (stop_flag->load(std::memory_order_acquire)) [[unlikely]] {
			__atomic_store_n(&buf_->is_ready, 0, __ATOMIC_RELEASE);
			break;
		}

		if (__atomic_load_n(&buf_->is_ready, __ATOMIC_ACQUIRE)) [[likely]] {
			is_running_ = true;
			if (read())
				continue;
		} else {
			if (is_running_) {
				is_running_ = false;
				break;
			}
		}

		std::this_thread::sleep_for(wait_for_readyness);
	}

}

unsigned int
TfwMmapBufferReader::get_cpu_id() const noexcept
{
	return buf_->cpu;
}

bool
TfwMmapBufferReader::read()
{
	const auto head = __atomic_load_n(&buf_->head, __ATOMIC_ACQUIRE);
	const auto tail = buf_->tail;

	const char *data = buf_->data + (tail & buf_->mask);
	const uint64_t size = head - tail;
	callback_(std::span<const char>(data, size));

	__atomic_store_n(&buf_->tail, head, __ATOMIC_RELEASE);

	return static_cast<bool>(size);
}
