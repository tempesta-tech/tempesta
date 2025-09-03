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
#include <memory>

#include <spdlog/spdlog.h>

#include "mmap_buffer.hh"
#include "error.hh"

TfwMmapBufferReader::TfwMmapBufferReader(const unsigned int ncpu, const int fd,
					 TfwClickhouse &db, ProcessEvents proc_ev)
	: buf_(nullptr), size_(0), proc_ev_(proc_ev), db_(db)
{
	unsigned int area_size;

	init_buffer_size(fd);

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

[[nodiscard]] Error<bool>
TfwMmapBufferReader::read() noexcept
{
	uint64_t head, tail;

	head = __atomic_load_n(&buf_->head, __ATOMIC_ACQUIRE);
	tail = buf_->tail;

	assert(head >= tail);
	if (head - tail == 0) [[unlikely]]
		return false;

	uint64_t size = static_cast<uint64_t>(head - tail);
	const auto start = buf_->data + (tail & buf_->mask);

	auto res = proc_ev_(std::span<const char>(start, size));
	if (res && *res) [[likely]]
		size = *res;
	// ...else consume the whole buffer in case of error.

	assert(tail + size <= head);

	// Move the RB pointer only for really processed events.
	// Events are copied to a database buffer, so we can move the RB pointer
	// before heavyweight database transaction.
	__atomic_store_n(&buf_->tail, tail + size, __ATOMIC_RELEASE);

	if (!res)
		return error(Err::DB_SRV_FATAL);

	if (*res && !db_.commit())
		return error(Err::DB_SRV_FATAL);

	return true;
}

/**
 * The main reing-buffer processing routine, controlling the Clickhouse database
 * flushed and the logger thread sleeping.
 *
 * @return false in casse of error and true otherwise.
 */
bool
TfwMmapBufferReader::run(std::atomic<bool> &stop_flag) noexcept
{
	// Read from the ring buffer in polling mode and sleep only if 10 tries
	// in a row were unsuccessful. We sleep for 1ms - theoretically we might
	// get up to 1000 records during the delya in the buffer, which is fine
	// with our defaults.
	// TODO #2442: this can be improved with true kernel sleep like perf does
	// on it's events ring buffer.
	constexpr size_t POLL_N = 10;
	constexpr std::chrono::milliseconds delay(1);

	for (size_t tries = 0; ; ) {
		const int is_ready = __atomic_load_n(&buf_->is_ready,
						     __ATOMIC_ACQUIRE);
		if (stop_flag.load(std::memory_order_acquire)) [[unlikely]] {
			// Notify the kernel that the daemong is done - now no
			// new events will be pushed to the buffer and we can
			// process the rest of the events.
			__atomic_store_n(&buf_->is_ready, 0, __ATOMIC_RELEASE);
		}

		auto res = read();
		if (!res) [[unlikely]]
			return false;

		if (*res) [[likely]] {
			tries = 0;
			continue;
		}

		if (!is_ready) {
			// The kernel notified us that we have to stop and we
			// read all the data - propage the stop flag to the main
			// thread loop and exit.
			spdlog::info("Shutdown notification from the kernel");
			stop_flag.store(true, std::memory_order_release);
			return true;
		}

		if (++tries < POLL_N) {
			// Several tries with no waiting and yielding the CPU
			// to not get penalty from the scheduler.
			std::this_thread::yield();
		}
		else if (tries == POLL_N) {
			// Flush the collected buffer to the database before
			// going to sleep:
			// 1. we have no work now, so it's a good time to do
			//    some housekeeping;
			// 2. free resources for possible spike - we likely miss
			//    events while we're flushing a full buffer;
			// 3. No need to track wait time before sync explicitly -
			//    if we have a stream of events, we flush on full
			//    buffer, once we get a real time delay, we flush to
			//    the database.
			if (!db_.commit(TfwClickhouse::FORCE))
				return false;
		}
		else if (tries > POLL_N) {
			std::this_thread::sleep_for(delay);
		}
	}

	std::unreachable();
}

unsigned int
TfwMmapBufferReader::get_cpu_id() const noexcept
{
	return buf_->cpu;
}

void
TfwMmapBufferReader::init_buffer_size(const int fd)
{
	buf_ = (TfwMmapBuffer *)mmap(NULL, TFW_MMAP_BUFFER_DATA_OFFSET,
				    PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf_ == MAP_FAILED)
		throw Except("Failed to get buffers info");

	size_ = buf_->size;

	munmap(buf_, TFW_MMAP_BUFFER_DATA_OFFSET);
}
