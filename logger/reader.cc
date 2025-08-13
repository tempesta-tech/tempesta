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

#include "reader.hh"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <pthread.h>
#include <sched.h>

#include <cassert>
#include <chrono>
#include <thread>

#include <spdlog/spdlog.h>

#include "parser.hh"
#include "signal_handler.hh"

namespace {

uint32_t
get_buffer_size(const int fd)
{
	void *buf = mmap(NULL, TFW_MMAP_BUFFER_DATA_OFFSET,
			 PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		throw std::runtime_error("Failed to get buffer size");

	const uint32_t size = static_cast<const TfwMmapBuffer *>(buf)->size;

	munmap(buf, TFW_MMAP_BUFFER_DATA_OFFSET);

	return size;
}

} // namespace

Reader::Reader(unsigned int ncpu, int fd, Sender sender)
    : ncpu_(ncpu), buf_(nullptr), size_(get_buffer_size(fd)),
      waiting_for_readyness_(true), sender_(std::move(sender))
{
	const size_t len = TFW_MMAP_BUFFER_FULL_SIZE(size_);
	const __off_t offset = static_cast<__off_t>(len) * ncpu;

	buf_ = static_cast<TfwMmapBuffer *>(
		mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset));
	if (buf_ == MAP_FAILED)
		throw std::runtime_error("Failed to map buffer");

	spdlog::debug("Reader {} mapped buffer at offset {} with size {}",
		      ncpu, offset, len);
}

Reader::Reader(Reader &&other) noexcept
    : ncpu_(std::exchange(other.ncpu_, 0)),
      buf_(std::exchange(other.buf_, nullptr)),
      size_(std::exchange(other.size_, 0)),
      waiting_for_readyness_(std::exchange(other.waiting_for_readyness_, true)),
      sender_(std::move(other.sender_))
{
}

Reader::~Reader()
{
	if (buf_)
		assert(munmap(buf_, TFW_MMAP_BUFFER_FULL_SIZE(size_)) == 0);
}

bool
Reader::run()
{
	while (true) {
		const bool buffer_ready =
			__atomic_load_n(&buf_->is_ready, __ATOMIC_ACQUIRE);

		if (!buffer_ready) [[unlikely]]
			return waiting_for_readyness_;

		if (waiting_for_readyness_) [[unlikely]] {
			waiting_for_readyness_ = false;
			spdlog::debug("Reader {} ready to process data", ncpu_);
		}

		switch (process_batch()) {
		case ProcessResult::Success:
			continue;
		case ProcessResult::NoData:
			return true;
		case ProcessResult::FailedToProcess:
			return false;
		}
	}
}

Reader::ProcessResult
Reader::process_batch()
{
	const auto head = __atomic_load_n(&buf_->head, __ATOMIC_ACQUIRE);
	const auto tail = buf_->tail;

	const char *data = static_cast<const char *>(buf_->data);
	const char *data_tail = data + (tail & buf_->mask);
	const uint64_t size = head - tail;

	if (size > 0) {
		spdlog::debug("Reader {} processing batch of size {}", ncpu_,
			      size);
	}

	Parser parser(std::as_bytes(std::span(data_tail, size)));
	while (auto log = parser.parse_next_event())
		if (!sender_.add(std::move(*log)))
			return ProcessResult::FailedToProcess;

	if (!sender_.commit())
		return ProcessResult::FailedToProcess;

	if (size == 0)
		return ProcessResult::NoData;

	__atomic_store_n(&buf_->tail, head, __ATOMIC_RELEASE);
	return ProcessResult::Success;
}

std::optional<int>
open_mmap_device(const char *dev_path)
{
	constexpr std::chrono::seconds wait_for_dev{1};
	while (true) {
		if (stop_requested())
			return std::nullopt;

		spdlog::info("Opening device {} ...", dev_path);

		const int fd = open(dev_path, O_RDWR);
		if (fd != -1) {
			spdlog::info("Successfully opened device: {}",
				     dev_path);
			return fd;
		}

		if (errno != ENOENT) {
			throw std::runtime_error(
				fmt::format("Cannot open device {}: {}",
					    dev_path, strerror(errno)));
		}

		spdlog::info("Device {} not found", dev_path);
		std::this_thread::sleep_for(wait_for_dev);
	}
}