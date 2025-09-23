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

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <errno.h>
#include <cstring>
#include <cstdio>

#include <spdlog/spdlog.h>

#include "../libtus/error.hh"
#include "plugin_interface.hh"
#include "mmap_processor.hh"

namespace {

size_t
get_buffer_size(const int fd)
{
	TfwMmapBuffer *buf =
		(TfwMmapBuffer *)mmap(NULL,
				      TFW_MMAP_BUFFER_DATA_OFFSET,
				      PROT_READ | PROT_WRITE, MAP_PRIVATE,
				      fd, 0);
	if (buf == MAP_FAILED)
		throw tus::Except("Failed to get buffers info");

	size_t size = buf->size;

	munmap(buf, TFW_MMAP_BUFFER_DATA_OFFSET);

	return size;
}

template <typename ColType, typename ValType>
void
read_int(TfwBinLogFields ind, TfwClickhouse &db,
	 const auto *event, std::span<const char> &data)
{
	if (TFW_MMAP_LOG_FIELD_IS_SET(event, ind)) {
		const size_t len = tfw_mmap_log_field_len(ind);

		if (data.size() < len) [[unlikely]]
			throw tus::Except("Incorrect integer eventent length");

		const ValType *val =
			reinterpret_cast<const ValType *>(data.data());
		db.append_int<ColType, ValType>(ind, *val);

		data = data.subspan(len);
	} else {
		db.append_int<ColType, ValType>(ind, ValType{});
	}
}

void
read_str(TfwBinLogFields ind, TfwClickhouse &db,
	 const auto *event, std::span<const char> &data)
{
	if (TFW_MMAP_LOG_FIELD_IS_SET(event, ind)) {
		constexpr int len_size = sizeof(uint16_t);

		if (data.size() < len_size) [[unlikely]]
			throw tus::Except("Too short string event");

		const size_t len =
			*reinterpret_cast<const uint16_t *>(data.data());
		if (data.size() < len_size + len) [[unlikely]]
			throw tus::Except("Incorrect string event length");

		data = data.subspan(len_size);
		std::string_view str(data.data(), len);
		db.append_string(ind, str);

		data = data.subspan(len);
	} else {
		db.append_string(ind, std::string_view{});
	}
}

size_t
read_access_log_event(TfwClickhouse &db, std::span<const char> data)
{
	const auto *ev = reinterpret_cast<const TfwBinLogEvent *>(data.data());

	data = data.subspan(sizeof(TfwBinLogEvent));

	db.append_timestamp(ev->timestamp);

	read_int<ch::ColumnIPv6, in6_addr>(TFW_MMAP_LOG_ADDR, db, ev, data);
	read_int<ch::ColumnUInt8, uint8_t>(TFW_MMAP_LOG_METHOD, db, ev, data);
	read_int<ch::ColumnUInt8, uint8_t>(TFW_MMAP_LOG_VERSION, db, ev, data);
	read_int<ch::ColumnUInt16, uint16_t>(TFW_MMAP_LOG_STATUS, db, ev, data);
	read_int<ch::ColumnUInt32, uint32_t>(TFW_MMAP_LOG_RESP_CONT_LEN, db, ev, data);
	read_int<ch::ColumnUInt32, uint32_t>(TFW_MMAP_LOG_RESP_TIME, db, ev, data);

	read_str(TFW_MMAP_LOG_VHOST, db, ev, data);
	read_str(TFW_MMAP_LOG_URI, db, ev, data);
	read_str(TFW_MMAP_LOG_REFERER, db, ev, data);
	read_str(TFW_MMAP_LOG_USER_AGENT, db, ev, data);

	read_int<ch::ColumnUInt64, uint64_t>(TFW_MMAP_LOG_TFT, db, ev, data);
	read_int<ch::ColumnUInt64, uint64_t>(TFW_MMAP_LOG_TFH, db, ev, data);
	read_int<ch::ColumnUInt64, uint64_t>(TFW_MMAP_LOG_DROPPED, db, ev, data);

	return data.data() - reinterpret_cast<const char*>(ev);
}

#ifdef DEBUG
void
dbg_hexdump(std::span<const char> data)
{
	const auto *buf = reinterpret_cast<const unsigned char *>(data.data());
	const size_t buflen = data.size();
	std::ostringstream oss;

	oss << "data dump of len=" << buflen << std::endl;
	oss << std::hex << std::setfill('0');
	for (size_t i = 0; i < buflen; i += 16) {
		oss << std::setw(6) << i << ": ";

		for (int j = 0; j < 16; ++j)
			if (i + j < buflen)
				oss << std::setw(2)
				    << static_cast<unsigned>(buf[i + j]) << " ";
			else
				oss << "   ";
		oss << " ";
		for (int j = 0; j < 16; ++j) {
			if (i + j >= buflen)
				break;
			const char c = buf[i + j];
			oss << static_cast<char>(std::isprint(c) ? c : '.');
		}
		oss << std::endl;
	}
	spdlog::info("{}", oss.str());
}
#else
void
dbg_hexdump([[maybe_unused]] std::span<const char> data)
{
}
#endif /* DEBUG */

/**
 * Read, process and send to ClickHouse events.
 *
 * We may copy from the kernel buffer more events than it was configured with
 * max_events - this may cause dynamic memory allocations, but frees space
 * in the kernel buffer as quickly as possible.
 *
 * @return the amount of data read, can be less than all available data,
 * e.g. if ClickHouse throws and exception or some event record is broken.
 */
[[nodiscard]] tus::Error<size_t>
process_events(TfwClickhouse &db, std::span<const char> data) noexcept
{
	size_t read = 0;

	dbg_hexdump(data);

	try {
		while (data.size()) {
			if (data.size() < sizeof(TfwBinLogEvent)) [[unlikely]]
				throw tus::Except("Partial event in the access log");

			const auto *ev
				= reinterpret_cast<const TfwBinLogEvent *>(
								data.data());

			switch (ev->type) {
			case TFW_MMAP_LOG_TYPE_ACCESS: {
				const auto off = read_access_log_event(db, data);
				data = data.subspan(off);
				read += off;
				break;
			}
			default:
				throw tus::Except("Unsupported event type: {}",
					     static_cast<unsigned int>(ev->type));
			}
		}
	}

	// In case of exception, we return 0 to fully consume it from the kernel
	// buffer. We have to do this since here we loose the knowledge which
	// column raised a Clickhouse exceptions, the Clickhouse API doesn't
	// allow to rollback appended column values and in case of parsing error
	// the whole buffer might be corrupted.
	//
	// These exceptions are severe, like memory allocation failure or memory
	// corruption, so there is probably no reason to try hard to recover.
	catch (const tus::Exception &e) {
		spdlog::error("Access log is corrupted, skip current buffer:"
			      " {}", e.what());
		if (!db.handle_block_error())
			return tus::error(tus::Err::DB_SRV_FATAL);
		return 0;
	}
	catch (const std::exception &e) {
		spdlog::error("Cought a Clickhouse exception: {}."
			      " Many events can be lost", e.what());
		return tus::error(tus::Err::DB_SRV_FATAL);
	}

	assert(read);

	return read;
}

} // anonymous namespace

MmapProcessor::MmapProcessor(std::shared_ptr<TfwClickhouse> db,
			     unsigned processor_id,
			     int device_fd)
	: EventProcessor(std::move(db), processor_id)
	, device_fd_(device_fd)
{
	plugin_log_debug(fmt::format("Creating MmapProcessor with device: {}",
				     device_fd_).c_str());

	unsigned int area_size;

	size_ = get_buffer_size(device_fd_);

	area_size = TFW_MMAP_BUFFER_FULL_SIZE(size_);

	buffer_ = (TfwMmapBuffer *)mmap(nullptr, area_size,
					PROT_READ|PROT_WRITE,
					MAP_SHARED, device_fd_,
					area_size * processor_id);
	if (buffer_ == MAP_FAILED)
		throw tus::Except("Failed to map buffer");

	plugin_log_info("MmapProcessor created successfully");
}

MmapProcessor::~MmapProcessor()
{
	assert(munmap(buffer_, TFW_MMAP_BUFFER_FULL_SIZE(size_)) == 0);
	plugin_log_debug("MmapProcessor destroyed");
}

tus::Error<bool>
MmapProcessor::do_consume_event()
{
	uint64_t head, tail;

	head = __atomic_load_n(&buffer_->head, __ATOMIC_ACQUIRE);
	tail = buffer_->tail;

	assert(head >= tail);
	if (head - tail == 0) [[unlikely]]
		return false;

	uint64_t size = static_cast<uint64_t>(head - tail);
	const auto start = buffer_->data + (tail & buffer_->mask);

	auto res = process_events(*db_, std::span<const char>(start, size));
	if (res && *res) [[likely]]
		size = *res;
	// ...else consume the whole buffer in case of error.

	assert(tail + size <= head);

	// Move the RB pointer only for really processed events.
	// Events are copied to a database buffer, so we can move the RB pointer
	// before heavyweight database transaction.
	__atomic_store_n(&buffer_->tail, tail + size, __ATOMIC_RELEASE);

	if (!res)
		return tus::error(tus::Err::DB_SRV_FATAL);

	// Ideally if we can move flushing into main loop of tfw_logger
	// after all event processors to read events from the associated RBs
	// and then ask all of them to flush what they have to Clickhouse.
	if (*res && flush())
		return tus::error(tus::Err::DB_SRV_FATAL);

	return true;
}

void
MmapProcessor::request_stop() noexcept
{
	__atomic_store_n(&buffer_->is_ready, 0, __ATOMIC_RELEASE);
}

bool
MmapProcessor::stop_requested() noexcept
{
	return !__atomic_load_n(&buffer_->is_ready, __ATOMIC_ACQUIRE);
}

unsigned int
MmapProcessor::get_cpu_id() const noexcept
{
	assert(buffer_);
	return buffer_->cpu;
}
