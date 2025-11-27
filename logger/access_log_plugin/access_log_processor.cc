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
#include <cstdio>
#include <cstring>
#include <errno.h>
#include <sys/mman.h>

#include "../../libtus/error.hh"
#include "../plugin_interface.hh"

#include "access_log_processor.hh"

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

template <TfwBinLogFields FieldType>
requires std::is_arithmetic_v<typename TfwBinLogTypeTraits<FieldType>::ValType> ||
	 std::is_same_v<typename TfwBinLogTypeTraits<FieldType>::ValType, struct in6_addr>
void
read_field(AccessLogClickhouseDecorator &db, const auto *event, std::span<const char> &data)
{
	using Traits  = TfwBinLogTypeTraits<FieldType>;
	using ValType = typename Traits::ValType;

	if (TFW_MMAP_LOG_FIELD_IS_SET(event, FieldType)) {
		const size_t len = tfw_mmap_log_field_len(FieldType);

		if (data.size() < len) [[unlikely]]
			throw tus::Except("Incorrect integer eventent length");

		const ValType *val =
			reinterpret_cast<const ValType *>(data.data());
		db.append<FieldType>(*val);

		data = data.subspan(len);
	} else {
		db.append<FieldType>(ValType{});
	}
}

template <TfwBinLogFields FieldType>
requires std::same_as<typename TfwBinLogTypeTraits<FieldType>::ValType, std::string_view>
void
read_field(AccessLogClickhouseDecorator &db, const auto *event, std::span<const char> &data)
{
	if (TFW_MMAP_LOG_FIELD_IS_SET(event, FieldType)) {
		constexpr int len_size = sizeof(uint16_t);

		if (data.size() < len_size) [[unlikely]]
			throw tus::Except("Too short string event");

		const size_t len =
			*reinterpret_cast<const uint16_t *>(data.data());
		if (data.size() < len_size + len) [[unlikely]]
			throw tus::Except("Incorrect string event length");

		data = data.subspan(len_size);
		std::string_view str(data.data(), len);
		db.append<FieldType>(str);

		data = data.subspan(len);
	} else {
		db.append<FieldType>(std::string_view{});
	}
}

size_t
read_access_log_event(AccessLogClickhouseDecorator &db, std::span<const char> data)
{
	const auto *ev = reinterpret_cast<const TfwBinLogEvent *>(data.data());

	data = data.subspan(sizeof(TfwBinLogEvent));

	db.append_timestamp(ev->timestamp);

	read_field<TFW_MMAP_LOG_ADDR>(db, ev, data);
	read_field<TFW_MMAP_LOG_METHOD>(db, ev, data);
	read_field<TFW_MMAP_LOG_VERSION>(db, ev, data);
	read_field<TFW_MMAP_LOG_STATUS>(db, ev, data);
	read_field<TFW_MMAP_LOG_RESP_CONT_LEN>(db, ev, data);
	read_field<TFW_MMAP_LOG_RESP_TIME>(db, ev, data);

	read_field<TFW_MMAP_LOG_VHOST>(db, ev, data);
	read_field<TFW_MMAP_LOG_URI>(db, ev, data);
	read_field<TFW_MMAP_LOG_REFERER>(db, ev, data);
	read_field<TFW_MMAP_LOG_USER_AGENT>(db, ev, data);

	read_field<TFW_MMAP_LOG_TFT>(db, ev, data);
	read_field<TFW_MMAP_LOG_TFH>(db, ev, data);
	read_field<TFW_MMAP_LOG_DROPPED>(db, ev, data);

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
	plugin_log_info(oss.view().data());
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
process_events(AccessLogClickhouseDecorator &db, std::span<const char> data) noexcept
{
	size_t read = 0;

	dbg_hexdump(data);

	try {
		while (data.size()) {
			if (data.size() < sizeof(TfwBinLogEvent)) [[unlikely]]
				throw tus::Except(
					"Partial event in the access log");

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
				throw tus::Except(
					"Unsupported event type: {}",
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
		plugin_log_error(fmt::format(
			"Access log is corrupted, skip current buffer: {}",
			e.what()).c_str());
		if (!db.handle_block_error())
			return tus::error(tus::Err::DB_SRV_FATAL);
		return 0;
	}
	catch (const std::exception &e) {
		plugin_log_error(fmt::format(
			"Caught a Clickhouse exception: {}."
			" Many events can be lost", e.what()).c_str());
		return tus::error(tus::Err::DB_SRV_FATAL);
	}

	assert(read);

	return read;
}

} // anonymous namespace

AccessLogProcessor::AccessLogProcessor(std::unique_ptr<IClickhouse> writer,
				       unsigned cpu_id,
				       int device_fd,
				       const char* table_name,
				       size_t max_events)
	: writer_(std::move(writer), table_name, max_events)
	, device_fd_(device_fd)
{
	plugin_log_debug(fmt::format("Creating AccessLogProcessor with device: {}",
				     device_fd_).c_str());

	unsigned int area_size;

	size_ = get_buffer_size(device_fd_);

	area_size = TFW_MMAP_BUFFER_FULL_SIZE(size_);

	buffer_ = (TfwMmapBuffer *)mmap(nullptr, area_size,
					PROT_READ|PROT_WRITE,
					MAP_SHARED, device_fd_,
					area_size * cpu_id);
	if (buffer_ == MAP_FAILED)
		throw tus::Except("Failed to map buffer");

	plugin_log_info("AccessLogProcessor created successfully");
}

AccessLogProcessor::~AccessLogProcessor()
{
	assert(munmap(buffer_, TFW_MMAP_BUFFER_FULL_SIZE(size_)) == 0);
	plugin_log_debug("AccessLogProcessor destroyed");
}

int
AccessLogProcessor::consume(size_t *cnt) noexcept
{
	*cnt = 0;

	// TODO: It might be better to have one ClickHouse instance per CPU.
	// This would allow moving this check outside and avoid continuously
	//  polling ClickHouse in a busy loop, which wastes CPU time.
	// Ideally, we would sleep until the ReconnectPolicy allows the next retry.
	// I would prefer to implement this once we integrate all our solutions
	// into the monorepo to prevent potential compiler incompatibilities.
	if (!writer_.ensure_connected())
		return 0;

	uint64_t head, tail;

	head = __atomic_load_n(&buffer_->head, __ATOMIC_ACQUIRE);
	tail = buffer_->tail;

	assert(head >= tail);
	if (head - tail == 0) [[unlikely]]
		return 0;

	uint64_t size = static_cast<uint64_t>(head - tail);
	const auto start = buffer_->data + (tail & buffer_->mask);

	auto res = process_events(writer_, std::span<const char>(start, size));
	if (res && *res) [[likely]]
		size = *res;
	// ...else consume the whole buffer in case of error.

	assert(tail + size <= head);

	// Move the RB pointer only for really processed events.
	// Events are copied to a database buffer, so we can move the RB pointer
	// before heavyweight database transaction.
	__atomic_store_n(&buffer_->tail, tail + size, __ATOMIC_RELEASE);

	if (!res)
		return static_cast<int>(tus::Err::DB_SRV_FATAL);

	*cnt = *res;
	return 0;
}

int
AccessLogProcessor::send(bool force) noexcept
{
	if (writer_.flush(force))
		return 0;

	return static_cast<int>(tus::Err::DB_CLT_TRANSIENT);
}

std::string_view
AccessLogProcessor::name() const noexcept
{
	using namespace std::literals;
	return "access_log"sv;
}

void
AccessLogProcessor::request_stop() noexcept
{
	// Let the kernel know that it doesn’t have a listener.
	__atomic_store_n(&buffer_->is_ready, 0, __ATOMIC_RELEASE);
}

int
AccessLogProcessor::has_stopped() noexcept
{
	return __atomic_load_n(&buffer_->is_ready, __ATOMIC_ACQUIRE);
}
