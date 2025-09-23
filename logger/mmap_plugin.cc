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
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include <boost/program_options.hpp>
#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#include "../fw/access_log.h"
#include "../libtus/pidfile.hh"
#include "../libtus/error.hh"
#include "clickhouse.hh"
#include "mmap_buffer.hh"
#include "tfw_logger_config.hh"


// Global state
static std::atomic<bool> stop_flag{false};
static TfwLoggerConfig config;

namespace {

/**
 * TODO #2399, #182 (escudo xFW).
 *
 * The 4 functions below must be moved to a Tempesta FW
 * specific plugin, most likely to a new class(es)
 * There will be similar functions (class API) for the security events logging.
 *
 * The classes should inherit the same interface, e.g.
 *
 *	class IEventProcessor {
 *	public:
 *		Error<bool> consume_event();
 *		void make_background_work();
 *		[[nodiscard]] bool flush(bool force = false) noexcept;
 *	};
 */
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

		std::string_view str(data.data() + len_size, len);
		db.append_string(ind, str);

		data = data.subspan(len_size + len);
	} else {
		db.append_empty_string(ind);
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

	read_int<ch::ColumnUInt64, uint64_t>(TFW_MMAP_LOG_JA5T, db, ev, data);
	read_int<ch::ColumnUInt64, uint64_t>(TFW_MMAP_LOG_JA5H, db, ev, data);
	read_int<ch::ColumnUInt64, uint64_t>(TFW_MMAP_LOG_DROPPED, db, ev, data);

	return data.data() - reinterpret_cast<const char*>(ev);
}

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
				break;
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

void
run_thread(const int ncpu, const int fd, const TfwLoggerConfig &config) noexcept
{
	// The most Clickhouse API errors can be handled with simple connection
	// reset and reconnection
	//
	//   https://github.com/ClickHouse/clickhouse-cpp/issues/184
	//
	// We start with zerro reconnection timeout. However, the database can
	// be restarted, so we use indefinite loop with double backoff in
	// reconnection attempts.
	std::chrono::seconds reconnect_timeout(0);

	cpu_set_t cpuset;
	bool affinity_is_set = false;
	int r;

	while (!stop_flag.load(std::memory_order_acquire))
	try {
		const auto &ch_cfg = config.clickhouse;
		spdlog::debug("Worker {} connecting to ClickHouse: {}",
			      ncpu, ch_cfg);

		TfwClickhouse db(ch_cfg);
		auto cb = [&db](std::span<const char> data) {
			return process_events(db, data);
		};
		TfwMmapBufferReader mbr(ncpu, fd, db, std::move(cb));

		if (!affinity_is_set) {
			CPU_ZERO(&cpuset);
			CPU_SET(mbr.get_cpu_id(), &cpuset);
			r = pthread_setaffinity_np(pthread_self(),
						   sizeof(cpu_set_t), &cpuset);
			if (r != 0)
				throw tus::Except("Failed to set CPU affinity");
			affinity_is_set = true;
			spdlog::debug("Worker {} bound to CPU {}", ncpu,
				      mbr.get_cpu_id());
		}

		// At this moment we were able to connect to Clickhouse.
		reconnect_timeout = std::chrono::seconds(0);

		if (mbr.run(stop_flag))
			break;
		// ...else, reset the Clickhouse connection.
	}
	catch (const tus::Exception &e) {
		spdlog::error("Critical error: {}", e.what());
		break;
	}
	catch (const std::exception &e) {
		spdlog::error("A Clickhouse exception caught: {}."
			      " Reset connection and reconnect in {}s.",
			      e.what(), reconnect_timeout.count());
		if (reconnect_timeout == std::chrono::seconds{0}) {
			std::this_thread::sleep_for(reconnect_timeout);
			reconnect_timeout *= 2;
		} else {
			reconnect_timeout = std::chrono::seconds(1);
		}
	}

	spdlog::debug("Worker {} stopped", ncpu);
}

void
run_main_loop(int fd)
{
	/*
	 * Use sysconf() instead of std::thread::hardware_concurrency() because
	 * it respects process CPU affinity, cgroups, and container limits,
	 * is more reliable on NUMA systems and machines with 100+ CPUs while
	 * hardware_concurrency() is just a "hint".
	 */
	auto cpu_count = static_cast<size_t>(sysconf(_SC_NPROCESSORS_ONLN));
	if (cpu_count <= 0)
		throw tus::Except("Cannot determine CPU count");

	spdlog::info("Using {} CPU(s)", cpu_count);
	spdlog::info("Starting {} worker threads", cpu_count);

	// Start worker threads
	std::vector<std::thread> threads;
	for (size_t i = 0; i < cpu_count; ++i)
		threads.emplace_back(run_thread, static_cast<int>(i), fd,
							 std::ref(config));

	spdlog::info("All {} worker threads started", cpu_count);

	for (auto &t : threads) {
		if (t.joinable())
			t.join();
	}
}

void
cleanup_resources(int fd, int pidfile_fd)
{
	if (fd >= 0) {
		close(fd);
		spdlog::info("Device closed");
	}

	if (pidfile_fd >= 0) {
		tus::pidfile_remove(pid_file_path, pidfile_fd);
		spdlog::info("PID file removed");
	}
}

} // anonymous namespace


// mmap plugin
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <fmt/format.h>

#include "clickhouse.hh"
#include "mmap_buffer.h"
#include "tfw_logger_plugin.hh"

namespace {

TfwLoggerPluginApi plugin_api = {
	.version		= TFW_PLUGIN_VERSION,
	.name			= "mmap",
	.init			= nullptr,
	.done			= nullptr,
	.create_processor	= nullptr,
	.destroy_processor	= nullptr
};

constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr std::chrono::seconds wait_for_dev{1};

std::shared_ptr<TfwClickhouse> db;
int dev_fd = -1;

int
open_mmap_device()
{
	int fd;

	plugin_log_info("Opening device: {}", dev_path);

	// Try to open the device with retries
	while ((fd = open(dev_path, O_RDWR)) == -1) {
		if (stop_flag.load(std::memory_order_acquire)) {
			plugin_log_info("Stop flag set, exiting device open loop");
			return -1;
		}

		if (errno != ENOENT) {
			plugin_log_error("Cannot open device {}", dev_path);
			return -1;
		}

		plugin_log_debug("Device {} not found, retrying...", dev_path);
		std::this_thread::sleep_for(wait_for_dev);
	}

	plugin_log_info("Successfully opened device: {}", dev_path);
	return fd;
}

int
mmap_plugin_init(const ClickHouseConfig *config)
{
	assert(config);

	plugin_log_info("Mmap plugin initialization");

	try {
		db = std::make_shared<TfwClickhouse>(*config);
		plugin_log_info("Created clickhouse connection");
	} catch (const std::exception& e) {
		plugin_log_error(
			"Failed to create clickhouse connection: %s",
			e.what());
		return -1;
	}

	dev_fd = open_mmap_device();
	if (dev_fd < 0) {
		plugin_log_error("Failed to open device {}: {}", dev_path);
		return -1;
	}

	return 0;
}

void
mmap_plugin_done(void)
{
	if (dev_fd >= 0)
	{
		close(dev_fd);
		dev_fd = -1;
	}

	db.reset();
	plugin_log_info("Clickhouse connection closed");
}

void*
mmap_create_processor(TfwLoggerProcessorContext ctx)
{
	try {
		plugin_log_debug("Creating MmapProcessor for CPU: %d",
				 ctx.cpu_id);

		auto processor = std::make_unique<MmapProcessor>(db, dev_fd,
								 ctx);

		return processor.release();
	} catch (const std::exception& e) {
		plugin_log_error("Failed to create MmapProcessor: %s",
				 e.what());
	}

	return nullptr;
}

void
mmap_destroy_processor(void *processor)
{
	if (!processor) return;
	delete static_cast<EventProcessor*>(processor);
	plugin_log_debug("Destroyed MmapProcessor instance");
}

void
mmap_plugin_populate_api()
{
	plugin_api.init = mmap_plugin_init;
	plugin_api.done = mmap_plugin_done;
	plugin_api.create_processor = mmap_create_processor;
	plugin_api.destroy_processor = mmap_destroy_processor;
}

} // anonymous namespace

extern "C" TfwLoggerPluginApi* get_plugin_api(void)
{
	mmap_plugin_populate_api();
	return &plugin_api;
}
