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
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <fmt/format.h>
#include <thread>

#include "../../fw/mmap_buffer.h"
#include "../plugin_interface.hh"
#include "../clickhouse/clickhouse_with_reconnect.hh"
#include "../clickhouse/lazy_init_clickhouse.hh"

#include "access_log_processor.hh"

namespace {

TfwLoggerPluginApi plugin_api = {
	.version		= TFW_PLUGIN_VERSION,
	.name			= "access_log",
	.init			= nullptr,
	.done			= nullptr,
	.create_processor	= nullptr,
	.destroy_processor	= nullptr,
	.has_stopped		= nullptr,
	.request_stop		= nullptr,
	.consume		= nullptr,
	.send			= nullptr
};

constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr std::chrono::seconds wait_for_dev{1};

int dev_fd = -1;

int
open_mmap_device(StopFlag* stop_flag)
{
	int fd;

	plugin_log_info(fmt::format("Opening device: {}", dev_path).c_str());

	// Try to open the device with retries
	while ((fd = open(dev_path, O_RDWR)) == -1) {
		if (stop_flag && stop_flag->stop_requested()) {
			plugin_log_info("Stop flag set, exiting device open loop");
			return -1;
		}

		if (errno != ENOENT) {
			plugin_log_error(fmt::format("Cannot open device {}",
						     dev_path).c_str());
			return -1;
		}

		plugin_log_debug(fmt::format("Device {} not found, retrying...",
					     dev_path).c_str());
		std::this_thread::sleep_for(wait_for_dev);
	}

	plugin_log_info(fmt::format("Successfully opened device: {}",
			dev_path).c_str());
	return fd;
}

int
mmap_plugin_init(StopFlag* stop_flag)
{
	plugin_log_info("Mmap plugin initialization");

	dev_fd = open_mmap_device(stop_flag);
	if (dev_fd < 0) {
		plugin_log_error(fmt::format("Failed to open device {}",
					     dev_path).c_str());
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
		plugin_log_info("Device closed");
	}
}

ProcessorInstance
mmap_create_processor(const PluginConfigApi *config, unsigned cpu_id)
{
	assert(config);

	try {
		plugin_log_debug(fmt::format("Creating MmapProcessor for CPU: {}",
					     cpu_id).c_str());

		ch::ClientOptions options;
		options.SetHost(config->host)
		       .SetPort(config->port)
		       .SetDefaultDatabase(config->db_name)
		       .SetUser(config->user)
		       .SetPassword(config->password);

		auto factory = [opts = std::move(options)]() -> LazyInitClickhouse::Ptr {
			return std::make_unique<ClickhouseWithReconnection>(opts);
		};

		// We are creating a ClickHouse instance here, but later we might
		// decide to share a single instance per CPU across all processors.
		// Passing the ClickHouse instance from outside would save resources:
		// instead of Ncpu * Mplugins workers, we would have just Ncpu workers.
		auto writer = std::make_unique<LazyInitClickhouse>(factory);

		auto processor = std::make_unique<AccessLogProcessor>(std::move(writer),
			cpu_id, dev_fd, config->table_name, config->max_events);

		return processor.release();
	} catch (const std::exception& e) {
		plugin_log_error(fmt::format("Failed to create MmapProcessor: {}",
					     e.what()).c_str());
	}

	return nullptr;
}

void
mmap_destroy_processor(ProcessorInstance processor)
{
	if (!processor)
		return;

	std::unique_ptr<AccessLogProcessor> p(
		static_cast<AccessLogProcessor*>(processor));
	plugin_log_debug("Destroyed MmapProcessor instance");
}

int
mmap_has_stopped(ProcessorInstance processor)
{
	assert(!!processor);
	auto* p = static_cast<AccessLogProcessor*>(processor);
	return p->has_stopped();
}

void
mmap_request_stop(ProcessorInstance processor)
{
	assert(!!processor);
	auto* p = static_cast<AccessLogProcessor*>(processor);
	return p->request_stop();
}

int
mmap_consume(ProcessorInstance processor, size_t *cnt)
{
	assert(!!processor);
	auto* p = static_cast<AccessLogProcessor*>(processor);
	return p->consume(cnt);
}

int
mmap_send(ProcessorInstance processor, bool force)
{
	assert(!!processor);
	auto* p = static_cast<AccessLogProcessor*>(processor);
	return p->send(force);
}

void
mmap_plugin_populate_api()
{
	plugin_api.init			= mmap_plugin_init;
	plugin_api.done			= mmap_plugin_done;
	plugin_api.create_processor	= mmap_create_processor;
	plugin_api.destroy_processor	= mmap_destroy_processor;
	plugin_api.has_stopped		= mmap_has_stopped;
	plugin_api.request_stop		= mmap_request_stop;
	plugin_api.consume		= mmap_consume;
	plugin_api.send			= mmap_send;
}

} // anonymous namespace

extern "C" TfwLoggerPluginApi* get_plugin_api(void)
{
	mmap_plugin_populate_api();
	return &plugin_api;
}
