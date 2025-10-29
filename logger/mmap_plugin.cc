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

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <thread>
#include <fmt/format.h>

#include "clickhouse.hh"
#include "plugin_interface.hh"
#include "mmap_processor.hh"

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

std::atomic<bool> *global_stop_flag;
std::shared_ptr<TfwClickhouse> db;
int dev_fd = -1;

int
open_mmap_device()
{
	int fd;

	plugin_log_info(fmt::format("Opening device: {}", dev_path).c_str());

	// Try to open the device with retries
	while ((fd = open(dev_path, O_RDWR)) == -1) {
		if (global_stop_flag->load(std::memory_order_acquire)) {
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
mmap_plugin_init(const ClickHouseConfig *config, void *stop_flag)
{
	assert(config);

	plugin_log_info("Mmap plugin initialization");

	global_stop_flag = reinterpret_cast<std::atomic<bool> *>(stop_flag);

	try {
		db = std::make_shared<TfwClickhouse>(*config);
		plugin_log_info("Created clickhouse connection");
	} catch (const std::exception& e) {
		plugin_log_error(fmt::format(
			"Failed to create clickhouse connection: {}",
			e.what()).c_str());
		return -1;
	}

	dev_fd = open_mmap_device();
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
	}

	db.reset();
	plugin_log_info("Clickhouse connection closed");
}

void*
mmap_create_processor(unsigned processor_id)
{
	try {
		plugin_log_debug(fmt::format("Creating MmapProcessor for CPU: {}",
					     processor_id).c_str());

		auto processor = std::make_unique<MmapProcessor>(db,
								 processor_id,
								 dev_fd);

		return processor.release();
	} catch (const std::exception& e) {
		plugin_log_error(fmt::format("Failed to create MmapProcessor: {}",
					     e.what()).c_str());
	}

	return nullptr;
}

void
mmap_destroy_processor(void *processor)
{
	if (!processor)
		return;
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
