/**
*		Tempesta FW
*
* Copyright (C) 2025 Tempesta Technologies, Inc.
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

#pragma once

#include <string>
#include <memory>

#include "plugin_interface.hh"
#include "clickhouse_config.hh"

class EventProcessor;

class EventProcessorDeleter {
public:
	explicit EventProcessorDeleter(TfwLoggerPluginApi* api): api_(api) {}

	void operator()(EventProcessor* processor) const {
		if (processor && api_ && api_->destroy_processor) {
			api_->destroy_processor(static_cast<void *>(processor));
		}
	}

private:
	TfwLoggerPluginApi* api_;
};

using EventProcessorPtr = std::unique_ptr<EventProcessor, EventProcessorDeleter>;

class Plugin {
public:
	explicit Plugin(const std::string &plugin_path,
			const ClickHouseConfig& config,
			std::atomic<bool> *stop_flag);

	Plugin(const Plugin&) = delete;
	Plugin& operator=(const Plugin&) = delete;

	Plugin(Plugin&& other) noexcept;
	Plugin& operator=(Plugin&& other) noexcept;

	~Plugin();

public:
	EventProcessorPtr create_processor(unsigned processor_id);

	const std::string& get_name() const { return name_; };

private:
	void cleanup();

private:
	void* handle_ = nullptr;
	TfwLoggerPluginApi* api_ = nullptr;
	bool initialized_ = false;
	std::string name_ = "unknown";
};
