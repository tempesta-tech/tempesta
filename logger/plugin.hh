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

/**
 * RAII wrapper for a processor instance created by a plugin.
 *
 * Manages a processor handle obtained from TfwLoggerPluginApi and ensures
 * that it is properly destroyed via `api_->destroy_processor(handle_)` when the
 * object goes out of scope.
 *
 * The class also safely forwards (reinvokes) plugin API functions, passing the
 * stored handle back to the plugin as needed.
 */
class ProcessorHandle
{
public:
	ProcessorHandle(TfwLoggerPluginApi* api, void* processor)
		: api_(api), processor_(processor)
	{}

	~ProcessorHandle()
	{
		if (api_ && api_->destroy_processor && processor_) {
			api_->destroy_processor(processor_);
			processor_ = nullptr;
		}
	}

	ProcessorHandle(const ProcessorHandle&) = delete;
	ProcessorHandle& operator=(const ProcessorHandle&) = delete;

	ProcessorHandle(ProcessorHandle&& other) noexcept
		: api_(other.api_), processor_(other.processor_)
	{
		other.processor_ = nullptr;
	}

public:
	//TODO: implement
	tus::Error<bool> consume() noexcept
	{
		return false;
	}

	bool make_background_work() noexcept
	{
		return false;
	}

	void request_stop() const noexcept
	{
	}

	bool stop_requested() const noexcept
	{
		return false;
	}

	std::string_view name() const noexcept { return api_->name; };

public:
	ProcessorHandle& operator=(ProcessorHandle&& other) noexcept
	{
		if (this != &other) {
			if (processor_ && api_ && api_->destroy_processor)
				api_->destroy_processor(processor_);
			api_ = other.api_;
			processor_ = other.processor_;
			other.processor_ = nullptr;
		}
		return *this;
	}

private:
	TfwLoggerPluginApi*	api_;
	void*			processor_;
};

/**
 * Implementation of the Plugin class — a safe dynamic plugin loader. Responsible for:
 *  - Dynamic loading of shared libraries (.so) using dlopen();
 *  - Retrieval of the exported function `get_plugin_api()` via dlsym();
 *  - Initialization and cleanup of the plugin API;
 */
class Plugin {
public:
	explicit Plugin(const std::string &plugin_path,
			const ClickHouseConfig& config,
			std::atomic<bool> *stop_flag); //TODO: replace flag with API?

	Plugin(const Plugin&) = delete;
	Plugin& operator=(const Plugin&) = delete;

	Plugin(Plugin&& other) noexcept;
	Plugin& operator=(Plugin&& other) noexcept;

	~Plugin();

public:
	ProcessorHandle create_processor(unsigned processor_id) const;

private:
	void shutdown_plugin();

private:
	struct DlCloser
	{
		void operator()(void* h) const noexcept;
	};
	using DlHandle = std::unique_ptr<void, DlCloser>;

private:
	DlHandle		handle_;
	TfwLoggerPluginApi*	api_ = nullptr;
};
