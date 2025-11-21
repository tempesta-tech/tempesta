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
#include "plugin_config.hh"
#include "plugin_processor_iface.hh"

/**
 * Implementation of the Plugin class — a safe dynamic plugin loader. Responsible for:
 *  - Dynamic loading of shared libraries (.so) using dlopen();
 *  - Retrieval of the exported function `get_plugin_api()` via dlsym();
 *  - Initialization and cleanup of the plugin API;
 */
class Plugin {
public:
	explicit Plugin(const std::string &plugin_path,
			const PluginConfig &config,
			StopFlag *stop_flag);

	Plugin(const Plugin&) = delete;
	Plugin& operator=(const Plugin&) = delete;

	Plugin(Plugin&& other) noexcept;
	Plugin& operator=(Plugin&& other) noexcept;

	~Plugin();

public:
	std::unique_ptr<IPluginProcessor>
	create_processor(unsigned cpu_id) const;

private:
	void shutdown_plugin();

private:
	struct DlCloser
	{
		void operator()(void *h) const noexcept;
	};
	using DlHandle = std::unique_ptr<void, DlCloser>;

private:
	PluginConfig		plugin_config_;
	PluginConfigApi		plugin_config_api_;
	DlHandle		handle_;
	TfwLoggerPluginApi*	api_ = nullptr;
};
