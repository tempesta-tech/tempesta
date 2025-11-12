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

#include <dlfcn.h>
#include <spdlog/spdlog.h>
#include <fmt/format.h>

#include "../libtus/error.hh"
#include "plugin.hh"

Plugin::Plugin(const std::string &plugin_path, const ClickHouseConfig& config,
	std::atomic<bool> *stop_flag)
{
	//TODO: split to several minor functions: load_library, get_plugin_api, init_plugin
	void * handle = dlopen(plugin_path.c_str(),
			 RTLD_LAZY | RTLD_LOCAL | RTLD_DEEPBIND);
	if (!handle)
		throw tus::Except("Failed to load plugin {}: {}",
				  plugin_path, dlerror());
	handle_ = DlHandle(handle);

	auto get_api = reinterpret_cast<TfwLoggerPluginGetApiFunc>(
		dlsym(handle_.get(), "get_plugin_api"));

	if (!get_api)
		throw tus::Except("Plugin {} missing get_plugin_api function",
				  plugin_path);

	api_ = get_api();
	if (!api_ || api_->version != TFW_PLUGIN_VERSION)
		throw tus::Except("Plugin {} version mismatch", plugin_path);

	spdlog::info("Loaded plugin: {} ({})", api_->name, plugin_path);

	if (api_->init) {
		int ret = api_->init(&config, stop_flag);
		if (ret < 0)
			throw tus::Except("Plugin {} init failed with code {}",
					  api_->name, ret);
		spdlog::info("Plugin {} initialized", api_->name);
	}
}

Plugin::~Plugin()
{
	shutdown_plugin();
}

Plugin::Plugin(Plugin&& other) noexcept
	: handle_(std::move(other.handle_))
	, api_(other.api_)
{
	other.api_ = nullptr;
}

Plugin&
Plugin::operator=(Plugin&& other) noexcept
{
	if (this != &other) {
		handle_ = std::move(other.handle_);
		api_ = std::move(other.api_);
	}

	return *this;
}

void
Plugin::shutdown_plugin()
{
	if (api_ && api_->done) {
		api_->done();
		spdlog::info("Plugin {} cleaned up", api_->name);
	}
}

ProcessorHandle Plugin::create_processor(unsigned processor_id) const
{
	if (!api_ || !api_->create_processor)
		throw tus::Except("Plugin {} not properly loaded", api_->name);

	void* raw_processor = api_->create_processor(processor_id);
	if (!raw_processor)
		throw tus::Except("Plugin {} failed to create processor",
				  api_->name);

	return ProcessorHandle(api_, raw_processor);
}


void
Plugin::DlCloser::operator()(void* h) const noexcept
{
	if (h)
		dlclose(h);
}