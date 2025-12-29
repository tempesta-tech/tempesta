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
#include <fmt/format.h>

#include <spdlog/spdlog.h>

#include "../libtus/error.hh"
#include "plugin.hh"

inline PluginConfigApi
make_plugin_config_api(const PluginConfig &cfg)
{
	PluginConfigApi c_cfg{};

	c_cfg.host       = cfg.host.c_str();
	c_cfg.port       = cfg.port;
	c_cfg.db_name    = cfg.db_name.c_str();
	c_cfg.table_name = cfg.table_name.c_str();

	c_cfg.user       = cfg.user ? cfg.user->c_str() : "default";
	c_cfg.password   = cfg.password ? cfg.password->c_str() : "";

	c_cfg.max_events = cfg.max_events;

	return c_cfg;
}

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
class ProcessorHandle final: public IPluginProcessor
{
public:
	ProcessorHandle(TfwLoggerPluginApi *api, void *processor)
		: api_(api), processor_(processor)
	{
		if (!api || !processor || !api_->has_stopped || !api_->request_stop
		         || !api_->consume || !api_->send)
			throw tus::Except("Plugin api is not fully presented");
	}

	~ProcessorHandle() override
	{
		if (api_->destroy_processor) {
			api_->destroy_processor(processor_);
			processor_ = nullptr;
		}
	}

	ProcessorHandle(const ProcessorHandle&) = delete;
	ProcessorHandle& operator=(const ProcessorHandle&) = delete;

	ProcessorHandle(ProcessorHandle &&other) noexcept
		: api_(other.api_), processor_(other.processor_)
	{
		other.processor_ = nullptr;
	}

	ProcessorHandle& operator=(ProcessorHandle &&other) noexcept
	{
		if (this != &other) {
			if (api_->destroy_processor)
				api_->destroy_processor(processor_);
			api_ = other.api_;
			processor_ = other.processor_;
			other.processor_ = nullptr;
		}
		return *this;
	}

public:
	virtual int has_stopped() noexcept override
	{
		assert(api_->has_stopped);
		return api_->has_stopped(processor_);
	}

	virtual void request_stop() noexcept override
	{
		assert(api_->request_stop);
		return api_->request_stop(processor_);
	}

	virtual int consume(size_t *cnt) noexcept override
	{
		assert(api_->consume);
		return api_->consume(processor_, cnt);
	}

	virtual int send(bool force) noexcept override
	{
		assert(api_->send);
		return api_->send(processor_, force);
	}

	virtual std::string_view name() const noexcept override { return api_->name; };

private:
	TfwLoggerPluginApi*	api_;
	void*			processor_;
};

Plugin::Plugin(const std::string &plugin_path, const PluginConfig &config,
	StopFlag *stop_flag)
	: plugin_config_(config)
	, plugin_config_api_(make_plugin_config_api(plugin_config_))
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
		int ret = api_->init(stop_flag);
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

Plugin::Plugin(Plugin &&other) noexcept
	: plugin_config_(std::move(other.plugin_config_))
	, plugin_config_api_(make_plugin_config_api(plugin_config_))
	, handle_(std::move(other.handle_))
	, api_(other.api_)
{
	other.api_ = nullptr;
}

Plugin&
Plugin::operator=(Plugin &&other) noexcept
{
	if (this != &other) {
		plugin_config_ = std::move(other.plugin_config_);
		plugin_config_api_ = make_plugin_config_api(plugin_config_);
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

std::unique_ptr<IPluginProcessor>
Plugin::create_processor(unsigned cpu_id) const
{
	if (!api_ || !api_->create_processor)
		throw tus::Except("Plugin {} not properly loaded", api_->name);

	void* raw_processor = api_->create_processor(&plugin_config_api_, cpu_id);
	if (!raw_processor)
		throw tus::Except("Plugin {} failed to create processor",
				  api_->name);

	return std::make_unique<ProcessorHandle>(api_, raw_processor);
}

void
Plugin::DlCloser::operator()(void *h) const noexcept
{
	if (h)
		dlclose(h);
}
