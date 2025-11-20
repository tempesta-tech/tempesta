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

#pragma once

#include <filesystem>
#include <optional>

#include <boost/property_tree/ptree_fwd.hpp>

#include "plugin_config.hh"

namespace fs = std::filesystem;

struct TfwLoggerConfig {
	// Log file path - default set in tfw_logger.cc
	fs::path log_path;
	std::optional<std::string> access_log_plugin_path;
	std::optional<std::string> xfw_events_plugin_path;
	std::optional<PluginConfig> clickhouse_mmap;
	std::optional<PluginConfig> clickhouse_xfw;

	static std::optional<TfwLoggerConfig>
	load_from_file(const fs::path &path);

	void
	validate() const;

	void
	parse_from_ptree(const boost::property_tree::ptree &tree);
};
