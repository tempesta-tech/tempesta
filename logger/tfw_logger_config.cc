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

#include "tfw_logger_config.hh"

#include <iostream>
#include <stdexcept>

#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

void
TfwLoggerConfig::parse_from_ptree(const pt::ptree &tree)
{
	if (const auto val = tree.get_optional<std::string>("log_path"))
		log_path = *val;

	if (const auto node = tree.get_child_optional("access_log")) {
		if (const auto path_val = node->get_optional<std::string>("plugin_path"))
			access_log_plugin_path = *path_val;

		clickhouse_mmap.emplace();
		clickhouse_mmap->parse_from_ptree(*node);
	}

	if (const auto node = tree.get_child_optional("xfw_events")) {
		if (const auto path_val = node->get_optional<std::string>("plugin_path"))
			xfw_events_plugin_path = *path_val;

		clickhouse_xfw.emplace();
		clickhouse_xfw->parse_from_ptree(*node);
	}
}

void
TfwLoggerConfig::validate() const
{
	if (clickhouse_mmap)
		clickhouse_mmap->validate();

	if (clickhouse_xfw)
		clickhouse_xfw->validate();
}

std::optional<TfwLoggerConfig>
TfwLoggerConfig::load_from_file(const fs::path &path)
try {
	if (!fs::exists(path)) {
		std::cerr << "Config file not found: " << path << std::endl;
		return std::nullopt;
	}

	TfwLoggerConfig config;
	pt::ptree tree;
	pt::read_json(path.string(), tree);
	config.parse_from_ptree(tree);
	return config;
} catch (const pt::json_parser_error &e) {
	std::cerr << "Error parsing config file: " << e.what()
		  << std::endl;
	return std::nullopt;
} catch (const pt::ptree_error &e) {
	std::cerr << "Error in config structure: " << e.what()
		  << std::endl;
	return std::nullopt;
} catch (const std::exception &e) {
	std::cerr << "Error loading config: " << e.what() << std::endl;
	return std::nullopt;
}
