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
#include <sstream>

#include <boost/property_tree/json_parser.hpp>

#include "error.hh"

namespace pt = boost::property_tree;

void
TfwLoggerConfig::parse_from_ptree(const pt::ptree &tree)
{
	// Parse paths and settings
	if (auto log_path_opt = tree.get_optional<std::string>("log_path"))
		log_path_ = *log_path_opt;

	buffer_size_ = tree.get<size_t>("buffer_size", buffer_size_);

	// Validate buffer size
	if (buffer_size_ < MIN_BUFFER_SIZE)
		throw std::runtime_error("Buffer size must be at least " +
					 std::to_string(MIN_BUFFER_SIZE) +
					 " bytes (one memory page)");

	// Parse ClickHouse configuration if present
	if (auto ch_node = tree.get_child_optional("clickhouse")) {
		clickhouse_.host =
		    ch_node->get<std::string>("host", clickhouse_.host);
		clickhouse_.port =
		    ch_node->get<uint16_t>("port", clickhouse_.port);
		clickhouse_.table_name = ch_node->get<std::string>(
		    "table_name", clickhouse_.table_name);

		// Parse optional authentication
		if (auto user = ch_node->get_optional<std::string>("user"))
			clickhouse_.user = *user;

		if (auto password =
		    ch_node->get_optional<std::string>("password"))
			clickhouse_.password = *password;

		// Parse performance settings
		clickhouse_.max_events =
		    ch_node->get<size_t>("max_events", clickhouse_.max_events);
		int max_wait_ms = ch_node->get<int>(
		    "max_wait_ms",
		    static_cast<int>(clickhouse_.max_wait.count()));
		if (max_wait_ms < 0)
			throw std::runtime_error(
			    "max_wait_ms must be non-negative");

		clickhouse_.max_wait = std::chrono::milliseconds(max_wait_ms);
	}

	// Validate ClickHouse settings
	if (clickhouse_.host.empty())
		throw std::runtime_error("ClickHouse host cannot be empty");

	if (clickhouse_.port == 0)
		throw std::runtime_error("Invalid ClickHouse port");

	if (clickhouse_.table_name.empty())
		throw std::runtime_error("ClickHouse table name cannot be empty");

	if (clickhouse_.max_events == 0)
		throw std::runtime_error("max_events must be greater than 0");
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
