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

#include "clickhouse_config.hh"

namespace fs = std::filesystem;

struct TfwLoggerConfig {
	// Log file path - default set in tfw_logger.cc
	fs::path log_path;
	// mmap buffer size (4MB default)
	size_t buffer_size{4 * 1024 * 1024};
	// ClickHouse connection settings
	ClickHouseConfig clickhouse;

	// Minimum buffer size (one memory page)
	static constexpr size_t MIN_BUFFER_SIZE = 4096;

	/**
	 * Load configuration from a JSON file.
	 *
	 * @param path JSON configuration file path
	 * @return Configuration object if successful, empty optional on error
	 */
	static std::optional<TfwLoggerConfig>
	load_from_file(const fs::path &path);

	void
	validate() const;

	void
	parse_from_ptree(const boost::property_tree::ptree &tree);
};
