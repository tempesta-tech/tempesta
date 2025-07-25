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

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

#include <boost/property_tree/ptree_fwd.hpp>

#include "clickhouse_config.hh"

namespace fs = std::filesystem;

/**
 * Configuration for Tempesta FW Logger.
 *
 * This class handles loading configuration from JSON files and provides
 * methods to override settings from command line arguments.
 */
class TfwLoggerConfig
{
public:
	/**
	 * Default constructor.
	 */
	TfwLoggerConfig() = default;

	/**
	 * Get minimum buffer size constant.
	 */
	static constexpr size_t
	get_min_buffer_size() noexcept
	{
		return MIN_BUFFER_SIZE;
	}

	/**
	 * Load configuration from a JSON file.
	 *
	 * @param path JSON configuration file path
	 * @return Configuration object if successful, empty optional on error
	 */
	static std::optional<TfwLoggerConfig>
	load_from_file(const fs::path &path);

	// Getters
	const fs::path &
	get_log_path() const
	{
		return log_path_;
	}

	size_t
	get_buffer_size() const
	{
		return buffer_size_;
	}

	const ClickHouseConfig &
	get_clickhouse() const
	{
		return clickhouse_;
	}

	// Override methods for command line arguments
	void
	override_log_path(const fs::path &path)
	{
		log_path_ = path;
	}

	void
	override_buffer_size(size_t size)
	{
		buffer_size_ = size;
	}

	void
	override_clickhouse_host(const std::string &host)
	{
		clickhouse_.host = host;
	}

	void
	override_clickhouse_port(uint16_t port)
	{
		clickhouse_.port = port;
	}

	void
	override_clickhouse_db_name(const std::string &db_name)
	{
		clickhouse_.db_name = db_name;
	}

	void
	override_clickhouse_table(const std::string &table)
	{
		clickhouse_.table_name = table;
	}

	void
	override_clickhouse_user(const std::string &user)
	{
		clickhouse_.user = user;
	}

	void
	override_clickhouse_password(const std::string &password)
	{
		clickhouse_.password = password;
	}

	void
	override_clickhouse_max_events(size_t events)
	{
		clickhouse_.max_events = events;
	}

	void
	override_clickhouse_max_wait(int ms)
	{
		clickhouse_.max_wait = std::chrono::milliseconds(ms);
	}

private:
	// Minimum buffer size (one memory page)
	static constexpr size_t MIN_BUFFER_SIZE = 4096;

	// Log file path - default set in tfw_logger.cc
	fs::path log_path_;
	// mmap buffer size (4MB default)
	size_t buffer_size_{4 * 1024 * 1024};
	// ClickHouse connection settings
	ClickHouseConfig clickhouse_;

	/**
	 * Parse configuration from property tree (loaded from JSON).
	 *
	 * @param tree Property tree containing configuration
	 * @throws std::runtime_error on invalid configuration values
	 */
	void
	parse_from_ptree(const boost::property_tree::ptree &tree);
};
