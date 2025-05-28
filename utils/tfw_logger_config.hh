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

#include <boost/property_tree/ptree.hpp>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

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
	struct ClickHouseConfig {
		std::string host{"localhost"};           // ClickHouse server hostname
		uint16_t port{9000};                     // ClickHouse native protocol port
		std::string table_name{"access_log"};   // ClickHouse table name
		std::optional<std::string> user;         // Optional username for authentication
		std::optional<std::string> password;     // Optional password for authentication
		size_t max_events{1000};                 // Number of events before forcing commit
		std::chrono::milliseconds max_wait{100}; // Maximum time before forcing commit
	};

	/**
	 * Default constructor.
	 */
	TfwLoggerConfig() = default;

	/**
	 * Load configuration from a JSON file.
	 *
	 * @param path JSON configuration file path
	 * @return Configuration object if successful, empty optional on error
	 */
	static std::optional<TfwLoggerConfig> load_from_file(const fs::path &path);

	// Getters
	const fs::path& get_log_path() const { return log_path_; }
	size_t get_buffer_size() const { return buffer_size_; }
	size_t get_cpu_count() const { return cpu_count_; }
	const ClickHouseConfig& get_clickhouse() const { return clickhouse_; }

	// Override methods for command line arguments
	void override_log_path(const fs::path& path) { log_path_ = path; }
	void override_buffer_size(size_t size) { buffer_size_ = size; }
	void override_cpu_count(size_t count) { cpu_count_ = count; }
	void override_clickhouse_host(const std::string& host) { clickhouse_.host = host; }
	void override_clickhouse_port(uint16_t port) { clickhouse_.port = port; }
	void override_clickhouse_table(const std::string& table) { clickhouse_.table_name = table; }
	void override_clickhouse_user(const std::string& user) { clickhouse_.user = user; }
	void override_clickhouse_password(const std::string& password) { clickhouse_.password = password; }
	void override_clickhouse_max_events(size_t events) { clickhouse_.max_events = events; }
	void override_clickhouse_max_wait(int ms) { clickhouse_.max_wait = std::chrono::milliseconds(ms); }

private:
	fs::path log_path_;                          // Log file path - default set in tfw_logger.cc
	size_t buffer_size_{4 * 1024 * 1024};       // mmap buffer size (4MB default)
	size_t cpu_count_{0};                        // 0 means auto-detect
	ClickHouseConfig clickhouse_;                // ClickHouse connection settings

	/**
	 * Parse configuration from property tree (loaded from JSON).
	 *
	 * @param tree Property tree containing configuration
	 * @throws std::runtime_error on invalid configuration values
	 */
	void parse_from_ptree(const boost::property_tree::ptree &tree);
};
