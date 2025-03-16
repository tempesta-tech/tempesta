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

#include <string>
#include <chrono>
#include <filesystem>
#include <optional>
#include <boost/property_tree/ptree.hpp>

namespace fs = std::filesystem;

/**
 * Configuration for Tempesta FW Logger
 */
class TfwLoggerConfig
{
public:
  enum class Mode
  {
    DAEMON, // Run as a daemon
    HANDLE  // Run in foreground for debugging
  };

  struct ClickHouseConfig
  {
    std::string host;                        // ClickHouse server host
    uint16_t port{9000};                     // ClickHouse server port
    std::optional<std::string> user;         // Optional username
    std::optional<std::string> password;     // Optional password
    std::string table_name{"access_log"};    // Table name
    std::string database{"default"};         // Database name
    size_t max_events{1000};                 // Maximum events in a batch
    std::chrono::milliseconds max_wait{100}; // Maximum wait time for batch
  };

  /**
   * Load configuration from a JSON file
   *
   * @param path Path to the configuration file
   * @return Loaded configuration or empty optional on error
   */
  static std::optional<TfwLoggerConfig> load_from_file(const fs::path &path);

  /**
   * Create configuration from command line arguments
   * Used for quick setup and testing
   */
  static TfwLoggerConfig from_cli_args(int argc, char *argv[]);

  /**
   * Write configuration to a file
   *
   * @param path Path to the configuration file
   * @return True if successful, false otherwise
   */
  bool save_to_file(const fs::path &path) const;

  // Getters
  Mode get_mode() const { return mode; }
  fs::path get_log_path() const { return log_path; }
  fs::path get_pid_file() const { return pid_file; }
  size_t get_buffer_size() const { return buffer_size; }
  size_t get_cpu_count() const { return cpu_count; }
  const ClickHouseConfig &get_clickhouse() const { return clickhouse; }
  bool get_debug() const { return debug; }

private:
  Mode mode{Mode::DAEMON};                               // Default to daemon mode
  fs::path log_path{"/var/log/tempesta/tfw_logger.log"}; // Log file path
  fs::path pid_file{"/var/run/tfw_logger.pid"};          // PID file path
  size_t buffer_size{4 * 1024 * 1024};                   // 4MB default buffer size
  size_t cpu_count{0};                                   // 0 means auto-detect
  ClickHouseConfig clickhouse;                           // ClickHouse configuration
  bool debug{false};                                     // Debug mode flag

  void parse_from_ptree(const boost::property_tree::ptree &pt);
};
