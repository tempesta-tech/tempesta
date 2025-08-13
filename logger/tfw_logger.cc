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

#include <stdio.h>
#include <unistd.h>

#include <chrono>
#include <iostream>

#include <boost/program_options.hpp>

#include <spdlog/common.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/dup_filter_sink.h>
#include <spdlog/spdlog.h>

#include "main_loop.hh"
#include "pidfile.hh"
#include "signal_handler.hh"
#include "tfw_logger_config.hh"

namespace po = boost::program_options;

namespace
{

constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr char pid_file_path[] = "/var/run/tfw_logger.pid";
constexpr char default_config_path[] = "/etc/tempesta/tfw_logger.json";
constexpr char default_log_path[] = "/var/log/tempesta/tfw_logger.log";

// Global state
static TfwLoggerConfig config;

/**
 * Command line options structure
 */
struct ParsedOptions {
	bool				help = false;
	bool				stop_daemon = false;
	bool				foreground = false;
	bool				test_config = false;

	std::optional<fs::path>		config_path;
	std::optional<std::string>	clickhouse_host;
	std::optional<uint16_t>		clickhouse_port;
	std::optional<std::string>	clickhouse_db_name;
	std::optional<std::string>	clickhouse_table;
	std::optional<std::string>	clickhouse_user;
	std::optional<std::string>	clickhouse_password;
	std::optional<size_t>		clickhouse_max_events;
	std::optional<int>		clickhouse_max_wait_ms;
	std::optional<fs::path>		log_path;
};

// Configuration handling
ParsedOptions
parse_command_line(int argc, char *argv[])
try {
	ParsedOptions result;
	po::options_description desc("Tempesta FW Logger options");

	// Create description string for config option
	std::string config_desc = "Path to configuration file (default: " +
				  std::string(default_config_path) + ")";

	desc.add_options()
		("help,h", po::bool_switch(&result.help),
		 "Show this help message and exit")
		("stop,s", po::bool_switch(&result.stop_daemon),
		 "Stop the daemon")
		("foreground,f", po::bool_switch(&result.foreground),
		 "Run in foreground (do not daemonize)")
		("test-config", po::bool_switch(&result.test_config),
		 "Test configuration file and exit")
		("config,c", po::value<fs::path>(), config_desc.c_str())
		("host,H", po::value<std::string>(),
		 "ClickHouse host (overrides config)")
		("port,P", po::value<uint16_t>(),
		 "ClickHouse port (overrides config)")
		("database,d", po::value<std::string>(),
		 "ClickHouse database name (overrides config)")
		("table,t", po::value<std::string>(),
		 "ClickHouse table name (overrides config)")
		("user,u", po::value<std::string>(),
		 "ClickHouse username (overrides config)")
		("password,p", po::value<std::string>(),
		 "ClickHouse password (overrides config)")
		("max-events", po::value<size_t>(),
		 "Maximum events before commit (overrides config)")
		("max-wait", po::value<int>(),
		 "Maximum wait time in ms before commit (overrides config)")
		("log-path,l", po::value<fs::path>(),
		 "Path to log file (overrides config)");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (result.help) {
		std::cout << "Usage: tfw_logger [options]" << std::endl
			  << std::endl;
		std::cout << desc << std::endl;
		std::cout << "\nExamples:" << std::endl;
		std::cout << "  tfw_logger --config " << default_config_path
			  << std::endl;
		std::cout << "  tfw_logger --host localhost --table "
			     "access_log_v2"
			  << std::endl;
		std::cout << "  tfw_logger --stop" << std::endl;
		std::cout << "  tfw_logger --foreground --config "
			     "/tmp/test_config.json"
			  << std::endl;
		std::cout << "  tfw_logger --test-config --config "
			     "/path/to/config.json"
			  << std::endl;
		return result;
	}

	// Extract option values
	if (vm.count("config"))
		result.config_path = vm["config"].as<fs::path>();
	if (vm.count("host"))
		result.clickhouse_host = vm["host"].as<std::string>();
	if (vm.count("port"))
		result.clickhouse_port = vm["port"].as<uint16_t>();
	if (vm.count("database"))
		result.clickhouse_db_name = vm["database"].as<std::string>();
	if (vm.count("table"))
		result.clickhouse_table = vm["table"].as<std::string>();
	if (vm.count("user"))
		result.clickhouse_user = vm["user"].as<std::string>();
	if (vm.count("password"))
		result.clickhouse_password = vm["password"].as<std::string>();
	if (vm.count("max-events"))
		result.clickhouse_max_events = vm["max-events"].as<size_t>();
	if (vm.count("max-wait"))
		result.clickhouse_max_wait_ms = vm["max-wait"].as<int>();
	if (vm.count("log-path"))
		result.log_path = vm["log-path"].as<fs::path>();

	return result;
}
catch (const po::error &e) {
	std::cerr << "Error: " << e.what() << std::endl;
	std::cerr << "Use --help for usage information" << std::endl;
	exit(1);
}

void
load_configuration(const ParsedOptions &opts)
{
	fs::path config_path =
	    opts.config_path.value_or(fs::path(default_config_path));

	auto loaded_config = TfwLoggerConfig::load_from_file(config_path);
	if (!loaded_config) {
		throw std::runtime_error(
			fmt::format("Failed to load configuration from: {}",
				    config_path.string()));
	}

	config = std::move(*loaded_config);

	// Set default log path if not specified in config
	if (config.log_path.empty())
		config.log_path = fs::path(default_log_path);

	// Apply command line overrides
	if (opts.clickhouse_host)
		config.clickhouse.host = *opts.clickhouse_host;
	if (opts.clickhouse_port)
		config.clickhouse.port = *opts.clickhouse_port;
	if (opts.clickhouse_db_name)
		config.clickhouse.db_name = *opts.clickhouse_db_name;
	if (opts.clickhouse_table)
		config.clickhouse.table_name = *opts.clickhouse_table;
	if (opts.clickhouse_user)
		config.clickhouse.user = *opts.clickhouse_user;
	if (opts.clickhouse_password)
		config.clickhouse.password = *opts.clickhouse_password;
	if (opts.clickhouse_max_events)
		config.clickhouse.max_events = *opts.clickhouse_max_events;
	if (opts.clickhouse_max_wait_ms)
		config.clickhouse.max_wait = std::chrono::milliseconds(
			*opts.clickhouse_max_wait_ms);
	if (opts.log_path)
		config.log_path = *opts.log_path;

	config.validate();
}

void
setup_daemon_mode(const ParsedOptions &opts)
{
	// Check if daemon is already running
	int ret = pidfile_check(pid_file_path);
	if (ret < 0)
		throw std::runtime_error("PID file checking failed");

	/*
	 * When the daemon forks, it inherits the file descriptor for
	 * /tmp/tempesta-lock-file, which was originally opened and locked
	 * by flock in the tempesta.sh script. After daemonizing, the daemon
	 * process continues to hold this lock, preventing subsequent
	 * executions of tempesta.sh.
	 *
	 * Close all descriptors before daemonizing.
	 */
	closefrom(3);

	// Daemonize if not in foreground mode
	if (!opts.foreground) {
		std::cout << "Daemonizing..." << std::endl;

		if (daemon(0, 0) < 0)
			throw std::runtime_error("Daemonization failed");
	}
}

void
initialize_logging()
{
	// Create log directory if needed
	fs::create_directories(config.log_path.parent_path());

	constexpr auto max_skip_duration = std::chrono::milliseconds(100);
	constexpr auto skipped_msg_notification_lvl = spdlog::level::debug;

	auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
		config.log_path.string());
	auto dup_sink = std::make_shared<spdlog::sinks::dup_filter_sink_mt>(
		max_skip_duration, skipped_msg_notification_lvl);
	dup_sink->add_sink(file_sink);

	auto logger =
		std::make_shared<spdlog::logger>("access_logger", dup_sink);

	spdlog::set_default_logger(logger);
	spdlog::set_level(spdlog::level::info);
	logger->flush_on(spdlog::level::info);

	// Set custom log pattern to include thread ID
	// %Y-%m-%d %H:%M:%S.%e - Date and time with milliseconds
	// %n - Logger name
	// %l - Log level
	// %t - Thread ID
	// %v - Log message
	logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%l] [%t] %v");
}

void
cleanup_resources(int fd, int pidfile_fd)
{
	if (fd >= 0) {
		close(fd);
		spdlog::info("Device closed");
	}

	if (pidfile_fd >= 0) {
		pidfile_remove(pid_file_path, pidfile_fd);
		spdlog::info("PID file removed");
	}
}

} // anonymous namespace

/**
 * Main entry point for Tempesta FW Logger.
 * Supports both daemon and foreground modes for flexibility.
 */
int
main(int argc, char *argv[])
try {
	const auto opts = parse_command_line(argc, argv);

	// Handle simple commands that don't need full setup
	if (opts.help)
		return 0; // Help was already shown

	if (opts.stop_daemon) {
		pidfile_stop_daemon(pid_file_path);
		return 0;
	}

	// Load and setup configuration
	load_configuration(opts);

	// Test configuration and exit if requested
	if (opts.test_config) {
		std::cout << "Configuration file is valid" << std::endl;
		return 0;
	}

	// Setup daemon mode (check PID, close FDs, daemonize)
	setup_daemon_mode(opts);

	// Initialize logging after daemonization
	initialize_logging();

	// Create PID file after daemonization
	const int pidfile_fd = pidfile_create(pid_file_path);
	if (pidfile_fd < 0)
		throw std::runtime_error("Cannot create PID file");

	// Log startup information
	spdlog::info("Starting Tempesta FW Logger...");
	spdlog::info("ClickHouse configuration: {}", config.clickhouse);

	// Setup signal handlers for graceful shutdown
	setup_signal_handlers();

	// Open mmap device
	const auto mmap_fd = open_mmap_device(dev_path);
	if (!mmap_fd)
		return 0;

	spdlog::info("Daemon started");

	run_main_loop([mmap_fd](unsigned int ncpu) {
		std::optional<Reader> result;
		if (auto sender = make_sender(config.clickhouse))
			result.emplace(ncpu, *mmap_fd, std::move(*sender));

		return result;
	});

	spdlog::info("Tempesta FW Logger stopped");
	cleanup_resources(*mmap_fd, pidfile_fd);
	return 0;
} catch (const std::exception &e) {
	if (spdlog::default_logger())
		spdlog::error("Error: {}", e.what());
	else
		std::cerr << "Error: " << e.what() << std::endl;
	return 1;
}
