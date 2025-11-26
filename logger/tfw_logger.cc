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
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include <boost/program_options.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#include "../libtus/pidfile.hh"
#include "../libtus/error.hh"
#include "plugin.hh"
#include "tfw_logger_config.hh"

namespace po = boost::program_options;

namespace {

constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr char pid_file_path[] = "/var/run/tfw_logger.pid";
constexpr char default_config_path[] = "/etc/tempesta/tfw_logger.json";
constexpr char default_log_path[] = "/var/log/tempesta/tfw_logger.log";
constexpr std::chrono::seconds wait_for_dev{1};

std::atomic<bool> stop_flag{false};
TfwLoggerConfig config;

/**
 * Command line options structure
 */
struct ParsedOptions {
	bool				help = false;
	bool				stop_daemon = false;
	bool				foreground = false;
	bool				test_config = false;

	std::optional<fs::path>		config_path;

	std::optional<std::string>	mmap_clickhouse_host;
	std::optional<uint16_t>		mmap_clickhouse_port;
	std::optional<std::string>	mmap_clickhouse_db_name;
	std::optional<std::string>	mmap_clickhouse_table;
	std::optional<std::string>	mmap_clickhouse_user;
	std::optional<std::string>	mmap_clickhouse_password;
	std::optional<size_t>		mmap_clickhouse_max_events;

	std::optional<std::string>	xfw_clickhouse_host;
	std::optional<uint16_t>		xfw_clickhouse_port;
	std::optional<std::string>	xfw_clickhouse_db_name;
	std::optional<std::string>	xfw_clickhouse_table;
	std::optional<std::string>	xfw_clickhouse_user;
	std::optional<std::string>	xfw_clickhouse_password;
	std::optional<size_t>		xfw_clickhouse_max_events;

	std::optional<fs::path>		log_path;
};

static const bool FORCE = true;
static const bool NOT_FORCE = false;

// All processors must be non-null
void
event_loop(std::vector<std::unique_ptr<IPluginProcessor>> &&processors) noexcept
{
	// Read from the ring buffer in polling mode and sleep only if POLL_N tries
	// in a row were unsuccessful. We sleep for 1ms - theoretically we might
	// get up to 1000 records during the delay in the buffer, which is fine
	// with our defaults.
	//
	// TODO #2442: this can be improved with true kernel sleep like perf does
	// on it's events ring buffer.
	//
	// It is hard to balance all the factors. For small events, e.g. produced
	// with basic load generator, Clickhouse behave the best with batches of
	// size 100k (about several megabytes of raw data). However, these large
	// batches introduce higher delays on commit(), so we starting to get
	// dropped events. We need to increase mmap_log_buffer_size. Next, we
	// can have quite a different number of worker threads, so Clickhouse
	// may knee under such a load. I made a basic performance test and with
	// the current POLL_N I saw relatively low number of force commits.
	constexpr size_t POLL_N = 10;
	constexpr std::chrono::milliseconds delay(1);

	std::vector<std::unique_ptr<IPluginProcessor>> inactive_processors;
	for (size_t tries = 0; ; ) {
		if (stop_flag.load(std::memory_order_acquire)) [[unlikely]] {
			// Notify the processors that the daemong is done
			// now no new events will be pushed to the buffer
			// and we can process the rest of the events.
			for (auto& processor : processors)
				processor->request_stop();
		}

		bool consumed_something = false;
		for (auto it = processors.begin(); it != processors.end(); ) {
			auto& processor = *it;
			size_t consumed = 0;
			const int err = processor->consume(&consumed);
			if (err) [[unlikely]] {
				spdlog::error("Processor {} error: {}",
					processor->name(),
					tus::make_error_code_from_int(err).message());
       				++it;
				continue;
			}

			if (consumed) {
				consumed_something = true;
			}
			else {
				// Some of the processors finished their job
				// and we already read all their data.
				if (!processor->is_active()) {
        				inactive_processors.push_back(std::move(*it));
					it = processors.erase(it);
				} else {
					++it;
				}
			}
		}

		if (consumed_something) [[likely]] {
			tries = 0;
			for (auto& processor : processors)
				processor->send(NOT_FORCE);
			continue;
		}

		if (processors.empty()) {
			spdlog::info("All processors finished their jobs, nothing to do");
			stop_flag.store(true, std::memory_order_release);
			return;
		}

		if (++tries < POLL_N) {
			// Several tries with small sleeping to let the kernel
			// fill the buffer and not to consume CPU in vain.
			std::this_thread::sleep_for(delay);
		}
		else {
			// There were nothing to do for POLL_Nms and probably
			// the system is just idle - good time to flush all
			// clollected data:
			// 1. we have no work now, so it's a good time to do
			//    some housekeeping;
			// 2. free resources for possible spike - we likely miss
			//    events while we're flushing a full buffer;
			// 3. No need to track wait time before sync explicitly -
			//    if we have a stream of events, we flush on full
			//    buffer, once we get a real time delay, we flush to
			//    the database.
			for (auto& processor : processors)
				processor->send(FORCE);
			// We don't have any indication that the processor
			// can be removed at all. During system idle time,
			// it's fine if we do some extra work.
			for (auto& processor : inactive_processors)
				processor->send(FORCE);

			tries = 0;
		}
	}

	std::unreachable();
}

void
run_thread(const unsigned worker_id, const std::vector<Plugin>& plugins) noexcept
{
	cpu_set_t cpuset;
	int r;
	unsigned cpu_id = worker_id;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu_id, &cpuset);
	r = pthread_setaffinity_np(pthread_self(),
				   sizeof(cpu_set_t), &cpuset);
	if (r != 0) {
		spdlog::error("Failed to set CPU affinity");
		stop_flag.store(true, std::memory_order_release);
		return;
	}
	spdlog::debug("Worker {} bound to CPU {}", worker_id, cpu_id);

	std::vector<std::unique_ptr<IPluginProcessor>> processors;
	try {
		processors.reserve(plugins.size());

		for (const auto& plugin : plugins) {
			auto processor = plugin.create_processor(cpu_id);
			processors.emplace_back(std::move(processor));
		}
	}
	catch(const tus::Exception &e) {
		spdlog::error("Worker {} stopped: {}", worker_id, e.what());
		return;
	}
	catch(std::bad_alloc& e) {
		spdlog::error("Worker {} stopped: {}", worker_id, e.what());
		return;
	}

	event_loop(std::move(processors));

	spdlog::debug("Worker {} stopped", worker_id);
}

// Signal handling
void
sig_handler([[maybe_unused]] int sig_num) noexcept
{
	stop_flag.store(true, std::memory_order_release);
}

void
setup_signal_handlers()
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGTERM);

	sa.sa_handler = sig_handler;
	sa.sa_flags = SA_RESTART;

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

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
		("mmap-host,H", po::value<std::string>(),
		 "Mmap plugin ClickHouse host (overrides config)")
		("mmap-port,P", po::value<uint16_t>(),
		 "Mmap plugin ClickHouse port (overrides config)")
		("mmap-database,d", po::value<std::string>(),
		 "Mmap plugin ClickHouse database name (overrides config)")
		("mmap-table,t", po::value<std::string>(),
		 "Mmap plugin ClickHouse table name (overrides config)")
		("mmap-user,u", po::value<std::string>(),
		 "Mmap plugin ClickHouse username (overrides config)")
		("mmap-password,p", po::value<std::string>(),
		 "Mmap plugin ClickHouse password (overrides config)")
		("mmap-max-events", po::value<size_t>(),
		 "Mmap plugin maximum events before commit (overrides config)")

		("xfw-host", po::value<std::string>(),
		 "Xfw plugin ClickHouse host (overrides config)")
		("xfw-port", po::value<uint16_t>(),
		 "Xfw plugin ClickHouse port (overrides config)")
		("xfw-database", po::value<std::string>(),
		 "Xfw plugin ClickHouse database name (overrides config)")
		("xfw-table", po::value<std::string>(),
		 "Xfw plugin ClickHouse table name (overrides config)")
		("xfw-user", po::value<std::string>(),
		 "Xfw plugin ClickHouse username (overrides config)")
		("xfw-password", po::value<std::string>(),
		 "Xfw plugin ClickHouse password (overrides config)")
		("xfw-max-events", po::value<size_t>(),
		 "Xfw plugin maximum events before commit (overrides config)")

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
		std::cout << "  tfw_logger --mmap-host localhost --mmap-table "
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

	if (vm.count("mmap-host"))
		result.mmap_clickhouse_host = vm["mmap-host"].as<std::string>();
	if (vm.count("mmap-port"))
		result.mmap_clickhouse_port = vm["mmap-port"].as<uint16_t>();
	if (vm.count("mmap-database"))
		result.mmap_clickhouse_db_name = vm["mmap-database"].as<std::string>();
	if (vm.count("mmap-table"))
		result.mmap_clickhouse_table = vm["mmap-table"].as<std::string>();
	if (vm.count("mmap-user"))
		result.mmap_clickhouse_user = vm["mmap-user"].as<std::string>();
	if (vm.count("mmap-password"))
		result.mmap_clickhouse_password = vm["mmap-password"].as<std::string>();
	if (vm.count("mmap-max-events"))
		result.mmap_clickhouse_max_events = vm["mmap-max-events"].as<size_t>();

	if (vm.count("xfw-host"))
		result.xfw_clickhouse_host = vm["xfw-host"].as<std::string>();
	if (vm.count("xfw-port"))
		result.xfw_clickhouse_port = vm["xfw-port"].as<uint16_t>();
	if (vm.count("xfw-database"))
		result.xfw_clickhouse_db_name = vm["xfw-database"].as<std::string>();
	if (vm.count("xfw-table"))
		result.xfw_clickhouse_table = vm["xfw-table"].as<std::string>();
	if (vm.count("xfw-user"))
		result.xfw_clickhouse_user = vm["xfw-user"].as<std::string>();
	if (vm.count("xfw-password"))
		result.xfw_clickhouse_password = vm["xfw-password"].as<std::string>();
	if (vm.count("xfw-max-events"))
		result.xfw_clickhouse_max_events = vm["xfw-max-events"].as<size_t>();

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
		throw tus::Except("Failed to load configuration from: {}",
			     config_path.string());
	}

	config = std::move(*loaded_config);

	// Set default log path if not specified in config
	if (config.log_path.empty())
		config.log_path = fs::path(default_log_path);

	// Apply command line overrides
	if (opts.mmap_clickhouse_host || opts.mmap_clickhouse_port
	    || opts.mmap_clickhouse_db_name || opts.mmap_clickhouse_table
	    || opts.mmap_clickhouse_user || opts.mmap_clickhouse_password
	    || opts.mmap_clickhouse_max_events)
		config.clickhouse_mmap = {};
	if (opts.mmap_clickhouse_host)
		config.clickhouse_mmap->host = *opts.mmap_clickhouse_host;
	if (opts.mmap_clickhouse_port)
		config.clickhouse_mmap->port = *opts.mmap_clickhouse_port;
	if (opts.mmap_clickhouse_db_name)
		config.clickhouse_mmap->db_name = *opts.mmap_clickhouse_db_name;
	if (opts.mmap_clickhouse_table)
		config.clickhouse_mmap->table_name = *opts.mmap_clickhouse_table;
	if (opts.mmap_clickhouse_user)
		config.clickhouse_mmap->user = *opts.mmap_clickhouse_user;
	if (opts.mmap_clickhouse_password)
		config.clickhouse_mmap->password = *opts.mmap_clickhouse_password;
	if (opts.mmap_clickhouse_max_events)
		config.clickhouse_mmap->max_events = *opts.mmap_clickhouse_max_events;

	if (opts.xfw_clickhouse_host || opts.xfw_clickhouse_port
	    || opts.xfw_clickhouse_db_name || opts.xfw_clickhouse_table
	    || opts.xfw_clickhouse_user || opts.xfw_clickhouse_password
	    || opts.xfw_clickhouse_max_events)
		config.clickhouse_mmap = {};
	if (opts.xfw_clickhouse_host)
		config.clickhouse_xfw->host = *opts.xfw_clickhouse_host;
	if (opts.xfw_clickhouse_port)
		config.clickhouse_xfw->port = *opts.xfw_clickhouse_port;
	if (opts.xfw_clickhouse_db_name)
		config.clickhouse_xfw->db_name = *opts.xfw_clickhouse_db_name;
	if (opts.xfw_clickhouse_table)
		config.clickhouse_xfw->table_name = *opts.xfw_clickhouse_table;
	if (opts.xfw_clickhouse_user)
		config.clickhouse_xfw->user = *opts.xfw_clickhouse_user;
	if (opts.xfw_clickhouse_password)
		config.clickhouse_xfw->password = *opts.xfw_clickhouse_password;
	if (opts.xfw_clickhouse_max_events)
		config.clickhouse_xfw->max_events = *opts.xfw_clickhouse_max_events;

	if (opts.log_path)
		config.log_path = *opts.log_path;

	config.validate();
}

void
setup_daemon_mode(const ParsedOptions &opts)
{
	// Check if daemon is already running
	int ret = tus::pidfile_check(pid_file_path);
	if (ret < 0)
		throw tus::Except("PID file checking failed");

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
#ifdef DEBUG
		std::cout << "Daemonizing..." << std::endl;
#endif

		if (daemon(0, 0) < 0)
			throw tus::Except("Daemonization failed");
	}
}

void
initialize_logging()
try {
	// Create log directory if needed
	fs::create_directories(config.log_path.parent_path());

	auto logger = spdlog::basic_logger_mt("event_logger",
					      config.log_path.string());
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
catch (const spdlog::spdlog_ex &ex) {
	throw tus::Except("Log initialization failed: {}", ex.what());
}

void
execute_workers() noexcept(false)
{
	StopFlag fstop{
		.stop_requested = []() -> int {
			return stop_flag.load(std::memory_order_relaxed);
		},
		.request_stop   = []() {
			stop_flag.store(1, std::memory_order_relaxed);
		}
	};

	std::vector<Plugin> plugins;
	plugins.reserve(2);
	//TODO: we don't need to separate different types of plugin in config
	if (config.clickhouse_mmap.has_value()) {
		if (!config.access_log_plugin_path.has_value()) {
			spdlog::error("Empty path for access log plugin");
			return;
		}
		const std::string plugin_path = config.access_log_plugin_path.value();
		plugins.emplace_back(plugin_path,
				     *config.clickhouse_mmap,
				     &fstop);
		spdlog::info("Loaded mmap plugin from: {}", plugin_path);
	}

	if (config.clickhouse_xfw.has_value()) {
		if (!config.xfw_events_plugin_path.has_value()) {
			spdlog::error("Empty path for xfw events plugin");
			return;
		}
		const std::string plugin_path =	config.xfw_events_plugin_path.value();
		plugins.emplace_back(plugin_path,
				     *config.clickhouse_xfw,
				     &fstop);
		spdlog::info("Loaded xfw plugin from: {}", plugin_path);
	}

	if (plugins.empty()) {
		spdlog::error("No plugins configured");
		return;
	}

	/*
	 * Use sysconf() instead of std::thread::hardware_concurrency() because
	 * it respects process CPU affinity, cgroups, and container limits,
	 * is more reliable on NUMA systems and machines with 100+ CPUs while
	 * hardware_concurrency() is just a "hint".
	 */
	auto cpu_count = static_cast<size_t>(sysconf(_SC_NPROCESSORS_ONLN));
	if (cpu_count <= 0)
		throw tus::Except("Cannot determine CPU count");

	spdlog::info("Using {} CPU(s)", cpu_count);
	spdlog::info("Starting {} worker threads", cpu_count);

	// Start worker threads
	std::vector<std::thread> threads;
	for (size_t i = 0; i < cpu_count; ++i)
		threads.emplace_back(run_thread, static_cast<unsigned>(i), std::cref(plugins));

	spdlog::info("All {} worker threads started", cpu_count);

	for (auto &t : threads) {
		if (t.joinable())
			t.join();
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
	int pidfile_fd = -1;

	// Parse command line options
	auto opts = parse_command_line(argc, argv);

	// Handle simple commands that don't need full setup
	if (opts.help)
		return 0; // Help was already shown

	if (opts.stop_daemon) {
		tus::pidfile_stop_daemon(pid_file_path);
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
	pidfile_fd = tus::pidfile_create(pid_file_path);
	if (pidfile_fd < 0)
		throw tus::Except("Cannot create PID file");

	// Log startup information
	spdlog::info("Starting Tempesta FW Logger...");
	if (config.clickhouse_mmap)
		spdlog::info("ClickHouse mmap configuration: {}",
			     *config.clickhouse_mmap);

	// Setup signal handlers for graceful shutdown
	setup_signal_handlers();

	spdlog::info("Daemon started");

	// Start workers and wait for them to finish
	execute_workers();

	spdlog::info("Tempesta FW Logger stopped");

	if (pidfile_fd >= 0) {
		tus::pidfile_remove(pid_file_path, pidfile_fd);
		spdlog::info("PID file removed");
	}

	return 0;
} catch (const tus::Exception &e) {
	if (spdlog::default_logger())
		spdlog::error("Fatal error: {}", e.what());
	else
		std::cerr << "Error: " << e.what() << std::endl;
	return 1;
} catch (const std::exception &e) {
	if (spdlog::default_logger())
		spdlog::error("Unhandled exception: {}", e.what());
	else
		std::cerr << "Unhandled error: " << e.what() << std::endl;
	return 2;
}

/*
 * Exporting logging routings from main for using in plugins instead of
 * homegrown plugin only logging routings.
 */
extern "C" {

__attribute__((visibility("default")))
void plugin_log_debug(const char* message) {
	spdlog::debug("{}", message);
}

__attribute__((visibility("default")))
void plugin_log_info(const char* message) {
	spdlog::info("{}", message);
}

__attribute__((visibility("default")))
void plugin_log_warn(const char* message) {
	spdlog::warn("{}", message);
}

__attribute__((visibility("default")))
void plugin_log_error(const char* message) {
	spdlog::error("{}", message);
}

} // extern "C"
