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
#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>

#include "../fw/access_log.h"
#include "../libtus/pidfile.hh"
#include "../libtus/error.hh"
#include "clickhouse.hh"
#include "mmap_buffer.hh"
#include "tfw_logger_config.hh"

namespace po = boost::program_options;

static constexpr int TFW_PLUGIN_COMPATIBLE_VERSION = 1;
constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr char pid_file_path[] = "/var/run/tfw_logger.pid";
constexpr char default_config_path[] = "/etc/tempesta/tfw_logger.json";
constexpr char default_log_path[] = "/var/log/tempesta/tfw_logger.log";
constexpr std::chrono::seconds wait_for_dev{1};

// Global state
static std::atomic<bool> stop_flag{false};
static TfwLoggerConfig config;

namespace {

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
	std::optional<fs::path>		log_path;
};

#ifdef DEBUG
void
dbg_hexdump(std::span<const char> data)
{
	const auto *buf = reinterpret_cast<const unsigned char *>(data.data());
	const size_t buflen = data.size();
	std::ostringstream oss;

	oss << "data dump of len=" << buflen << std::endl;
	oss << std::hex << std::setfill('0');
	for (size_t i = 0; i < buflen; i += 16) {
		oss << std::setw(6) << i << ": ";

		for (int j = 0; j < 16; ++j)
			if (i + j < buflen)
				oss << std::setw(2)
				    << static_cast<unsigned>(buf[i + j]) << " ";
			else
				oss << "   ";
		oss << " ";
		for (int j = 0; j < 16; ++j) {
			if (i + j >= buflen)
				break;
			const char c = buf[i + j];
			oss << static_cast<char>(std::isprint(c) ? c : '.');
		}
		oss << std::endl;
	}
	spdlog::info("{}", oss.str());
}
#else
void
dbg_hexdump([[maybe_unused]] std::span<const char> data)
{
}
#endif /* DEBUG */

void
run_thread(const int ncpu, const int fd, const TfwLoggerConfig &config) noexcept
{
	// The most Clickhouse API errors can be handled with simple connection
	// reset and reconnection
	//
	//   https://github.com/ClickHouse/clickhouse-cpp/issues/184
	//
	// We start with zero reconnection timeout. However, the database can
	// be restarted, so we use indefinite loop with double backoff in
	// reconnection attempts.
	std::chrono::seconds reconnect_timeout(0);

	cpu_set_t cpuset;
	bool affinity_is_set = false;
	int r;

	while (!stop_flag.load(std::memory_order_acquire))
	try {
		const auto &mmap_cfg = config.clickhouse_mmap;
		const auto &mmap_cfg = config.clickhouse_xfw;
		spdlog::debug("Worker {} connecting to ClickHouse: {}",
			      ncpu, ch_cfg);

		TfwClickhouse db(ch_cfg);
		auto cb = [&db](std::span<const char> data) {
			return process_events(db, data);
		};
		TfwMmapBufferReader mbr(ncpu, fd, db, std::move(cb));

		if (!affinity_is_set) {
			CPU_ZERO(&cpuset);
			CPU_SET(mbr.get_cpu_id(), &cpuset);
			r = pthread_setaffinity_np(pthread_self(),
						   sizeof(cpu_set_t), &cpuset);
			if (r != 0)
				throw tus::Except("Failed to set CPU affinity");
			affinity_is_set = true;
			spdlog::debug("Worker {} bound to CPU {}", ncpu,
				      mbr.get_cpu_id());
		}

		// At this moment we were able to connect to Clickhouse.
		reconnect_timeout = std::chrono::seconds(0);

		if (mbr.run(stop_flag))
			break;
		// ...else, reset the Clickhouse connection.
	}
	catch (const tus::Exception &e) {
		spdlog::error("Critical error: {}", e.what());
		break;
	}
	catch (const std::exception &e) {
		spdlog::error("A Clickhouse exception caught: {}."
			      " Reset connection and reconnect in {}s.",
			      e.what(), reconnect_timeout.count());
		if (reconnect_timeout == std::chrono::seconds{0}) {
			std::this_thread::sleep_for(reconnect_timeout);
			reconnect_timeout *= 2;
		} else {
			reconnect_timeout = std::chrono::seconds(1);
		}
	}

	spdlog::debug("Worker {} stopped", ncpu);
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

	auto logger = spdlog::basic_logger_mt("access_logger",
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
spdlog_vlog(spdlog::level::level_enum level, const char* format, va_list args)
{
	assert(format);

	std::shared_ptr<spdlog::logger> logger = spdlog::default_logger();
	fmt::format_args fmt_args = fmt::basic_format_args(args);

	logger->log(level, fmt::string_view(format), fmt_args);
}

void
run_main_loop()
{
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
		threads.emplace_back(run_thread, static_cast<int>(i), fd,
							 std::ref(config));

	spdlog::info("All {} worker threads started", cpu_count);

	for (auto &t : threads) {
		if (t.joinable())
			t.join();
	}
}

class PluginManager {
public:
	PluginManager() = default;

	bool load_plugin(const std::string& plugin_path) {
		handle_ = dlopen(plugin_path.c_str(),
				 RTLD_LAZY | RTLD_LOCAL | RTLD_DEEPBIND);
		if (!handle_) {
			spdlog::error("Cannot load plugin '{}': {}",
				      plugin_path, dlerror());
			return false;
		}
	}

		auto get_api_func =
			(TfwLoggerPluginApiFunc)dlsym(handle_,
						      "tfw_logger_plugin_get_api");
		if (!get_api_func) {
			spdlog::error("Plugin '{}' does not export api function",
				      plugin_path);
			return false;
		}

		api_ = get_api_func();
		if (!api_) {
			spdlog::error("Plugin '{}' returned invalid api",
				      plugin_path);
			return false;
		}

		if (api_->version != TFW_PLUGIN_COMPATIBLE_VERSION) {
			spdlog::error("Plugin '{}' version: expected {}, got {}",
				      plugin_path, TFW_PLUGIN_COMPATIBLE_VERSION,
				      api_->version);
			return false;
		}

		spdlog::info("Loaded plugin: {}", api_->name);
		return true;
	}

	TfwLoggerPluginApi* get_api() { return api_; }
	const char* get_name() { return api_ ? api_->name : "unknown"; }

	~PluginManager() {
		if (api_ && api_->done)
			api_->done();

		if (handle_)
			dlclose(handle_);
	}

private:
	void			*handle_ = nullptr;
	TfwLoggerPluginApi	*api_ = nullptr;
};

} // anonymous namespace

/**
 * Main entry point for Tempesta FW Logger.
 * Supports both daemon and foreground modes for flexibility.
 */
int
main(int argc, char *argv[])
try {
	int fd = -1;
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
	spdlog::info("ClickHouse configuration: {}", config.clickhouse);

	// Setup signal handlers for graceful shutdown
	setup_signal_handlers();

	spdlog::info("Daemon started");

	// Run main processing loop
	run_main_loop();

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
void plugin_log_debug(const char* format, ...) {
	va_list args;
	va_start(args, format);
	spdlog_vlog(spdlog::level::debug, format, args);
	va_end(args);
}

__attribute__((visibility("default")))
void plugin_log_info(const char* format, ...) {
	va_list args;
	va_start(args, format);
	spdlog_vlog(spdlog::level::info, format, args);
	va_end(args);
}

__attribute__((visibility("default")))
void plugin_log_warn(const char* format, ...) {
	va_list args;
	va_start(args, format);
	spdlog_vlog(spdlog::level::warn, format, args);
	va_end(args);
}

__attribute__((visibility("default")))
void plugin_log_error(const char* format, ...) {
	va_list args;
	va_start(args, format);
	spdlog_vlog(spdlog::level::error, format, args);
	va_end(args);
}

} // extern "C"
