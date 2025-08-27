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
#include "clickhouse.hh"
#include "error.hh"
#include "mmap_buffer.hh"
#include "pidfile.hh"
#include "tfw_logger_config.hh"

namespace po = boost::program_options;

constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr char pid_file_path[] = "/var/run/tfw_logger.pid";
constexpr char default_config_path[] = "/etc/tempesta/tfw_logger.json";
constexpr char default_log_path[] = "/var/log/tempesta/tfw_logger.log";
constexpr std::chrono::seconds wait_for_dev{1};
constexpr std::chrono::seconds reconnect_min_timeout{1};
constexpr std::chrono::seconds reconnect_max_timeout{16};

// Global state
std::atomic<bool> stop_flag{false};
static thread_local bool uncritical_error;
static TfwLoggerConfig config;

namespace
{

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

typedef struct {
	const char			*name;
	ch::Type::Code			code;
} TfwField;

static const TfwField tfw_fields[] = {
    [TFW_MMAP_LOG_ADDR]		= {"address", ch::Type::IPv6},
    [TFW_MMAP_LOG_METHOD]	= {"method", ch::Type::UInt8},
    [TFW_MMAP_LOG_VERSION]	= {"version", ch::Type::UInt8},
    [TFW_MMAP_LOG_STATUS]	= {"status", ch::Type::UInt16},
    [TFW_MMAP_LOG_RESP_CONT_LEN] = {"response_content_length", ch::Type::UInt32},
    [TFW_MMAP_LOG_RESP_TIME]	= {"response_time", ch::Type::UInt32},
    [TFW_MMAP_LOG_VHOST]	= {"vhost", ch::Type::String},
    [TFW_MMAP_LOG_URI]		= {"uri", ch::Type::String},
    [TFW_MMAP_LOG_REFERER]	= {"referer", ch::Type::String},
    [TFW_MMAP_LOG_USER_AGENT]	= {"user_agent", ch::Type::String},
    [TFW_MMAP_LOG_JA5T]		= {"ja5t", ch::Type::UInt64},
    [TFW_MMAP_LOG_JA5H]		= {"ja5h", ch::Type::UInt64},
    [TFW_MMAP_LOG_DROPPED]	= {"dropped_events", ch::Type::UInt64}};

#ifdef DEBUG
void
dbg_hexdump( std::span<const char> data)
{
	const auto *buf = reinterpret_cast<const unsigned char *>(data.data());
	const size_t buflen = data.size();
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');

#define PRINT_CHAR(c) (std::isprint(c) ? c : '.')
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
			oss << static_cast<char>(PRINT_CHAR(buf[i + j]));
		}
		oss << std::endl;
	}
	oss << std::dec << "len = " << buflen << std::endl;
	spdlog::info("{}", oss.str());
#undef PRINT_CHAR
}
#else
void
dbg_hexdump([[maybe_unused]] std::span<const char> data)
{
}
#endif /* DEBUG */

void
log_error(std::string msg, bool to_spdlog, bool unhandled)
{
	if (unhandled)
		msg = "Unhandled error: " + msg;

	if (to_spdlog)
		spdlog::error(msg);
	else
		std::cerr << msg << std::endl;
}

ch::Block
make_block()
{
	unsigned int i;
	auto block = ch::Block();

	auto col = std::make_shared<ch::ColumnDateTime64>(3);
	block.AppendColumn("timestamp", col);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		const TfwField *field = &tfw_fields[i];
		auto col = tfw_column_factory(field->code);
		block.AppendColumn(field->name, col);
	}

	return block;
}

template <auto method, typename ColType, typename ValType>
void
read_int(ch::Block &block, const auto *event, const char *&p, size_t &size)
{
	constexpr int ind = method + 1;

	if (TFW_MMAP_LOG_FIELD_IS_SET(event, method)) {
		const size_t len = tfw_mmap_log_field_len(method);

		if (len > size) [[unlikely]]
			throw Except("Incorrect integer eventent length");

		const ValType *val = reinterpret_cast<const ValType *>(p);
		block[ind]->As<ColType>()->Append(*val);

		p += len;
		size -= len;
	} else {
		block[ind]->As<ColType>()->Append(0);
	}
}

template <auto method>
void
read_str(ch::Block &block, const auto *event, const char *&p, size_t &size)
{
	constexpr int ind = method + 1;

	if (TFW_MMAP_LOG_FIELD_IS_SET(event, method)) {
		constexpr int len_size = sizeof(uint16_t);

		if (size < len_size) [[unlikely]]
			throw Except("Too short string eventent");

		const size_t len = *reinterpret_cast<const uint16_t *>(p);
		p += len_size;
		size -= len_size;
		if (len > size) [[unlikely]]
			throw Except("Incorrect string eventent length");

		block[ind]->As<ch::ColumnString>()->Append(std::string(p, len));
		p += len;
		size -= len;
	} else {
		block[ind]->As<clickhouse::ColumnString>()->Append(std::string(""));
	}
}

size_t
read_access_log_event(TfwClickhouse &clickhouse, std::span<const char> data)
{
	ch::Block &block = clickhouse.get_block();
	auto size = data.size();
	const char *p = data.data();
	const auto *event = reinterpret_cast<const TfwBinLogEvent *>(p);

	p += sizeof(TfwBinLogEvent);
	size -= sizeof(TfwBinLogEvent);

	block[0]->As<ch::ColumnDateTime64>()->Append(event->timestamp);

	read_int<TFW_MMAP_LOG_ADDR, ch::ColumnIPv6, in6_addr>(block, event, p, size);
	read_int<TFW_MMAP_LOG_METHOD, ch::ColumnUInt8, unsigned char>(
							block, event, p, size);
	read_int<TFW_MMAP_LOG_VERSION, ch::ColumnUInt8, unsigned char>(
							block, event, p, size);
	read_int<TFW_MMAP_LOG_STATUS, ch::ColumnUInt16, uint16_t>(
							block, event, p, size);
	read_int<TFW_MMAP_LOG_RESP_CONT_LEN, ch::ColumnUInt32, uint32_t>(
							block, event, p, size);
	read_int<TFW_MMAP_LOG_RESP_TIME, clickhouse::ColumnUInt32, uint32_t>(
							block, event, p, size);

	read_str<TFW_MMAP_LOG_VHOST>(block, event, p, size);
	read_str<TFW_MMAP_LOG_URI>(block, event, p, size);
	read_str<TFW_MMAP_LOG_REFERER>(block, event, p, size);
	read_str<TFW_MMAP_LOG_USER_AGENT>(block, event, p, size);

	read_int<TFW_MMAP_LOG_JA5T, ch::ColumnUInt64, uint64_t>(
							block, event, p, size);
	read_int<TFW_MMAP_LOG_JA5H, ch::ColumnUInt64, uint64_t>(
							block, event, p, size);
	read_int<TFW_MMAP_LOG_DROPPED, ch::ColumnUInt64, uint64_t>(
							block, event, p, size);

	return static_cast<size_t>(p - data.data());
}

void
callback(TfwClickhouse &clickhouse, std::span<const char> data)
{
	dbg_hexdump(data);

	while (data.size() > sizeof(TfwBinLogEvent)) {
		const auto *event
			= reinterpret_cast<const TfwBinLogEvent *>(data.data());

		switch (event->type) {
		case TFW_MMAP_LOG_TYPE_ACCESS: {
			const auto off = read_access_log_event(clickhouse, data);
			data = data.subspan(off);
			break;
		}
		default:
			throw Except("Unsupported log type: {}",
				     static_cast<unsigned int>(event->type));
		}
	}

	if (clickhouse.commit())
		uncritical_error = false;
}

void
run_thread(const int ncpu, const int fd, const TfwLoggerConfig &config) noexcept
try {
	static thread_local std::chrono::seconds timeout(reconnect_min_timeout);

	cpu_set_t cpuset;
	pthread_t current_thread = pthread_self();
	bool affinity_is_set = false;
	int r;
	auto block = make_block();

	while (!stop_flag)
	try {
		const auto &ch_cfg = config.clickhouse;
		spdlog::debug("Worker {} connecting to ClickHouse: {}",
			      ncpu, ch_cfg);
		TfwClickhouse clickhouse(ch_cfg, block);
		auto cb = [&clickhouse](std::span<const char> data) {
			callback(clickhouse, data);
		};
		TfwMmapBufferReader mbr(ncpu, fd, std::move(cb));
		if (!affinity_is_set) {
			CPU_ZERO(&cpuset);
			CPU_SET(mbr.get_cpu_id(), &cpuset);
			r = pthread_setaffinity_np(current_thread,
						   sizeof(cpu_set_t), &cpuset);
			if (r != 0)
				throw Except("Failed to set CPU affinity");
			affinity_is_set = true;
			spdlog::debug("Worker {} bound to CPU {}", ncpu,
				      mbr.get_cpu_id());
		}
		mbr.run(&stop_flag);
		break;
	}
	catch (const Exception &e) {
		log_error(e.what(), true, false);
		block.Clear(); // bug: block was moved!
		break;
	}
	catch (const std::exception &e) {
		if (!uncritical_error) {
			log_error(e.what(), true, true);
			timeout = reconnect_min_timeout;
			uncritical_error = true;
		}
		std::this_thread::sleep_for(timeout);
		if (timeout < reconnect_max_timeout)
			timeout *= 2;
	}

	block.RefreshRowCount(); // bug: block was moved!
	while (block.GetRowCount() > 0)
	try {
		spdlog::debug("Worker {} flushing remaining events...", ncpu);
		TfwClickhouse clickhouse(config.clickhouse, block);
		clickhouse.commit(/*force=*/true);
	}
	catch (const std::exception &e) {
		log_error(e.what(), true, false);
		std::this_thread::sleep_for(timeout);
		if (timeout < reconnect_max_timeout)
			timeout *= 2;
	}

	spdlog::debug("Worker {} stopped", ncpu);
}
catch (...) {
	spdlog::error("Worker {}: Unexpected exception in thread function", ncpu);
}

// Signal handling
void
sig_handler([[maybe_unused]] int sig_num) noexcept
{
	stop_flag = true;
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
		throw Except("Failed to load configuration from: {}",
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
		throw Except("PID file checking failed");

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
		spdlog::debug("Daemonizing...");

		if (daemon(0, 0) < 0)
			throw Except("Daemonization failed");
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
} catch (const spdlog::spdlog_ex &ex) {
	throw Except("Log initialization failed: {}", ex.what());
}

int
open_mmap_device()
{
	int fd;

	spdlog::info("Opening device: {}", dev_path);

	// Try to open the device with retries
	while ((fd = open(dev_path, O_RDWR)) == -1) {
		if (stop_flag.load(std::memory_order_acquire)) {
			spdlog::info("Stop flag set, exiting device open loop");
			return -1;
		}

		if (errno != ENOENT)
			throw Except("Cannot open device {}", dev_path);

		spdlog::debug("Device {} not found, retrying...", dev_path);
		std::this_thread::sleep_for(wait_for_dev);
	}

	spdlog::info("Successfully opened device: {}", dev_path);
	return fd;
}

void
run_main_loop(int fd)
{
	/*
	 * Use sysconf() instead of std::thread::hardware_concurrency() because
	 * it respects process CPU affinity, cgroups, and container limits,
	 * is more reliable on NUMA systems and machines with 100+ CPUs while
	 * hardware_concurrency() is just a "hint".
	 */
	auto cpu_count = static_cast<size_t>(sysconf(_SC_NPROCESSORS_ONLN));
	if (cpu_count <= 0)
		throw Except("Cannot determine CPU count");

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
	int fd = -1;
	int pidfile_fd = -1;

	// Parse command line options
	auto opts = parse_command_line(argc, argv);

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
	pidfile_fd = pidfile_create(pid_file_path);
	if (pidfile_fd < 0)
		throw Except("Cannot create PID file");

	// Log startup information
	spdlog::info("Starting Tempesta FW Logger...");
	spdlog::info("ClickHouse configuration: {}", config.clickhouse);

	// Setup signal handlers for graceful shutdown
	setup_signal_handlers();

	// Open mmap device
	fd = open_mmap_device();
	if (fd < 0)
		throw Except("Failed to open device");

	spdlog::info("Daemon started");

	// Run main processing loop
	run_main_loop(fd);

	spdlog::info("Tempesta FW Logger stopped");
	cleanup_resources(fd, pidfile_fd);
	return 0;
} catch (const Exception &e) {
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
