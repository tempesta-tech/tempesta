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
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#include <stdio.h>
#include <unistd.h>

#include <fstream>
#include <thread>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <atomic>
#include <vector>

#include <boost/program_options.hpp>
#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

#include "../fw/access_log.h"
#include "clickhouse.hh"
#include "mmap_buffer.hh"
#include "error.hh"
#include "tfw_logger_config.hh"

namespace po = boost::program_options;

constexpr char dev_path[] = "/dev/tempesta_mmap_log";
constexpr std::chrono::seconds wait_for_dev{1};
constexpr std::chrono::seconds reconnect_min_timeout{1};
constexpr std::chrono::seconds reconnect_max_timeout{16};

typedef struct {
	const char		*name;
	clickhouse::Type::Code	code;
} TfwField;

static const TfwField tfw_fields[] = {
	[TFW_MMAP_LOG_ADDR]		= {"address", clickhouse::Type::IPv6},
	[TFW_MMAP_LOG_METHOD]		= {"method", clickhouse::Type::UInt8},
	[TFW_MMAP_LOG_VERSION]		= {"version", clickhouse::Type::UInt8},
	[TFW_MMAP_LOG_STATUS]		= {"status", clickhouse::Type::UInt16},
	[TFW_MMAP_LOG_RESP_CONT_LEN]	= {"response_content_length", clickhouse::Type::UInt32},
	[TFW_MMAP_LOG_RESP_TIME]	= {"response_time", clickhouse::Type::UInt32},
	[TFW_MMAP_LOG_VHOST]		= {"vhost", clickhouse::Type::String},
	[TFW_MMAP_LOG_URI]		= {"uri", clickhouse::Type::String},
	[TFW_MMAP_LOG_REFERER]		= {"referer", clickhouse::Type::String},
	[TFW_MMAP_LOG_USER_AGENT]	= {"user_agent", clickhouse::Type::String},
	[TFW_MMAP_LOG_JA5T]		= {"ja5t", clickhouse::Type::UInt64},
	[TFW_MMAP_LOG_JA5H]		= {"ja5h", clickhouse::Type::UInt64},
	[TFW_MMAP_LOG_DROPPED]		= {"dropped_events", clickhouse::Type::UInt64}
};

std::atomic<bool> stop_flag{false};
static thread_local bool uncritical_error;
static TfwLoggerConfig config;

/**
 * Parse all command line options in one place.
 */
struct ParsedOptions {
	// Basic commands
	std::optional<fs::path> config_path;
	bool generate = false;
	bool help = false;
	
	// Configuration overrides
	std::optional<std::string> clickhouse_host;
	std::optional<uint16_t> clickhouse_port;
	std::optional<std::string> clickhouse_user;
	std::optional<std::string> clickhouse_password;
	std::optional<size_t> clickhouse_max_events;
	std::optional<int> clickhouse_max_wait_ms;
	std::optional<size_t> cpu_count;
	std::optional<fs::path> log_path;
};

#ifdef DEBUG
static void
dbg_hexdump(const char *data, int buflen)
{
	const unsigned char *buf = (const unsigned char*)data;
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');

#define PRINT_CHAR(c) (std::isprint(c) ? c : '.')
	for (int i = 0; i < buflen; i += 16) {
		oss << std::setw(6) << i << ": ";

		for (int j = 0; j < 16; ++j)
			if (i + j < buflen)
				oss << std::setw(2) << (unsigned)buf[i + j] << " ";
			else
				oss << "   ";
		oss << " ";
		for (int j = 0; j < 16; ++j) {
			if (i + j >= buflen)
				break;
			oss << (char)PRINT_CHAR(buf[i + j]);
		}
		oss << std::endl;
	}
	oss << std::dec << "len = " << buflen << std::endl;
	spdlog::info("{}", oss.str());
#undef PRINT_CHAR
}
#else
static void
dbg_hexdump([[maybe_unused]] const char *data, [[maybe_unused]] int buflen)
{
}
#endif /* DEBUG */

void log_error(std::string msg, bool to_spdlog, bool unhandled)
{
	if (unhandled)
		msg = "Unhandled error: " + msg;

	if (to_spdlog)
		spdlog::error(msg);
	else
		std::cerr << msg << std::endl;
}

clickhouse::Block
make_block()
{
	unsigned int i;
	auto block = clickhouse::Block();

	auto col = std::make_shared<clickhouse::ColumnDateTime64>(3);
	block.AppendColumn("timestamp", col);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		const TfwField *field = &tfw_fields[i];
		auto col = tfw_column_factory(field->code);
		block.AppendColumn(field->name, col);
	}

	return block;
}

int
read_access_log_event(const char *data, int size, TfwClickhouse *clickhouse)
{
	auto block = clickhouse->get_block();
	const char *p = data;
	TfwBinLogEvent *event = (TfwBinLogEvent *)p;
	int len, ind;

	p += sizeof(TfwBinLogEvent);
	size -= sizeof(TfwBinLogEvent);

	(*block)[0]->As<clickhouse::ColumnDateTime64>()->Append(event->timestamp);

#define READ_INT(method, col_type, val_type)				\
	ind = method + 1; /* column 0 is timestamp */			\
	if (TFW_MMAP_LOG_FIELD_IS_SET(event, method)) {			\
		len = tfw_mmap_log_field_len((TfwBinLogFields)method);	\
		if (len > size) [[unlikely]]				\
			goto error;					\
		(*block)[ind]->As<col_type>()->Append(*(val_type *)p);	\
		p += len;						\
		size -= len;						\
	} else								\
		(*block)[ind]->As<col_type>()->Append(0);		\

	READ_INT(TFW_MMAP_LOG_ADDR, clickhouse::ColumnIPv6, struct in6_addr);
	READ_INT(TFW_MMAP_LOG_METHOD, clickhouse::ColumnUInt8, unsigned char);
	READ_INT(TFW_MMAP_LOG_VERSION, clickhouse::ColumnUInt8, unsigned char);
	READ_INT(TFW_MMAP_LOG_STATUS, clickhouse::ColumnUInt16, uint16_t);
	READ_INT(TFW_MMAP_LOG_RESP_CONT_LEN, clickhouse::ColumnUInt32, uint32_t);
	READ_INT(TFW_MMAP_LOG_RESP_TIME, clickhouse::ColumnUInt32, uint32_t);

#define READ_STR(method)						\
	ind = method + 1; /* column 0 is timestamp */			\
	if (TFW_MMAP_LOG_FIELD_IS_SET(event, method)) {			\
		len = *((uint16_t *)p);					\
		if (len > size) [[unlikely]]				\
			goto error;					\
		(*block)[ind]->As<clickhouse::ColumnString>()->Append(	\
			std::string(p + 2, len));			\
		len += 2;						\
		p += len;						\
		size -= len;						\
	} else								\
		(*block)[ind]->As<clickhouse::ColumnString>()->Append(	\
			std::string(""));

	READ_STR(TFW_MMAP_LOG_VHOST);
	READ_STR(TFW_MMAP_LOG_URI);
	READ_STR(TFW_MMAP_LOG_REFERER);
	READ_STR(TFW_MMAP_LOG_USER_AGENT);

	READ_INT(TFW_MMAP_LOG_JA5T, clickhouse::ColumnUInt64, uint64_t);
	READ_INT(TFW_MMAP_LOG_JA5H, clickhouse::ColumnUInt64, uint64_t);
	READ_INT(TFW_MMAP_LOG_DROPPED, clickhouse::ColumnUInt64, uint64_t);

	return p - data;
error:
	throw Except("Incorrect event length");
#undef READ_STR
#undef READ_INT
}

void
callback(const char *data, int size, void *private_data)
{
	TfwClickhouse *clickhouse = (TfwClickhouse *)private_data;
	TfwBinLogEvent *event;
	const char *p = data;
	int r;

	dbg_hexdump(data, size);

	 while (size > (int)sizeof(TfwBinLogEvent)) {
		event = (TfwBinLogEvent *)p;

		switch (event->type) {
		case TFW_MMAP_LOG_TYPE_ACCESS:
			r = read_access_log_event(p, size, clickhouse);
			size -= r;
			p += r;
			break;
		default:
			throw Except("Unsupported log type: {}",
				     (unsigned int)event->type);
		}
	}

	if (clickhouse->commit())
		uncritical_error = false;
}

void 
run_thread(const int ncpu, const int fd, const TfwLoggerConfig &config)
{
	static thread_local std::chrono::seconds timeout(reconnect_min_timeout);
	cpu_set_t cpuset;
	pthread_t current_thread = pthread_self();
	bool affinity_is_set = false;
	int r;

	while (!stop_flag) {
		try {
			const auto &ch_cfg = config.get_clickhouse();

			spdlog::info("Worker {} connecting to ClickHouse at {}:{}",
				     ncpu, ch_cfg.host, ch_cfg.port);

			// Use full table name to avoid confusion
			TfwClickhouse clickhouse(ch_cfg.host, "access_log.access_log",
						ch_cfg.user ? *ch_cfg.user : "",
						ch_cfg.password ? *ch_cfg.password : "",
						make_block());

			TfwMmapBufferReader mbr(ncpu, fd, &clickhouse, callback);

			// Set CPU affinity for this thread
			if (!affinity_is_set) {
				CPU_ZERO(&cpuset);
				CPU_SET(mbr.get_cpu_id(), &cpuset);

				r = pthread_setaffinity_np(current_thread,
							   sizeof(cpu_set_t), &cpuset);
				if (r != 0)
					throw Except("Failed to set CPU affinity");

				affinity_is_set = true;
				spdlog::debug("Worker {} bound to CPU {}",
					      ncpu, mbr.get_cpu_id());
			}

			// Main processing loop
			mbr.run(&stop_flag);

			break;
		}
		catch (const Exception &e) {
			log_error(e.what(), true, false);
			// All manually thrown exceptions are critical
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
	}

	spdlog::info("Worker {} stopped", ncpu);
}

void
sig_handler([[maybe_unused]] int sig_num) noexcept
{
	stop_flag = true;
	spdlog::info("Received signal {}, stopping...", sig_num);
}

void
set_sig_handlers() noexcept
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

/**
 * Create default configuration file if it doesn't exist.
 */
void 
ensure_default_config(const fs::path &config_path)
{
	if (fs::exists(config_path)) {
		std::cout << "Configuration file already exists: " << config_path << std::endl;
		return;
	}

	std::cout << "Creating default configuration at: " << config_path << std::endl;

	// Create directory if needed
	fs::create_directories(config_path.parent_path());

	// Create and save default configuration
	TfwLoggerConfig default_config;
	if (!default_config.save_to_file(config_path)) {
		throw Except("Failed to create default configuration file");
	}
}

/**
 * Setup spdlog logger based on configuration.
 */
std::shared_ptr<spdlog::logger> 
setup_logger(const TfwLoggerConfig &config)
{
	// Create log directory if needed
	fs::create_directories(fs::path(config.get_log_path()).parent_path());
	
	try {
		auto logger = spdlog::basic_logger_mt("access_logger", 
						      config.get_log_path().string());
		spdlog::set_default_logger(logger);
		spdlog::set_level(spdlog::level::info);
		logger->flush_on(spdlog::level::info);
		return logger;
	}
	catch (const spdlog::spdlog_ex &ex) {
		throw Except("Log initialization failed: {}", ex.what());
	}
}

/**
 * Determine number of CPUs to use.
 */
size_t 
determine_cpu_count(const TfwLoggerConfig &config)
{
	size_t cpu_cnt;
 
	if (config.get_cpu_count() > 0) {
		cpu_cnt = config.get_cpu_count();
	}
	else {
		cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
		if (cpu_cnt <= 0)
			throw Except("Cannot determine CPU count");
	}
	spdlog::info("Using {} CPU(s)", cpu_cnt);
	return cpu_cnt;
}

/**
 * Open mmap device with retry logic.
 */
int 
open_device()
{
	int fd;

	// Try to open the device with retries
	while ((fd = open(dev_path, O_RDWR)) == -1) {
		if (stop_flag.load(std::memory_order_acquire)) {
			spdlog::info("Stop flag set, exiting device open loop");
			return -1;
		}
 
		if (errno != ENOENT) {
			throw Except("Cannot open device {}", dev_path);
		}

		spdlog::debug("Device {} not found, retrying...", dev_path);
		std::this_thread::sleep_for(wait_for_dev);
	}

	spdlog::info("Successfully opened device: {}", dev_path);
	return fd;
}

/**
 * Start worker threads for each CPU.
 */
void 
run_worker_threads(int fd, size_t cpu_count)
{
	std::vector<std::thread> threads;

	for (size_t i = 0; i < cpu_count; ++i) {
		threads.emplace_back(run_thread, i, fd, std::ref(config));
	}

	spdlog::info("All {} worker threads started", cpu_count);

	// Wait for all threads to complete
	for (auto &t : threads) {
		if (t.joinable())
			t.join();
	}
}

/**
 * Parse all command line arguments at once.
 */
ParsedOptions 
parse_all_options(int argc, char *argv[])
{
	ParsedOptions result;
	po::options_description desc("Tempesta FW Logger options");
	
	desc.add_options()
		("help,h", po::bool_switch(&result.help), 
			"Show this help message and exit")
		("generate,g", po::bool_switch(&result.generate), 
			"Generate default configuration file and exit")
		("config,c", po::value<fs::path>(), 
			"Path to configuration file (default: /etc/tempesta/tfw_logger.json)")
		("host,H", po::value<std::string>(), 
			"ClickHouse host (overrides config)")
		("port,P", po::value<uint16_t>(), 
			"ClickHouse port (overrides config)")
		("user,u", po::value<std::string>(), 
			"ClickHouse username (overrides config)")
		("password,p", po::value<std::string>(), 
			"ClickHouse password (overrides config)")
		("max-events", po::value<size_t>(), 
			"Maximum events before commit (overrides config)")
		("max-wait", po::value<int>(), 
			"Maximum wait time in ms before commit (overrides config)")
		("cpu-count,n", po::value<size_t>(), 
			"Number of CPUs to use, 0=auto-detect (overrides config)")
		("log-path,l", po::value<fs::path>(), 
			"Path to log file (overrides config)");
	
	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	}
	catch (const po::error &e) {
		std::cerr << "Error: " << e.what() << std::endl;
		std::cerr << "Use --help for usage information" << std::endl;
		exit(1);
	}
	
	// Show help if requested
	if (result.help) {
		std::cout << "Usage: tfw_logger [options]" << std::endl << std::endl;
		std::cout << desc << std::endl;
		std::cout << "\nExamples:" << std::endl;
		std::cout << "  tfw_logger --config /etc/tempesta/tfw_logger.json" << std::endl;
		std::cout << "  tfw_logger --host localhost -n 4" << std::endl;
		std::cout << "  tfw_logger --generate" << std::endl;
std::cout << "\nExamples:" << std::endl;
   	std::cout << "  tfw_logger --config /etc/tempesta/tfw_logger.json" << std::endl;
   	std::cout << "  tfw_logger --host localhost -n 4" << std::endl;
   	std::cout << "  tfw_logger --generate" << std::endl;
   	std::cout << "\nFor systemd service management:" << std::endl;
   	std::cout << "  systemctl start tempesta-logger" << std::endl;
   	std::cout << "  systemctl stop tempesta-logger" << std::endl;
   	std::cout << "  systemctl status tempesta-logger" << std::endl;
   	return result;
   }
   
   // Extract option values
   if (vm.count("config")) 
   	result.config_path = vm["config"].as<fs::path>();
   if (vm.count("host")) 
   	result.clickhouse_host = vm["host"].as<std::string>();
   if (vm.count("port")) 
   	result.clickhouse_port = vm["port"].as<uint16_t>();
   if (vm.count("user")) 
   	result.clickhouse_user = vm["user"].as<std::string>();
   if (vm.count("password")) 
   	result.clickhouse_password = vm["password"].as<std::string>();
   if (vm.count("max-events")) 
   	result.clickhouse_max_events = vm["max-events"].as<size_t>();
   if (vm.count("max-wait")) 
   	result.clickhouse_max_wait_ms = vm["max-wait"].as<int>();
   if (vm.count("cpu-count")) 
   	result.cpu_count = vm["cpu-count"].as<size_t>();
   if (vm.count("log-path")) 
   	result.log_path = vm["log-path"].as<fs::path>();
   
   return result;
}

/**
* Apply command line overrides to configuration.
*/
void 
apply_overrides(TfwLoggerConfig& config, const ParsedOptions& opts)
{
   if (opts.clickhouse_host) 
   	config.override_clickhouse_host(*opts.clickhouse_host);
   if (opts.clickhouse_port) 
   	config.override_clickhouse_port(*opts.clickhouse_port);
   if (opts.clickhouse_user) 
   	config.override_clickhouse_user(*opts.clickhouse_user);
   if (opts.clickhouse_password) 
   	config.override_clickhouse_password(*opts.clickhouse_password);
   if (opts.clickhouse_max_events) 
   	config.override_clickhouse_max_events(*opts.clickhouse_max_events);
   if (opts.clickhouse_max_wait_ms) 
   	config.override_clickhouse_max_wait(*opts.clickhouse_max_wait_ms);
   if (opts.cpu_count) 
   	config.override_cpu_count(*opts.cpu_count);
   if (opts.log_path) 
   	config.override_log_path(*opts.log_path);
}

/**
* Main entry point for Tempesta FW Logger.
* Runs as a regular foreground process, suitable for systemd management.
*/
int 
main(int argc, char *argv[])
{
   int fd = -1;
   int res = 0;
   
   try {
   	// Parse all command line options at once
   	auto opts = parse_all_options(argc, argv);
   	
   	// Handle commands that don't need configuration
   	if (opts.help) {
   		return 0;  // Help was already shown
   	}
   	
   	// Determine configuration file path
   	fs::path config_path = opts.config_path.value_or(
   		fs::path("/etc/tempesta/tfw_logger.json")
   	);
   	
   	if (opts.generate) {
   		ensure_default_config(config_path);
   		return 0;
   	}
   	
   	// Load configuration from file
   	auto loaded_config = TfwLoggerConfig::load_from_file(config_path);
   	if (!loaded_config) {
   		std::cerr << "Failed to load configuration from: " << config_path << std::endl;
   		std::cerr << "Use --generate to create a default configuration" << std::endl;
   		return 1;
   	}
   	
   	config = std::move(*loaded_config);

   	apply_overrides(config, opts);
   	
   	// Setup logging
   	auto logger = setup_logger(config);
   	spdlog::info("Starting Tempesta FW Logger...");
   	spdlog::info("Configuration: {}", config_path.string());
   	spdlog::info("ClickHouse: {}:{}", config.get_clickhouse().host, 
   		     config.get_clickhouse().port);
   	
   	// Determine CPU count
   	size_t cpu_cnt = determine_cpu_count(config);
   	
   	// Setup signal handlers for graceful shutdown
   	set_sig_handlers();
   	
   	// Open mmap device
   	spdlog::info("Opening device: {}", dev_path);
   	fd = open_device();
   	if (fd < 0) {
   		spdlog::error("Failed to open device");
   		return 1;
   	}

   	// Start worker threads
   	spdlog::info("Starting {} worker threads", cpu_cnt);
   	run_worker_threads(fd, cpu_cnt);
   	
   	spdlog::info("Tempesta FW Logger stopped");
   }
   catch (const Exception &e) {
   	std::cerr << "Error: " << e.what() << std::endl;
   	if (spdlog::default_logger()) {
   		spdlog::error("Fatal error: {}", e.what());
   	}
   	res = 1;
   }
   catch (const std::exception &e) {
   	std::cerr << "Unhandled error: " << e.what() << std::endl;
   	if (spdlog::default_logger()) {
   		spdlog::error("Unhandled exception: {}", e.what());
   	}
   	res = 2;
   }
   
   // Cleanup
   if (fd >= 0) {
   	close(fd);
   	spdlog::info("Device closed");
   }
   
   return res;
}