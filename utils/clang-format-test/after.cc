#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <optional>
#include <vector>

#include <boost/program_options.hpp>

#include <spdlog/spdlog.h>

#include "../fw/access_log.h"
#include "some_header.hh"

namespace po = boost::program_options;

// Bad formatting examples that should be fixed

class TestClass {
public:
	int
	badly_formatted_function(int a, int b, int c)
	{
		if (a > 0) {
			std::cout << "Value is positive" << std::endl;
			return a + b + c;
		}
		else if (a < 0)
			return -1; // This should be on separate lines
		else
			return 0;
	}

	void
	another_function(int x, int y)
	{
		for (int i = 0; i < 10; ++i)
			if (i % 2 == 0)
				std::cout << i << " ";
	}

	// Pointer alignment issues
	char *ptr1;
	int *ptr2;
	void *ptr3;
};

int
func_test(int argc, char *argv[])
{
	TestClass obj;
	int result = obj.badly_formatted_function(1, 2, 3);

	// Single line if statements (should remain as they are per CodingStyle)
	if (result > 0)
		std::cout << "Result is positive" << std::endl;

	if (result < 0)
		std::cout
		<< "This should be split"; // Bad - action on same line

	// Array initialization with bad alignment
	int array[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

	// Function calls with bad parameter alignment
	obj.another_function(5, 10);

	return 0;
}

typedef struct {
	const char *name;
	clickhouse::Type::Code code;
} TfwField;

static const TfwField tfw_fields[] = {
[TFW_MMAP_LOG_ADDR] = {"address", clickhouse::Type::IPv6},
[TFW_MMAP_LOG_METHOD] = {"method", clickhouse::Type::UInt8},
[TFW_MMAP_LOG_RESP_CONT_LEN] = {"response_content_length",
				clickhouse::Type::UInt32},
};

void
run_thread(const int ncpu, const int fd) noexcept
try {
	static thread_local std::chrono::seconds timeout(reconnect_min_timeout);
	cpu_set_t cpuset;
	int r;

	while (!stop_flag) {
		try {
			spdlog::debug("Worker {} connecting to ClickHouse at "
				      "{}:{}, table: {}",
				      ncpu, ch_cfg.host, ch_cfg.port,
				      ch_cfg.table_name);
			TfwClickhouse clickhouse(
			ch_cfg.host, ch_cfg.table_name,
			ch_cfg.user ? *ch_cfg.user : "",
			ch_cfg.password ? *ch_cfg.password : "", make_block());
			if (!affinity_is_set) {
				CPU_ZERO(&cpuset);
				r = pthread_setaffinity_np(
				current_thread, sizeof(cpu_set_t), &cpuset);
				if (r != 0)
					throw Except(
					"Failed to set CPU affinity");
			}
		}
		catch (const std::exception &e) {
			if (!uncritical_error) {
				log_error(e.what(), true, true);
				timeout = reconnect_min_timeout;
				uncritical_error = true;
			}
			if (timeout < reconnect_max_timeout)
				timeout *= 2;
		}
	}
}
catch (...) {
	spdlog::error("Worker {}: Unexpected exception in thread function",
		      ncpu);
}

void
parse_options()
{
	desc.add_options()("help,h", po::bool_switch(&result.help),
			   "Show this help message and exit")(
	"stop,s", po::bool_switch(&result.stop_daemon), "Stop the daemon")(
	"max-wait", po::value<int>(),
	"Maximum wait time in ms before commit "
	"(overrides config)")("log-path,l", po::value<fs::path>(),
			      "Path to log file (overrides config)");

	if (vm.count("config"))
		result.config_path = vm["config"].as<fs::path>();
	if (vm.count("host"))
		result.clickhouse_host = vm["host"].as<std::string>();
	if (vm.count("port"))
		result.clickhouse_port = vm["port"].as<uint16_t>();
}

void
validate_config()
{
	if (clickhouse_.host.empty())
		throw std::runtime_error("ClickHouse host cannot be empty");

	if (clickhouse_.port == 0)
		throw std::runtime_error("Invalid ClickHouse port");

	if (clickhouse_.table_name.empty())
		throw std::runtime_error(
		"ClickHouse table name cannot be empty");

	if (clickhouse_.max_events == 0)
		throw std::runtime_error("max_events must be greater than 0");
}

int
pidfile_create(const std::string &fname)
{
	int fd = -1;
	char pid_str[64] = {0};
	int pid_str_len;

	// Get PID as string
	pid_str_len =
	snprintf(pid_str, sizeof(pid_str), "%ld", static_cast<long>(getpid()));

	if (access(fname.c_str(), F_OK) != -1) {
		unlink(fname.c_str());
		errno = 0;
	}

	fd = open(fname.c_str(), O_RDWR | O_CREAT, mask);
	if (fd == -1) {
		std::cerr << "Cannot create pidfile: " << fname << std::endl;
		return -1;
	}

	if (write(fd, &pid_str[0], pid_str_len) == -1) {
		std::cerr << "Cannot write pid into pidfile: " << fname
			  << std::endl;
		close(fd);
		return -1;
	}

	return fd;
}

void
pidfile_stop_daemon(const std::string &fname)
{
	std::ifstream pid_file(fname);

	if (!pid_file) {
		throw Except(
		"No PID file found at '{}'. Is the daemon running?", fname);
	}

	if (kill(pid, SIGTERM) < 0) {
		if (errno == ESRCH) {
			// Process not running - remove stale PID file
			unlink(fname.c_str());
			return;
		}
		throw Except("Failed to stop daemon (PID {}): {}", pid,
			     strerror(errno));
	}

	// Wait for graceful shutdown
	for (int i = 0; i < GRACEFUL_WAIT_ITERATIONS; ++i) {
		if (kill(pid, 0) == -1 && errno == ESRCH)
			return; // Process died gracefully
		std::this_thread::sleep_for(STOP_WAIT_INTERVAL);
	}

	if (kill(pid, SIGKILL) < 0) {
		if (errno == ESRCH)
			return; // Process already stopped
		throw Except("Failed to kill daemon (PID {}): {}", pid,
			     strerror(errno));
	}
}

#define READ_INT(method, col_type, val_type)                                   \
	ind = method + 1; /* column 0 is timestamp */                          \
	if (TFW_MMAP_LOG_FIELD_IS_SET(event, method)) {                        \
		len =                                                          \
		tfw_mmap_log_field_len(static_cast<TfwBinLogFields>(method));  \
		if (len > size) [[unlikely]]                                   \
			goto error;                                            \
		(*block)[ind]->As<col_type>()->Append(                         \
		*reinterpret_cast<const val_type *>(p));                       \
	}                                                                      \
	else                                                                   \
		(*block)[ind]->As<col_type>()->Append(0);

int
main()
{
	// All these issues should be fixed by clang-format
	return 0;
}