/**
 *		Tempesta FW
 *
 * Copyright (C) 2024 Tempesta Technologies, Inc.
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
#include <future>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <boost/program_options.hpp>
#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

#include "../fw/access_log.h"
#include "clickhouse.hh"
#include "mmap_buffer.hh"
#include "error.hh"

namespace po = boost::program_options;

#define FILE_PATH	"/dev/tempesta_mmap_log"
#define TABLE_NAME	"access_log"

constexpr char pid_file_path[] = "/var/run/tfw_logger.pid";
constexpr size_t WAIT_FOR_FILE = 1;  /* s */
constexpr size_t WAIT_FOR_STOP = 10; /* ms */

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
	[TFW_MMAP_LOG_DROPPED]		= {"dropped_events", clickhouse::Type::UInt64},
};

std::atomic<bool> stop_flag{false};

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
	std::cout << oss.str();
#undef PRINT_CHAR
}
#else
static void
dbg_hexdump([[maybe_unused]] const char *data, [[maybe_unused]] int buflen)
{
}
#endif /* DEBUG */

static std::shared_ptr<clickhouse::Block>
make_block()
{
	unsigned int i;
	auto block = std::make_shared<clickhouse::Block>();

	auto col = std::make_shared<clickhouse::ColumnDateTime64>(3);
	block->AppendColumn("timestamp", col);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		const TfwField *field = &tfw_fields[i];

		auto col = tfw_column_factory(field->code);
		block->AppendColumn(field->name, col);
	}

	return block;
}

int
read_access_log_event(const char *data, int size, TfwClickhouse *clickhouse)
{
	auto block = clickhouse->get_block();
	const char *p = data;
	TfwBinLogEvent *event = (TfwBinLogEvent *)p;
	int i;

	p += sizeof(TfwBinLogEvent);
	size -= sizeof(TfwBinLogEvent);

#define INT_CASE(method, col_type, val_type)					\
	case method:								\
		if (TFW_MMAP_LOG_FIELD_IS_SET(event, i)) {			\
			if (len > size)						\
				return -1;					\
			(*block)[ind]->As<col_type>()->Append(*(val_type *)p);	\
		} else								\
			(*block)[ind]->As<col_type>()->Append(0);		\
		break;


	(*block)[0]->As<clickhouse::ColumnDateTime64>()->Append(event->timestamp);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		int len, ind = i + 1;

		len = tfw_mmap_log_field_len((TfwBinLogFields)i);

		switch (i) {
		INT_CASE(TFW_MMAP_LOG_ADDR,
			 clickhouse::ColumnIPv6, struct in6_addr);
		INT_CASE(TFW_MMAP_LOG_METHOD,
			 clickhouse::ColumnUInt8, unsigned char);
		INT_CASE(TFW_MMAP_LOG_VERSION,
			 clickhouse::ColumnUInt8, unsigned char);
		INT_CASE(TFW_MMAP_LOG_STATUS,
			 clickhouse::ColumnUInt16, uint16_t);
		INT_CASE(TFW_MMAP_LOG_RESP_CONT_LEN,
			 clickhouse::ColumnUInt32, uint32_t);
		INT_CASE(TFW_MMAP_LOG_RESP_TIME,
			 clickhouse::ColumnUInt32, uint32_t);
		INT_CASE(TFW_MMAP_LOG_DROPPED,
			 clickhouse::ColumnUInt64, uint64_t);

		case TFW_MMAP_LOG_VHOST:
		case TFW_MMAP_LOG_URI:
		case TFW_MMAP_LOG_REFERER:
		case TFW_MMAP_LOG_USER_AGENT:
			if (!TFW_MMAP_LOG_FIELD_IS_SET(event, i)) {
				(*block)[ind]->As<clickhouse::ColumnString>()->Append(
					std::move(std::string("")));
				break;
			}
			len = *((uint16_t *)p);
			if (len + 2 > size)
				return -1;
			(*block)[ind]->As<clickhouse::ColumnString>()->Append(
				std::move(std::string(p + 2, len)));
			len += 2;
			break;
		default:
			throw Except("Unknown field type: {}", i);
		}

		if (TFW_MMAP_LOG_FIELD_IS_SET(event, i)) {
			p += len;
			size -= len;
		}
	}

	return p - data;
}

void
callback(const char *data, int size, void *private_data)
{
	TfwClickhouse *clickhouse = (TfwClickhouse *)private_data;
	TfwBinLogEvent *event;
	const char *p = data;
	int r;

	dbg_hexdump(data, size);

	do {
		if (size < (int)sizeof(TfwBinLogEvent))
			return;

		event = (TfwBinLogEvent *)p;

		switch (event->type) {
		case TFW_MMAP_LOG_TYPE_ACCESS:
			r = read_access_log_event(p, size, clickhouse);
			if (r < 0)
				return;
			size -= r;
			p += r;
			break;
		default:
			throw Except("Unsupported log type: {}",
				     (unsigned int)event->type);
			return;
		}
	} while (size > 0);

	clickhouse->commit();
}

void
run_thread(int ncpu, int fd, std::string host,
	   std::string user, std::string password,
	   std::promise<void> promise)
try {
	cpu_set_t cpuset;
	pthread_t current_thread = pthread_self();

	TfwClickhouse clickhouse(host, TABLE_NAME, user, password, make_block);

	TfwMmapBufferReader mbr(ncpu, fd, &clickhouse, callback);

	CPU_ZERO(&cpuset);
	CPU_SET(mbr.get_cpu_id(), &cpuset);

	assert(pthread_setaffinity_np(current_thread,
				      sizeof(cpu_set_t), &cpuset) == 0);

	mbr.run(&stop_flag);

	promise.set_value();
}
catch (...) {
	promise.set_exception(std::current_exception());
}

void
sig_handler([[maybe_unused]] int  sig_num) noexcept
{
	stop_flag = true;
	spdlog::info("Stopping daemon...");
}

void
set_sig_handlers()
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

void stop_daemon()
{
	pid_t pid;
	std::ifstream pid_file(pid_file_path);

	std::cout << "Stopping daemon..." << std::endl;

	if (!pid_file)
		throw Except("No PID file found. Is the daemon running?");

	pid_file >> pid;
	pid_file.close();

	if (pid <= 0)
		throw Except("Invalid PID in PID file.");

	if (kill(pid, SIGTERM) < 0)
		throw Except("Failed to stop daemon: {}", strerror(errno));

	while (1) {
		if (kill(pid, 0) == -1 && errno == ESRCH)
			break;
		std::this_thread::sleep_for(
			std::chrono::milliseconds(WAIT_FOR_STOP));
        }

	std::cout << "Daemon stopped." << std::endl;
}

int
main(int argc, char* argv[])
{
	std::vector<std::thread> thrs;
	std::vector<std::future<void>> futures;
	unsigned int i;
	long int cpu_cnt;
	int fd = -1, res = 0;
	bool stop = false;
	std::shared_ptr<spdlog::logger> logger = nullptr;

	try {
		po::options_description desc{"Usage: tfw_logger "
					     "([options] <host> <log>) | --stop"};
		desc.add_options()
			("help,h", "show this message and exit")
			("host,H", po::value<std::string>(),
				"clickserver host address (required)")
			("log,l", po::value<std::string>(),
				"log path (required)")
			("ncpu,n", po::value<unsigned int>(),
				"manually specifying the number of CPUs")
			("stop,s", po::bool_switch(&stop), "stop the daemon")
			("user,u", po::value<std::string>(), "clickhouse user")
			("password,p", po::value<std::string>(),
			 "clickhouse password")
			;
		po::positional_options_description pos_desc;
		pos_desc.add("host", 1);
		pos_desc.add("log", -1);
		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv)
			.options(desc)
			.positional(pos_desc)
			.run(),
			vm);
		po::notify(vm);

		if (stop) {
			if (vm.size() > 1)
				throw Except("--stop can't be used with "
					     "another arguments");
			stop_daemon();
			return 0;
		}

		if (vm.count("help")) {
			std::cout << desc << std::endl;
			return 0;
		}

		if (!vm.count("host")) {
			std::cerr << "'host' argument is requred" << std::endl;
			return 1;
		}

		if (!vm.count("log"))
			throw Except("please, specify log path");

		if (vm.count("ncpu")) {
			cpu_cnt = vm["ncpu"].as<unsigned int>();
		} else {
			cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
			if (cpu_cnt < 0)
				throw Except("Can't get CPU number");
		}

		auto user = vm.count("user") ?
			    vm["user"].as<std::string>() : std::string("");
		auto password = vm.count("password") ?
				vm["password"].as<std::string>() :
				std::string("");

		/*
		 * When the daemon forks, it inherits the file descriptor for
		 * /tmp/tempesta-lock-file, which was originally opened and locked by flock
		 * in the tempesta.sh script. After daemonizing, the daemon process continues
		 * to hold this lock, preventing subsequent executions of tempesta.sh.
		 *
		 * Close all descriptors before daemonizing.
		 */
		closefrom(3);

		logger = spdlog::basic_logger_mt("access_logger",
						 vm["log"].as<std::string>());
		spdlog::set_default_logger(logger);
		spdlog::set_level(spdlog::level::info);

		spdlog::info("Starting daemon...");

		if (daemon(0, 0) < 0)
			throw Except("Daemonization failed");

		set_sig_handlers();

		std::ofstream pid_file(pid_file_path);
		if (!pid_file)
			throw Except("Failed to open PID file");
		pid_file << getpid();
		pid_file.close();

		while ((fd = open(FILE_PATH, O_RDWR)) == -1) {
			if (stop_flag.load(std::memory_order_acquire))
				return 0;
			if (errno != ENOENT)
				throw Except("Can't open device");
			sleep(WAIT_FOR_FILE);
		}

		for (i = 0; i < cpu_cnt; ++i) {
			std::promise<void> promise;
			futures.push_back(promise.get_future());
			thrs.push_back(std::thread(run_thread, i, fd,
				       vm["host"].as<std::string>(),
				       user, password, std::move(promise)));
		}

		spdlog::info("Daemon started");

		for (i = 0; i < cpu_cnt; ++i)
			thrs[i].join();

		for (auto& future : futures)
			future.get();

		spdlog::info("Daemon stopped");

	}
	catch (Exception &e) {
		if (logger)
			spdlog::error(e.what());
		else
			std::cerr << e.what() << std::endl;
		res = 1;
	}
	catch (std::exception &e) {
		if (logger)
			spdlog::error("Unhandled error: {}", e.what());
		else
			std::cerr << "Unhandled error: " << e.what() << std::endl;
		res = 2;
	}

	if (fd >= 0)
		close(fd);

	return res;
}
