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

constexpr char dev_path[]	= "/dev/tempesta_mmap_log";
constexpr char table_name[]	= "access_log";
constexpr char pid_file_path[]	= "/var/run/tfw_logger.pid";
constexpr std::chrono::seconds		wait_for_dev{1};
constexpr std::chrono::milliseconds	wait_for_stop(10);
constexpr std::chrono::seconds		reconnect_min_timeout{1};
constexpr std::chrono::seconds		reconnect_max_timeout{16};

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
run_thread(const int ncpu, const int fd, const std::string &host,
	   const std::string &user, const std::string &password)
{
	static thread_local std::chrono::seconds timeout(reconnect_min_timeout);
	cpu_set_t cpuset;
	pthread_t current_thread = pthread_self();
	bool affinity_is_set = false;
	int r;

	while (!stop_flag) {
		try {
			TfwClickhouse clickhouse(host, table_name,
						 user, password, make_block());

			TfwMmapBufferReader mbr(ncpu, fd, &clickhouse, callback);

			if (!affinity_is_set) {
				CPU_ZERO(&cpuset);
				CPU_SET(mbr.get_cpu_id(), &cpuset);

				r = pthread_setaffinity_np(current_thread,
							sizeof(cpu_set_t), &cpuset);
				if (r != 0)
					throw Except("Affinity setting failed");

				affinity_is_set = true;
			}

			mbr.run(&stop_flag);

			break;
		}
		catch (const Exception &e) {
			log_error(e.what(), true, false);
			/* All the manually thrown exceptions are critical */
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
}

void
sig_handler([[maybe_unused]] int  sig_num) noexcept
{
	stop_flag = true;
	spdlog::info("Stopping daemon...");
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
		std::this_thread::sleep_for(wait_for_stop);
        }

	std::cout << "Daemon stopped." << std::endl;
}

int
main(int argc, char* argv[])
{
	std::vector<std::thread> threads;
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
		logger->flush_on(spdlog::level::info);

		spdlog::info("Starting daemon...");

		if (daemon(0, 0) < 0)
			throw Except("Daemonization failed");

		set_sig_handlers();

		std::ofstream pid_file(pid_file_path);
		if (!pid_file)
			throw Except("Failed to open PID file");
		pid_file << getpid();
		pid_file.close();

		while ((fd = open(dev_path, O_RDWR)) == -1) {
			if (stop_flag.load(std::memory_order_acquire))
				goto end;
			if (errno != ENOENT)
				throw Except("Can't open device");
			std::this_thread::sleep_for(wait_for_dev);
		}

		for (i = 0; i < cpu_cnt; ++i) {
			std::packaged_task<void(int, int, std::string, std::string,
						std::string)> task(run_thread);
			futures.push_back(task.get_future());
			threads.emplace_back(std::move(task), i, fd,
					     vm["host"].as<std::string>(), user, password);
		}

		spdlog::info("Daemon started");

		for (auto& future : futures)
			future.get();

		spdlog::info("Daemon stopped");

	}
	catch (const Exception &e) {
		log_error(e.what(), logger != nullptr, false);
		res = 1;
	}
	catch (const std::exception &e) {
		log_error(e.what(), logger != nullptr, true);
		res = 2;
	}

	for (auto &t : threads)
		t.join();

	if (fd >= 0)
		close(fd);
end:
	if (std::remove(pid_file_path) != 0)
		spdlog::error("Cant remove PID file.");

	return res;
}
