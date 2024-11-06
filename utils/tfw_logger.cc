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
#include <unistd.h>
#include <stdio.h>

#include <future>
#include <iostream>

#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

#include "../fw/access_log.h"
#include "clickhouse.h"
#include "mmap_buffer.h"
#include "error.h"

#define FILE_PATH	"/dev/tempesta_mmap_log"
#define TABLE_NAME	"access_log"

constexpr size_t WAIT_FOR_FILE = 1;  /* s */

typedef struct {
	const char	*name;
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
};

#ifdef DEBUG
static void
hexdump(const char *data, int buflen)
{
	const unsigned char *buf = (const unsigned char*)data;
	int i, j;

#define PRINT_CHAR(c) (isprint(c) ? c : '.')
	for (i = 0; i < buflen; i += 16) {
		printf("%06x: ", i);
		for (j = 0; j < 16; ++j)
			if (i + j < buflen)
				printf("%02x ", buf[i + j]);
			else
				printf("   ");
		printf(" ");
		for (j = 0; j < 16; ++j)
			if (i + j < buflen)
				printf("%c", PRINT_CHAR(buf[i + j]));
		printf("\n");
	}
#undef PRINT_CHAR
}
#endif /* DEBUG */

static clickhouse::Block *
make_block()
{
	unsigned int i;
	clickhouse::Block *block = new clickhouse::Block();

	auto col = tfw_column_factory(clickhouse::Type::UInt64);
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
	clickhouse::Block *block = clickhouse->get_block();
	const char *p = data;
	TfwBinLogEvent *event = (TfwBinLogEvent *)p;
	int i;

	p += sizeof(TfwBinLogEvent);
	size -= sizeof(TfwBinLogEvent);

#define INT_CASE(method, col_type, val_type)					\
	case method:								\
		if (len > size)							\
			return -1;						\
		if (TFW_MMAP_LOG_FIELD_IS_SET(event, i))			\
			(*block)[ind]->As<col_type>()->Append(*(val_type *)p);	\
		else								\
			(*block)[ind]->As<col_type>()->Append(0);		\
		break;


	(*block)[0]->As<clickhouse::ColumnUInt64>()->Append(event->timestamp);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		int len, ind = i + 1;

		len = tfw_mmap_log_field_len((TfwBinLogFields)i);

		switch (i) {
		INT_CASE(TFW_MMAP_LOG_ADDR, clickhouse::ColumnIPv6, struct in6_addr);
		INT_CASE(TFW_MMAP_LOG_METHOD, clickhouse::ColumnUInt8, unsigned char);
		INT_CASE(TFW_MMAP_LOG_VERSION, clickhouse::ColumnUInt8, unsigned char);
		INT_CASE(TFW_MMAP_LOG_STATUS, clickhouse::ColumnUInt16, uint16_t);
		INT_CASE(TFW_MMAP_LOG_RESP_CONT_LEN, clickhouse::ColumnUInt32, uint32_t);
		INT_CASE(TFW_MMAP_LOG_RESP_TIME, clickhouse::ColumnUInt32, uint32_t);

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
			std::cerr << "Unknown field type: " << i << std::endl;
			return -1;
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

#ifdef DEBUG
	hexdump(data, size);
#endif /* DEBUG */

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
		case TFW_MMAP_LOG_TYPE_DROPPED:
			p += sizeof(TfwBinLogEvent);
			size -= sizeof(TfwBinLogEvent);
			if ((int)sizeof(u64) > size) {
				std::cerr << "Incorrect event length" << std::endl;
				return;
			}

			std::cerr << "Dropped events: " << *(u64 *)p << std::endl;
			size -= sizeof(u64);
			p += sizeof(u64);
			return;
		default:
			std::cerr << "Unsupported log type: " << event->type << std::endl;
			return;
		}
	} while (size > 0);

	clickhouse->commit();
}

void
run_thread(int ncpu, int fd, std::string host, std::promise<void> promise)
try {
	cpu_set_t cpuset;
	pthread_t current_thread = pthread_self();

	TfwClickhouse clickhouse(host, TABLE_NAME, make_block);

	TfwMmapBufferReader mbr(ncpu, fd, &clickhouse, callback);

	CPU_ZERO(&cpuset);
	CPU_SET(mbr.get_cpu_id(), &cpuset);

	assert(pthread_setaffinity_np(current_thread,
				      sizeof(cpu_set_t), &cpuset) == 0);

	mbr.run();

	promise.set_value();
}
catch (...) {
	promise.set_exception(std::current_exception());
}

int
main(int argc, char* argv[])
try {
	std::vector<std::thread> thrs;
	std::vector<std::future<void>> futures;
	unsigned int i, cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);
	int fd;

	if (argc != 2) {
		std::cout << "Usage:" << std::endl;
		std::cout << "\t" << argv[0] << " <host>" << std::endl;
		return -EINVAL;
	}

	while ((fd = open(FILE_PATH, O_RDWR)) == -1) {
		if (errno != ENOENT)
			throw Except("Can't open device");
		sleep(WAIT_FOR_FILE);
	}

	for (i = 0; i < cpu_cnt; ++i) {
		std::promise<void> promise;
		futures.push_back(promise.get_future());
		thrs.push_back(std::thread(run_thread, i, fd, std::move(argv[1]),
					std::move(promise)));
	}

	for (i = 0; i < cpu_cnt; ++i)
		thrs[i].join();

	close(fd);

	for (auto& future : futures)
		future.get();

	return 0;
}
catch (Exception &e) {
	std::cerr << "Error: " << e.what() << std::endl;
	return 1;
}
catch (std::exception &e) {
	std::cerr << "Unhandled error: " << e.what() << std::endl;
	return 2;
}
