#include "mmap_buffer.h"
#include "clickhouse.h"
#include "../fw/access_log.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <clickhouse/client.h>
#include <clickhouse/base/socket.h>

using namespace std;

#define FILE_PATH	"/dev/tempesta_mmap_log"
#define TABLE_NAME	"access_log"

typedef struct {
	const char	*name;
	Type::Code	code;
} TfwField;

static const TfwField tfw_fields[] = {
	[TFW_MMAP_LOG_ADDR]		= {"address", Type::IPv6},
	[TFW_MMAP_LOG_METHOD]		= {"method", Type::UInt8},
	[TFW_MMAP_LOG_VERSION]		= {"version", Type::UInt8},
	[TFW_MMAP_LOG_STATUS]		= {"status", Type::UInt16},
	[TFW_MMAP_LOG_RESP_CONT_LEN]	= {"response_content_length", Type::UInt32},
	[TFW_MMAP_LOG_RESP_TIME]	= {"response_time", Type::UInt32},
	[TFW_MMAP_LOG_VHOST]		= {"vhost", Type::String},
	[TFW_MMAP_LOG_URI]		= {"uri", Type::String},
	[TFW_MMAP_LOG_REFERER]		= {"referer", Type::String},
	[TFW_MMAP_LOG_USER_AGENT]	= {"user_agent", Type::String},
};

TfwClickhouse *tfw_clickhouse;
TfwColumnFactory *tfw_column_factory;

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

static Block *
make_block()
{
	unsigned int i;
	Block *block = new Block();

	auto col = tfw_column_factory->create(Type::UInt64);
	block->AppendColumn("timestamp", col);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		const TfwField *field = &tfw_fields[i];

		auto col = tfw_column_factory->create(field->code);
		block->AppendColumn(field->name, col);
	}

	return block;
}

int
read_access_log_event(const char *data, int size, int cpu)
{
	Block *block = tfw_clickhouse->getBlock(cpu);
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


	(*block)[0]->As<ColumnUInt64>()->Append(event->timestamp);

	for (i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		int len, ind = i + 1;

		len = tfw_mmap_log_field_len((TfwBinLogFields)i);

		switch (i) {
		INT_CASE(TFW_MMAP_LOG_ADDR, ColumnIPv6, struct in6_addr);
		INT_CASE(TFW_MMAP_LOG_METHOD, ColumnUInt8, unsigned char);
		INT_CASE(TFW_MMAP_LOG_VERSION, ColumnUInt8, unsigned char);
		INT_CASE(TFW_MMAP_LOG_STATUS, ColumnUInt16, uint16_t);
		INT_CASE(TFW_MMAP_LOG_RESP_CONT_LEN, ColumnUInt32, uint32_t);
		INT_CASE(TFW_MMAP_LOG_RESP_TIME, ColumnUInt32, uint32_t);

		case TFW_MMAP_LOG_VHOST:
		case TFW_MMAP_LOG_URI:
		case TFW_MMAP_LOG_REFERER:
		case TFW_MMAP_LOG_USER_AGENT:
			if (!TFW_MMAP_LOG_FIELD_IS_SET(event, i)) {
				(*block)[ind]->As<ColumnString>()->Append(move(string("")));
				break;
			}
			len = *((uint16_t *)p);
			if (len + 2 > size)
				return -1;
			(*block)[ind]->As<ColumnString>()->Append(move(string(p + 2, len)));
			len += 2;
			break;
		default:
			cerr << "Unknown field type: " << i << endl;
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
callback(const char *data, int size, unsigned int cpu)
{
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
			r = read_access_log_event(p, size, cpu);
			if (r < 0)
				return;
			size -= r;
			p += r;
			break;
		case TFW_MMAP_LOG_TYPE_DROPPED:
			p += sizeof(TfwBinLogEvent);
			size -= sizeof(TfwBinLogEvent);
			if ((int)sizeof(u64) > size) {
				cerr << "Incorrect event length" << endl;
				return;
			}

			cerr << "Dropped events: " << *(u64 *)p << endl;
			size -= sizeof(u64);
			p += sizeof(u64);
			return;
		default:
			cerr << "Unsupported log type: " << event->type << endl;
			return;
		}
	} while (size > 0);

	tfw_clickhouse->commit(cpu);
}

int
main(int argc, char* argv[])
{
	unsigned int cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN);

	if (argc != 2) {
		cout << "Usage:" << endl;
		cout << "\t" << argv[0] << " <host>" << endl;
		return -EINVAL;
	}

	tfw_column_factory = new TfwColumnFactory();
	tfw_clickhouse = new TfwClickhouse(argv[1], TABLE_NAME, cpu_cnt, make_block);

	TfwMmapBufferReader MB(FILE_PATH, cpu_cnt, callback);

	MB.run();

	delete tfw_clickhouse;
	delete tfw_column_factory;

	return 0;
}
