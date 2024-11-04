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

#ifndef __TFW_CLICKHOUSE_H__
#define __TFW_CLICKHOUSE_H__

#include <iostream>

#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

using namespace clickhouse;
using namespace std;

/**
 * Class for sending records to a Clickhouse database.
 * It manages multiple instances of the Clickhouse client (one per thread) to
 * handle concurrent operations, as the Clickhouse client itself is not
 * thread-safe.
 *
 * Constructor:
 *    @TfwClickhouse - Initializes the Clickhouse connection for each CPU core,
 *        setting up individual clients and data blocks, with a provided callback.
 *
 * Destructor:
 *    @~TfwClickhouse - Cleans up by deleting all Client and Block instances
 *        and freeing the tasks array.
 *    @getBlock - Returns a pointer to the data block for the specified CPU core.
 *    @commit - Commits the data in the block to the Clickhouse database if the
 *        elapsed time since the last insertion exceeds a predefined threshold
 *        or the block’s row count exceeds a maximum event threshold. After
 *        committing, the block is deleted, a new block is created via
 *        block_callback and last_time is updated.
 *
 * Private Struct:
 *    @struct TfwTask - Holds task-specific data for each CPU core, including:
 *        @client - Clickhouse Client instance for sending data to the database.
 *        @block - Block instance holding data records to be inserted.
 *        @last_time - The last timestamp when data was sent.
 *
 * Private Members:
 *    @tasks - Array of tasks, one for each CPU core, to manage per-thread data
 *        and clients.
 *    @block_callback - Callback function that creates a new Block for data
 *        storage.
 *    @cpu_cnt - Number of CPU cores to be used.
 *    @table_name - Name of the Clickhouse table where data is inserted.
 */
class TfwClickhouse {
public:
	TfwClickhouse(string host, string table_name,
		      unsigned int cpu_cnt, Block *(*cb)());
	~TfwClickhouse();
	Block *getBlock(unsigned int cpu);
	void commit(unsigned int cpu);

private:
	typedef struct {
		Client		*client;
		Block		*block;
		uint64_t	last_time;
	} TfwTask;

	TfwTask		*tasks;
	Block		*(*block_callback)();
	unsigned int	cpu_cnt;
	string		table_name;
};

/**
 * TfwColumnFactory is a factory class for creating objects of classes derived
 * from Column based on a specified type code. It allows dynamic creation of
 * column objects depending on the type required, simplifying column handling
 * for different data types.
 *
 * Constructor:
 *    @TfwColumnFactory - Initializes a mapping from `Type::Code` values to
 *        corresponding column creation functions. This mapping links specific
 *        type codes (e.g., `Type::UInt8`, `Type::IPv4`) to functions that
 *        instantiate columns of the appropriate derived type.
 *
 * Public Method:
 *    @create - Creates and returns a shared pointer to a column object based
 *        on the provided type code. Looks up the map_ for a matching function
 *        pointer for the specified code.
 *
 * Private Member:
 *    @map_ - A map associating Type::Code enums with function pointers.
 */
template <typename T> shared_ptr<Column> createColumn()
{
	return make_shared<T>();
}

class TfwColumnFactory {
public:
	TfwColumnFactory() {
		map_[Type::UInt8] = &createColumn<ColumnUInt8>;
		map_[Type::UInt16] = &createColumn<ColumnUInt16>;
		map_[Type::UInt32] = &createColumn<ColumnUInt32>;
		map_[Type::UInt64] = &createColumn<ColumnUInt64>;
		map_[Type::IPv4] = &createColumn<ColumnIPv4>;
		map_[Type::IPv6] = &createColumn<ColumnIPv6>;
		map_[Type::String] = &createColumn<ColumnString>;
	}

	shared_ptr<Column> create(Type::Code code) {
		auto it = map_.find(code);
		if (it != map_.end())
			return it->second();
		throw runtime_error("Column factory: incorrect code");
	}

private:
	map<Type::Code, shared_ptr<Column>(*)()> map_;
};

#endif /* __TFW_CLICKHOUSE_H__ */
