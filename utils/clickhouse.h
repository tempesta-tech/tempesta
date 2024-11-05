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
 * Other public methods:
 *    @getBlock - Returns a pointer to the data block for the specified CPU core.
 *    @commit - Commits the data in the block to the Clickhouse database if the
 *        elapsed time since the last insertion exceeds a predefined threshold
 *        or the block’s row count exceeds a maximum event threshold. After
 *        committing, the block is deleted, a new block is created via
 *        block_callback and last_time is updated.
 *
 * Private Members:
 *    @client - Clickhouse Client instance for sending data to the database.
 *    @block - Block instance holding data records to be inserted.
 *    @last_time - The last timestamp when data was sent.
 *    @block_callback - Callback function that creates a new Block for data
 *        storage.
 *    @table_name - Name of the Clickhouse table where data is inserted.
 */
class TfwClickhouse {
public:
	TfwClickhouse(std::string host, std::string table_name,
		      clickhouse::Block *(*cb)());
	TfwClickhouse(const TfwClickhouse &) = delete;
	TfwClickhouse &operator=(const TfwClickhouse &) = delete;

	clickhouse::Block *get_block();
	void commit();

private:
	std::unique_ptr<clickhouse::Client>	client;
	clickhouse::Block	*block;
	uint64_t		last_time;
	clickhouse::Block	*(*block_callback)();
	std::string		table_name;
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
template <typename T> std::shared_ptr<clickhouse::Column> createColumn()
{
	return std::make_shared<T>();
}

class TfwColumnFactory {
public:
	TfwColumnFactory() {
		map_[clickhouse::Type::UInt8] = &createColumn<clickhouse::ColumnUInt8>;
		map_[clickhouse::Type::UInt16] = &createColumn<clickhouse::ColumnUInt16>;
		map_[clickhouse::Type::UInt32] = &createColumn<clickhouse::ColumnUInt32>;
		map_[clickhouse::Type::UInt64] = &createColumn<clickhouse::ColumnUInt64>;
		map_[clickhouse::Type::IPv4] = &createColumn<clickhouse::ColumnIPv4>;
		map_[clickhouse::Type::IPv6] = &createColumn<clickhouse::ColumnIPv6>;
		map_[clickhouse::Type::String] = &createColumn<clickhouse::ColumnString>;
	}

	std::shared_ptr<clickhouse::Column> create(clickhouse::Type::Code code) {
		auto it = map_.find(code);
		if (it != map_.end())
			return it->second();
		throw std::runtime_error("Column factory: incorrect code");
	}

private:
	std::map<clickhouse::Type::Code, std::shared_ptr<clickhouse::Column>(*)()> map_;
};

#endif /* __TFW_CLICKHOUSE_H__ */
