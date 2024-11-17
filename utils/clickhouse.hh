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

#pragma once

#include <iostream>

#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

/**
 * Class for sending records to a Clickhouse database.
 *
 * Constructor:
 *    @TfwClickhouse - Initializes the Clickhouse connection, and create a data
 *        block, with a provided callback.
 *
 * Destructor:
 *    @~TfwClickhouse - Delete Block object in block_.
 *
 * Other public methods:
 *    @get_block - Returns a pointer to the data block for the specified CPU core.
 *    @commit - Commits the data in the block to the Clickhouse database if the
 *        elapsed time since the last insertion exceeds a predefined threshold
 *        or the block’s row count exceeds a maximum event threshold. After
 *        committing, the block is deleted, a new block is created via
 *        block_callback and last_time is updated.
 *
 * Private Members:
 *    @client_ - Clickhouse Client instance for sending data to the database.
 *    @block_ - Block instance holding data records to be inserted.
 *    @last_time_ - The last timestamp when data was sent.
 *    @block_callback_ - Callback function that creates a new Block for data
 *        storage.
 *    @table_name_ - Name of the Clickhouse table where data is inserted.
 */
class TfwClickhouse {
public:
	TfwClickhouse(std::string host, std::string table_name,
		      std::string user, std::string password,
		      clickhouse::Block block);
	TfwClickhouse(const TfwClickhouse &) = delete;
	TfwClickhouse &operator=(const TfwClickhouse &) = delete;
	~TfwClickhouse();

	clickhouse::Block *get_block() noexcept;
	void commit();

private:
	std::unique_ptr<clickhouse::Client>	client_;
	clickhouse::Block			block_;
	std::chrono::milliseconds		last_time_;
	std::string				table_name_;
};

template <typename T> std::shared_ptr<clickhouse::Column>
create_column() {
	return std::make_shared<T>();
}

static std::shared_ptr<clickhouse::Column>
tfw_column_factory(clickhouse::Type::Code code)
{
	switch (code) {
	case clickhouse::Type::UInt8:
		return create_column<clickhouse::ColumnUInt8>();
	case clickhouse::Type::UInt16:
		return create_column<clickhouse::ColumnUInt16>();
	case clickhouse::Type::UInt32:
		return create_column<clickhouse::ColumnUInt32>();
	case clickhouse::Type::UInt64:
		return create_column<clickhouse::ColumnUInt64>();
	case clickhouse::Type::IPv4:
		return create_column<clickhouse::ColumnIPv4>();
	case clickhouse::Type::IPv6:
		return create_column<clickhouse::ColumnIPv6>();
	case clickhouse::Type::String:
		return create_column<clickhouse::ColumnString>();
	default:
		throw std::runtime_error("Column factory: incorrect code");
	}
}
