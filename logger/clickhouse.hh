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
#pragma once

#include <chrono>
#include <memory>
#include <string>

#include <clickhouse/block.h>
#include <clickhouse/client.h>
#include <clickhouse/columns/column.h>
#include <clickhouse/types/types.h>

#include "clickhouse_config.hh"

namespace ch = clickhouse;

/**
 * Class for sending records to a Clickhouse database.
 *
 * Constructor:
 *    @TfwClickhouse - Initializes the Clickhouse connection, and create a data
 *        block, with a provided callback.
 *
 * Other public methods:
 *    @get_block - Returns a pointer to the data block for the specified CPU core.
 *    @commit - Commits the data in the block to the Clickhouse database if the
 *        elapsed time since the last insertion exceeds a predefined threshold
 *        or the block’s row count exceeds a maximum event threshold. After
 *        committing, the block is deleted, a new block is created via
 *        block_callback and last_time is updated. If a block was committed
 *        return true, otherwise return false.
 *
 * Private Members:
 *    @client_ - Clickhouse Client instance for sending data to the database.
 *    @block_ - Block instance holding data records to be inserted.
 *    @last_time_ - The last timestamp when data was sent.
 *    @table_name_ - Name of the Clickhouse table where data is inserted.
 *    @max_events_ - Maximum number of events to insert before committing.
 *    @max_wait_ - Maximum time to wait before committing.
 */
class TfwClickhouse {
public:
	TfwClickhouse(const ClickHouseConfig &config, ch::Block block);
	TfwClickhouse(const TfwClickhouse &) = delete;
	TfwClickhouse &operator=(const TfwClickhouse &) = delete;

	ch::Block &get_block() noexcept;
	bool commit(bool force = false);

private:
	std::unique_ptr<clickhouse::Client>	client_;
	ch::Block				block_;
	std::chrono::milliseconds		last_time_;
	const std::string			table_name_;
	const size_t				max_events_;
	const std::chrono::milliseconds		max_wait_;
};

std::shared_ptr<clickhouse::Column>
tfw_column_factory(clickhouse::Type::Code code);
