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

#include <memory>
#include <string>

#include <clickhouse/block.h>
#include <clickhouse/client.h>
#include <clickhouse/columns/column.h>
#include <clickhouse/types/types.h>

#include "../fw/access_log.h"
#include "clickhouse_config.hh"
#include "../libtus/error.hh"

namespace ch = clickhouse;

/**
 * Class for sending records to a Clickhouse database.
 *
 * Constructor:
 *    @TfwClickhouse - Initializes the Clickhouse connection and create a data
 *        block.
 *
 * Other public methods:
 *    @get_block - Returns a pointer to the data block for the specified CPU core.
 *    @commit - Commits the data in the block to the Clickhouse database if the
 *        block’s row count exceeds a maximum event threshold. After
 *        committing, the block is deleted, a new block is created via
 *        block_callback and last_time is updated. If a block was committed
 *        return true, otherwise return false.
 *    @handle_block_error() - try to recover from a Clickhouse API error or an
 *        access event parsing.
 *
 * Private Members:
 *    @client_ - Clickhouse Client instance for sending data to the database.
 *    @block_ - Block instance holding data records to be inserted.
 *    @table_name_ - Name of the Clickhouse table where data is inserted.
 *    @max_events_ - Maximum number of events to insert before committing.
 */
class TfwClickhouse {
public:
	static const bool FORCE = true;

	TfwClickhouse(const ClickHouseConfig &config);
	TfwClickhouse(const TfwClickhouse &) = delete;
	TfwClickhouse &operator=(const TfwClickhouse &) = delete;

	~TfwClickhouse();

	void append_timestamp(uint64_t timestamp);

	template <typename ColType, typename ValType>
	void append_int(TfwBinLogFields field, ValType value);

	void append_string(TfwBinLogFields field, std::string_view value);
	void append_empty_string(TfwBinLogFields field);

	[[nodiscard]] bool commit(bool force = false) noexcept;
	bool handle_block_error() noexcept;

private:
	constexpr size_t
	field_to_column_index(TfwBinLogFields field) const noexcept {
		return static_cast<size_t>(field) + 1;
	}

	void make_block();

private:
	std::unique_ptr<ch::Client>	client_;
	ch::Block			block_;
	const std::string		table_name_;
	const size_t			max_events_;
};

std::shared_ptr<ch::Column>
tfw_column_factory(ch::Type::Code code);
