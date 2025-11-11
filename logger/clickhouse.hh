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

template<TfwBinLogFields FieldType>
struct TfwBinLogTypeCommonTraits
{
	static constexpr size_t index = static_cast<size_t>(FieldType) + 1;
};

template<TfwBinLogFields FieldType>
struct TfwBinLogTypeTraits
{
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_ADDR>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_ADDR>
{
	using ColType = ch::ColumnIPv6;
	using ValType = struct in6_addr;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_METHOD>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_METHOD>
{
	using ColType = ch::ColumnUInt8;
	using ValType = uint8_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_VERSION>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_VERSION>
{
	using ColType = ch::ColumnUInt8;
	using ValType = uint8_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_STATUS>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_STATUS>
{
	using ColType = ch::ColumnUInt16;
	using ValType = uint16_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_RESP_CONT_LEN>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_RESP_CONT_LEN>
{
	using ColType = ch::ColumnUInt32;
	using ValType = uint32_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_RESP_TIME>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_RESP_TIME>
{
	using ColType = ch::ColumnUInt32;
	using ValType = uint32_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_VHOST>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_VHOST>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_URI>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_URI>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_REFERER>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_REFERER>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_USER_AGENT>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_USER_AGENT>
{
	using ColType = ch::ColumnString;
	using ValType = std::string_view;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_TFT>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_TFT>
{
	using ColType = ch::ColumnUInt64;
	using ValType = uint64_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_TFH>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_TFH>
{
	using ColType = ch::ColumnUInt64;
	using ValType = uint64_t;
};

template<>
struct TfwBinLogTypeTraits<TFW_MMAP_LOG_DROPPED>
	: TfwBinLogTypeCommonTraits<TFW_MMAP_LOG_DROPPED>
{
	using ColType = ch::ColumnUInt64;
	using ValType = uint64_t;
};

//TODO: fix description
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

	template<TfwBinLogFields FieldType>
	void append(
		const typename TfwBinLogTypeTraits<FieldType>::ValType& value);
	void append_timestamp(uint64_t timestamp);

	[[nodiscard]] bool commit(bool force = false) noexcept;
	bool handle_block_error() noexcept;

	bool should_attempt_reconnect() const noexcept;
	bool do_reconnect() noexcept;

public:
	std::atomic<bool> needs_reconnect{false};
	std::atomic<std::chrono::steady_clock::time_point>
		last_reconnect_attempt{
			std::chrono::steady_clock::time_point::min()};
	// The most Clickhouse API errors can be handled with simple connection
	// reset and reconnection
	//
	//   https://github.com/ClickHouse/clickhouse-cpp/issues/184
	//
	// We start with zero reconnection timeout. However, the database can
	// be restarted, so we use indefinite loop with double backoff in
	// reconnection attempts.
	std::atomic<std::chrono::seconds> reconnect_timeout{
		std::chrono::seconds(0)
	};

private:
	// We store timestamp at index 0
	constexpr size_t
	field_to_column_index(TfwBinLogFields field) const noexcept {
		return static_cast<size_t>(field) + 1;
	}

	void make_block();
	void update_reconnect_timeout(bool success) noexcept;

private:
	const std::string		table_name_;
	const size_t			max_events_;
	const ch::ClientOptions		client_options_;

	ch::Block			block_;
	std::unique_ptr<ch::Client>	client_;
};

std::shared_ptr<ch::Column>
tfw_column_factory(ch::Type::Code code);

template <TfwBinLogFields FieldType>
void
TfwClickhouse::append(
	const typename TfwBinLogTypeTraits<FieldType>::ValType& value)
{
	using Traits   = TfwBinLogTypeTraits<FieldType>;
	using ColType  = typename Traits::ColType;

	block_[Traits::index]->template As<ColType>()->Append(value);
}
