/**
 *		Tempesta FW
 *
 * Clickhouse interfaces using the C++ client library.
 * For code samples and the source code reference:
 *
 *   https://github.com/ClickHouse/clickhouse-cpp.git
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
#include <iostream>
#include <string_view>
#include <netinet/in.h>

#include <fmt/format.h>

#include <spdlog/spdlog.h>

#include "../fw/access_log.h"
#include "../libtus/error.hh"
#include "clickhouse.hh"

namespace {

constexpr std::string_view table_creation_query_template =
	"CREATE TABLE IF NOT EXISTS {} "
	"(timestamp DateTime64(3, 'UTC'),"
	" address IPv6,"
	" method UInt8,"
	" version UInt8,"
	" status UInt16,"
	" response_content_length UInt64,"
	" response_time UInt32,"
	" vhost String,"
	" uri String,"
	" referer String,"
	" user_agent String,"
	" tft UInt64,"
	" tfh UInt64,"
	" dropped_events UInt64"
	") ENGINE = MergeTree() ORDER BY timestamp";

typedef struct {
	const char			*name;
	ch::Type::Code			code;
} TfwField;

static const TfwField tfw_fields[] = {
	[TFW_MMAP_LOG_ADDR]		= {"address", ch::Type::IPv6},
	[TFW_MMAP_LOG_METHOD]		= {"method", ch::Type::UInt8},
	[TFW_MMAP_LOG_VERSION]		= {"version", ch::Type::UInt8},
	[TFW_MMAP_LOG_STATUS]		= {"status", ch::Type::UInt16},
	[TFW_MMAP_LOG_RESP_CONT_LEN]	= {"response_content_length", ch::Type::UInt32},
	[TFW_MMAP_LOG_RESP_TIME]	= {"response_time", ch::Type::UInt32},
	[TFW_MMAP_LOG_VHOST]		= {"vhost", ch::Type::String},
	[TFW_MMAP_LOG_URI]		= {"uri", ch::Type::String},
	[TFW_MMAP_LOG_REFERER]		= {"referer", ch::Type::String},
	[TFW_MMAP_LOG_USER_AGENT]	= {"user_agent", ch::Type::String},
	[TFW_MMAP_LOG_TFT]		= {"tft", ch::Type::UInt64},
	[TFW_MMAP_LOG_TFH]		= {"tfh", ch::Type::UInt64},
	[TFW_MMAP_LOG_DROPPED]		= {"dropped_events", ch::Type::UInt64}
};

} // anonymous namespace

void
TfwClickhouse::make_block()
{
	block_ = ch::Block();

	auto col = std::make_shared<ch::ColumnDateTime64>(3);
	block_.AppendColumn("timestamp", col);

	for (int i = TFW_MMAP_LOG_ADDR; i < TFW_MMAP_LOG_MAX; ++i) {
		const TfwField *field = &tfw_fields[i];
		auto col = tfw_column_factory(field->code);
		block_.AppendColumn(field->name, col);
	}

	// We may read more data in one shot, so reserve more memory.
	block_.Reserve(max_events_ * 2);
}

bool
TfwClickhouse::reestablish_connection() noexcept
{
	try {
		auto client = std::make_unique<ch::Client>(client_options_);
		client_.swap(client);

		spdlog::info("Successfully reconnected to ClickHouse");
		return true;
	}
	catch (const std::exception& e) {
		spdlog::error("Failed to reconnect to ClickHouse: {}", e.what());
		return false;
	}
	catch (...) {
		spdlog::error("Failed to reconnect to ClickHouse: unknown error");
		return false;
	}
}

void
TfwClickhouse::append_timestamp(uint64_t timestamp)
{
	block_[0]->As<ch::ColumnDateTime64>()->Append(timestamp);
}

bool
TfwClickhouse::handle_block_error() noexcept
{
	try {
		block_.Clear();
		return true;
	}
	catch (const std::exception &e) {
		spdlog::error("Cannot clear a Clickhouse block: {}", e.what());
	}
	return false;
}

TfwClickhouse::TfwClickhouse(const ClickHouseConfig &config)
	: table_name_(config.table_name)
	, max_events_(config.max_events)
	, client_options_([config]()
	{
		ch::ClientOptions options;
		options.SetHost(config.host)
		       .SetPort(config.port)
		       .SetDefaultDatabase(config.db_name);
		if (const auto user = config.user.value_or(""); !user.empty())
			options.SetUser(user);
		if (const auto pswd = config.password.value_or(""); !pswd.empty())
			options.SetPassword(pswd);
		return options;
	}())
{
	client_ = std::make_unique<ch::Client>(client_options_);

	std::string table_creation_query =
		fmt::format(table_creation_query_template, table_name_);
	client_->Execute(table_creation_query);

	make_block();
}

TfwClickhouse::~TfwClickhouse()
{
	handle_block_error();
}

[[nodiscard]] bool
TfwClickhouse::commit(bool force) noexcept
{
	try {
		block_.RefreshRowCount();


		if (force) {
			if (block_.GetRowCount() == 0)
				return true;
		} else {
			if (block_.GetRowCount() < max_events_)
				return true;
		}

		client_->Insert(table_name_, block_);
		block_.Clear();
	}
	catch (const std::exception &e) {
		spdlog::error("Clickhouse insert error: {}", e.what());
		return false;
	}

	return true;
}

template <typename T> std::shared_ptr<ch::Column>
create_column() {
	return std::make_shared<T>();
}

std::shared_ptr<ch::Column>
tfw_column_factory(ch::Type::Code code)
{
	switch (code) {
	case ch::Type::UInt8:
		return create_column<ch::ColumnUInt8>();
	case ch::Type::UInt16:
		return create_column<ch::ColumnUInt16>();
	case ch::Type::UInt32:
		return create_column<ch::ColumnUInt32>();
	case ch::Type::UInt64:
		return create_column<ch::ColumnUInt64>();
	case ch::Type::IPv4:
		return create_column<ch::ColumnIPv4>();
	case ch::Type::IPv6:
		return create_column<ch::ColumnIPv6>();
	case ch::Type::String:
		return create_column<ch::ColumnString>();
	default:
		throw std::runtime_error("Column factory: incorrect code");
	}
}
