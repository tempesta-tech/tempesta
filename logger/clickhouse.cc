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

#include <iostream>
#include <string_view>

#include <fmt/format.h>

#include "clickhouse.hh"

static auto
now_ms()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch());
}

constexpr std::string_view table_creation_query_template = 
	"CREATE TABLE IF NOT EXISTS {} "
	"(timestamp DateTime64(3, 'UTC'), address IPv6, method UInt8, "
	"version UInt8, status UInt16, response_content_length UInt32, "
	"response_time UInt32, vhost String, uri String, referer String, "
	"user_agent String, ja5t UInt64, ja5h UInt64, dropped_events UInt64) "
	"ENGINE = MergeTree() ORDER BY timestamp";

TfwClickhouse::TfwClickhouse(const ClickHouseConfig &config,
			     clickhouse::Block block)
	: block_(std::move(block)),
	  last_time_(now_ms()),
	  table_name_(config.table_name),
	  max_events_(config.max_events),
	  max_wait_(config.max_wait)
{
	auto opts = clickhouse::ClientOptions();

	opts.SetHost(config.host);
	opts.SetPort(config.port);
	opts.SetDefaultDatabase(config.db_name);

	if (const auto user = config.user.value_or(""); !user.empty())
		opts.SetUser(user);
	if (const auto pswd = config.password.value_or(""); !pswd.empty())
		opts.SetPassword(pswd);

	client_ = std::make_unique<clickhouse::Client>(opts);

	std::string table_creation_query =
		fmt::format(table_creation_query_template, table_name_);
	client_->Execute(table_creation_query);
}

clickhouse::Block &
TfwClickhouse::get_block() noexcept
{
	return block_;
}

bool
TfwClickhouse::commit()
{
	auto now = now_ms();

	block_.RefreshRowCount();
	if ((now - last_time_ > max_wait_ && block_.GetRowCount() > 0)
	    || block_.GetRowCount() > max_events_) {

		client_->Insert(table_name_, block_);

		for (size_t i = 0; i < block_.GetColumnCount(); ++i)
			block_[i]->Clear();

		last_time_ = now;

		return true;
	}
	return false;
}

template <typename T> std::shared_ptr<clickhouse::Column>
create_column() {
	return std::make_shared<T>();
}

std::shared_ptr<clickhouse::Column>
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
