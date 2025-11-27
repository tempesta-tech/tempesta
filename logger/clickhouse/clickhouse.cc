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
#include <spdlog/spdlog.h>

#include "../../libtus/error.hh"
#include "clickhouse.hh"


bool
TfwClickhouse::reestablish_connection() noexcept
{
	try {
		client_.ResetConnection();

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

// An exception can occur here, but it is not related to the connection.
// At this stage, we are only creating the class; no connection is established yet.
TfwClickhouse::TfwClickhouse(ch::ClientOptions &&client_options)
	: client_(std::move(client_options))
{
}

bool
TfwClickhouse::ensure_connected() noexcept
{
	return true;
}

bool
TfwClickhouse::execute(const std::string &query) noexcept
{
	try {
		client_.Execute(query);
		return true;
	}
	catch (const std::exception &e) {
		spdlog::error("Clickhouse insert error: {}", e.what());
		return false;
	}
}

bool
TfwClickhouse::flush(const std::string &table_name, ch::Block &block) noexcept
{
	try {
		client_.Insert(table_name, block);
		return true;
	}
	catch (const std::exception &e) {
		spdlog::error("Clickhouse insert error: {}", e.what());
		return false;
	}
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
	case ch::Type::DateTime64:
		return std::make_shared<ch::ColumnDateTime64>(3);
	default:
		throw std::runtime_error("Column factory: incorrect code");
	}
}
