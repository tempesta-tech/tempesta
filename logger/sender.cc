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

#include "sender.hh"

#include <chrono>
#include <string_view>
#include <thread>

#include <spdlog/spdlog.h>

#include "signal_handler.hh"

#include <fmt/format.h>

namespace {

template <typename T>
void
append_column(clickhouse::Block &block, const char *name, const auto &...args)
{
	auto col = std::make_shared<T>(args...);
	block.AppendColumn(name, col);
}

clickhouse::Block
make_block()
{
	using ColumnDateTime64 = clickhouse::ColumnDateTime64;
	using ColumnIPv6 = clickhouse::ColumnIPv6;
	using ColumnUInt8 = clickhouse::ColumnUInt8;
	using ColumnUInt16 = clickhouse::ColumnUInt16;
	using ColumnUInt32 = clickhouse::ColumnUInt32;
	using ColumnString = clickhouse::ColumnString;
	using ColumnUInt64 = clickhouse::ColumnUInt64;

	clickhouse::Block block;
	append_column<ColumnDateTime64>(block, "timestamp", 3);
	append_column<ColumnIPv6>(block, "address");
	append_column<ColumnUInt8>(block, "method");
	append_column<ColumnUInt8>(block, "version");
	append_column<ColumnUInt16>(block, "status");
	append_column<ColumnUInt32>(block, "response_content_length");
	append_column<ColumnUInt32>(block, "response_time");
	append_column<ColumnString>(block, "vhost");
	append_column<ColumnString>(block, "uri");
	append_column<ColumnString>(block, "referer");
	append_column<ColumnString>(block, "user_agent");
	append_column<ColumnUInt64>(block, "ja5t");
	append_column<ColumnUInt64>(block, "ja5h");
	append_column<ColumnUInt64>(block, "dropped_events");

	return block;
}

std::string
make_query_id()
{
	const auto now = std::chrono::system_clock::now();
	const auto time_since_epoch = now.time_since_epoch().count();

	constexpr std::hash<std::thread::id> hasher;
	const auto thread_id = hasher(std::this_thread::get_id());

	return fmt::format("tfw-access-log-{}-{}", thread_id, time_since_epoch);
}

bool
reset_connection(clickhouse::Client &client)
{
	constexpr std::chrono::seconds sleep_time(1);
	while (true) {
		if (stop_requested()) [[unlikely]]
			return false;

		spdlog::debug("Resetting ClickHouse connection...");
		try {
			client.ResetConnectionEndpoint();
			break;
		}
		catch (const std::exception &e) {
			spdlog::warn("Failed to reset ClickHouse connection: "
				     "{}",
				     e.what());
		}
		std::this_thread::sleep_for(sleep_time);
	}
	spdlog::debug("ClickHouse connection successfully reset");
	return true;
}

bool
create_table(const std::string &table_name, clickhouse::Client &client)
{
	constexpr std::string_view query_template =
	"CREATE TABLE IF NOT EXISTS {} "
	"(timestamp DateTime64(3, 'UTC'),"
	" address IPv6,"
	" method UInt8,"
	" version UInt8,"
	" status UInt16,"
	" response_content_length UInt32,"
	" response_time UInt32,"
	" vhost String,"
	" uri String,"
	" referer String,"
	" user_agent String,"
	" ja5t UInt64,"
	" ja5h UInt64,"
	" dropped_events UInt64) "
	"ENGINE = MergeTree() "
	"ORDER BY timestamp";

	const auto query = fmt::format(query_template, table_name);
	while (true) {
		if (stop_requested()) [[unlikely]]
			return false;

		spdlog::debug("Creating {} table in ClickHouse...", table_name);
		try {
			client.Execute(query);
			break;
		}
		catch (const std::exception &e) {
			spdlog::warn("Failed to create {} table in ClickHouse: "
				     "{}",
				     table_name, e.what());
		}

		if (!reset_connection(client)) [[unlikely]]
			return false;
	}
	spdlog::debug("{} table successfully created in ClickHouse",
		      table_name);
	return true;
}

std::unique_ptr<clickhouse::Client>
connect_to_clickhouse(const ClickHouseConfig &config)
{
	auto opts = clickhouse::ClientOptions();

	opts.SetHost(config.host);
	opts.SetPort(config.port);
	opts.SetDefaultDatabase(config.db_name);

	if (const auto user = config.user.value_or(""); !user.empty())
		opts.SetUser(user);
	if (const auto pswd = config.password.value_or(""); !pswd.empty())
		opts.SetPassword(pswd);

	std::unique_ptr<clickhouse::Client> result;
	while (true) {
		if (stop_requested()) [[unlikely]]
			return result;

		spdlog::debug("Connecting to ClickHouse...");
		try {
			result = std::make_unique<clickhouse::Client>(opts);
			break;
		}
		catch (const std::exception &e) {
			spdlog::error("Failed to connect to ClickHouse: {}",
				      e.what());
		}
	}
	spdlog::debug("Connected to ClickHouse");
	return result;
}

} // namespace

Sender::Sender(const ClickHouseConfig &config,
	       std::unique_ptr<clickhouse::Client> client)
    : table_name_(config.table_name), max_events_(config.max_events),
      max_wait_(config.max_wait), client_(std::move(client)),
      block_(make_block())
{
}

bool
Sender::add(AccessLog &&log)
{
	if (stop_requested()) [[unlikely]]
		return false;

	spdlog::trace("New event: {}", log);

	block_[0]->As<clickhouse::ColumnDateTime64>()->Append(
		log.timestamp.count());
	block_[1]->As<clickhouse::ColumnIPv6>()->Append(log.address);
	block_[2]->As<clickhouse::ColumnUInt8>()->Append(log.method);
	block_[3]->As<clickhouse::ColumnUInt8>()->Append(log.version);
	block_[4]->As<clickhouse::ColumnUInt16>()->Append(log.status);
	block_[5]->As<clickhouse::ColumnUInt32>()->Append(
		log.response_content_length);
	block_[6]->As<clickhouse::ColumnUInt32>()->Append(log.response_time);
	block_[7]->As<clickhouse::ColumnString>()->Append(std::move(log.vhost));
	block_[8]->As<clickhouse::ColumnString>()->Append(std::move(log.uri));
	block_[9]->As<clickhouse::ColumnString>()->Append(
		std::move(log.referer));
	block_[10]->As<clickhouse::ColumnString>()->Append(
		std::move(log.user_agent));
	block_[11]->As<clickhouse::ColumnUInt64>()->Append(log.ja5t);
	block_[12]->As<clickhouse::ColumnUInt64>()->Append(log.ja5h);
	block_[13]->As<clickhouse::ColumnUInt64>()->Append(log.dropped_events);

	return commit();
}

bool
Sender::commit()
{
	if (stop_requested()) [[unlikely]]
		return false;

	const auto now = std::chrono::system_clock::now();
	const auto time_passed = now - last_commit_time_;

	block_.RefreshRowCount();
	const auto row_count = block_.GetRowCount();
	if (row_count == 0 ||
	    (time_passed < max_wait_ && row_count < max_events_))
		return true;

	if (!insert()) [[unlikely]]
		return false;

	last_commit_time_ = now;
	return true;
}

bool
Sender::insert()
{
	const auto query_id = make_query_id();
	while (true) {
		if (stop_requested()) [[unlikely]]
			return false;

		spdlog::debug("Inserting {} events to ClickHouse "
			      "(query_id: {})...",
			      block_.GetRowCount(), query_id);
		try {
			client_->Insert(table_name_, query_id, block_);
			break;
		}
		catch (const std::exception &e) {
			spdlog::warn("Failed to insert events to ClickHouse: "
				     "{}",
				     e.what());
		}

		if (!reset_connection(*client_)) [[unlikely]]
			return false;
	}
	spdlog::debug("Events successfully inserted to ClickHouse "
		      "(query_id: {})",
		      query_id);
	block_.Clear();
	return true;
}

std::optional<Sender>
make_sender(const ClickHouseConfig &config)
{
	auto client = connect_to_clickhouse(config);
	if (!client) [[unlikely]]
		return std::nullopt;

	if (!create_table(config.table_name, *client)) [[unlikely]]
		return std::nullopt;

	return Sender(config, std::move(client));
}
