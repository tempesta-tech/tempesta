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

#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

#include "clickhouse.hh"

constexpr std::chrono::milliseconds max_wait(100);
constexpr size_t max_events = 1000;
constexpr char table_creation_querry[] = "CREATE TABLE IF NOT EXISTS "
	"access_log (timestamp DateTime64(3, 'UTC'), address IPv6, method UInt8, "
	"version UInt8, status UInt16, response_content_length UInt64, "
	"response_time UInt32, vhost String, uri String, referer String, "
	"user_agent String, tft UInt64, tfh UInt64, dropped_events UInt64,"
	"PRIMARY KEY(timestamp));";

static auto
now_ms()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch());
}

TfwClickhouse::TfwClickhouse(const std::string &host, const std::string &table_name,
			     const std::string &user, const std::string &password,
			     clickhouse::Block block)
	: block_(block), last_time_(now_ms()), table_name_(table_name)
{
	auto opts = clickhouse::ClientOptions();

	opts.SetHost(host);

	if (!user.empty())
		opts.SetUser(user);
	if (!password.empty())
		opts.SetPassword(password);

	client_ = std::make_unique<clickhouse::Client>(opts);

	client_->Execute(table_creation_querry);
}

clickhouse::Block *
TfwClickhouse::get_block() noexcept
{
	return &block_;
}

bool
TfwClickhouse::commit()
{
	auto now = now_ms();

	block_.RefreshRowCount();
	if ((now - last_time_ > max_wait && block_.GetRowCount() > 0)
	    || block_.GetRowCount() > max_events) {

		client_->Insert(table_name_, block_);

		for (size_t i = 0; i < block_.GetColumnCount(); ++i)
			block_[i]->Clear();

		last_time_ = now;

		return true;
	}
	return false;
}
