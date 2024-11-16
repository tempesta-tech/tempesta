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

#include <iostream>

#include <clickhouse/base/socket.h>
#include <clickhouse/client.h>

#include "clickhouse.hh"


constexpr size_t MAX_MSEC = 100;
constexpr size_t MAX_EVENTS = 1000;

static auto
now_ms()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch())
		.count();
}

TfwClickhouse::TfwClickhouse(std::string host, std::string table_name,
			     std::string user, std::string password,
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
}

clickhouse::Block *
TfwClickhouse::get_block()
{
	return &block_;
}

void
TfwClickhouse::commit()
{
	uint64_t now = now_ms();

	block_.RefreshRowCount();
	if ((now - last_time_ > MAX_MSEC && block_.GetRowCount() > 0)
	    || block_.GetRowCount() > MAX_EVENTS) {

		client_->Insert(table_name_, block_);

		for (size_t i = 0; i < block_.GetColumnCount(); ++i)
			block_[i]->Clear();

		last_time_ = now;
	}
}
