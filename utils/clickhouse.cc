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

#include "clickhouse.h"


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
			     std::shared_ptr<clickhouse::Block> (*cb)())
{
	auto opts = clickhouse::ClientOptions();

	block_callback_ = cb;
	table_name_ = table_name;

	opts.SetHost(std::move(host));

	if (!user.empty())
		opts.SetUser(std::move(user));
	if (!password.empty())
		opts.SetPassword(std::move(password));

	client_ = std::make_unique<clickhouse::Client>(std::move(opts));
	block_ = cb();

	last_time_ = now_ms();
}

std::shared_ptr<clickhouse::Block>
TfwClickhouse::get_block()
{
	return block_;
}

void
TfwClickhouse::commit()
{
	uint64_t now = now_ms();

	block_->RefreshRowCount();
	if ((now - last_time_ > MAX_MSEC && block_->GetRowCount() > 0)
		|| block_->GetRowCount() > MAX_EVENTS) {

		client_->Insert(std::move(table_name_), *block_);

		block_ = block_callback_();
		last_time_ = now;
	}
}
