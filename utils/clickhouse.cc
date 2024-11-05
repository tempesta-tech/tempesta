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
			     clickhouse::Block *(*cb)())
{
	block_callback = cb;
	this->table_name = table_name;

	client = std::make_unique<clickhouse::Client>(
		clickhouse::ClientOptions().SetHost(std::move(host)));
	block = cb();

	last_time = now_ms();
}

clickhouse::Block *
TfwClickhouse::get_block()
{
	return block;
}

void
TfwClickhouse::commit()
{
	uint64_t now = now_ms();

	block->RefreshRowCount();
	if ((now - last_time > MAX_MSEC && block->GetRowCount() > 0)
		|| block->GetRowCount() > MAX_EVENTS) {

		client->Insert(std::move(table_name), *block);
		delete block;

		block = block_callback();
		last_time = now;
	}
}
