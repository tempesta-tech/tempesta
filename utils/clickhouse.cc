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

using namespace std;
using namespace chrono;

constexpr size_t MAX_MSEC = 100;
constexpr size_t MAX_EVENTS = 1000;

#define NOW_MS() \
	duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()

TfwClickhouse::TfwClickhouse(string host, string table_name, Block *(*cb)())
{
	block_callback = cb;
	this->table_name = table_name;

	client = make_unique<Client>(ClientOptions().SetHost(move(host)));
	block = cb();

	last_time = NOW_MS();
}

Block *
TfwClickhouse::get_block()
{
	return block;
}

void
TfwClickhouse::commit()
{
	uint64_t now = NOW_MS();

	block->RefreshRowCount();
	if ((now - last_time > MAX_MSEC && block->GetRowCount() > 0)
		|| block->GetRowCount() > MAX_EVENTS) {

		client->Insert(move(table_name), *block);
		delete block;

		block = block_callback();
		last_time = now;
	}
}
