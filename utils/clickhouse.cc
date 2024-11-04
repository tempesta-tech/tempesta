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

#include "clickhouse.h"
#include <iostream>
#include <clickhouse/client.h>
#include <clickhouse/base/socket.h>

using namespace std;
using namespace chrono;

#define MAX_MSEC 100
#define MAX_EVENTS 1000

#define NOW_MS() \
	duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count()


TfwClickhouse::TfwClickhouse(string host, string table_name,
			     unsigned int cpu_cnt, Block *(*cb)())
{
	unsigned int i;

	block_callback = cb;
	this->table_name = table_name;
	this->cpu_cnt = cpu_cnt;

	tasks = new TfwTask[cpu_cnt];

	for (i = 0; i < cpu_cnt; ++i) {
		tasks[i].client = new Client(ClientOptions().SetHost(move(host)));
		tasks[i].block = cb();
		tasks[i].last_time = NOW_MS();
	}
}

TfwClickhouse::~TfwClickhouse()
{
	unsigned int i;

	for (i = 0; i < cpu_cnt; ++i) {
		delete tasks[i].client;
		delete tasks[i].block;
	}

	delete tasks;
}

Block *
TfwClickhouse::getBlock(unsigned int cpu)
{
	return tasks[cpu].block;
}

void
TfwClickhouse::commit(unsigned int cpu)
{
	TfwTask *task = &tasks[cpu];
	uint64_t now = NOW_MS();

	task->block->RefreshRowCount();
	if ((now - task->last_time > MAX_MSEC && task->block->GetRowCount() > 0)
		|| task->block->GetRowCount() > MAX_EVENTS) {

		task->client->Insert(move(table_name), *task->block);
		delete task->block;

		task->block = block_callback();
		task->last_time = now;
	}
}
