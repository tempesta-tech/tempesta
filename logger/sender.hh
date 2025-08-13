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

#pragma once

#include <chrono>
#include <memory>
#include <string>

#include <clickhouse/block.h>
#include <clickhouse/client.h>

#include "access_log.hh"
#include "clickhouse_config.hh"

class Sender {
public:
	Sender(const ClickHouseConfig &config,
	       std::unique_ptr<clickhouse::Client> client);

	[[nodiscard]] bool
	add(AccessLog &&log);

	[[nodiscard]] bool
	commit();

private:
	[[nodiscard]] bool
	insert();

private:
	std::string table_name_;
	size_t max_events_;
	std::chrono::milliseconds max_wait_;
	std::unique_ptr<clickhouse::Client> client_;
	clickhouse::Block block_;
	std::chrono::system_clock::time_point last_commit_time_;
};

std::optional<Sender>
make_sender(const ClickHouseConfig &config);
