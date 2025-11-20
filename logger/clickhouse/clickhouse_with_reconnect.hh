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
#pragma once

#include <memory>

#include "clickhouse.hh"

class ClickhouseWithReconnection final: public TfwClickhouse {
public:
	ClickhouseWithReconnection(ch::ClientOptions &&client_options);
	~ClickhouseWithReconnection() noexcept = default;

public:
	ClickhouseWithReconnection(const ClickhouseWithReconnection&) = delete;
	ClickhouseWithReconnection& operator=(const ClickhouseWithReconnection&) = delete;

public:
	virtual bool
	execute(const std::string &query) noexcept override;

	virtual bool
	flush(const std::string &table_name, ch::Block &block) noexcept override;

private:
	bool handle_reconnection();

private:
	bool should_attempt_reconnect() const noexcept;
	void update_reconnect_timeout(bool success) noexcept;
	bool do_reconnect() noexcept;

private:
	std::atomic<bool> needs_reconnect{false};
	std::atomic<std::chrono::steady_clock::time_point>
		last_reconnect_attempt{
			std::chrono::steady_clock::time_point::min()};
	// The most Clickhouse API errors can be handled with simple connection
	// reset and reconnection
	//
	//   https://github.com/ClickHouse/clickhouse-cpp/issues/184
	//
	// We start with zero reconnection timeout. However, the database can
	// be restarted, so we use indefinite loop with double backoff in
	// reconnection attempts.
	std::atomic<std::chrono::seconds> reconnect_timeout{
		std::chrono::seconds(0)
	};
};
