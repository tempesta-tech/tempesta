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

/**
 * Wrapper around a ClickHouse client with automatic reconnection logic.
 *
 * This class tracks the connection state and performs a reconnect on the next
 * access if needed. If a connection attempt fails, the timeout before the next
 * reconnect attempt is increased in a backoff manner: initially 0 seconds, then
 * 1 second, and subsequently multiplied by 2 on each failure.
 *
 * NOTE: This class is not thread-safe. Concurrent access must be externally synchronized.
 *
 * TODO: Consider changing the design to perform the reconnect immediately
 * rather than waiting for the next access.
 */
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

	//should be called only if needs_reconnect_ = true
	bool reconnect_attempt_allowed() const noexcept;

	void update_reconnect_timeout(bool success) noexcept;
	bool do_reconnect() noexcept;

private:
	bool needs_reconnect_{false};
	std::chrono::steady_clock::time_point
		last_reconnect_attempt_{
			std::chrono::steady_clock::time_point::min()};
	// The most Clickhouse API errors can be handled with simple connection
	// reset and reconnection
	//
	//   https://github.com/ClickHouse/clickhouse-cpp/issues/184
	//
	// We start with zero reconnection timeout. However, the database can
	// be restarted, so we use indefinite loop with double backoff in
	// reconnection attempts.
	std::chrono::seconds reconnect_timeout_{std::chrono::seconds(0)};
};
