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

#include <stdexcept>

#include <spdlog/spdlog.h>

#include "../../libtus/error.hh"
#include "clickhouse_with_reconnect.hh"

ClickhouseWithReconnection::ClickhouseWithReconnection(ch::ClientOptions &&client_options)
	: TfwClickhouse(std::forward<ch::ClientOptions>(client_options))
{
}

bool
ClickhouseWithReconnection::execute(const std::string &query) noexcept
{
	if (!handle_reconnection()) {
		spdlog::debug("Query '{}' execution skipped due to reconnection issues", query);
		return false;
	}
	return TfwClickhouse::execute(query);
}

bool
ClickhouseWithReconnection::flush(const std::string &table_name, ch::Block &block) noexcept
{
	if (!handle_reconnection()) {
		spdlog::debug("DB flushing skipped due to reconnection issues");
		return false;
	}

	if (TfwClickhouse::flush(table_name, block))
		return true;

	needs_reconnect_ = true;
	return false;
}

bool
ClickhouseWithReconnection::handle_reconnection()
{
	if (!needs_reconnect_) [[likely]]
		return true;

	if (!reconnect_attempt_allowed())
		return false;

	spdlog::info("TfwClickhouse: reconnection attempt.");

	last_reconnect_attempt_ = std::chrono::steady_clock::now();

	bool success = do_reconnect();
	if (success) {
		needs_reconnect_ = false;
		spdlog::info("TfwClickhouse: reconnection was successful.");
		return true;
	} else {
		needs_reconnect_ = true;
		return false;
	}
}

bool
ClickhouseWithReconnection::reconnect_attempt_allowed() const noexcept
{
	assert(needs_reconnect_);

	auto now = std::chrono::steady_clock::now();
	return (now - last_reconnect_attempt_) >= reconnect_timeout_;
}

void
ClickhouseWithReconnection::update_reconnect_timeout(bool success) noexcept
{
	if (success) {
		reconnect_timeout_ = std::chrono::seconds(0);
		return;
	}

	if (reconnect_timeout_.count() == 0)
		reconnect_timeout_ = std::chrono::seconds(1);
	else if (reconnect_timeout_.count() < 300)
		reconnect_timeout_ *= 2;
}

bool
ClickhouseWithReconnection::do_reconnect() noexcept
{
	bool success = reestablish_connection();
	if (success)
		needs_reconnect_ = false;

	last_reconnect_attempt_ = std::chrono::steady_clock::now();
	update_reconnect_timeout(success);
	return success;
}
