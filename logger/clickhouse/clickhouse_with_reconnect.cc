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

ClickhouseWithReconnection::ClickhouseWithReconnection(const ch::ClientOptions &client_options)
	: TfwClickhouse(client_options)
{
}

bool
ClickhouseWithReconnection::execute(const std::string &query) noexcept
{
	if (!ensure_connected()) {
		spdlog::debug("Query '{}' execution skipped due to reconnection issues", query);
		return false;
	}
	if (TfwClickhouse::execute(query))
		return true;

	needs_reconnect_ = true;
	return false;
}

bool
ClickhouseWithReconnection::flush(const std::string &table_name, ch::Block &block) noexcept
{
	if (!ensure_connected()) {
		spdlog::debug("Flushing skipped due to reconnection issues");
		return false;
	}

	if (TfwClickhouse::flush(table_name, block))
		return true;

	needs_reconnect_ = true;
	return false;
}

bool
ClickhouseWithReconnection::ensure_connected() noexcept
{
	if (!needs_reconnect_) [[likely]]
		return true;

	if (!reconnect_policy_.can_attempt())
		return false;

	return do_reconnect();
}

bool
ClickhouseWithReconnection::do_reconnect() noexcept
{
	spdlog::info("Clickhouse reconnect attempt. ");

	const bool success = reestablish_connection();

	spdlog::info("Clickhouse reconnection result = {}.",
		     success? "success": "fail");

	if (success) {
		needs_reconnect_ = false;
		reconnect_policy_.on_success();
	}
	else {
		needs_reconnect_ = true;
		reconnect_policy_.on_failure();
	}
	return success;
}
