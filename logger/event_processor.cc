
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

#include "../libtus/error.hh"
#include "event_processor.hh"

EventProcessor::EventProcessor(std::shared_ptr<TfwClickhouse> db,
			       unsigned processor_id)
	: processor_id(processor_id)
	, db_(std::move(db))
{
}

bool
EventProcessor::make_background_work() noexcept
{
	return flush(true);
}

bool
EventProcessor::flush(bool force) noexcept
{
	if (!handle_reconnection()) {
		spdlog::debug("DB flushing skipped due to reconnection issues");
		return false;
	}

	if (!db_->commit(force ? TfwClickhouse::FORCE : false)) {
		db_->needs_reconnect.store(true, std::memory_order_release);
		return false;
	}

	return true;
}

tus::Error<bool>
EventProcessor::consume_event()
{
	auto reconnect_result = handle_reconnection();
	if (!reconnect_result) {
		return tus::error(tus::Err::DB_CLT_TRANSIENT);
	}

	return do_consume_event();
}

bool
EventProcessor::handle_reconnection()
{
	if (!db_->needs_reconnect.load(std::memory_order_acquire))
		return true;

	if (!db_->should_attempt_reconnect())
		return false;

	spdlog::info("Attempting reconnection for processor {}", processor_id);

	db_->last_reconnect_attempt.store(
		std::chrono::steady_clock::now(),
		std::memory_order_release
	);

	bool success = false;
	try {
		success = db_->do_reconnect();
	} catch (...) {
		success = false;
	}

	db_->update_reconnect_timeout(success);

	if (success) {
		db_->needs_reconnect.store(false,
					   std::memory_order_release);
		spdlog::info("Reconnection successful for processor {}",
			     processor_id);
		return true;
	} else {
		db_->needs_reconnect.store(true,
					   std::memory_order_release);
		return false;
	}
}
