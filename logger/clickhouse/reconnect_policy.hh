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

#include <chrono>
#include <algorithm>

/**
 * The most Clickhouse API errors can be handled with simple connection
 *  reset and reconnection
 *
 * https://github.com/ClickHouse/clickhouse-cpp/issues/184
 *
 * We start with zero reconnection timeout. However, the database can
 * be restarted, so we use indefinite loop with double backoff in
 * reconnection attempts.
 */

/**
 * Implements a simple exponential backoff policy for reconnect attempts.
 * Keeps track of successive failures and calculates the next allowed
 * retry time. Can be used for clients, tables, or queries that need
 * delayed retry after failure.
 */
class ReconnectPolicy {
public:
	using Clock = std::chrono::steady_clock;

	ReconnectPolicy(std::chrono::milliseconds initial = std::chrono::seconds(1),
			std::chrono::milliseconds max_delay = std::chrono::minutes(1))
		: initial_delay_(initial), max_delay_(max_delay), next_retry_(Clock::now())
	{}

	// Returns true if a new attempt can be made now
	bool can_attempt() const
	{
		return Clock::now() >= next_retry_;
	}

	// Call after a successful attempt to reset the backoff
	void on_success()
	{
		attempts_ = 0;
		delay_ = std::chrono::milliseconds(0);
		next_retry_ = Clock::now();
	}

	// Call after a failed attempt to update backoff delay
	void on_failure()
	{
		++attempts_;
		if (attempts_ == 1)
			delay_ = initial_delay_;
		else
			delay_ = std::min(delay_ * 2, max_delay_);

		next_retry_ = Clock::now() + delay_;
	}

private:
	const std::chrono::milliseconds initial_delay_;	// delay after second failure
	const std::chrono::milliseconds max_delay_;	// maximum delay

	int attempts_ = 0;				// consecutive failure count
	std::chrono::milliseconds delay_{0};		// current delay
	Clock::time_point next_retry_;			// time point of next allowed attempt
};
