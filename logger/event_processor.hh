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

#include "../libtus/error.hh"
#include "clickhouse.hh"
#include "plugin_interface.hh"

class EventProcessor {
public:
	EventProcessor(std::shared_ptr<TfwClickhouse> db,
		       unsigned processor_id);
	virtual ~EventProcessor() noexcept = default;

	EventProcessor(const EventProcessor&) = delete;
	EventProcessor& operator=(const EventProcessor&) = delete;

	bool make_background_work() noexcept;
	[[nodiscard]] bool flush(bool force = false) noexcept;
	virtual tus::Error<bool> consume_event();

	virtual void request_stop() noexcept = 0;
	virtual bool stop_requested() noexcept = 0;

public:
	const unsigned processor_id;

protected:
	virtual tus::Error<bool> do_consume_event() = 0;

protected:
	std::shared_ptr<TfwClickhouse> db_;

private:
	bool handle_reconnection();
};
