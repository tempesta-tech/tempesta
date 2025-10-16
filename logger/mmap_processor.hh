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

#include <string>
#include <memory>

#include "../libtus/error.hh"
#include "tfw_logger_plugin.hh"
#include "event_processor.hh"

class MmapProcessor : public EventProcessor {
public:
	explicit MmapProcessor(std::shared_ptr<TfwClickhouse> db,
			       int device_fd
			       const TfwLoggerProcessorContext &context);
	~MmapProcessor() override;

	tus::Error<bool> consume_event() override;
	void make_background_work() override;
	[[nodiscard]] void flush(bool force = false) noexcept override;

private:
	int device_fd_;
	int cpu_id_;
	std::atomic<bool> *stop_flag_;
	TfwMmapBuffer *buffer_;
	size_t size_;
};
