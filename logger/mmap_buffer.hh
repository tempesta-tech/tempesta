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

#include <functional>
#include <span>
#include <string>
#include <thread>

#include "../fw/mmap_buffer.h"
#include "../libtus/error.hh"

#include "clickhouse.hh"

/**
 * Tempesta user space ring buffer reader
 * TfwMmapBufferReader is a reader from a ring buffer mapped into user space.
 * It monitors the buffer for new data. When new data is available, it invokes
 * a specified callback, providing a pointer to the start of the data, its size
 * and CPU number.
 *
 * Constructor:
 *    @TfwMmapBufferReader - Initializes own fields, maps the buffer.
 *
 * Destructor:
 *    @~TfwMmapBufferReader - Unmaps the buffer.
 *
 * Other public methods:
 *    @run - Main reading loop. Continuously checks if new data is available by
 *        polling the `is_ready` flag in the shared buffer and outer stop_flag.
 *        Calls `read()` to process data if available and notifies the callback.
 *    @get_cpu_id - Returns the CPU ID from the shared buffer.
 *
 * Private methods:
 *    @init_buffer_size - Retrieves the size of the ring buffer for proper data
 *        management and sets to the private size_ field.
 *    @read - checks if there is a new data block and executes the callback when
 *        new data is detected.
 */
class TfwMmapBufferReader {
public:
	using ProcessEventsFn = std::function<tus::Error<size_t> (std::span<const char>)>;

	TfwMmapBufferReader(const unsigned int ncpu, const int fd,
			    TfwClickhouse &db, ProcessEventsFn proc_ev);
	TfwMmapBufferReader(const TfwMmapBufferReader &) = delete;
	TfwMmapBufferReader &operator=(const TfwMmapBufferReader &) = delete;
	~TfwMmapBufferReader();

	[[nodiscard]] bool run(std::atomic<bool> &stop_flag) noexcept;
	unsigned int get_cpu_id() const noexcept;

private:
	TfwMmapBuffer	*buf_;
	size_t		size_;
	ProcessEventsFn	proc_ev_;
	TfwClickhouse	&db_;

	void init_buffer_size(const int fd);
	tus::Error<bool> read() noexcept;
};
