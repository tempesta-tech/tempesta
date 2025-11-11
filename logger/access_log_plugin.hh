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

#include "../libtus/error.hh"
#include "../fw/mmap_buffer.h"

#include "event_processor.hh"

class AccessLogProcessor : public EventProcessor {
public:
	explicit AccessLogProcessor(std::shared_ptr<TfwClickhouse> db,
				    unsigned processor_id,
				    int device_fd);
	~AccessLogProcessor() noexcept override;

	void request_stop() noexcept override;
	bool stop_requested() noexcept override;
	unsigned int get_cpu_id() const noexcept;

private:
	tus::Error<bool> do_consume() override;

private:
	int	     device_fd_;
	TfwMmapBuffer   *buffer_;
	size_t	  size_;
};
