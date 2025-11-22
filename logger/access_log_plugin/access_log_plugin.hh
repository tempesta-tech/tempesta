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

#include "../../libtus/error.hh"
#include "../../fw/mmap_buffer.h"

#include "../clickhouse/clickhouse.hh"
#include "../plugin_processor_iface.hh"

#include "access_log_clickhouse.hh"

class AccessLogProcessor final: public IPluginProcessor
{
public:
	explicit AccessLogProcessor(std::unique_ptr<TfwClickhouse> writer,
				    unsigned cpu_id,
				    int device_fd,
				    const char* table_name,
				    size_t max_events);
	~AccessLogProcessor() override;

public:
	//Part of plugin API
	virtual int is_active() noexcept override;
	virtual void request_stop() noexcept override;

	virtual int consume(int* cnt) noexcept override;
	virtual int send(bool force) noexcept override;

	virtual std::string_view name() const noexcept override;
private:
	AccessLogClickhouseDecorator writer_;

	int		device_fd_;
	TfwMmapBuffer	*buffer_;
	size_t		size_;
};
