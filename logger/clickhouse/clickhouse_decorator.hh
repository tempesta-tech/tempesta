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

#include <span>

#include <clickhouse/block.h>

#include "clickhouse.hh"

class ClickHouseDecorator {
public:
	struct TfwField
	{
		const char	*name;
		ch::Type::Code	code;
	};

	/**
	 * table_creation_query_template, fields have to have static lifetime.
	 */
	ClickHouseDecorator(std::unique_ptr<IClickhouse> client,
			    std::string_view table_creation_query_template,
			    std::string_view table_name,
			    std::span<const TfwField> fields,
			    size_t max_events);

	virtual ~ClickHouseDecorator();

public:
	bool
	ensure_connected() noexcept;

	bool
	handle_block_error() noexcept;

	// Currently 'force' is a runtime parameter, but if we made it a template
	// parameter, we could eliminate one runtime branch.
	bool
	flush(bool force = false) noexcept;

private:
	static ch::Block
	make_block(std::span<const TfwField> fields, size_t max_events);

	bool ensure_table_created() noexcept;

private:
	const std::string			table_name_;
	const std::string			table_creation_query_;
	const size_t				max_events_;

	bool					needs_create_table_{true};
	std::unique_ptr<IClickhouse>		client_;

protected:
	ch::Block				block_;
};