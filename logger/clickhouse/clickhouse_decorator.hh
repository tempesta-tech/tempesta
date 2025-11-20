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
	static const bool FORCE = true;

	struct TfwField
	{
		const char	*name;
		ch::Type::Code	code;
	};

	/**
	 * table_creation_query_template, table_name, fields has to have static lifetime
	 */
	ClickHouseDecorator(std::unique_ptr<TfwClickhouse> client,
			    std::string_view table_creation_query_template,
			    std::string_view table_name,
			    std::span<const TfwField> fields,
			    size_t max_events);

	virtual ~ClickHouseDecorator();

public:
	bool
	handle_block_error() noexcept;

	bool
	flush(bool force = false) noexcept;

private:
	static ch::Block
	make_block(std::span<const TfwField> fields, size_t max_events);

private:
	const std::string			table_name_;
	const std::span<const TfwField>		table_fields_;
	const size_t				max_events_;

	std::unique_ptr<TfwClickhouse>		client_;

protected:
	ch::Block				block_;
};