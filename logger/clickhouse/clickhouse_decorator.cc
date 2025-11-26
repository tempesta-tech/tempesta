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

#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include "../../libtus/error.hh"
#include "clickhouse_decorator.hh"

ClickHouseDecorator::ClickHouseDecorator(std::unique_ptr<IClickhouse> client,
			    std::string_view table_template,
			    std::string_view table_name,
			    std::span<const TfwField> fields,
			    size_t max_events)
	: table_name_(table_name)
	, table_creation_query_(fmt::format(fmt::runtime(table_template), table_name_))
	, max_events_(max_events)
	, client_(std::move(client))
	, block_(make_block(fields, max_events))
{
	ensure_table_created();
}

ClickHouseDecorator::~ClickHouseDecorator()
{
	if (!flush(true))
		handle_block_error();
}

bool
ClickHouseDecorator::ensure_table_created() noexcept
{
	if (!needs_create_table_) [[likely]]
		return true;

	needs_create_table_ = client_->execute(table_creation_query_);
	return needs_create_table_;
}

bool
ClickHouseDecorator::ensure_connected() noexcept
{
	return client_->ensure_connected();
}

bool
ClickHouseDecorator::handle_block_error() noexcept
{
	try {
		block_.Clear();
		return true;
	}
	catch (const std::exception &e) {
		spdlog::error("Cannot clear a Clickhouse block: {}", e.what());
		return false;
	}
}

bool
ClickHouseDecorator::flush(bool force) noexcept
{
	if (!ensure_table_created())
		return false;

	try {
		block_.RefreshRowCount();

		if (force) {
			if (block_.GetRowCount() == 0)
				return true;
		} else {
			if (block_.GetRowCount() < max_events_)
				return true;
		}

		// We don't want to miss events
		const bool res = client_->flush(table_name_, block_);
		if (res)
			block_.Clear();

		return res;
	}
	catch (const std::exception &e) {
		spdlog::error("Clickhouse insert error: {}", e.what());
		return false;
	}
}

ch::Block
ClickHouseDecorator::make_block(std::span<const TfwField> fields, size_t max_events)
{
	auto block = ch::Block();

	for (const auto& field : fields) {
		auto col = tfw_column_factory(field.code);
		block.AppendColumn(field.name, col);
	}

	// We may read more data in one shot, so reserve more memory.
	block.Reserve(max_events * 2);
	return block;
}