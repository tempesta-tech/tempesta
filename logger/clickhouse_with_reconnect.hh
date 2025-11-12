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

//TODO: what do we really wants to share? ClickhouseWithReconnection or Clickhouse
//TODO: we also need to create wrapper for every plugin to make a plugin-dependings
//initialization and get rid of mane append methods
class ClickhouseWithReconnection {
public:
	ClickhouseWithReconnection(std::shared_ptr<TfwClickhouse> db,
				   unsigned processor_id);
	virtual ~ClickhouseWithReconnection() noexcept = default;

	ClickhouseWithReconnection(const ClickhouseWithReconnection&) = delete;
	ClickhouseWithReconnection& operator=(const ClickhouseWithReconnection&) = delete;

public:
	template<TfwBinLogFields FieldType>
	void append(
		const typename TfwBinLogTypeTraits<FieldType>::ValType& value)
	{
		return db_->append<FieldType>(value);
	}

	void append_timestamp(uint64_t timestamp)
	{
		return db_->append_timestamp(timestamp);
	}
	bool handle_block_error() noexcept
	{
		return db_->handle_block_error();
	}
public:
	bool flush(bool force = false) noexcept;

private:
	bool handle_reconnection();

private:
	const unsigned			processor_id_;
	std::shared_ptr<TfwClickhouse>	db_;
};
