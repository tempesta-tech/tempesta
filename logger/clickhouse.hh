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
#include <string>

#include <clickhouse/client.h>
#include <clickhouse/types/types.h>

#include "../libtus/error.hh"

namespace ch = clickhouse;

/**
 * Class for sending records to a Clickhouse database.
 *
 * Constructor:
 *    @TfwClickhouse - Initializes the Clickhouse connection and create a data
 *        block.
 *
 * Other public methods:
 *    @flush - Commits the data from the block to the Clickhouse database.
 * If a block was committed return true, otherwise return false.
 *
 * Private Members:
 *    @client_ - Clickhouse Client instance for sending data to the database.
 *    @client_options_ - settings to establish new connection
 */
class TfwClickhouse {
public:
	TfwClickhouse(ch::ClientOptions &&client_options);
	virtual ~TfwClickhouse() {}

public:
	TfwClickhouse(const TfwClickhouse &) = delete;
	TfwClickhouse &operator=(const TfwClickhouse &) = delete;

public:
	virtual bool execute(const std::string &query) noexcept;

	virtual bool
	flush(const std::string &table_name, ch::Block &block) noexcept;
public:
	bool reestablish_connection() noexcept;

private:
	const ch::ClientOptions		client_options_;
	std::unique_ptr<ch::Client>	client_;
};

std::shared_ptr<ch::Column>
tfw_column_factory(ch::Type::Code code);
