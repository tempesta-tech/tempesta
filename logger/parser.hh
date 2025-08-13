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

#include <cstddef>
#include <optional>
#include <span>

#include "../fw/access_log.h"
#include "access_log.hh"

class Parser {
public:
	using Bytes = std::span<const std::byte>;

	explicit Parser(Bytes data) : data_(data)
	{
	}

	[[nodiscard]] std::optional<AccessLog>
	parse_next_event();

private:
	[[nodiscard]] std::optional<AccessLog>
	parse_access_log_event(const TfwBinLogEvent &event);

private:
	Bytes data_;
};
