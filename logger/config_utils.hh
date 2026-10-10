/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
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
#include <regex>
#include <stdexcept>

namespace cfg_utils {

inline void
validate_table_name(const std::string &table_name)
{
	// Check length limit (ClickHouse uses filesystem, 128 should be enough)
	if (table_name.length() > 128)
		throw std::runtime_error(
				"Table name is too long (max 128 characters): "
				+ table_name);

	// Check for allowed characters only: A-Z, a-z, 0-9, _
	std::regex valid_name_regex;
	valid_name_regex.imbue(std::locale::classic());
	valid_name_regex.assign(R"(^[A-Za-z0-9_]+$)");
	if (!std::regex_match(table_name, valid_name_regex))
		throw std::runtime_error("Table name contains invalid characters. "
					 "Only A-Z, a-z, 0-9, and _ are allowed: "
					 + table_name);
}

} // cfg_utils
