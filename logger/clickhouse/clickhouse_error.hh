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
#include "../../libtus/error.hh"

enum ClickhouseErrorEnum : uint16_t {
	DB_SRV_FATAL		= 1,
	DB_CLT_TRANSIENT	= 2,
};

static constexpr std::string_view message(ClickhouseErrorEnum e)
{
	using namespace std::literals;

	switch (e) {
	case ClickhouseErrorEnum::DB_SRV_FATAL:
		return "Database unrecoverable server error"sv;
	case ClickhouseErrorEnum::DB_CLT_TRANSIENT:
		return "Database recoverable client error"sv;
	}
	return {};
}

using ClickhouseError = tus::Error<ClickhouseErrorEnum, tus::TfwCategory>;