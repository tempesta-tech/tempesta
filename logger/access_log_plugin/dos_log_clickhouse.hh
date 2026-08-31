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

#include <netinet/in.h>
#include <string_view>
#include <span>

#include "../../fw/event_log.h"
#include "../clickhouse/clickhouse_decorator.hh"

template<TfwDosLogFields FieldType>
struct TfwDosLogTypeCommonTraits
{
	static constexpr size_t index = static_cast<size_t>(FieldType) + 1;
};

template<TfwDosLogFields FieldType>
struct TfwDosLogTypeTraits;

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_ADDR>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_ADDR>
{
	using ColType = ch::ColumnIPv6;
};

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_CLIENT_PORT>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_CLIENT_PORT>
{
	using ColType = ch::ColumnUInt16;
};

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_LOCAL_PORT>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_LOCAL_PORT>
{
	using ColType = ch::ColumnUInt16;
};

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_EVENT_TYPE>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_EVENT_TYPE>
{
	using ColType = ch::ColumnUInt16;
};

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_EVENT_BODY>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_EVENT_BODY>
{
	using ColType = ch::ColumnString;
};

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_IP_BLOCK>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_IP_BLOCK>
{
	using ColType = ch::ColumnUInt8;
};

template<>
struct TfwDosLogTypeTraits<TFW_DOS_LOG_DROPPED>
	: TfwDosLogTypeCommonTraits<TFW_DOS_LOG_DROPPED>
{
	using ColType = ch::ColumnUInt64;
};

/**
 * ClickHouse decorator specialized for access-log events.
 *
 * Provides type-safe append operations for various binlog fields defined
 * in TfwDosLogFields. Each field maps to the corresponding ClickHouse column
 * type using TfwDosLogTypeTraits.
 *
 * This decorator delegates table creation and block management to the
 * base ClickHouseDecorator class. It provides a convenient API for
 * appending timestamps and binlog field values without exposing
 * low-level block or table creation details.
 */
class DosLogClickhouseDecorator final: public ClickHouseDecorator
{
public:
	DosLogClickhouseDecorator(std::shared_ptr<IClickhouse> client,
		std::string_view table_name, size_t max_events);

public:
	/**
	 * Appends a timestamp value to the current block.
	 */
	void
	append_timestamp(uint64_t timestamp);
};
