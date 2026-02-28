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

template<TfwWebAttackLogFields FieldType>
struct TfwWebAttackLogTypeCommonTraits
{
	static constexpr size_t index = static_cast<size_t>(FieldType) + 1;
};

template<TfwWebAttackLogFields FieldType>
struct TfwWebAttackLogTypeTraits;

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_ADDR>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_ADDR>
{
	using ColType = ch::ColumnIPv6;
};

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_CLIENT_PORT>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_CLIENT_PORT>
{
	using ColType = ch::ColumnUInt16;
};

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_LOCAL_PORT>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_LOCAL_PORT>
{
	using ColType = ch::ColumnUInt16;
};

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_EVENT_TYPE>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_EVENT_TYPE>
{
	using ColType = ch::ColumnUInt16;
};

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_EVENT_BODY>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_EVENT_BODY>
{
	using ColType = ch::ColumnString;
};

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_IP_BLOCK>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_IP_BLOCK>
{
	using ColType = ch::ColumnUInt8;
};

template<>
struct TfwWebAttackLogTypeTraits<TFW_WA_LOG_DROPPED>
	: TfwWebAttackLogTypeCommonTraits<TFW_WA_LOG_DROPPED>
{
	using ColType = ch::ColumnUInt64;
};

/**
 * ClickHouse decorator specialized for web attack log events.
 */
class WebAttackLogClickhouseDecorator final: public ClickHouseDecorator
{
public:
	WebAttackLogClickhouseDecorator(std::shared_ptr<IClickhouse> client,
		std::string_view table_name, size_t max_events);

public:
	/**
	 * Appends a timestamp value to the current block.
	 */
	void
	append_timestamp(uint64_t timestamp);
};
